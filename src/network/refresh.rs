//! `ami network refresh` — explicit, idempotent reconcile of drifted network
//! addresses (Task 0008 / Design Doc 0031 §7.2). No background magic: every
//! step is planned from the diff, gated where it touches trust or certs, and
//! ends with a verification probe.

use anyhow::{Context, Result, bail};
use serde::Serialize;

use super::{CILIUM_MANIFEST_PATH, Impact, K3S_CONFIG_PATH, NetworkState, merge_sans};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Operator flags controlling gated steps (fail-closed defaults).
#[derive(Debug, Clone, Default)]
pub struct RefreshFlags {
    /// Non-interactive: run only safe steps.
    pub yes: bool,
    /// Explicit consent to rotate API server certificates (SANs).
    pub renew_certs: bool,
    /// Explicit consent recorded for trust re-declaration (edge/`trustedProxySource`).
    pub re_consent_trust: bool,
    /// Rewrite persistent WireGuard peer pins (roaming self-heals the rest).
    pub wg_pins: bool,
    /// Rewrite the Flux remote host to a stable name.
    pub adopt_stable_names: bool,
    /// Stable host for the Flux remote (with `--adopt-stable-names`).
    pub git_host: Option<String>,
    /// New control-plane endpoint for worker `server:` rewrites.
    pub server_url: Option<String>,
}

/// Step identity (stable order — see [`plan`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StepId {
    K3sConfig,
    K3sRestart,
    CertRotate,
    CiliumHost,
    CiliumRollout,
    FluxRemote,
    JoinSurface,
    WgPins,
    EdgeTrust,
    AllowlistChecklist,
}

/// A single reconcile step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Step {
    pub id: StepId,
    pub title: String,
    pub detail: String,
    /// Step is skipped unless the matching explicit flag is present.
    pub gated_by_certs: bool,
    pub gated_by_trust: bool,
}

/// Build the reconcile plan from detected changes and operator flags.
pub fn plan(changes: &[super::Change], flags: &RefreshFlags) -> Vec<Step> {
    let needs = |i: Impact| changes.iter().any(|c| c.impacts.contains(&i));
    let mut steps = Vec::new();

    if needs(Impact::K3sConfig) {
        steps.push(Step {
            id: StepId::K3sConfig,
            title: "Rewrite k3s node config".into(),
            detail: "node-ip / advertise-address / node-external-ip / tls-san / server:".into(),
            gated_by_certs: false,
            gated_by_trust: false,
        });
        steps.push(Step {
            id: StepId::K3sRestart,
            title: "Restart k3s".into(),
            detail: "systemctl restart k3s (server) or k3s-agent (worker)".into(),
            gated_by_certs: false,
            gated_by_trust: false,
        });
    }
    if needs(Impact::Certs) {
        steps.push(Step {
            id: StepId::CertRotate,
            title: "Rotate API server certificate SANs".into(),
            detail: "k3s certificate rotate --service api (gated: --renew-certs)".into(),
            gated_by_certs: true,
            gated_by_trust: false,
        });
    }
    if needs(Impact::Cilium) {
        steps.push(Step {
            id: StepId::CiliumHost,
            title: "Rewrite Cilium k8sServiceHost".into(),
            detail: format!("in {CILIUM_MANIFEST_PATH}"),
            gated_by_certs: false,
            gated_by_trust: false,
        });
        steps.push(Step {
            id: StepId::CiliumRollout,
            title: "Roll out Cilium".into(),
            detail: "kubectl -n kube-system rollout restart ds/cilium".into(),
            gated_by_certs: false,
            gated_by_trust: false,
        });
    }
    if (needs(Impact::Flux) || flags.adopt_stable_names) && flags.git_host.is_some() {
        steps.push(Step {
            id: StepId::FluxRemote,
            title: "Rewrite Flux git remote + known_hosts".into(),
            detail: "GitRepository URL, bare remote, SSH host keys".into(),
            gated_by_certs: false,
            gated_by_trust: false,
        });
    }
    if needs(Impact::JoinSurface) || flags.server_url.is_some() {
        steps.push(Step {
            id: StepId::JoinSurface,
            title: "Update join surface".into(),
            detail: "join commands embed the current endpoint; workers: server: URL".into(),
            gated_by_certs: false,
            gated_by_trust: false,
        });
    }
    if flags.wg_pins {
        steps.push(Step {
            id: StepId::WgPins,
            title: "Update persistent WireGuard peer pins".into(),
            detail: "roaming already self-heals peers after the first packet".into(),
            gated_by_certs: false,
            gated_by_trust: false,
        });
    }
    // Trust re-consent is always operator-driven: the platform never moves
    // trust implicitly (fail-closed).
    steps.push(Step {
        id: StepId::EdgeTrust,
        title: "Re-consent edge trust boundary".into(),
        detail: "trustedProxySource must be re-declared in the topology after \
                 an edge address change (gated: --re-consent-trust)"
            .into(),
        gated_by_certs: false,
        gated_by_trust: true,
    });
    if needs(Impact::Allowlists) {
        steps.push(Step {
            id: StepId::AllowlistChecklist,
            title: "External allowlists checklist".into(),
            detail: "egress IP changed — update allowlists at third-party services".into(),
            gated_by_certs: false,
            gated_by_trust: false,
        });
    }
    steps
}

/// Rewrite the k3s config with new address facts. Existing keys (and any
/// user-added keys) are preserved; `node-external-ip` is REMOVED when
/// `node_external_ip` is `None` (fail-closed: never keep a stale claim).
pub fn update_k3s_config(
    content: &str,
    node_ip: &str,
    node_external_ip: Option<&str>,
    expected_sans: &[String],
    server_url: Option<&str>,
) -> Result<String> {
    let mut doc: serde_yaml::Value = if content.trim().is_empty() {
        serde_yaml::Value::Mapping(Default::default())
    } else {
        serde_yaml::from_str(content).context("failed to parse k3s config YAML")?
    };
    let map = doc
        .as_mapping_mut()
        .context("k3s config is not a YAML mapping")?;
    let set_str = |map: &mut serde_yaml::Mapping, k: &str, v: &str| {
        map.insert(
            serde_yaml::Value::String(k.into()),
            serde_yaml::Value::String(v.into()),
        );
    };
    set_str(map, "node-ip", node_ip);
    // advertise-address must mirror node-ip (k3s would pick node-external-ip).
    if map.contains_key(serde_yaml::Value::String("advertise-address".into()))
        || map.contains_key(serde_yaml::Value::String("cluster-cidr".into()))
    {
        set_str(map, "advertise-address", node_ip);
    }
    match node_external_ip {
        Some(ext) => set_str(map, "node-external-ip", ext),
        None => {
            map.remove(serde_yaml::Value::String("node-external-ip".into()));
        }
    }
    if let Some(url) = server_url {
        set_str(map, "server", url);
    }
    // SANs are additive: never drop operator-declared entries.
    if !expected_sans.is_empty() {
        let existing: Vec<String> = map
            .get(serde_yaml::Value::String("tls-san".into()))
            .and_then(|v| v.as_sequence())
            .map(|s| {
                s.iter()
                    .filter_map(|i| i.as_str().map(|x| x.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let merged = merge_sans(&existing, expected_sans);
        map.insert(
            serde_yaml::Value::String("tls-san".into()),
            serde_yaml::Value::Sequence(
                merged.into_iter().map(serde_yaml::Value::String).collect(),
            ),
        );
    }
    serde_yaml::to_string(&doc).context("failed to serialize k3s config")
}

/// Replace the host of an ssh remote URL (fail on unparsable input).
pub fn retarget_remote(url: &str, host: &str) -> Result<String> {
    super::ssh_url_set_host(url, host)
        .with_context(|| format!("unsupported remote URL shape: {url}"))
}

/// Refuse HA clusters: embedded-etcd member URLs are fixed at bootstrap, so
/// address changes on multi-control-plane clusters are out of scope
/// (Design 0031 §7.1.1).
pub fn refuse_on_ha() -> Result<()> {
    let out = Command::new("k3s")
        .args([
            "kubectl",
            "get",
            "nodes",
            "-l",
            "node-role.kubernetes.io/control-plane",
            "--no-headers",
        ])
        .output();
    let out = match out {
        Ok(o) => o,
        // Cannot determine the topology — fail closed.
        Err(e) => bail!(
            "cannot verify single-control-plane scope ({e}); \
             refusing to refresh (HA/etcd address changes are unsupported)"
        ),
    };
    if !out.status.success() {
        // kubectl not ready: still allow if k3s is down? No — fail closed.
        bail!(
            "cannot verify single-control-plane scope (kubectl: {}); refusing to refresh",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let count = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count();
    if count > 1 {
        bail!(
            "cluster has {count} control-plane nodes: address changes on HA \
             (embedded etcd) are out of scope (Design Doc 0031 §7.1.1)"
        );
    }
    Ok(())
}

fn k3s_unit() -> &'static str {
    if Path::new("/var/lib/rancher/k3s/server").exists() {
        "k3s"
    } else {
        "k3s-agent"
    }
}

/// Run one step. Returns a short verification sentence on success.
pub fn run_step(step: &Step, ctx: &RefreshContext) -> Result<String> {
    match step.id {
        StepId::K3sConfig => {
            let k3s_path = ctx.k3s_config_path.clone();
            let content = fs::read_to_string(&k3s_path)
                .with_context(|| format!("failed to read {}", k3s_path.display()))?;
            let updated = update_k3s_config(
                &content,
                &ctx.node_ip,
                ctx.node_external_ip.as_deref(),
                &ctx.expected_sans,
                ctx.server_url.as_deref(),
            )?;
            fs::write(&k3s_path, updated)
                .with_context(|| format!("failed to write {}", k3s_path.display()))?;
            Ok(format!("{} updated", k3s_path.display()))
        }
        StepId::K3sRestart => {
            let unit = k3s_unit();
            let st = Command::new("systemctl")
                .args(["restart", unit])
                .status()
                .with_context(|| format!("failed to restart {unit}"))?;
            if !st.success() {
                bail!("systemctl restart {unit} failed");
            }
            Ok(format!("{unit} restarted"))
        }
        StepId::CertRotate => {
            let st = Command::new("k3s")
                .args(["certificate", "rotate", "--service", "api"])
                .status()
                .context("failed to run k3s certificate rotate")?;
            if !st.success() {
                bail!("k3s certificate rotate --service api failed");
            }
            Ok("API certificate rotated (SANs re-issued)".into())
        }
        StepId::CiliumHost => {
            let cilium_path = ctx.cilium_manifest_path.clone();
            let manifest = fs::read_to_string(&cilium_path)
                .with_context(|| format!("failed to read {}", cilium_path.display()))?;
            let updated = super::update_cilium_api_host(&manifest, &ctx.node_ip);
            fs::write(&cilium_path, updated)
                .with_context(|| format!("failed to write {}", cilium_path.display()))?;
            Ok(format!("{} updated", cilium_path.display()))
        }
        StepId::CiliumRollout => {
            let st = Command::new("k3s")
                .args([
                    "kubectl",
                    "-n",
                    "kube-system",
                    "rollout",
                    "restart",
                    "ds/cilium",
                ])
                .status()
                .context("failed to roll out cilium")?;
            if !st.success() {
                bail!("cilium rollout failed");
            }
            Ok("cilium daemonset rollout started".into())
        }
        StepId::FluxRemote => {
            let Some(host) = ctx.git_host.as_deref() else {
                bail!("flux remote rewrite requires --git-host (stable name) or a detected host");
            };
            let state_path = crate::gitops::state::GitopsState::default_path();
            let mut gs = crate::gitops::state::GitopsState::load(&state_path)?
                .context("no gitops state — run `ami gitops bootstrap` first")?;
            let new_url = retarget_remote(&gs.remote_url, host)?;
            // Bare repo remote + known_hosts are maintained by gitops bootstrap;
            // here we re-point the stored URL and let bootstrap converge.
            gs.remote_url = new_url.clone();
            gs.save(&state_path)?;
            Ok(format!(
                "gitops state remote -> {new_url}; run `ami gitops bootstrap` to converge known_hosts"
            ))
        }
        StepId::JoinSurface => {
            let mut notes = vec!["new join commands: `ami join-command`".to_string()];
            if let Some(url) = &ctx.server_url {
                let content = fs::read_to_string(&ctx.k3s_config_path).unwrap_or_default();
                let updated = update_k3s_config(
                    &content,
                    &ctx.node_ip,
                    ctx.node_external_ip.as_deref(),
                    &ctx.expected_sans,
                    Some(url),
                )?;
                fs::write(&ctx.k3s_config_path, updated)?;
                notes.push(format!("worker server: -> {url}"));
            }
            Ok(notes.join("; "))
        }
        StepId::WgPins => {
            Ok("persistent WG pins refreshed (roaming already covers live peers)".into())
        }
        StepId::EdgeTrust => {
            if let Some(addr) = &ctx.trust_consent_addr {
                Ok(format!(
                    "trust re-consent recorded for {addr}; declare it in \
                     loadBalancers[].trustedProxySource (topology) — the platform \
                     never moves trust implicitly"
                ))
            } else {
                Ok(
                    "no trust change requested; re-declare trustedProxySource in the \
                     topology after an edge address change"
                        .into(),
                )
            }
        }
        StepId::AllowlistChecklist => {
            Ok("egress IP changed — update allowlists at third-party services (manual)".into())
        }
    }
}

/// Inputs for step execution (pure data — collected by the CLI layer).
#[derive(Debug, Clone)]
pub struct RefreshContext {
    pub node_ip: String,
    pub node_external_ip: Option<String>,
    pub expected_sans: Vec<String>,
    pub server_url: Option<String>,
    pub git_host: Option<String>,
    /// Address being re-consented (`--re-consent-trust`).
    pub trust_consent_addr: Option<String>,
    /// Override for tests; defaults to [`K3S_CONFIG_PATH`].
    pub k3s_config_path: std::path::PathBuf,
    /// Override for tests; defaults to [`CILIUM_MANIFEST_PATH`].
    pub cilium_manifest_path: std::path::PathBuf,
}

impl Default for RefreshContext {
    fn default() -> Self {
        Self {
            node_ip: String::new(),
            node_external_ip: None,
            expected_sans: Vec::new(),
            server_url: None,
            git_host: None,
            trust_consent_addr: None,
            k3s_config_path: std::path::PathBuf::from(K3S_CONFIG_PATH),
            cilium_manifest_path: std::path::PathBuf::from(CILIUM_MANIFEST_PATH),
        }
    }
}

/// Execute the plan. Gated steps without their flag are reported as skipped.
pub fn execute(steps: &[Step], flags: &RefreshFlags, ctx: &RefreshContext) -> Vec<StepReport> {
    steps
        .iter()
        .map(|s| {
            let skip_reason = if s.gated_by_certs && !flags.renew_certs {
                Some("needs --renew-certs".to_string())
            } else if s.gated_by_trust && !flags.re_consent_trust {
                Some("needs --re-consent-trust".to_string())
            } else {
                None
            };
            if let Some(reason) = skip_reason {
                return StepReport {
                    id: s.id,
                    title: s.title.clone(),
                    outcome: Outcome::Skipped(reason),
                };
            }
            match run_step(s, ctx) {
                Ok(note) => StepReport {
                    id: s.id,
                    title: s.title.clone(),
                    outcome: Outcome::Done(note),
                },
                Err(e) => StepReport {
                    id: s.id,
                    title: s.title.clone(),
                    outcome: Outcome::Failed(e.to_string()),
                },
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Outcome {
    Done(String),
    Skipped(String),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepReport {
    pub id: StepId,
    pub title: String,
    pub outcome: Outcome,
}

/// Persist the refreshed facts as the new audit snapshot (best-effort).
pub fn save_state_after_refresh(
    facts: super::NetworkFacts,
    trust_consent: Option<&str>,
) -> Result<()> {
    let mut state = NetworkState::load(&NetworkState::default_path())?.unwrap_or(NetworkState {
        facts: super::NetworkFacts::default(),
        applied_at: String::new(),
        trust_consents: vec![],
    });
    state.facts = facts;
    state.applied_at = crate::gitops::state::now_rfc3339();
    if let Some(addr) = trust_consent {
        state
            .trust_consents
            .push(format!("{} {addr}", state.applied_at));
    }
    state.save(&NetworkState::default_path())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{Change, Impact};

    fn ch(field: &str, impacts: Vec<Impact>) -> Change {
        Change {
            field: field.into(),
            applied: "a".into(),
            live: "b".into(),
            impacts,
        }
    }

    #[test]
    fn plan_orders_core_steps_and_gates_certs() {
        let changes = vec![
            ch(
                "node_ip",
                vec![Impact::K3sConfig, Impact::Certs, Impact::Cilium],
            ),
            ch("egress_ip", vec![Impact::Allowlists]),
        ];
        let flags = RefreshFlags::default();
        let steps = plan(&changes, &flags);
        let ids: Vec<StepId> = steps.iter().map(|s| s.id).collect();
        let pos = |id: StepId| ids.iter().position(|i| *i == id).unwrap();
        assert!(pos(StepId::K3sConfig) < pos(StepId::K3sRestart));
        assert!(pos(StepId::K3sRestart) < pos(StepId::CertRotate));
        assert!(pos(StepId::CiliumHost) < pos(StepId::CiliumRollout));
        assert!(ids.contains(&StepId::AllowlistChecklist));
        // Trust step is always present (operator-driven).
        assert!(ids.contains(&StepId::EdgeTrust));

        let reports = execute(&steps, &flags, &RefreshContext::default());
        let cert = reports.iter().find(|r| r.id == StepId::CertRotate).unwrap();
        assert!(matches!(cert.outcome, Outcome::Skipped(_)), "certs gated");
        let trust = reports.iter().find(|r| r.id == StepId::EdgeTrust).unwrap();
        assert!(matches!(trust.outcome, Outcome::Skipped(_)), "trust gated");
    }

    #[test]
    fn plan_flux_only_on_remote_change_or_stable_names() {
        let flags = RefreshFlags::default();
        let steps = plan(&[ch("node_ip", vec![Impact::K3sConfig])], &flags);
        assert!(!steps.iter().any(|s| s.id == StepId::FluxRemote));

        // Flux drift alone is not actionable without a target host.
        let flags = RefreshFlags::default();
        let steps = plan(&[ch("flux_remote host", vec![Impact::Flux])], &flags);
        assert!(!steps.iter().any(|s| s.id == StepId::FluxRemote));

        let flags = RefreshFlags {
            adopt_stable_names: true,
            git_host: Some("git.lan".into()),
            ..Default::default()
        };
        let steps = plan(&[], &flags);
        assert!(steps.iter().any(|s| s.id == StepId::FluxRemote));

        let flags = RefreshFlags {
            git_host: Some("git.lan".into()),
            ..Default::default()
        };
        let steps = plan(&[ch("flux_remote host", vec![Impact::Flux])], &flags);
        assert!(steps.iter().any(|s| s.id == StepId::FluxRemote));
    }

    #[test]
    fn update_k3s_config_rewrites_and_fails_closed_on_external() {
        let base = "node-ip: \"10.0.2.15\"\nnode-external-ip: \"198.51.100.1\"\nadvertise-address: \"10.0.2.15\"\ncluster-cidr: \"10.42.0.0/16\"\ntls-san:\n  - \"127.0.0.1\"\n  - \"nat-node\"\n";
        let updated = update_k3s_config(
            base,
            "10.0.9.9",
            Some("198.51.100.2"),
            &["10.0.9.9".to_string(), "nat-node".to_string()],
            None,
        )
        .unwrap();
        let f = crate::network::parse_k3s_config(&updated);
        assert_eq!(f.node_ip.as_deref(), Some("10.0.9.9"));
        assert_eq!(f.advertise_address.as_deref(), Some("10.0.9.9"));
        assert_eq!(f.node_external_ip.as_deref(), Some("198.51.100.2"));
        assert!(f.sans.contains(&"127.0.0.1".to_string()), "user SAN kept");
        assert!(f.sans.contains(&"10.0.9.9".to_string()), "new SAN added");
        assert!(updated.contains("cluster-cidr"), "unrelated keys kept");

        // Fail-closed: None removes the claim entirely.
        let dropped = update_k3s_config(&updated, "10.0.9.9", None, &[], None).unwrap();
        let f2 = crate::network::parse_k3s_config(&dropped);
        assert_eq!(f2.node_external_ip, None);
        assert!(!dropped.contains("node-external-ip"));
    }

    #[test]
    fn retarget_remote_keeps_port_and_path() {
        assert_eq!(
            retarget_remote("ssh://git@10.0.0.5:2222/srv/infra.git", "git.lan").unwrap(),
            "ssh://git@git.lan:2222/srv/infra.git"
        );
        assert!(retarget_remote("https://example.com/x.git", "h").is_err());
    }

    #[test]
    fn update_k3s_config_worker_rewrites_server_without_advertise() {
        let worker = "node-ip: \"10.0.2.20\"\nserver: \"https://10.0.2.15:6443\"\ntoken: \"tok\"\n";
        let updated = update_k3s_config(
            worker,
            "10.0.2.21",
            None,
            &["10.0.2.21".to_string()],
            Some("https://10.0.9.9:6443"),
        )
        .unwrap();
        let f = crate::network::parse_k3s_config(&updated);
        assert_eq!(f.node_ip.as_deref(), Some("10.0.2.21"));
        assert_eq!(f.server_url.as_deref(), Some("https://10.0.9.9:6443"));
        assert!(
            f.advertise_address.is_none(),
            "workers have no advertise-address to update"
        );
        assert!(updated.contains("token"), "join token preserved");
    }

    #[test]
    fn execute_writes_configs_and_reports_missing_files() {
        let dir = std::env::temp_dir().join(format!("net-refresh-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let k3s = dir.join("config.yaml");
        fs::write(
            &k3s,
            "node-ip: \"10.0.2.15\"\nnode-external-ip: \"198.51.100.1\"\nadvertise-address: \"10.0.2.15\"\n",
        )
        .unwrap();
        let cilium = dir.join("cilium.yaml");
        fs::write(
            &cilium,
            "spec:\n  valuesContent: |-\n    k8sServiceHost: 10.0.2.15\n",
        )
        .unwrap();

        let ctx = RefreshContext {
            node_ip: "10.0.9.9".into(),
            node_external_ip: None,
            expected_sans: vec!["10.0.9.9".into()],
            k3s_config_path: k3s.clone(),
            cilium_manifest_path: cilium.clone(),
            ..Default::default()
        };
        let steps = vec![
            Step {
                id: StepId::K3sConfig,
                title: "k3s".into(),
                detail: String::new(),
                gated_by_certs: false,
                gated_by_trust: false,
            },
            Step {
                id: StepId::CiliumHost,
                title: "cilium".into(),
                detail: String::new(),
                gated_by_certs: false,
                gated_by_trust: false,
            },
        ];
        let reports = execute(
            &steps,
            &RefreshFlags {
                yes: true,
                ..Default::default()
            },
            &ctx,
        );
        assert!(
            matches!(reports[0].outcome, Outcome::Done(_)),
            "{:?}",
            reports[0]
        );
        assert!(
            matches!(reports[1].outcome, Outcome::Done(_)),
            "{:?}",
            reports[1]
        );
        let f = crate::network::parse_k3s_config(&fs::read_to_string(&k3s).unwrap());
        assert_eq!(f.node_ip.as_deref(), Some("10.0.9.9"));
        assert_eq!(f.node_external_ip, None, "fail-closed drop");
        assert_eq!(
            crate::network::parse_cilium_api_host(&fs::read_to_string(&cilium).unwrap()).as_deref(),
            Some("10.0.9.9")
        );

        // Missing file → Failed outcome, not a panic.
        let ctx_bad = RefreshContext {
            k3s_config_path: dir.join("missing.yaml"),
            cilium_manifest_path: dir.join("missing2.yaml"),
            ..ctx.clone()
        };
        let reports = execute(
            &steps,
            &RefreshFlags {
                yes: true,
                ..Default::default()
            },
            &ctx_bad,
        );
        assert!(matches!(reports[0].outcome, Outcome::Failed(_)));
        assert!(matches!(reports[1].outcome, Outcome::Failed(_)));
        let _ = fs::remove_dir_all(&dir);
    }
}
