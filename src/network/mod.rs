//! Network address lifecycle (Task 0008, Design Doc 0031 §7).
//!
//! Network addresses are *re-diffable declared facts*: `network-state.yaml`
//! records what was applied at init/join (audit trail), while the source of
//! truth is the live set of applied configs (k3s config, Cilium manifest,
//! Flux remote). `ami network status` diffs live discovery against those
//! configs; `ami network refresh` reconciles explicitly, step by step.

pub mod cli;
pub mod refresh;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Snapshot of applied network facts (audit trail, NOT the source of truth).
pub const STATE_PATH: &str = "/var/lib/amiterra/network-state.yaml";
/// k3s node config written by `ami init` / `ami join`.
pub const K3S_CONFIG_PATH: &str = "/etc/rancher/k3s/config.yaml";
/// Cilium HelmChart manifest written by `ami init` (pins `k8sServiceHost`).
pub const CILIUM_MANIFEST_PATH: &str = "/var/lib/rancher/k3s/server/manifests/cilium.yaml";

/// Address facts that pin network identity into configs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkFacts {
    pub node_ip: String,
    /// Declared/owned external IP only (never a NAT gateway egress).
    pub node_external_ip: Option<String>,
    /// Egress IP as seen by the outside world (allowlist value; may be a NAT
    /// gateway address — informational only).
    pub egress_ip: Option<String>,
    pub hostname: String,
    /// Address-relevant TLS SANs expected on the API server.
    #[serde(default)]
    pub sans: Vec<String>,
    /// Cilium `k8sServiceHost` (must track the control-plane endpoint).
    pub api_host: Option<String>,
    /// Flux Git remote URL (IP-pinned remotes are a change hazard).
    pub flux_remote: Option<String>,
}

/// Audit snapshot stored at init/join and updated by successful refreshes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkState {
    pub facts: NetworkFacts,
    /// RFC3339 UTC timestamp of the capture.
    pub applied_at: String,
    /// Operator consents recorded by `ami network refresh --re-consent-trust`
    /// (each entry: `"<timestamp> <declared-address>"`).
    #[serde(default)]
    pub trust_consents: Vec<String>,
}

impl NetworkState {
    pub fn load(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let state: Self =
            serde_yaml::from_str(&raw).context("failed to parse network-state YAML")?;
        Ok(Some(state))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let yaml = serde_yaml::to_string(self).context("failed to serialize network state")?;
        let tmp = path.with_extension("yaml.tmp");
        fs::write(&tmp, &yaml).with_context(|| format!("failed to write {}", tmp.display()))?;
        fs::rename(&tmp, path).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }

    pub fn default_path() -> PathBuf {
        PathBuf::from(STATE_PATH)
    }
}

/// Why a changed fact matters (impact surface of Design 0031 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Impact {
    /// `/etc/rancher/k3s/config.yaml` must be rewritten + k3s restarted.
    K3sConfig,
    /// API server certificate SANs (requires explicit `--renew-certs`).
    Certs,
    /// Cilium `k8sServiceHost` + rollout.
    Cilium,
    /// Flux Git remote + known_hosts.
    Flux,
    /// Join commands / worker `server:` endpoint.
    JoinSurface,
    /// External allowlists of third-party services (manual follow-up).
    Allowlists,
}

impl Impact {
    pub fn label(self) -> &'static str {
        match self {
            Impact::K3sConfig => "k3s config rewrite + restart",
            Impact::Certs => "API cert SANs (explicit --renew-certs)",
            Impact::Cilium => "Cilium k8sServiceHost + rollout",
            Impact::Flux => "Flux remote + known_hosts",
            Impact::JoinSurface => "join commands / worker server: endpoint",
            Impact::Allowlists => "external allowlists (manual checklist)",
        }
    }
}

/// One detected drift between live and applied facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    pub field: String,
    pub applied: String,
    pub live: String,
    pub impacts: Vec<Impact>,
}

/// k3s config facts parsed back from the applied file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct K3sFacts {
    pub node_ip: Option<String>,
    pub node_external_ip: Option<String>,
    pub advertise_address: Option<String>,
    pub server_url: Option<String>,
    pub sans: Vec<String>,
}

/// Parse the applied k3s config (valid YAML rendered by `render_k3s_config`).
pub fn parse_k3s_config(content: &str) -> K3sFacts {
    let mut facts = K3sFacts::default();
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return facts;
    };
    let get = |k: &str| doc.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
    facts.node_ip = get("node-ip");
    facts.node_external_ip = get("node-external-ip");
    facts.advertise_address = get("advertise-address");
    facts.server_url = get("server");
    if let Some(list) = doc.get("tls-san").and_then(|v| v.as_sequence()) {
        facts.sans = list
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
    }
    facts
}

/// Address-relevant SANs expected on the API server: the node address, the
/// declared/owned external address (never NAT egress) and the hostname.
pub fn expected_sans(facts: &NetworkFacts) -> Vec<String> {
    let mut out = Vec::new();
    for v in [&facts.node_ip, &facts.hostname] {
        if !v.is_empty() && !out.contains(v) {
            out.push(v.clone());
        }
    }
    if let Some(ext) = &facts.node_external_ip
        && !out.contains(ext)
    {
        out.push(ext.clone());
    }
    out
}

/// Extract the host part of an `ssh://user@host/path` remote URL.
pub fn ssh_url_host(url: &str) -> Option<String> {
    let rest = url.strip_prefix("ssh://")?;
    let hostport = rest.split('@').nth(1)?;
    let host = hostport.split('/').next()?;
    let host = host.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Replace the host part of an `ssh://user@host/path` remote URL.
pub fn ssh_url_set_host(url: &str, host: &str) -> Option<String> {
    let rest = url.strip_prefix("ssh://")?;
    let (user_part, after_at) = rest.split_once('@')?;
    let path = after_at.split_once('/').map(|(_, p)| p);
    let hostport = after_at.split('/').next()?;
    // Preserve an explicit port if present.
    let port = hostport.split_once(':').map(|(_, p)| p);
    let new_hostport = match port {
        Some(p) if !p.is_empty() => format!("{host}:{p}"),
        _ => host.to_string(),
    };
    Some(match path {
        Some(p) => format!("ssh://{user_part}@{new_hostport}/{p}"),
        None => format!("ssh://{user_part}@{new_hostport}"),
    })
}

/// Parse `k8sServiceHost` from the Cilium HelmChart manifest values block.
pub fn parse_cilium_api_host(manifest: &str) -> Option<String> {
    for line in manifest.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("k8sServiceHost:") {
            return Some(rest.trim().trim_matches('"').to_string());
        }
    }
    None
}

/// Rewrite `k8sServiceHost` in the Cilium HelmChart manifest (line-local:
/// everything else in the manifest is preserved byte-for-byte).
pub fn update_cilium_api_host(manifest: &str, host: &str) -> String {
    let mut out = String::new();
    let mut done = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if !done && trimmed.starts_with("k8sServiceHost:") {
            let indent = &line[..line.len() - trimmed.len()];
            out.push_str(&format!("{indent}k8sServiceHost: {host}\n"));
            done = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !done {
        out.push_str(&format!("    k8sServiceHost: {host}\n"));
    }
    out
}

/// Diff *live* facts against *applied* configs. Empty result = no drift.
pub fn diff_facts(live: &NetworkFacts, applied: &NetworkFacts) -> Vec<Change> {
    let mut changes = Vec::new();
    let mut push = |field: &str, applied: &str, live: &str, impacts: Vec<Impact>| {
        if applied != live {
            changes.push(Change {
                field: field.to_string(),
                applied: applied.to_string(),
                live: live.to_string(),
                impacts,
            });
        }
    };

    push(
        "node_ip",
        &applied.node_ip,
        &live.node_ip,
        vec![
            Impact::K3sConfig,
            Impact::Certs,
            Impact::JoinSurface,
            // Cilium tracks the control-plane endpoint when it pins this IP.
            Impact::Cilium,
        ],
    );
    push(
        "node_external_ip",
        applied.node_external_ip.as_deref().unwrap_or(""),
        live.node_external_ip.as_deref().unwrap_or(""),
        vec![Impact::K3sConfig, Impact::Certs],
    );
    push(
        "egress_ip",
        applied.egress_ip.as_deref().unwrap_or(""),
        live.egress_ip.as_deref().unwrap_or(""),
        vec![Impact::Allowlists],
    );

    // Cilium pin: only drift when it does not match the live node address.
    if let Some(api_host) = &applied.api_host
        && api_host != &live.node_ip
    {
        push(
            "api_host (Cilium k8sServiceHost)",
            api_host,
            &live.node_ip,
            vec![Impact::Cilium],
        );
    }

    // Flux remote pinned to an IP that is no longer ours.
    if let Some(remote) = &applied.flux_remote
        && let Some(host) = ssh_url_host(remote)
        && host.parse::<std::net::IpAddr>().is_ok()
        && host != live.node_ip
    {
        push("flux_remote host", &host, &live.node_ip, vec![Impact::Flux]);
    }

    // Missing address-relevant SANs (additive check — user SANs are kept).
    let expected = expected_sans(live);
    let missing: Vec<String> = expected
        .into_iter()
        .filter(|s| !applied.sans.contains(s))
        .collect();
    if !missing.is_empty() {
        changes.push(Change {
            field: "tls SANs (missing)".to_string(),
            applied: applied.sans.join(","),
            live: missing.join(","),
            impacts: vec![Impact::Certs],
        });
    }

    changes
}

/// Facts of the host as they are *right now* in applied configs.
/// Pure collection from strings — I/O lives in [`collect_applied`].
pub fn facts_from_configs(
    k3s_config: &str,
    cilium_manifest: Option<&str>,
    flux_remote: Option<String>,
    egress_ip: Option<String>,
    hostname: String,
) -> NetworkFacts {
    let k3s = parse_k3s_config(k3s_config);
    let node_ip = k3s.node_ip.clone().unwrap_or_default();
    let mut sans = k3s.sans.clone();
    // `server:` host of a worker is the control-plane endpoint — it is the
    // API host pin on agents.
    let api_host = cilium_manifest
        .and_then(parse_cilium_api_host)
        .or(k3s.server_url.as_deref().and_then(ssh_url_host))
        .or_else(|| {
            k3s.server_url.as_deref().and_then(|u| {
                u.trim_start_matches("https://")
                    .split(':')
                    .next()
                    .map(String::from)
            })
        });
    let node_external_ip = k3s.node_external_ip.clone();
    if sans.is_empty() {
        sans = expected_sans(&NetworkFacts {
            node_ip: node_ip.clone(),
            node_external_ip: node_external_ip.clone(),
            hostname: hostname.clone(),
            ..Default::default()
        });
    }
    NetworkFacts {
        node_ip,
        node_external_ip,
        egress_ip,
        hostname,
        sans,
        api_host,
        flux_remote,
    }
}

/// Read applied facts from the real host files (best-effort, no probing).
pub fn collect_applied() -> Result<NetworkFacts> {
    let k3s_config = fs::read_to_string(K3S_CONFIG_PATH).unwrap_or_default();
    let cilium_manifest = fs::read_to_string(CILIUM_MANIFEST_PATH).ok();
    let flux_remote = crate::gitops::state::GitopsState::load(
        &crate::gitops::state::GitopsState::default_path(),
    )?
    .map(|s| s.remote_url);
    let hostname = hostname();
    Ok(facts_from_configs(
        &k3s_config,
        cilium_manifest.as_deref(),
        flux_remote,
        None,
        hostname,
    ))
}

/// Short hostname of this host.
pub fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "amiterra-node".to_string())
}

/// Record the currently applied facts as the audit snapshot (called at the
/// end of init/join and after successful refreshes).
pub fn capture_snapshot() -> Result<()> {
    let facts = collect_applied()?;
    let state = NetworkState {
        facts,
        applied_at: crate::gitops::state::now_rfc3339(),
        trust_consents: Vec::new(),
    };
    state.save(&NetworkState::default_path())
}

/// Quick consistency hint for `ami doctor` (sync, file-based only).
pub fn doctor_hint() -> Option<String> {
    let state = NetworkState::load(&NetworkState::default_path()).ok()??;
    let applied = collect_applied().ok()?;
    drift_hint(&state, &applied)
}

/// Pure core of [`doctor_hint`]: snapshot vs applied-config drift.
pub fn drift_hint(state: &NetworkState, applied: &NetworkFacts) -> Option<String> {
    if state.facts.node_ip != applied.node_ip {
        return Some(format!(
            "network drift: node_ip changed since {} (applied {}, now {}) — run `ami network status`",
            state.applied_at, state.facts.node_ip, applied.node_ip
        ));
    }
    None
}

/// Union of SAN lists preserving order (applied first, then new expected).
pub fn merge_sans(applied: &[String], expected: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for s in applied.iter().chain(expected.iter()) {
        if seen.insert(s.clone()) {
            out.push(s.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const K3S: &str = r#"# Amiterra Production Headless K3s Configuration
node-ip: "10.0.2.15"
node-external-ip: "198.51.100.1"
flannel-backend: "none"
advertise-address: "10.0.2.15"
tls-san:
  - "127.0.0.1"
  - "10.0.2.15"
  - "nat-node"
kubelet-arg:
  - "system-reserved=cpu=100m,memory=200Mi"
"#;

    #[test]
    fn parses_k3s_config() {
        let f = parse_k3s_config(K3S);
        assert_eq!(f.node_ip.as_deref(), Some("10.0.2.15"));
        assert_eq!(f.node_external_ip.as_deref(), Some("198.51.100.1"));
        assert_eq!(f.advertise_address.as_deref(), Some("10.0.2.15"));
        assert_eq!(f.sans, vec!["127.0.0.1", "10.0.2.15", "nat-node"]);
    }

    #[test]
    fn parses_cilium_api_host() {
        let m = "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nspec:\n  valuesContent: |-\n    kubeProxyReplacement: true\n    k8sServiceHost: 10.0.2.15\n    k8sServicePort: 6443\n";
        assert_eq!(parse_cilium_api_host(m).as_deref(), Some("10.0.2.15"));
        let updated = update_cilium_api_host(m, "10.9.9.9");
        assert_eq!(parse_cilium_api_host(&updated).as_deref(), Some("10.9.9.9"));
        assert!(updated.contains("k8sServicePort: 6443"), "rest preserved");
    }

    #[test]
    fn ssh_url_host_and_replace() {
        let url = "ssh://git@10.0.0.5/srv/git/infra.git";
        assert_eq!(ssh_url_host(url).as_deref(), Some("10.0.0.5"));
        assert_eq!(
            ssh_url_set_host(url, "git.lan").as_deref(),
            Some("ssh://git@git.lan/srv/git/infra.git")
        );
        assert_eq!(
            ssh_url_set_host("ssh://git@10.0.0.5:2222/repo.git", "git.lan").as_deref(),
            Some("ssh://git@git.lan:2222/repo.git")
        );
    }

    #[test]
    fn diff_detects_node_ip_blast_radius() {
        let applied = NetworkFacts {
            node_ip: "10.0.2.15".into(),
            hostname: "nat-node".into(),
            sans: vec!["10.0.2.15".into(), "nat-node".into()],
            api_host: Some("10.0.2.15".into()),
            ..Default::default()
        };
        let live = NetworkFacts {
            node_ip: "10.0.9.9".into(),
            hostname: "nat-node".into(),
            ..Default::default()
        };
        let changes = diff_facts(&live, &applied);
        let fields: Vec<&str> = changes.iter().map(|c| c.field.as_str()).collect();
        assert!(fields.contains(&"node_ip"));
        assert!(fields.contains(&"api_host (Cilium k8sServiceHost)"));
        let node_change = changes.iter().find(|c| c.field == "node_ip").unwrap();
        assert!(node_change.impacts.contains(&Impact::JoinSurface));
        assert!(node_change.impacts.contains(&Impact::Certs));
    }

    #[test]
    fn diff_egress_only_touches_allowlists() {
        let applied = NetworkFacts {
            node_ip: "10.0.2.15".into(),
            egress_ip: Some("154.1.1.1".into()),
            hostname: "nat-node".into(),
            sans: vec!["10.0.2.15".into(), "nat-node".into()],
            ..Default::default()
        };
        let live = NetworkFacts {
            egress_ip: Some("178.2.2.2".into()),
            ..applied.clone()
        };
        let changes = diff_facts(&live, &applied);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "egress_ip");
        assert_eq!(changes[0].impacts, vec![Impact::Allowlists]);
    }

    #[test]
    fn diff_flags_missing_sans_and_stale_flux_remote() {
        let applied = NetworkFacts {
            node_ip: "10.0.2.15".into(),
            hostname: "nat-node".into(),
            sans: vec!["127.0.0.1".into()],
            flux_remote: Some("ssh://git@10.0.2.15/srv/git/infra.git".into()),
            ..Default::default()
        };
        // Live node_ip changed → old pinned remote host is stale too.
        let live = NetworkFacts {
            node_ip: "10.0.9.9".into(),
            hostname: "nat-node".into(),
            ..Default::default()
        };
        let changes = diff_facts(&live, &applied);
        let fields: Vec<&str> = changes.iter().map(|c| c.field.as_str()).collect();
        assert!(fields.contains(&"tls SANs (missing)"), "{fields:?}");
        assert!(fields.contains(&"flux_remote host"), "{fields:?}");
    }

    #[test]
    fn flux_remote_with_stable_name_is_not_flagged() {
        let applied = NetworkFacts {
            node_ip: "10.0.2.15".into(),
            hostname: "nat-node".into(),
            sans: vec!["10.0.2.15".into(), "nat-node".into()],
            flux_remote: Some("ssh://git@git.lan/srv/git/infra.git".into()),
            ..Default::default()
        };
        let live = NetworkFacts {
            node_ip: "10.0.9.9".into(),
            ..applied.clone()
        };
        let changes = diff_facts(&live, &applied);
        assert!(
            !changes.iter().any(|c| c.field == "flux_remote host"),
            "stable DNS remote must not be flagged as drift"
        );
    }

    #[test]
    fn merge_sans_is_union_in_order() {
        let merged = merge_sans(
            &["127.0.0.1".to_string(), "10.0.2.15".to_string()],
            &["10.0.2.15".to_string(), "nat-node".to_string()],
        );
        assert_eq!(merged, vec!["127.0.0.1", "10.0.2.15", "nat-node"]);
    }

    #[test]
    fn state_roundtrip_and_defaults() {
        let dir = std::env::temp_dir().join(format!("net-state-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("network-state.yaml");
        let state = NetworkState {
            facts: NetworkFacts {
                node_ip: "10.0.2.15".into(),
                ..Default::default()
            },
            applied_at: "2026-11-08T00:00:00Z".into(),
            trust_consents: vec![],
        };
        state.save(&path).unwrap();
        let loaded = NetworkState::load(&path).unwrap().unwrap();
        assert_eq!(loaded, state);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn facts_from_configs_prefers_cilium_pin() {
        let facts = facts_from_configs(
            K3S,
            Some("valuesContent: |-\n    k8sServiceHost: 10.0.2.15\n"),
            Some("ssh://git@10.0.2.15/srv/git/infra.git".into()),
            Some("154.1.1.1".into()),
            "nat-node".into(),
        );
        assert_eq!(facts.api_host.as_deref(), Some("10.0.2.15"));
        assert_eq!(facts.egress_ip.as_deref(), Some("154.1.1.1"));
        assert_eq!(facts.node_external_ip.as_deref(), Some("198.51.100.1"));
        assert!(!facts.sans.is_empty());
    }

    #[test]
    fn worker_config_pins_api_host_from_server_url() {
        let worker = "node-ip: \"10.0.2.20\"\nserver: \"https://10.0.2.15:6443\"\ntoken: \"tok\"\n";
        let facts = facts_from_configs(worker, None, None, None, "worker-1".into());
        assert_eq!(facts.node_ip, "10.0.2.20");
        assert_eq!(facts.api_host.as_deref(), Some("10.0.2.15"));
    }

    #[test]
    fn drift_hint_reports_snapshot_mismatch() {
        let state = NetworkState {
            facts: NetworkFacts {
                node_ip: "10.0.2.15".into(),
                ..Default::default()
            },
            applied_at: "2026-11-08T00:00:00Z".into(),
            trust_consents: vec![],
        };
        let applied = NetworkFacts {
            node_ip: "10.0.9.9".into(),
            ..Default::default()
        };
        assert!(
            drift_hint(&state, &applied)
                .unwrap()
                .contains("network drift")
        );
        assert!(drift_hint(&state, &state.facts.clone()).is_none());
    }
}
