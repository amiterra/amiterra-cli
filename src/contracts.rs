//! Platform contract registry (Task 0007, Design Doc 0027).
//!
//! A *contract* is any name / path / version / form that crosses the
//! "platform <-> user or application" boundary and that the platform
//! guarantees to keep stable (or honestly marks as unenforced). The registry
//! is the constants themselves — one named place per value — surfaced by
//! `ami contracts` / `ami versions` and verified against the public docs
//! page by the code<->docs test at the bottom of this module.
//!
//! Ownership is federated: host-runtime contracts live here, compiler-output
//! contracts are imported from `amispec-core` crates, schema contracts live
//! in `amispec` (CUE). This module only *aggregates* — values never move.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Stability guarantee of a contract (Design Doc 0027 §1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Stability {
    /// Production-grade; changes only with release notes + deprecation window.
    Stable,
    /// Usable but may break; changes land in the changelog.
    Experimental,
    /// Not an interface; documented for debugging only.
    Internal,
}

impl Stability {
    pub fn as_str(self) -> &'static str {
        match self {
            Stability::Stable => "stable",
            Stability::Experimental => "experimental",
            Stability::Internal => "internal",
        }
    }
}

/// Registry section (filterable via `ami contracts --section`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Section {
    Storage,
    Gitops,
    Cluster,
    Versions,
    State,
    Behavior,
    Cli,
    Amispec,
    Paths,
}

impl Section {
    pub const ALL: [Section; 9] = [
        Section::Storage,
        Section::Gitops,
        Section::Cluster,
        Section::Versions,
        Section::State,
        Section::Behavior,
        Section::Cli,
        Section::Amispec,
        Section::Paths,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Section::Storage => "storage",
            Section::Gitops => "gitops",
            Section::Cluster => "cluster",
            Section::Versions => "versions",
            Section::State => "state",
            Section::Behavior => "behavior",
            Section::Cli => "cli",
            Section::Amispec => "amispec",
            Section::Paths => "paths",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|sec| sec.as_str() == s)
    }

    pub fn title(self) -> &'static str {
        match self {
            Section::Storage => "Storage",
            Section::Gitops => "GitOps & delivery",
            Section::Cluster => "Cluster",
            Section::Versions => "Version pins",
            Section::State => "State files",
            Section::Behavior => "Behavior & honesty",
            Section::Cli => "CLI surface",
            Section::Amispec => "AmiSpec schema",
            Section::Paths => "Host paths",
        }
    }
}

/// One registry entry. `value` is the promised literal users may rely on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Contract {
    pub id: &'static str,
    pub section: Section,
    pub title: &'static str,
    pub value: String,
    pub stability: Stability,
    pub since: &'static str,
    /// Where the value is enforced (file::CONSTANT).
    pub source: &'static str,
    pub notes: &'static str,
}

/// Runtime version pins — same constants the installer writes
/// (`ami versions`, Design Doc 0027 §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionPins {
    pub cli: String,
    pub k3s: &'static str,
    #[serde(rename = "ciliumChart")]
    pub cilium_chart: &'static str,
    pub flux: &'static str,
    #[serde(rename = "certManager")]
    pub cert_manager: &'static str,
    #[serde(rename = "amispecSchema")]
    pub amispec_schema: &'static str,
}

pub fn versions() -> VersionPins {
    VersionPins {
        cli: env!("CARGO_PKG_VERSION").to_string(),
        k3s: crate::providers::server::K3S_VERSION,
        cilium_chart: crate::providers::server::CILIUM_CHART_VERSION,
        flux: crate::gitops::flux::FLUX_VERSION,
        cert_manager: amispec_compile::exposure::CERT_MANAGER_CHART_VERSION,
        amispec_schema: amispec_schema::AMISPEC_STANDARD_VERSION,
    }
}

/// Full contract registry (Design Doc 0027 §1.3).
pub fn registry() -> Vec<Contract> {
    use crate::gitops;
    use crate::join_command;
    use crate::network;
    use crate::providers::server::{CILIUM_CHART_VERSION, K3S_VERSION};
    use crate::storage;
    use crate::tune;
    use Section as S;
    use Stability as St;

    let mut v = vec![
        Contract {
            id: "storage-class-local",
            section: S::Storage,
            title: "StorageClass name for stateful passports",
            value: storage::LOCAL_SC_NAME.to_string(),
            stability: St::Stable,
            since: "0.1",
            source: "storage/mod.rs::LOCAL_SC_NAME",
            notes: "Stable across provisioner swaps; passports may rely on it",
        },
        Contract {
            id: "storage-data-root",
            section: S::Storage,
            title: "Stateful data root",
            value: storage::DATA_ROOT.to_string(),
            stability: St::Stable,
            since: "0.1",
            source: "storage/mod.rs::DATA_ROOT",
            notes: "Bind-mount source of amiterra-local volumes",
        },
        Contract {
            id: "storage-lvm-names",
            section: S::Storage,
            title: "LVM volume group / logical volume names",
            value: format!(
                "{} / {}",
                storage::prepare::DEFAULT_VG,
                storage::prepare::DATA_LV
            ),
            stability: St::Stable,
            since: "0.1",
            source: "storage/prepare.rs::{DEFAULT_VG,DATA_LV}",
            notes: "Created by `ami storage prepare`",
        },
        Contract {
            id: "storage-labels",
            section: S::Storage,
            title: "Storage label vocabulary",
            value: format!(
                "{}, {}, {}",
                storage::LABEL_CLASS,
                storage::LABEL_TIER,
                storage::LABEL_POLICY
            ),
            stability: St::Stable,
            since: "0.1",
            source: "storage/mod.rs::LABEL_*",
            notes: "Node labels used by the placement advisor",
        },
        Contract {
            id: "gitops-repo-layout",
            section: S::Gitops,
            title: "Fleet repository layout",
            value: "clusters/<id>/{flux-system, 01-node-tuning, 02-operators-and-networking, \
                    03-stateful-clusters, 04a-provisioners-day2, 04b-app-migrations-expand, \
                    05-applications, 06-zero-trust-and-observability}, catalog/, topology.yaml, \
                    _intent/, _meta/"
                .to_string(),
            stability: St::Stable,
            since: "0.1",
            source: "amispec-compile/src/lib.rs (Design Doc 0026 §1.3)",
            notes: "Supersedes the flux,platform,apps sketch in Design Doc 0020 §3.2",
        },
        Contract {
            id: "gitops-remote",
            section: S::Gitops,
            title: "local-bare remote URL shape",
            value: format!(
                "ssh://{}@<node-ip>{}",
                gitops::local_bare::GIT_USER,
                gitops::local_bare::REPO_PATH
            ),
            stability: St::Stable,
            since: "0.1",
            source: "gitops/local_bare.rs::{GIT_USER,REPO_PATH}",
            notes: "Flux deploy key is read-only (git-upload-pack)",
        },
        Contract {
            id: "gitops-write-channel",
            section: S::Gitops,
            title: "Intent socket (single write channel)",
            value: crate::delivery::channel::default_socket()
                .to_string_lossy()
                .into_owned(),
            stability: St::Stable,
            since: "0.1",
            source: "delivery/channel.rs::default_socket",
            notes: "ADR 0014: the agent is the only Git writer",
        },
        Contract {
            id: "gitops-intent-audit",
            section: S::Gitops,
            title: "Intent audit trail",
            value: "_intent/<change-id>.yaml + `Change-Id` commit trailer".to_string(),
            stability: St::Stable,
            since: "0.1",
            source: "delivery/{intent,agent}.rs",
            notes: "Every applied change is reconstructable from the repo",
        },
        Contract {
            id: "gitops-state",
            section: S::Gitops,
            title: "GitOps state snapshot",
            value: gitops::state::STATE_PATH.to_string(),
            stability: St::Stable,
            since: "0.1",
            source: "gitops/state.rs::STATE_PATH",
            notes: "Recorded at `ami gitops bootstrap`",
        },
        Contract {
            id: "gitops-flux-namespace",
            section: S::Gitops,
            title: "Flux namespace / root Kustomization home",
            value: gitops::flux::FLUX_NAMESPACE.to_string(),
            stability: St::Stable,
            since: "0.1",
            source: "gitops/flux.rs::FLUX_NAMESPACE",
            notes: "Gateways live here too (see amispec-compile::GATEWAY_NAMESPACE)",
        },
        Contract {
            id: "cluster-api-access",
            section: S::Cluster,
            title: "API endpoint facts",
            value: format!(
                "port {}, token {}, k3s config {}",
                join_command::API_PORT,
                join_command::NODE_TOKEN_PATH,
                join_command::K3S_CONFIG_PATH
            ),
            stability: St::Stable,
            since: "0.1",
            source: "join_command.rs::{API_PORT,NODE_TOKEN_PATH,K3S_CONFIG_PATH}",
            notes: "Join commands embed `https://<endpoint>:6443`",
        },
        Contract {
            id: "cluster-cilium-invariants",
            section: S::Cluster,
            title: "Cilium HelmChart invariants",
            value: format!(
                "manifest {} — k8sServiceHost = cluster endpoint, advertise-address = node-ip",
                network::CILIUM_MANIFEST_PATH
            ),
            stability: St::Stable,
            since: "0.1",
            source: "providers/server.rs::render_cilium_manifest",
            notes: "Violating either breaks multi-node clusters (verified bugs, 2026-11)",
        },
        Contract {
            id: "versions-pins",
            section: S::Versions,
            title: "Pinned component versions",
            value: format!(
                "k3s {}, Cilium chart {}, Flux {}, cert-manager {}, AmiSpec schema {}",
                K3S_VERSION,
                CILIUM_CHART_VERSION,
                gitops::flux::FLUX_VERSION,
                amispec_compile::exposure::CERT_MANAGER_CHART_VERSION,
                amispec_schema::AMISPEC_STANDARD_VERSION
            ),
            stability: St::Stable,
            since: "0.1",
            source: "providers/server.rs::{K3S_VERSION,CILIUM_CHART_VERSION}, gitops/flux.rs::FLUX_VERSION, amispec-compile, amispec-schema",
            notes: "A pin change is a release event; see `ami versions --json`",
        },
        Contract {
            id: "state-baseline",
            section: S::State,
            title: "Tuning baseline snapshot",
            value: tune::BASELINE_PATH.to_string(),
            stability: St::Stable,
            since: "0.1",
            source: "tune/mod.rs::BASELINE_PATH",
            notes: "Written before tuning; `ami tune rollback` restores it",
        },
        Contract {
            id: "state-network",
            section: S::State,
            title: "Network facts snapshot",
            value: network::STATE_PATH.to_string(),
            stability: St::Stable,
            since: "0.1",
            source: "network/mod.rs::STATE_PATH",
            notes: "Audit trail for `ami network status/refresh`",
        },
        Contract {
            id: "behavior-enforcement-honesty",
            section: S::Behavior,
            title: "Declared-but-not-enforced semantics",
            value: "rateLimitRps, clientAuth: mtls, trustedProxySource XFF — contract, not \
                    enforced; CORS emits only for a single origin"
                .to_string(),
            stability: St::Stable,
            since: "0.1",
            source: "amispec-compile/src/exposure/*",
            notes: "Warnings say so explicitly; enforcement is future work",
        },
        Contract {
            id: "cli-json-forms",
            section: S::Cli,
            title: "Machine-readable output forms",
            value: "ami {status,doctor,contracts,versions,network status,storage} --json"
                .to_string(),
            stability: St::Experimental,
            since: "0.1",
            source: "cli.rs (per-command Args)",
            notes: "Field sets freeze to `stable` only after a changelog entry",
        },
        Contract {
            id: "amispec-schema",
            section: S::Amispec,
            title: "Passport / topology schema language",
            value: format!(
                "apiVersion topology.amispec.io/v1, schema {}",
                amispec_schema::AMISPEC_STANDARD_VERSION
            ),
            stability: St::Stable,
            since: "0.1",
            source: "amispec/schemas/*.cue + amispec/docs/specification.adoc",
            notes: "Open standard; CUE is the authority",
        },
        Contract {
            id: "amispec-provenance-labels",
            section: S::Amispec,
            title: "Provenance label vocabulary",
            value: "amispec.io/*".to_string(),
            stability: St::Experimental,
            since: "0.1",
            source: "amispec-compile/src/provenance.rs",
            notes: "Round-trips compiled trees back to topology",
        },
        Contract {
            id: "paths-runtime",
            section: S::Paths,
            title: "Host runtime paths and drop-ins",
            value: format!(
                "/var/lib/amiterra/ (runtime), config in ~/.amiterra/config.yaml or \
                 /etc/amiterra/config.yaml; sysctl {}, {}, limits {}",
                tune::PLATFORM_SYSCTL_PATH,
                tune::TUNE_SYSCTL_PATH,
                tune::TUNE_LIMITS_PATH
            ),
            stability: St::Stable,
            since: "0.1",
            source: "context.rs, tune/mod.rs",
            notes: "Also documented on the Configuration page",
        },
    ];
    v.sort_by(|a, b| a.id.cmp(b.id));
    v
}

// ---------------------------------------------------------------------------
// Doctor diagnostics (contract <-> cluster state)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Warn,
    Missing,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCheck {
    pub contract: String,
    pub status: CheckStatus,
    pub detail: String,
}

/// Pure invariant check for the Cilium manifest vs the k3s config
/// (`k8sServiceHost` must be a reachable API host; `advertise-address` must
/// be the node IP — the two verified multi-node bugs).
pub fn check_cilium_invariants(k3s_config: &str, cilium_manifest: &str) -> Vec<ContractCheck> {
    use crate::network;
    let k3s = network::parse_k3s_config(k3s_config);
    let mut out = Vec::new();

    let expected_host = k3s
        .server_url
        .as_deref()
        .map(|u| {
            u.trim()
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split(':')
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| k3s.node_ip.clone().unwrap_or_default());

    match network::parse_cilium_api_host(cilium_manifest) {
        Some(host) if host == expected_host && !expected_host.is_empty() => {
            out.push(ContractCheck {
                contract: "cluster-cilium-invariants".into(),
                status: CheckStatus::Ok,
                detail: format!("k8sServiceHost = {host}"),
            })
        }
        Some(host) => out.push(ContractCheck {
            contract: "cluster-cilium-invariants".into(),
            status: CheckStatus::Warn,
            detail: format!(
                "k8sServiceHost is `{host}` but the reachable endpoint is `{expected_host}` \
                 (worker nodes cannot reach the API through the wrong host)"
            ),
        }),
        None => out.push(ContractCheck {
            contract: "cluster-cilium-invariants".into(),
            status: CheckStatus::Skipped,
            detail: "no Cilium HelmChart manifest on disk".into(),
        }),
    }

    match (&k3s.advertise_address, &k3s.node_ip) {
        (Some(adv), Some(ip)) if adv == ip => out.push(ContractCheck {
            contract: "cluster-cilium-invariants".into(),
            status: CheckStatus::Ok,
            detail: format!("advertise-address = {adv}"),
        }),
        (Some(adv), Some(ip)) => out.push(ContractCheck {
            contract: "cluster-cilium-invariants".into(),
            status: CheckStatus::Warn,
            detail: format!(
                "advertise-address is `{adv}` but node-ip is `{ip}` (poisons \
                 kubernetes service endpoints)"
            ),
        }),
        _ => out.push(ContractCheck {
            contract: "cluster-cilium-invariants".into(),
            status: CheckStatus::Skipped,
            detail: "advertise-address not present in k3s config".into(),
        }),
    }
    out
}

/// Live contract diagnostics for `ami doctor` (best-effort, offline-friendly).
pub fn doctor_checks() -> Vec<ContractCheck> {
    use crate::storage;
    let mut out = Vec::new();

    // data-root
    if cfg!(target_os = "linux") {
        let exists = Path::new(storage::DATA_ROOT).exists();
        out.push(ContractCheck {
            contract: "storage-data-root".into(),
            status: if exists {
                CheckStatus::Ok
            } else {
                CheckStatus::Missing
            },
            detail: format!(
                "{} {}",
                storage::DATA_ROOT,
                if exists {
                    "exists"
                } else {
                    "missing (run `ami storage prepare`)"
                }
            ),
        });
    } else {
        out.push(ContractCheck {
            contract: "storage-data-root".into(),
            status: CheckStatus::Skipped,
            detail: "host is not Linux".into(),
        });
    }

    // StorageClass + PVC classes (best-effort via kubectl; skip on an
    // unprovisioned host — "missing" would be noise before `ami init`).
    let provisioned = Path::new(crate::network::K3S_CONFIG_PATH).exists();
    if !provisioned {
        out.push(ContractCheck {
            contract: "storage-class-local".into(),
            status: CheckStatus::Skipped,
            detail: "host not provisioned yet (no k3s config)".into(),
        });
    } else {
        match kubectl(&["get", "sc", storage::LOCAL_SC_NAME, "--no-headers"]) {
            Kubectl::Ok(_) => out.push(ContractCheck {
                contract: "storage-class-local".into(),
                status: CheckStatus::Ok,
                detail: format!("StorageClass {} present", storage::LOCAL_SC_NAME),
            }),
            Kubectl::OkEmpty => out.push(ContractCheck {
                contract: "storage-class-local".into(),
                status: CheckStatus::Missing,
                detail: format!(
                    "StorageClass {} absent (created by `ami storage prepare`)",
                    storage::LOCAL_SC_NAME
                ),
            }),
            Kubectl::Unavailable => out.push(ContractCheck {
                contract: "storage-class-local".into(),
                status: CheckStatus::Skipped,
                detail: "kubectl unavailable".into(),
            }),
        }
    }

    // Cilium invariants from the applied files.
    let k3s_config = std::fs::read_to_string(crate::network::K3S_CONFIG_PATH).unwrap_or_default();
    let cilium_manifest =
        std::fs::read_to_string(crate::network::CILIUM_MANIFEST_PATH).unwrap_or_default();
    if k3s_config.is_empty() {
        out.push(ContractCheck {
            contract: "cluster-cilium-invariants".into(),
            status: CheckStatus::Skipped,
            detail: "k3s config not found (host not provisioned)".into(),
        });
    } else {
        out.extend(check_cilium_invariants(&k3s_config, &cilium_manifest));
    }

    // PVC classes outside the registry — honest "outside guarantees" warning.
    if provisioned
        && let Kubectl::Ok(list) = kubectl(&[
            "get",
            "pvc",
            "-A",
            "-o",
            "jsonpath={range .items[*]}{.spec.storageClassName}{'\\n'}{end}",
        ])
    {
        let foreign: Vec<&str> = list
            .lines()
            .map(str::trim)
            .filter(|c| !c.is_empty() && *c != storage::LOCAL_SC_NAME)
            .collect();
        if !foreign.is_empty() {
            out.push(ContractCheck {
                contract: "storage-class-local".into(),
                status: CheckStatus::Warn,
                detail: format!(
                    "PVCs use classes outside the registry ({} ) — allowed, but outside \
                     platform guarantees",
                    foreign.join(", ")
                ),
            });
        }
    }
    out
}

enum Kubectl {
    Ok(String),
    OkEmpty,
    Unavailable,
}

fn kubectl(args: &[&str]) -> Kubectl {
    let out = std::process::Command::new("k3s")
        .arg("kubectl")
        .args(args)
        .output()
        .or_else(|_| std::process::Command::new("kubectl").args(args).output());
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if text.is_empty() {
                Kubectl::OkEmpty
            } else {
                Kubectl::Ok(text)
            }
        }
        Ok(_) => Kubectl::OkEmpty,
        Err(_) => Kubectl::Unavailable,
    }
}

// ---------------------------------------------------------------------------
// CLI rendering (`ami contracts` / `ami versions`)
// ---------------------------------------------------------------------------

/// Render the registry (Design Doc 0027 §2 JSON or grouped human output).
pub fn print_registry(json: bool, section: Option<&str>) -> anyhow::Result<()> {
    use crate::ui::Ui;
    let reg = registry();
    let filtered: Vec<&Contract> = match section {
        Some(name) => {
            let sec = Section::parse(name).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown section `{name}` — one of: {}",
                    Section::ALL
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
            reg.iter().filter(|c| c.section == sec).collect()
        }
        None => reg.iter().collect(),
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "contracts": filtered }))?
        );
        return Ok(());
    }

    Ui::header(
        "Platform contracts",
        "everything the platform guarantees — `ami contracts --json` for tooling",
    );
    for sec in Section::ALL {
        let group: Vec<&&Contract> = filtered.iter().filter(|c| c.section == sec).collect();
        if group.is_empty() {
            continue;
        }
        let items: Vec<(&str, String)> = group
            .iter()
            .map(|c| {
                (
                    c.title,
                    format!("[{}] {}  ({})", c.stability.as_str(), c.value, c.id),
                )
            })
            .collect();
        let item_refs: Vec<(&str, &str)> = items.iter().map(|(k, v)| (*k, v.as_str())).collect();
        Ui::card(sec.title(), &item_refs);
    }
    Ui::step_info(
        "Stability policy",
        "stable = release event to change; experimental = changelog; internal = no guarantees",
    );
    Ok(())
}

/// Render pinned versions (`ami versions`).
pub fn print_versions(json: bool) -> anyhow::Result<()> {
    use crate::ui::Ui;
    let v = versions();
    if json {
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    let items = [
        ("amiterra CLI", v.cli.as_str()),
        ("k3s", v.k3s),
        ("Cilium chart", v.cilium_chart),
        ("Flux", v.flux),
        ("cert-manager", v.cert_manager),
        ("AmiSpec schema", v.amispec_schema),
    ];
    Ui::card("Version pins (what the installer actually deploys)", &items);
    Ui::step_info(
        "Compatibility",
        "plan against these pins — see `ami contracts --section versions`",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_ids_are_unique_and_complete() {
        let reg = registry();
        let mut ids: Vec<&str> = reg.iter().map(|c| c.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate contract ids");
        for c in &reg {
            assert!(!c.source.is_empty(), "{} needs a source", c.id);
            assert!(!c.value.is_empty(), "{} needs a value", c.id);
        }
        // Every section is represented (keeps the page structure honest).
        for sec in Section::ALL {
            assert!(
                reg.iter().any(|c| c.section == sec),
                "section {} has no contracts",
                sec.as_str()
            );
        }
    }

    #[test]
    fn versions_come_from_install_constants() {
        let v = versions();
        assert_eq!(v.k3s, crate::providers::server::K3S_VERSION);
        assert_eq!(
            v.cilium_chart,
            crate::providers::server::CILIUM_CHART_VERSION
        );
        assert_eq!(v.flux, crate::gitops::flux::FLUX_VERSION);
        assert!(!v.cli.is_empty());
    }

    #[test]
    fn code_and_docs_agree_on_stable_values() {
        // The contract test: every registry value must appear verbatim on the
        // public Contracts page. Changing a constant without updating the page
        // fails the build (Design Doc 0027 §2). Backticks are markup-only and
        // are stripped from both sides before comparison.
        let page = include_str!("../docs/public/modules/ROOT/pages/contracts.adoc");
        let norm = |s: &str| {
            s.replace('`', "")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let haystack = norm(page);
        for c in registry() {
            let needle = norm(&c.value);
            assert!(
                haystack.contains(&needle),
                "contracts.adoc does not mention `{}` (value: `{}`) — update the page \
                 together with the constant",
                c.id,
                c.value
            );
        }
    }

    #[test]
    fn cilium_invariant_checks_catch_the_known_bugs() {
        // Bug 1 (2026-11): k8sServiceHost: 127.0.0.1 breaks workers.
        let k3s = "node-ip: \"10.0.2.15\"\nserver: \"https://10.0.2.15:6443\"\n";
        let bad = "valuesContent: |-\n    k8sServiceHost: 127.0.0.1\n";
        let checks = check_cilium_invariants(k3s, bad);
        assert!(
            checks
                .iter()
                .any(|c| c.status == CheckStatus::Warn && c.detail.contains("127.0.0.1"))
        );

        // Bug 2 (2026-11): advertise-address != node-ip poisons endpoints.
        let k3s = "node-ip: \"10.0.2.15\"\nadvertise-address: \"154.1.1.1\"\n";
        let good = "valuesContent: |-\n    k8sServiceHost: 10.0.2.15\n";
        let checks = check_cilium_invariants(k3s, good);
        assert!(
            checks
                .iter()
                .any(|c| c.status == CheckStatus::Warn && c.detail.contains("poisons"))
        );

        // Healthy pair is Ok.
        let k3s = "node-ip: \"10.0.2.15\"\nadvertise-address: \"10.0.2.15\"\n";
        let checks = check_cilium_invariants(k3s, good);
        assert!(
            checks.iter().all(|c| c.status == CheckStatus::Ok),
            "{checks:?}"
        );
    }
}
