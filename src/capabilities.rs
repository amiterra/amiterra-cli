//! Host capability probing for the unified `ami init` flow.
//!
//! One init pipeline presents the same environment choices everywhere.
//! Options that the current host cannot support stay **visible** but
//! **disabled**, with a short human-readable reason — no silent fork
//! between `--server` and `--dev` UX.

use serde::{Deserialize, Serialize};
use std::process::Command;

/// Coarse OS family relevant to Amiterra support policy (§5.3: Ubuntu/Debian LTS + typical macOS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsKind {
    Linux,
    Macos,
    Other,
}

/// Result of probing the current host.
#[derive(Debug, Clone, Serialize)]
pub struct HostCapabilities {
    pub os: OsKind,
    pub os_label: String,
    pub is_root: bool,
    pub container_runtime: Option<String>,
    pub qemu_available: bool,
    pub server_os_supported: bool,
    pub server_os_reason: String,
}

impl HostCapabilities {
    pub fn probe() -> Self {
        let os = if cfg!(target_os = "macos") {
            OsKind::Macos
        } else if cfg!(target_os = "linux") {
            OsKind::Linux
        } else {
            OsKind::Other
        };

        let os_label = std::env::consts::OS.to_string();
        let is_root = crate::preflight::is_root();

        let container_runtime = ["docker", "podman", "nerdctl"]
            .iter()
            .find(|bin| {
                Command::new(bin)
                    .arg("--version")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            })
            .map(|s| s.to_string());

        let qemu_available = ["qemu-system-aarch64", "qemu-system-x86_64", "qemu-img"]
            .iter()
            .any(|bin| {
                Command::new(bin)
                    .arg("--version")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            });

        let (server_os_supported, server_os_reason) = match os {
            OsKind::Macos => (
                false,
                "Production server needs bare Ubuntu 22.04/24.04 or Debian 12".to_string(),
            ),
            OsKind::Other => (
                false,
                "Only Ubuntu/Debian LTS and typical macOS are supported (90-day scope)".to_string(),
            ),
            OsKind::Linux => {
                if is_supported_server_distro() {
                    (true, "Ubuntu/Debian LTS detected".to_string())
                } else {
                    (
                        false,
                        "Distro not in MVP scope — use Ubuntu 22.04/24.04 or Debian 12".to_string(),
                    )
                }
            }
        };

        Self {
            os,
            os_label,
            is_root,
            container_runtime,
            qemu_available,
            server_os_supported,
            server_os_reason,
        }
    }

    /// Whether a root Linux server init can run here.
    pub fn can_run_production(&self) -> bool {
        self.os == OsKind::Linux && self.server_os_supported
    }

    /// Whether a container sandbox can run here.
    pub fn can_run_container_sandbox(&self) -> bool {
        self.container_runtime.is_some()
    }

    /// Whether the QEMU fidelity sandbox can run here.
    pub fn can_run_qemu_sandbox(&self) -> bool {
        self.qemu_available
    }
}

/// True when `/etc/os-release` looks like Ubuntu 22.04/24.04 or Debian 12+.
fn is_supported_server_distro() -> bool {
    let Ok(content) = std::fs::read_to_string("/etc/os-release") else {
        // Non-Linux or unusual layout — treat as unsupported for production.
        return false;
    };
    let id = content
        .lines()
        .find_map(|l| l.strip_prefix("ID="))
        .map(|v| v.trim_matches('"').to_ascii_lowercase())
        .unwrap_or_default();
    let version = content
        .lines()
        .find_map(|l| l.strip_prefix("VERSION_ID="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default();

    match id.as_str() {
        "ubuntu" => {
            let major: u32 = version.split('.').next().and_then(|s| s.parse().ok()).unwrap_or(0);
            major >= 22
        }
        "debian" => {
            let major: u32 = version.split('.').next().and_then(|s| s.parse().ok()).unwrap_or(0);
            major >= 12
        }
        _ => false,
    }
}

/// A selectable init target with availability and a short reason when disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InitTarget {
    /// Rootless container K3s sandbox (fast try).
    SandboxContainer,
    /// QEMU micro-VM sandbox (production-like kernel).
    SandboxQemu,
    /// Bare-metal / VPS production node.
    ProductionServer,
}

impl InitTarget {
    pub fn title(&self) -> &'static str {
        match self {
            InitTarget::SandboxContainer => "Local Sandbox · Container",
            InitTarget::SandboxQemu => "Local Sandbox · QEMU micro-VM",
            InitTarget::ProductionServer => "Production Server",
        }
    }

    pub fn summary(&self) -> &'static str {
        match self {
            InitTarget::SandboxContainer => {
                "Fastest start (~60s) · limited fidelity · zero host pollution"
            }
            InitTarget::SandboxQemu => {
                "Production-like kernel · sysctl/tune visible · multi-node ready"
            }
            InitTarget::ProductionServer => {
                "Bare Ubuntu/Debian · k3s + Cilium eBPF · full host control"
            }
        }
    }
}

/// One row in the environment picker.
#[derive(Debug, Clone)]
pub struct EnvChoice {
    pub target: InitTarget,
    pub available: bool,
    pub reason: String,
    pub recommended: bool,
}

/// Build the capability-gated choice list (same shape on every host).
pub fn env_choices(caps: &HostCapabilities) -> Vec<EnvChoice> {
    let mut list = vec![
        EnvChoice {
            target: InitTarget::SandboxContainer,
            available: caps.can_run_container_sandbox(),
            reason: if caps.can_run_container_sandbox() {
                format!("Runtime: {}", caps.container_runtime.as_deref().unwrap_or("?"))
            } else {
                "No container runtime (install Docker/OrbStack/Podman)".into()
            },
            // Fast first-touch — default when available.
            recommended: caps.can_run_container_sandbox(),
        },
        EnvChoice {
            target: InitTarget::SandboxQemu,
            available: caps.can_run_qemu_sandbox(),
            reason: if caps.can_run_qemu_sandbox() {
                "QEMU detected (HVF/KVM accel)".into()
            } else {
                "QEMU not installed (brew install qemu / apt install qemu-system)".into()
            },
            // Highest fidelity — recommend when present and container is not the only path.
            recommended: caps.can_run_qemu_sandbox() && !caps.can_run_container_sandbox(),
        },
        EnvChoice {
            target: InitTarget::ProductionServer,
            available: caps.can_run_production(),
            reason: if caps.can_run_production() {
                if caps.is_root {
                    "Root privileges detected".into()
                } else {
                    "Needs sudo/root to configure the host".into()
                }
            } else {
                caps.server_os_reason.clone()
            },
            recommended: caps.can_run_production() && caps.is_root,
        },
    ];

    // Prefer production as recommended when we are on a root Linux server.
    if caps.can_run_production() && caps.is_root {
        for c in &mut list {
            c.recommended = c.target == InitTarget::ProductionServer;
        }
    } else if caps.can_run_qemu_sandbox() {
        for c in &mut list {
            c.recommended = c.target == InitTarget::SandboxQemu;
        }
    }

    list
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps_macos_with_docker() -> HostCapabilities {
        HostCapabilities {
            os: OsKind::Macos,
            os_label: "macos".into(),
            is_root: false,
            container_runtime: Some("docker".into()),
            qemu_available: false,
            server_os_supported: false,
            server_os_reason: "Production server needs bare Ubuntu/Debian".into(),
        }
    }

    fn caps_linux_root() -> HostCapabilities {
        HostCapabilities {
            os: OsKind::Linux,
            os_label: "linux".into(),
            is_root: true,
            container_runtime: None,
            qemu_available: false,
            server_os_supported: true,
            server_os_reason: "Ubuntu/Debian LTS detected".into(),
        }
    }

    #[test]
    fn production_disabled_on_macos_with_reason() {
        let caps = caps_macos_with_docker();
        let choices = env_choices(&caps);
        let prod = choices
            .iter()
            .find(|c| c.target == InitTarget::ProductionServer)
            .unwrap();
        assert!(!prod.available);
        assert!(!prod.reason.is_empty());
        // Container is available → recommended.
        let cont = choices
            .iter()
            .find(|c| c.target == InitTarget::SandboxContainer)
            .unwrap();
        assert!(cont.available);
        assert!(cont.recommended);
    }

    #[test]
    fn production_recommended_on_linux_root() {
        let caps = caps_linux_root();
        let choices = env_choices(&caps);
        let prod = choices
            .iter()
            .find(|c| c.target == InitTarget::ProductionServer)
            .unwrap();
        assert!(prod.available);
        assert!(prod.recommended);
    }

    #[test]
    fn qemu_choice_visible_even_when_unavailable() {
        let caps = caps_macos_with_docker();
        let choices = env_choices(&caps);
        assert!(choices.iter().any(|c| c.target == InitTarget::SandboxQemu));
        let qemu = choices
            .iter()
            .find(|c| c.target == InitTarget::SandboxQemu)
            .unwrap();
        assert!(!qemu.available);
        assert!(qemu.reason.contains("QEMU"));
    }

    #[test]
    fn all_three_options_always_present() {
        for caps in [caps_macos_with_docker(), caps_linux_root()] {
            assert_eq!(env_choices(&caps).len(), 3);
        }
    }
}
