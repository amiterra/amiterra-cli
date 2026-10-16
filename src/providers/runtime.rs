use std::path::Path;
use std::process::Command;

/// Represents a detected container runtime on the host, including whether its daemon is currently running.
#[derive(Debug, Clone)]
pub struct DetectedRuntime {
    pub display_name: String,
    pub daemon_running: bool,
    pub start_hint: &'static str,
}

pub struct RuntimeDescriptor {
    pub display_name: &'static str,
    pub binary: &'static str,
    pub probe_args: &'static [&'static str],
    pub start_hint: &'static str,
}

const RUNTIME_PROBES: &[RuntimeDescriptor] = &[
    RuntimeDescriptor {
        display_name: "OrbStack",
        binary: "orbctl",
        probe_args: &["status"],
        start_hint: "open -a OrbStack",
    },
    RuntimeDescriptor {
        display_name: "Docker",
        binary: "docker",
        probe_args: &["info"],
        start_hint: if cfg!(target_os = "macos") {
            "open -a Docker"
        } else {
            "sudo systemctl start docker"
        },
    },
    RuntimeDescriptor {
        display_name: "Colima",
        binary: "colima",
        probe_args: &["status"],
        start_hint: "colima start",
    },
    RuntimeDescriptor {
        display_name: "Podman",
        binary: "podman",
        probe_args: &["info"],
        start_hint: "podman machine start",
    },
    RuntimeDescriptor {
        display_name: "containerd (nerdctl)",
        binary: "nerdctl",
        probe_args: &["info"],
        start_hint: "limactl start",
    },
];

fn refine_docker_name() -> String {
    if cfg!(target_os = "macos") {
        if Path::new("/Applications/OrbStack.app").exists()
            && Command::new("docker")
                .arg("context")
                .arg("show")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("orbstack"))
                .unwrap_or(false)
        {
            return "OrbStack (Docker Engine)".to_string();
        }
        if Path::new("/Applications/Rancher Desktop.app").exists()
            && Command::new("docker")
                .arg("context")
                .arg("show")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("rancher-desktop"))
                .unwrap_or(false)
        {
            return "Rancher Desktop (Docker Engine)".to_string();
        }
        if Path::new("/Applications/Docker.app").exists() {
            return "Docker Desktop".to_string();
        }
    }
    "Docker Engine".to_string()
}

fn is_binary_installed(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .or_else(|_| Command::new(bin).arg("version").output())
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Probes all registered container runtimes.
/// Prioritizes runtimes whose daemon is actively running; falls back to installed runtimes whose daemon is stopped.
pub fn detect_runtime_state() -> Option<DetectedRuntime> {
    if std::env::var("AMITERRA_SIMULATE_NO_RUNTIME")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return None;
    }

    // 1. First pass: look for a runtime with an active daemon
    // Check K3s embedded containerd on Linux
    if cfg!(target_os = "linux") {
        let k3s_sock = Path::new("/run/k3s/containerd/containerd.sock").exists();
        let k3s_active = Command::new("systemctl")
            .args(["is-active", "k3s"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false)
            || Command::new("systemctl")
                .args(["is-active", "k3s-agent"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
                .unwrap_or(false);

        if k3s_sock || k3s_active {
            return Some(DetectedRuntime {
                display_name: "K3s containerd".to_string(),
                daemon_running: true,
                start_hint: "sudo systemctl start k3s",
            });
        }

        if Path::new("/run/containerd/containerd.sock").exists() {
            let ct_active = Command::new("systemctl")
                .args(["is-active", "containerd"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
                .unwrap_or(false);
            if ct_active {
                return Some(DetectedRuntime {
                    display_name: "containerd".to_string(),
                    daemon_running: true,
                    start_hint: "sudo systemctl start containerd",
                });
            }
        }
    }

    for rt in RUNTIME_PROBES {
        let is_active = Command::new(rt.binary)
            .args(rt.probe_args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if is_active {
            let name = if rt.binary == "docker" {
                refine_docker_name()
            } else {
                rt.display_name.to_string()
            };
            return Some(DetectedRuntime {
                display_name: name,
                daemon_running: true,
                start_hint: rt.start_hint,
            });
        }
    }

    // 2. Second pass: look for an installed runtime whose daemon is currently stopped (or restricted)
    if cfg!(target_os = "linux") && (Path::new("/usr/local/bin/k3s").exists() || Path::new("/etc/rancher/k3s/config.yaml").exists()) {
        return Some(DetectedRuntime {
            display_name: "K3s containerd".to_string(),
            daemon_running: false,
            start_hint: "sudo systemctl start k3s",
        });
    }

    for rt in RUNTIME_PROBES {
        if is_binary_installed(rt.binary) {
            let name = if rt.binary == "docker" {
                refine_docker_name()
            } else {
                rt.display_name.to_string()
            };
            return Some(DetectedRuntime {
                display_name: name,
                daemon_running: false,
                start_hint: rt.start_hint,
            });
        }
    }

    // 3. macOS app bundle check even if CLI isn't in PATH yet
    if cfg!(target_os = "macos") && Path::new("/Applications/Docker.app").exists() {
        return Some(DetectedRuntime {
            display_name: "Docker Desktop".to_string(),
            daemon_running: false,
            start_hint: "open -a Docker",
        });
    }

    None
}

/// Convenience helper returning a formatted string of the detected runtime.
pub fn detect_active_runtime() -> Option<String> {
    detect_runtime_state().map(|rt| {
        if rt.daemon_running {
            format!("● active ({})", rt.display_name)
        } else {
            format!("○ inactive ({} · daemon stopped)", rt.display_name)
        }
    })
}
