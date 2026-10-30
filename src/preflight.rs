use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

use crate::providers::runtime::{detect_active_runtime, detect_runtime_state};
use crate::providers::sandbox::{detect_sandbox_engine, print_missing_engine_recommendations};

#[derive(Debug, Serialize, Deserialize)]
pub struct PreflightReport {
    pub process_name: String,
    pub os: String,
    pub arch: String,
    pub is_root: bool,
    pub is_workstation: bool,
    pub is_server: bool,
    pub kernel_version: Option<String>,
    pub cgroups_v2: bool,
    pub btf_available: bool,
    pub bbr_available: bool,
    pub container_runtime: Option<String>,
    pub sandbox_engine: Option<String>,
    pub k3s_installed: bool,
    pub k3s_active: bool,
    pub k3s_version: Option<String>,
    pub ready_for_server: bool,
    pub ready_for_dev: bool,
}

pub fn run_preflight() -> PreflightReport {
    let process_name = std::fs::read_to_string("/proc/self/comm")
        .ok()
        .map(|s| s.trim().to_string())
        .or_else(|| {
            std::env::args_os().next().and_then(|a| {
                Path::new(&a)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
            })
        })
        .unwrap_or_else(|| "amiterra".to_string());
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let is_root = is_root();
    let is_workstation = detect_workstation();

    let mut kernel_version = None;
    let mut cgroups_v2 = false;
    let mut btf_available = false;
    let mut bbr_available = false;

    if os == "linux" {
        kernel_version = get_kernel_version();
        cgroups_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
        btf_available = Path::new("/sys/kernel/btf/vmlinux").exists();
        bbr_available = check_bbr();
    }

    let k3s_installed = Path::new("/usr/local/bin/k3s").exists()
        || Path::new("/etc/rancher/k3s/config.yaml").exists();
    let k3s_active = if k3s_installed {
        Command::new("systemctl")
            .args(["is-active", "k3s"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false)
            || Command::new("systemctl")
                .args(["is-active", "k3s-agent"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
                .unwrap_or(false)
    } else {
        false
    };
    let k3s_version = if k3s_installed {
        get_k3s_version()
    } else {
        None
    };

    // Server posture is detected, not declared: anything that looks like a
    // server install (k3s, amiterra unit, root on Linux) reports as server.
    let is_server = !is_workstation
        || k3s_installed
        || Path::new("/etc/systemd/system/amiterra.service").exists()
        || Path::new("/etc/amiterra.conf").exists()
        || (os == "linux" && is_root && !is_workstation);

    let container_runtime = detect_active_runtime();
    let sandbox_engine = detect_sandbox_engine().map(|e| e.name().to_string());
    let ready_for_dev = sandbox_engine.is_some() && !k3s_active;
    // Cilium eBPF requires BTF — a kernel without /sys/kernel/btf/vmlinux
    // cannot run the production stack.
    let ready_for_server = os == "linux" && is_root && cgroups_v2 && btf_available;

    PreflightReport {
        process_name,
        os,
        arch,
        is_root,
        is_workstation,
        is_server,
        kernel_version,
        cgroups_v2,
        btf_available,
        bbr_available,
        container_runtime,
        sandbox_engine,
        k3s_installed,
        k3s_active,
        k3s_version,
        ready_for_server,
        ready_for_dev,
    }
}

use crate::ui::Ui;

pub fn print_preflight_report(report: &PreflightReport) {
    let pretty_os = match report.os.as_str() {
        "macos" => "macOS",
        "linux" => "Linux",
        "windows" => "Windows",
        other => other,
    };

    let mut items: Vec<(&str, String)> = vec![
        (
            "Process Identity",
            format!("{} (single binary)", report.process_name),
        ),
        (
            "Operating System",
            format!("{} ({})", pretty_os, report.arch),
        ),
        (
            "Privileges",
            (if report.is_root {
                "Yes (root/sudo)"
            } else {
                "User-space (rootless)"
            })
            .to_string(),
        ),
        (
            "Environment Type",
            (if report.is_server {
                "Dedicated Server / Headless"
            } else {
                "Workstation / Desktop"
            })
            .to_string(),
        ),
    ];

    if let Some(kv) = &report.kernel_version {
        items.push(("Linux Kernel", kv.clone()));
    }
    if report.os == "linux" {
        items.push((
            "cgroups v2",
            (if report.cgroups_v2 {
                "● supported"
            } else {
                "○ missing"
            })
            .to_string(),
        ));
        items.push((
            "eBPF BTF",
            (if report.btf_available {
                "● available (CO-RE)"
            } else {
                "○ missing"
            })
            .to_string(),
        ));
        items.push((
            "TCP BBR",
            (if report.bbr_available {
                "● available"
            } else {
                "○ requires activation"
            })
            .to_string(),
        ));
    }

    let cr_display = if let Some(cr) = &report.container_runtime {
        cr.clone()
    } else if report.k3s_installed {
        if report.k3s_active {
            "● active (K3s containerd)".to_string()
        } else {
            "○ inactive (K3s containerd · service stopped)".to_string()
        }
    } else if report.is_server {
        "○ not installed (will use K3s containerd)".to_string()
    } else {
        "○ not detected".to_string()
    };
    items.push(("Container Runtime", cr_display));

    let ke_label = if report.is_server {
        "Kubernetes Engine"
    } else {
        "Sandbox Engine"
    };
    let ke_display = if report.k3s_installed {
        let ver = report.k3s_version.as_deref().unwrap_or("v1.37");
        if report.k3s_active {
            format!("● active (Headless K3s {})", ver)
        } else {
            format!("○ inactive (Headless K3s {} · service stopped)", ver)
        }
    } else if let Some(se) = &report.sandbox_engine {
        format!("● ready ({})", se)
    } else if report.is_server {
        "○ not installed".to_string()
    } else {
        "○ none detected".to_string()
    };
    items.push((ke_label, ke_display));

    if report.is_server {
        let server_status = if report.k3s_active {
            "● active (Production Server Node)".to_string()
        } else if report.k3s_installed {
            "○ stopped (K3s service inactive)".to_string()
        } else if report.ready_for_server {
            "● ready (bare-metal Linux meets all prerequisites)".to_string()
        } else if report.os != "linux" {
            format!("○ ineligible (host is {} · requires Linux)", pretty_os)
        } else if !report.is_root {
            "○ requires root privileges (run with sudo)".to_string()
        } else if !report.cgroups_v2 {
            "○ missing cgroups v2 support".to_string()
        } else {
            "○ not ready".to_string()
        };
        items.push(("Server Profile", server_status));
        items.push((
            "Workstation Profile",
            "○ not applicable (Server Node)".to_string(),
        ));
    } else {
        let workstation_status = if let Some(rt) = detect_runtime_state() {
            if rt.daemon_running {
                "● ready (Headless K3s Sandbox)".to_string()
            } else {
                format!("● ready ({} · daemon stopped)", rt.display_name)
            }
        } else {
            "○ not ready (missing container runtime)".to_string()
        };
        items.push(("Workstation Profile", workstation_status));

        let server_status = if report.ready_for_server {
            "● ready (bare-metal Linux)".to_string()
        } else if report.os != "linux" {
            format!("○ ineligible (host is {} · requires Linux)", pretty_os)
        } else if !report.is_root {
            "○ requires root privileges (run with sudo)".to_string()
        } else {
            "○ not ready".to_string()
        };
        items.push(("Server Profile", server_status));
    }

    let item_refs: Vec<(&str, &str)> = items
        .iter()
        .map(|(label, val)| (*label, val.as_str()))
        .collect();

    Ui::card("Amiterra Doctor & Capability Inspection", &item_refs);

    if report.is_server {
        if report.k3s_active {
            Ui::next_steps(
                "Cluster status & inspection:",
                &[
                    "$ ami status",
                    "$ kubectl get nodes -o wide",
                    "$ journalctl -u amiterra -f",
                ],
            );
        } else if report.k3s_installed {
            Ui::step_warn("K3s service is installed but currently inactive.");
            Ui::next_steps(
                "To start server services:",
                &["$ sudo ami up", "$ sudo systemctl start k3s"],
            );
        } else if report.ready_for_server {
            Ui::step_info(
                "Server Ready for Bootstrap",
                "Host kernel (cgroups v2, eBPF BTF, BBR) satisfies all production requirements.",
            );
            Ui::next_steps(
                "Initialize canonical production stack (Headless K3s + Cilium eBPF):",
                &[
                    "Bootstrap new cluster : sudo ami init",
                    "Join existing cluster  : sudo ami join <endpoint> --token <token>",
                ],
            );
        } else {
            let mut reasons = Vec::new();
            if !report.is_root {
                reasons.push("Superuser privileges required : run with sudo");
            }
            if !report.cgroups_v2 {
                reasons.push("cgroups v2 not enabled         : add 'systemd.unified_cgroup_hierarchy=1' to kernel cmdline");
            }
            let reason_refs: Vec<&str> = reasons.to_vec();
            Ui::error_box(
                "Server Prerequisites Not Satisfied",
                "Production server node requires Linux with root privileges and cgroups v2.",
                &reason_refs,
                Some("https://github.com/amiterra/amiterra-cli/tree/main/docs"),
            );
        }
    } else {
        if report.ready_for_dev {
            if let Some(rt) = detect_runtime_state() {
                if !rt.daemon_running {
                    Ui::step_warn(&format!(
                        "{} is installed, but its daemon is stopped.",
                        rt.display_name
                    ));
                    let hint = format!("Start daemon: {}", rt.start_hint);
                    Ui::next_steps("Recommended next step:", &[&hint]);
                } else {
                    Ui::next_steps("Recommended next step:", &["$ ami up", "$ ami status"]);
                }
            }
        } else {
            print_missing_engine_recommendations("ami init");
        }
    }
}

pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        libc_geteuid() == 0
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(unix)]
fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

fn detect_workstation() -> bool {
    if std::env::consts::OS == "macos" {
        return true;
    }

    if std::env::var("DISPLAY").is_ok()
        || std::env::var("WAYLAND_DISPLAY").is_ok()
        || std::env::var("XDG_CURRENT_DESKTOP").is_ok()
    {
        return true;
    }

    if glob::glob("/sys/class/power_supply/BAT*")
        .map(|mut g| g.next().is_some())
        .unwrap_or(false)
    {
        return true;
    }

    false
}

fn get_kernel_version() -> Option<String> {
    Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
}

fn check_bbr() -> bool {
    if let Ok(content) =
        std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control")
    {
        return content.contains("bbr");
    }
    false
}

fn get_k3s_version() -> Option<String> {
    Command::new("k3s")
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|s| s.split_whitespace().nth(2).map(|v| v.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_preflight_report_server_active() {
        let report = PreflightReport {
            process_name: "amiterra".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            is_root: true,
            is_workstation: false,
            is_server: true,
            kernel_version: Some("6.8.0-generic".to_string()),
            cgroups_v2: true,
            btf_available: true,
            bbr_available: true,
            container_runtime: Some("● active (K3s containerd)".to_string()),
            sandbox_engine: Some("Native Headless K3s (systemd)".to_string()),
            k3s_installed: true,
            k3s_active: true,
            k3s_version: Some("v1.37.1+k3s1".to_string()),
            ready_for_server: true,
            ready_for_dev: false,
        };

        // Should render without panic
        print_preflight_report(&report);
    }

    #[test]
    fn test_print_preflight_report_server_greenfield() {
        let report = PreflightReport {
            process_name: "amiterra".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            is_root: true,
            is_workstation: false,
            is_server: true,
            kernel_version: Some("6.8.0-generic".to_string()),
            cgroups_v2: true,
            btf_available: true,
            bbr_available: true,
            container_runtime: None,
            sandbox_engine: None,
            k3s_installed: false,
            k3s_active: false,
            k3s_version: None,
            ready_for_server: true,
            ready_for_dev: false,
        };

        // Should render without panic and offer server bootstrap next steps
        print_preflight_report(&report);
    }

    #[test]
    fn test_print_preflight_report_workstation() {
        let report = PreflightReport {
            process_name: "amiterra".to_string(),
            os: "macos".to_string(),
            arch: "aarch64".to_string(),
            is_root: false,
            is_workstation: true,
            is_server: false,
            kernel_version: None,
            cgroups_v2: false,
            btf_available: false,
            bbr_available: false,
            container_runtime: Some("● active (OrbStack)".to_string()),
            sandbox_engine: Some("Docker (Headless K3s Sandbox)".to_string()),
            k3s_installed: false,
            k3s_active: false,
            k3s_version: None,
            ready_for_server: false,
            ready_for_dev: true,
        };

        print_preflight_report(&report);
    }
}
