use anyhow::{bail, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::context::{AmiterraConfig, EnvironmentMode, ExecutionContext};
use crate::discovery::NetworkDiscovery;
use crate::preflight::run_preflight;
use crate::providers::{EnvironmentBackend, EnvironmentStatus, StatusMetric};
use crate::ui::Ui;
use crate::wizard::{ClusterNodeConfig, NodeRole, TerminalWizard};

/// Health and architectural compliance status of an existing host K3s installation.
#[derive(Debug, PartialEq, Eq)]
pub enum K3sInspection {
    /// K3s is not installed on the system (clean greenfield host).
    NotInstalled,
    /// K3s is already installed and matches Amiterra baseline (flannel=none, kube-proxy=disabled, traefik disabled).
    CompliantAmiterraInstance,
    /// K3s is installed, but conflicts with Amiterra architecture (Flannel active, kube-proxy enabled, traefik active).
    ConflictingInstance {
        flannel_active: bool,
        kube_proxy_active: bool,
        traefik_active: bool,
        service_active: bool,
    },
}

/// Evaluates K3s installation configuration string against Amiterra requirements.
pub fn analyze_k3s_config(
    k3s_binary_exists: bool,
    config_content: Option<&str>,
    service_active: bool,
) -> K3sInspection {
    if !k3s_binary_exists {
        return K3sInspection::NotInstalled;
    }

    let content = config_content.unwrap_or_default();
    let flannel_none = content.contains("flannel-backend: \"none\"")
        || content.contains("flannel-backend: none");
    let kube_proxy_disabled = content.contains("disable-kube-proxy: true")
        || content.contains("disable-kube-proxy: \"true\"");
    let traefik_disabled = content.contains("traefik");

    if flannel_none && kube_proxy_disabled && traefik_disabled {
        K3sInspection::CompliantAmiterraInstance
    } else {
        K3sInspection::ConflictingInstance {
            flannel_active: !flannel_none,
            kube_proxy_active: !kube_proxy_disabled,
            traefik_active: !traefik_disabled,
            service_active,
        }
    }
}

/// Inspects host K3s binary and configuration on disk.
pub fn inspect_existing_k3s() -> K3sInspection {
    let binary_exists = Path::new("/usr/local/bin/k3s").exists();
    if !binary_exists {
        return K3sInspection::NotInstalled;
    }

    let config_path = Path::new("/etc/rancher/k3s/config.yaml");
    let config_content = fs::read_to_string(config_path).ok();

    let service_active = Command::new("systemctl")
        .args(["is-active", "k3s"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false);

    analyze_k3s_config(binary_exists, config_content.as_deref(), service_active)
}

#[derive(Default)]
pub struct LinuxServerBackend;

impl EnvironmentBackend for LinuxServerBackend {
    fn name(&self) -> &'static str {
        "Production Server Node (K3s + Cilium eBPF + Kernel Tuner)"
    }

    fn init(&self, ctx: &ExecutionContext, dry_run: bool) -> Result<()> {
        Ui::header(
            "Production Server Setup",
            "Headless K3s + Cilium eBPF Host-Routing + Autonomous Kernel Tuner",
        );

        if !crate::preflight::is_root() && !dry_run {
            bail!("Superuser privileges are required for production server setup. Run: sudo ami init --server");
        }

        let report = run_preflight(true);
        if report.is_workstation {
            Ui::step_warn("Workstation indicators detected: server kernel sysctl may disrupt Wi-Fi or Swap on a laptop.");
        }

        let init_args = ctx.init_args.clone().unwrap_or_default();

        // 1. Inspect existing K3s installation for conflicts or idempotent match
        let inspection = inspect_existing_k3s();
        match &inspection {
            K3sInspection::CompliantAmiterraInstance => {
                Ui::step_done(
                    "Existing Amiterra-compatible K3s cluster verified on host (Idempotent OK)",
                    None,
                );
                if dry_run {
                    Ui::step_info(
                        "Dry-run preview",
                        "Cluster configuration already matches Amiterra baseline. No changes needed.",
                    );
                    return Ok(());
                }

                // Ensure host invariants and amiterra daemon are running
                apply_host_invariants()?;
                install_systemd_unit()?;

                // Ensure K3s service is actively running and ready
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
                if !k3s_active {
                    let s_svc = Ui::spinner("Starting K3s systemd service...");
                    let service_name = if Path::new("/etc/systemd/system/k3s-agent.service").exists() {
                        "k3s-agent"
                    } else {
                        "k3s"
                    };
                    let out = Command::new("systemctl")
                        .args(["enable", "--now", service_name])
                        .output()?;
                    if !out.status.success() {
                        let err = String::from_utf8_lossy(&out.stderr);
                        bail!("Failed to start {}.service: {}", service_name, err.trim());
                    }
                    s_svc.success(&format!("{} systemd service active", service_name));
                }
                wait_for_node_readiness(60)?;

                let cfg = AmiterraConfig {
                    mode: EnvironmentMode::Server,
                    cluster: crate::context::ClusterConfig {
                        runtime: "k3s".to_string(),
                        networking: "cilium-ebpf (kube-proxy replacement)".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let _ = ctx.save_config(&cfg);

                Ui::step_done("Host is aligned with cluster state.", None);
                Ui::next_steps("Verify status:", &["$ ami status", "$ journalctl -u amiterra -f"]);
                return Ok(());
            }
            K3sInspection::ConflictingInstance {
                flannel_active,
                kube_proxy_active,
                traefik_active,
                ..
            } => {
                Ui::step_warn("Existing K3s installation detected with conflicting configuration:");
                if *flannel_active {
                    println!("    • Flannel CNI is active (Conflicts with Amiterra Cilium eBPF)");
                }
                if *kube_proxy_active {
                    println!("    • Kube-Proxy is active (Conflicts with Cilium eBPF Host-Routing)");
                }
                if *traefik_active {
                    println!("    • Traefik ingress is active (Conflicts with Amiterra API Gateway)");
                }

                if dry_run {
                    Ui::step_info(
                        "Dry-run preview",
                        "Would offer Safe Migration (backup & align) or Clean Reinstall.",
                    );
                } else {
                    use std::io::IsTerminal;
                    let remediation = if init_args.yes || !std::io::stdin().is_terminal() {
                        1 // Default to Safe Migration in non-interactive / yes mode
                    } else {
                        use std::io::Write;
                        println!("\n  Recommended Remediation Options:");
                        println!("    1. Safe Migration (Recommended) — Back up config and reconfigure to Amiterra eBPF");
                        println!("    2. Clean Reinstall              — Run k3s-uninstall.sh and perform fresh bootstrap");
                        println!("    3. Abort                        — Exit without modifying host");
                        print!(
                            "\n  {} Select remediation option [1-3, default 1]: ",
                            crate::ui::Palette::cyan("?")
                        );
                        std::io::stdout().flush()?;
                        let mut input = String::new();
                        std::io::stdin().read_line(&mut input)?;
                        match input.trim() {
                            "2" => 2,
                            "3" | "q" | "abort" => 3,
                            _ => 1,
                        }
                    };

                    match remediation {
                        3 => {
                            bail!("Installation aborted by user to resolve K3s configuration conflicts.");
                        }
                        2 => {
                            let s_clean = Ui::spinner("Running K3s uninstaller for clean reset...");
                            let _ = Command::new("/usr/local/bin/k3s-uninstall.sh").status();
                            let _ = fs::remove_dir_all("/etc/rancher/k3s");
                            s_clean.success("Existing K3s cleanly uninstalled");
                        }
                        _ => {
                            Ui::step_info(
                                "Safe Migration",
                                "Backing up existing config and aligning to Amiterra headless eBPF profile...",
                            );
                            let ts = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            let old_cfg = Path::new("/etc/rancher/k3s/config.yaml");
                            if old_cfg.exists() {
                                let bkp = format!("/etc/rancher/k3s/config.yaml.backup.{}", ts);
                                let _ = fs::copy(old_cfg, bkp);
                            }
                        }
                    }
                }
            }
            K3sInspection::NotInstalled => {}
        }

        // 2. Run network discovery to analyze host topology, RFC1918 interfaces, and CIDRs
        let disc_spinner = Ui::spinner("Running host network discovery & topology analysis...");
        let discovery = NetworkDiscovery::run();
        disc_spinner.success("Host network topology & collision-free CIDRs analyzed");

        // 3. Run Scenario B interactive terminal wizard (or auto-confirm if --yes or headless)
        let node_config = TerminalWizard::run(&discovery, &init_args)?;

        if dry_run {
            let role_title = node_config.role.display_title();
            let mut preview_items: Vec<(&str, &str)> = Vec::new();
            preview_items.push(("Target Node Role", role_title));
            preview_items.push(("Cluster Node IP", &node_config.node_ip));
            if let Some(ext) = &node_config.node_external_ip {
                preview_items.push(("External Ingress IP", ext));
            }
            let wg_status = if node_config.wireguard_enabled {
                "● Required (Transparent eBPF WAN mesh)"
            } else {
                "○ Disabled (Private L2 network)"
            };
            preview_items.push(("WireGuard Mesh", wg_status));
            preview_items.push(("Pod Network CIDR", &node_config.pod_cidr));
            preview_items.push(("Service CIDR", &node_config.service_cidr));

            let sans_formatted = if node_config.tls_sans.len() > 4 {
                format!(
                    "{}, ... (+{} more)",
                    node_config.tls_sans[..3].join(", "),
                    node_config.tls_sans.len() - 3
                )
            } else {
                node_config.tls_sans.join(", ")
            };
            preview_items.push(("TLS SANs", &sans_formatted));

            if let Some(srv) = &node_config.server_url {
                preview_items.push(("Control Plane Server", srv));
            }

            Ui::card("Planned Node Configuration (Dry-Run Preview)", &preview_items);

            println!("  {}", crate::ui::Palette::bold("Planned Host Modifications:"));
            println!(
                "    {} 1. Apply kernel sysctl profile: {}",
                crate::ui::Palette::cyan("›"),
                crate::ui::Palette::dim("/etc/sysctl.d/99-amiterra-bootstrap.conf (BBR, Somaxconn, 524k nofile)")
            );
            println!(
                "    {} 2. Write K3s headless config:   {}",
                crate::ui::Palette::cyan("›"),
                crate::ui::Palette::dim("/etc/rancher/k3s/config.yaml")
            );
            if node_config.role.is_control_plane() {
                let enc = if node_config.wireguard_enabled {
                    "wireguard"
                } else {
                    "direct"
                };
                let cilium_desc = format!("kube-proxy replacement · encryption={}", enc);
                println!(
                    "    {} 3. Deploy Cilium eBPF v1.16.2:  {}",
                    crate::ui::Palette::cyan("›"),
                    crate::ui::Palette::dim(&cilium_desc)
                );
            }
            println!(
                "    {} 4. Start systemd services:      {}",
                crate::ui::Palette::cyan("›"),
                crate::ui::Palette::dim("k3s.service · amiterra.service")
            );
            println!();
            Ui::step_done("Dry-run preview complete · Zero system modifications applied.", None);
            println!();
            return Ok(());
        }

        // 4. Host kernel invariants & limits
        let s1 = Ui::spinner("Applying host kernel invariants (sysctl & limits)...");
        apply_host_invariants()?;
        s1.success("Host kernel invariants applied (BBR, Somaxconn, 524k nofile)");

        // 5. K3s binary check & headless install
        if !Path::new("/usr/local/bin/k3s").exists() {
            let s_k3s = Ui::spinner("Installing K3s binary (channel v1.31, headless)...");
            install_k3s_binary(&node_config)?;
            s_k3s.success("K3s binary installed");
        }

        // 6. Tailored K3s configuration
        let s2 = Ui::spinner("Configuring Headless K3s (/etc/rancher/k3s/config.yaml)...");
        fs::create_dir_all("/etc/rancher/k3s")?;
        write_tailored_k3s_config(&node_config)?;
        s2.success("Headless K3s configuration written (custom CIDRs & SANs)");

        // 7. Cilium eBPF manifest (Control Plane nodes only)
        if node_config.role.is_control_plane() {
            let s3 = Ui::spinner("Deploying Cilium eBPF manifest...");
            fs::create_dir_all("/var/lib/rancher/k3s/server/manifests")?;
            deploy_cilium_manifest(node_config.wireguard_enabled)?;
            let enc_str = if node_config.wireguard_enabled {
                "with WireGuard WAN encryption"
            } else {
                "direct host routing"
            };
            s3.success(&format!("Cilium eBPF manifest deployed ({})", enc_str));
        }

        // 8. Systemd services
        let s4 = Ui::spinner("Starting K3s and Amiterra systemd services...");
        let service_name = if node_config.role == NodeRole::Worker {
            "k3s-agent"
        } else {
            "k3s"
        };
        let out = Command::new("systemctl")
            .args(["enable", "--now", service_name])
            .output()?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            bail!("Failed to start systemd service '{}': {}", service_name, err.trim());
        }
        install_systemd_unit()?;
        s4.success("Systemd services enabled and running");

        // 9. Active readiness probe
        if node_config.role.is_control_plane() {
            let s_ready = Ui::spinner("Waiting for control-plane readiness in cluster...");
            wait_for_node_readiness(60)?;
            s_ready.success("Control-plane node registered and active");
        }

        let cfg = AmiterraConfig {
            mode: EnvironmentMode::Server,
            cluster: crate::context::ClusterConfig {
                runtime: "k3s".to_string(),
                networking: format!(
                    "cilium-ebpf (kube-proxy replacement, wireguard={})",
                    node_config.wireguard_enabled
                ),
                ..Default::default()
            },
            ..Default::default()
        };
        let _ = ctx.save_config(&cfg);

        if node_config.role == NodeRole::ControlPlaneInit {
            let token = fs::read_to_string("/var/lib/rancher/k3s/server/node-token")
                .map(|t| t.trim().to_string())
                .unwrap_or_else(|_| "<token>".to_string());
            let join_worker = format!(
                "sudo ami join https://{}:6443 --token {}",
                node_config.node_ip, token
            );
            let join_cp = format!(
                "sudo ami join https://{}:6443 --token {} --control-plane",
                node_config.node_ip, token
            );

            let ready_items = [
                ("Cluster State", "● healthy (control plane online)"),
                ("Kubernetes API", &format!("https://{}:6443 (mTLS secured)", node_config.node_ip)),
                ("Networking Stack", "Cilium eBPF (Host-Routing)"),
                ("WireGuard Mesh", if node_config.wireguard_enabled { "● Active (Transparent WAN encryption)" } else { "○ Disabled (Private network)" }),
            ];
            Ui::card("Amiterra Production Cluster Initialized", &ready_items);

            println!("  {}", crate::ui::Palette::bold("To join additional nodes to this cluster, run on other servers:"));
            println!();
            println!("  {} Worker node:", crate::ui::Palette::cyan("›"));
            println!("    {} {}", crate::ui::Palette::dim("$"), crate::ui::Palette::cyan(&join_worker));
            println!();
            println!("  {} Control Plane node (HA):", crate::ui::Palette::cyan("›"));
            println!("    {} {}", crate::ui::Palette::dim("$"), crate::ui::Palette::cyan(&join_cp));
            println!();
            Ui::next_steps(
                "Inspect cluster status:",
                &["$ ami status", "$ kubectl get nodes -o wide", "$ journalctl -u amiterra -f"],
            );
        } else {
            Ui::step_done(
                "Amiterra node joined cluster successfully!",
                None,
            );
            Ui::next_steps(
                "Verify node status:",
                &["$ ami status", "$ journalctl -u amiterra -f"],
            );
        }

        Ok(())
    }

    fn up(&self, ctx: &ExecutionContext, dry_run: bool) -> Result<()> {
        if !Path::new("/etc/systemd/system/amiterra.service").exists() {
            return self.init(ctx, dry_run);
        }
        if dry_run {
            Ui::step_info("Dry-run preview", "Would start k3s.service and amiterra.service");
            return Ok(());
        }
        let sp = Ui::spinner("Starting Amiterra Production Server services...");
        let _ = Command::new("systemctl").args(["start", "k3s"]).status();
        let _ = Command::new("systemctl").args(["start", "amiterra"]).status();
        sp.success("Production server services started");
        Ui::next_steps("Verify health:", &["$ ami status"]);
        Ok(())
    }

    fn down(&self, _ctx: &ExecutionContext) -> Result<()> {
        let sp = Ui::spinner("Stopping Amiterra Production Server services...");
        let _ = Command::new("systemctl").args(["stop", "amiterra"]).status();
        let _ = Command::new("systemctl").args(["stop", "k3s"]).status();
        sp.success("Server services stopped");
        Ok(())
    }

    fn status(&self, _ctx: &ExecutionContext) -> Result<EnvironmentStatus> {
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

        let daemon_active = Command::new("systemctl")
            .args(["is-active", "amiterra"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false);

        let mut metrics = vec![
            StatusMetric {
                label: "Environment Mode".to_string(),
                value: "Production Server Node".to_string(),
            },
            StatusMetric {
                label: "K3s Service".to_string(),
                value: if k3s_active {
                    "● active (Headless — no Traefik / no ServiceLB)".to_string()
                } else {
                    "○ inactive (stopped)".to_string()
                },
            },
            StatusMetric {
                label: "Networking Stack".to_string(),
                value: "Cilium eBPF (kube-proxy replacement, Host-Routing)".to_string(),
            },
            StatusMetric {
                label: "Amiterra Daemon".to_string(),
                value: if daemon_active {
                    "● active (running)".to_string()
                } else {
                    "○ inactive (stopped)".to_string()
                },
            },
        ];

        if let Ok(bbr) = fs::read_to_string("/proc/sys/net/ipv4/tcp_congestion_control") {
            metrics.push(StatusMetric {
                label: "TCP Congestion".to_string(),
                value: bbr.trim().to_string(),
            });
        }
        if let Ok(somax) = fs::read_to_string("/proc/sys/net/core/somaxconn") {
            metrics.push(StatusMetric {
                label: "net.core.somaxconn".to_string(),
                value: somax.trim().to_string(),
            });
        }

        let healthy = k3s_active && daemon_active;
        let next_hint = if !healthy {
            Some("sudo ami up     Start production server services".to_string())
        } else {
            None
        };

        Ok(EnvironmentStatus {
            mode: "server".to_string(),
            healthy,
            summary: if healthy {
                "Production Node Healthy".to_string()
            } else {
                "Server Services Inactive".to_string()
            },
            metrics,
            next_hint,
        })
    }

    fn uninstall(&self, _ctx: &ExecutionContext, _purge: bool) -> Result<()> {
        if Path::new("/etc/systemd/system/amiterra.service").exists() {
            let _ = Command::new("systemctl").args(["stop", "amiterra"]).status();
            let _ = Command::new("systemctl").args(["disable", "amiterra"]).status();
            let _ = fs::remove_file("/etc/systemd/system/amiterra.service");
            Ui::step_done("Removed systemd service amiterra.service", None);
        }

        if Path::new("/usr/local/bin/k3s-uninstall.sh").exists() {
            let sp = Ui::spinner("Running K3s uninstaller...");
            let _ = Command::new("/usr/local/bin/k3s-uninstall.sh").status();
            sp.success("K3s cluster uninstalled");
        }

        if Path::new("/usr/local/bin/k3s-agent-uninstall.sh").exists() {
            let sp = Ui::spinner("Running K3s agent uninstaller...");
            let _ = Command::new("/usr/local/bin/k3s-agent-uninstall.sh").status();
            sp.success("K3s agent uninstalled");
        }

        if Path::new("/etc/sysctl.d/99-amiterra-bootstrap.conf").exists() {
            let _ = fs::remove_file("/etc/sysctl.d/99-amiterra-bootstrap.conf");
            let _ = Command::new("sysctl").arg("--system").status();
            Ui::step_done(
                "Reverted kernel sysctl profile /etc/sysctl.d/99-amiterra-bootstrap.conf",
                None,
            );
        }

        if Path::new("/etc/security/limits.d/99-amiterra.conf").exists() {
            let _ = fs::remove_file("/etc/security/limits.d/99-amiterra.conf");
            Ui::step_done(
                "Removed resource limits /etc/security/limits.d/99-amiterra.conf",
                None,
            );
        }

        if _purge {
            let _ = fs::remove_dir_all("/etc/amiterra");
            let _ = fs::remove_dir_all("/var/lib/amiterra");
        }

        Ok(())
    }
}

fn apply_host_invariants() -> Result<()> {
    let sysctl_content = r#"# Amiterra Day-0 Baseline Host Invariants
net.core.bpf_jit_enable = 1
net.core.bpf_jit_harden = 2
kernel.unprivileged_bpf_disabled = 1
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 16384
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 16384
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
fs.file-max = 2097152
fs.nr_open = 2097152
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 524288
vm.swappiness = 0
vm.panic_on_oom = 0
kernel.panic = 10
kernel.panic_on_oops = 1
"#;
    let sysctl_path = Path::new("/etc/sysctl.d/99-amiterra-bootstrap.conf");
    backup_file_if_exists(sysctl_path)?;
    fs::write(sysctl_path, sysctl_content)?;

    let limits_content = r#"* soft nofile 524288
* hard nofile 524288
root soft nofile 524288
root hard nofile 524288
"#;
    let limits_path = Path::new("/etc/security/limits.d/99-amiterra.conf");
    backup_file_if_exists(limits_path)?;
    fs::write(limits_path, limits_content)?;

    let _ = Command::new("sysctl").arg("--system").output();
    let _ = Command::new("ufw").args(["default", "allow", "routed"]).output();

    Ok(())
}

pub fn render_k3s_config(config: &ClusterNodeConfig) -> String {
    let mut yaml = String::new();
    yaml.push_str("# Amiterra Production Headless K3s Configuration\n");
    yaml.push_str(&format!("node-ip: \"{}\"\n", config.node_ip));
    if let Some(ext) = &config.node_external_ip {
        yaml.push_str(&format!("node-external-ip: \"{}\"\n", ext));
    }
    if config.role.is_control_plane() {
        yaml.push_str("flannel-backend: \"none\"\n");
        yaml.push_str("disable-network-policy: true\n");
        yaml.push_str("disable-kube-proxy: true\n");
        yaml.push_str("disable:\n  - traefik\n  - servicelb\n  - local-storage\n");
        yaml.push_str(&format!("cluster-cidr: \"{}\"\n", config.pod_cidr));
        yaml.push_str(&format!("service-cidr: \"{}\"\n", config.service_cidr));

        if !config.tls_sans.is_empty() {
            yaml.push_str("tls-san:\n");
            for san in &config.tls_sans {
                yaml.push_str(&format!("  - \"{}\"\n", san));
            }
        }

        if config.role == NodeRole::ControlPlaneInit {
            yaml.push_str("cluster-init: true\n");
        }
    }

    if let Some(url) = &config.server_url {
        yaml.push_str(&format!("server: \"{}\"\n", url));
    }
    if let Some(tok) = &config.cluster_token {
        yaml.push_str(&format!("token: \"{}\"\n", tok));
    }

    if config.isolate_control_plane && config.role.is_control_plane() {
        yaml.push_str("node-taint:\n  - \"CriticalAddonsOnly=true:NoSchedule\"\n");
    }

    yaml.push_str("kubelet-arg:\n");
    yaml.push_str("  - \"system-reserved=cpu=100m,memory=200Mi\"\n");
    yaml.push_str("  - \"kube-reserved=cpu=100m,memory=200Mi\"\n");
    yaml.push_str("  - \"feature-gates=NodeSwap=true\"\n");

    yaml
}

fn write_tailored_k3s_config(config: &ClusterNodeConfig) -> Result<()> {
    let content = render_k3s_config(config);
    let config_path = Path::new("/etc/rancher/k3s/config.yaml");
    backup_file_if_exists(config_path)?;
    fs::write(config_path, content)?;
    Ok(())
}

pub fn render_cilium_manifest(wireguard_enabled: bool) -> String {
    let enc_block = if wireguard_enabled {
        "    encryption:\n      enabled: true\n      type: wireguard"
    } else {
        "    encryption:\n      enabled: false"
    };

    format!(
        r#"apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: cilium
  namespace: kube-system
spec:
  repo: https://helm.cilium.io/
  chart: cilium
  version: "1.16.2"
  targetNamespace: kube-system
  bootstrap: true
  valuesContent: |-
    kubeProxyReplacement: true
    k8sServiceHost: 127.0.0.1
    k8sServicePort: 6443
    devices: ""
    ipam:
      mode: kubernetes
    bpf:
      masquerade: true
      hostRouting: true
{}
    operator:
      replicas: 1
    envoy:
      enabled: false
    hubble:
      enabled: true
      relay:
        enabled: false
      ui:
        enabled: false
"#,
        enc_block
    )
}

fn deploy_cilium_manifest(wireguard_enabled: bool) -> Result<()> {
    let manifest_content = render_cilium_manifest(wireguard_enabled);
    let manifest_path = Path::new("/var/lib/rancher/k3s/server/manifests/cilium-helmchart.yaml");
    if let Some(parent) = manifest_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(manifest_path, manifest_content)?;
    Ok(())
}


fn install_k3s_binary(config: &ClusterNodeConfig) -> Result<()> {
    let has_curl = Command::new("curl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !has_curl {
        bail!("'curl' command is required to install K3s. Please install curl (e.g. apt-get install -y curl).");
    }

    let exec_type = if config.role == NodeRole::Worker {
        "agent"
    } else {
        "server"
    };
    let cmd = format!(
        "set -e -o pipefail; curl -sfL https://get.k3s.io | INSTALL_K3S_SKIP_START=true INSTALL_K3S_CHANNEL=\"v1.31\" INSTALL_K3S_EXEC=\"{}\" sh -s -",
        exec_type
    );
    let output = Command::new("sh").arg("-c").arg(&cmd).output();
    match output {
        Ok(out) if out.status.success() => {
            if !Path::new("/usr/local/bin/k3s").exists() {
                bail!("K3s installer completed with status 0, but /usr/local/bin/k3s was not created on disk.");
            }
            Ok(())
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            bail!("Failed to download and install K3s: {}", err.trim());
        }
        Err(e) => bail!("Failed to execute K3s installation script: {}", e),
    }
}

fn wait_for_node_readiness(timeout_secs: u64) -> Result<()> {
    let start = std::time::Instant::now();
    while start.elapsed().as_secs() < timeout_secs {
        let out = Command::new("k3s")
            .args(["kubectl", "get", "nodes"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("Ready") {
                return Ok(());
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    let status_out = Command::new("systemctl")
        .args(["is-active", "k3s"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let journal_logs = Command::new("journalctl")
        .args(["-u", "k3s", "-n", "15", "--no-pager"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    bail!(
        "Timed out after {}s waiting for K3s node to reach 'Ready' state.\nService status: {}\nRecent logs:\n{}",
        timeout_secs,
        status_out,
        journal_logs
    );
}

fn install_systemd_unit() -> Result<()> {
    let unit_content = r#"[Unit]
Description=Amiterra Host & Workload Tuner Daemon
After=k3s.service
Wants=k3s.service

[Service]
Type=simple
Environment=RUST_LOG=info
ExecStart=/usr/local/bin/amiterra daemon
Restart=always
RestartSec=5
LimitNOFILE=524288
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#;
    let unit_path = Path::new("/etc/systemd/system/amiterra.service");
    fs::write(unit_path, unit_content)?;

    let _ = Command::new("systemctl").arg("daemon-reload").output();
    let _ = Command::new("systemctl").args(["enable", "--now", "amiterra"]).output();
    Ok(())
}

fn backup_file_if_exists(path: &Path) -> Result<()> {
    if path.exists() {
        let backup_path = path.with_extension("amiterra.bak");
        fs::copy(path, backup_path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_k3s_config_not_installed() {
        let res = analyze_k3s_config(false, None, false);
        assert_eq!(res, K3sInspection::NotInstalled);
    }

    #[test]
    fn test_analyze_k3s_config_compliant() {
        let sample = r#"
flannel-backend: "none"
disable-kube-proxy: true
disable:
  - traefik
  - servicelb
"#;
        let res = analyze_k3s_config(true, Some(sample), true);
        assert_eq!(res, K3sInspection::CompliantAmiterraInstance);
    }

    #[test]
    fn test_analyze_k3s_config_conflicting_default_k3s() {
        let sample = r#"
# Default K3s config with Flannel and Traefik active
node-ip: 10.0.0.5
"#;
        let res = analyze_k3s_config(true, Some(sample), true);
        match res {
            K3sInspection::ConflictingInstance {
                flannel_active,
                kube_proxy_active,
                traefik_active,
                service_active,
            } => {
                assert!(flannel_active);
                assert!(kube_proxy_active);
                assert!(traefik_active);
                assert!(service_active);
            }
            _ => panic!("Expected ConflictingInstance, got {:?}", res),
        }
    }

    #[test]
    fn test_render_k3s_config_control_plane_init() {
        let config = ClusterNodeConfig {
            role: NodeRole::ControlPlaneInit,
            node_ip: "65.109.10.20".to_string(),
            node_external_ip: None,
            wireguard_enabled: true,
            pod_cidr: "10.42.0.0/16".to_string(),
            service_cidr: "10.43.0.0/16".to_string(),
            tls_sans: vec!["node1.infra.amiterra.io".to_string()],
            server_url: None,
            cluster_token: Some("secret123".to_string()),
            isolate_control_plane: true,
        };

        let yaml = render_k3s_config(&config);
        assert!(yaml.contains("node-ip: \"65.109.10.20\""));
        assert!(yaml.contains("cluster-init: true"));
        assert!(yaml.contains("token: \"secret123\""));
        assert!(yaml.contains("cluster-cidr: \"10.42.0.0/16\""));
        assert!(yaml.contains("tls-san:\n  - \"node1.infra.amiterra.io\""));
        assert!(yaml.contains("node-taint:\n  - \"CriticalAddonsOnly=true:NoSchedule\""));
    }

    #[test]
    fn test_render_k3s_config_worker_join() {
        let config = ClusterNodeConfig {
            role: NodeRole::Worker,
            node_ip: "10.0.1.50".to_string(),
            node_external_ip: Some("198.51.100.1".to_string()),
            wireguard_enabled: false,
            pod_cidr: "10.42.0.0/16".to_string(),
            service_cidr: "10.43.0.0/16".to_string(),
            tls_sans: vec![],
            server_url: Some("https://10.0.1.10:6443".to_string()),
            cluster_token: Some("join-token".to_string()),
            isolate_control_plane: false,
        };

        let yaml = render_k3s_config(&config);
        assert!(yaml.contains("node-ip: \"10.0.1.50\""));
        assert!(yaml.contains("node-external-ip: \"198.51.100.1\""));
        assert!(yaml.contains("server: \"https://10.0.1.10:6443\""));
        assert!(yaml.contains("token: \"join-token\""));
        // Workers should not have cluster-init, disable, flannel-backend or disable-kube-proxy flags
        assert!(!yaml.contains("cluster-init: true"));
        assert!(!yaml.contains("disable:\n"));
        assert!(!yaml.contains("flannel-backend"));
        assert!(!yaml.contains("disable-kube-proxy"));
    }

    #[test]
    fn test_render_cilium_manifest_encryption() {
        let manifest_wg = render_cilium_manifest(true);
        assert!(manifest_wg.contains("encryption:\n      enabled: true\n      type: wireguard"));

        let manifest_no_wg = render_cilium_manifest(false);
        assert!(manifest_no_wg.contains("encryption:\n      enabled: false"));
        assert!(!manifest_no_wg.contains("type: wireguard"));
    }
}
