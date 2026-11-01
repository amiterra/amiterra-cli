use anyhow::{Context, Result, bail};
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

/// Operator choice when an existing K3s install conflicts with Amiterra.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemediationChoice {
    SafeMigration,
    CleanReinstall,
    Abort,
}

/// Pure parser for the remediation menu. `None` = invalid input (re-prompt).
/// Empty input = documented default (Safe Migration). Never maps garbage to a destructive path.
pub fn parse_remediation_choice(raw: &str) -> Option<RemediationChoice> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "1" => Some(RemediationChoice::SafeMigration),
        "2" => Some(RemediationChoice::CleanReinstall),
        "3" | "q" | "quit" | "abort" => Some(RemediationChoice::Abort),
        _ => None,
    }
}

/// True when `item` appears in the k3s `disable:` list (block or inline form).
/// A plain substring search would also match comments and unrelated keys.
fn disable_list_contains(content: &str, item: &str) -> bool {
    let mut in_disable = false;
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        if let Some(rest) = t.strip_prefix("disable:") {
            in_disable = true;
            let rest = rest.split('#').next().unwrap_or("").trim();
            if rest.starts_with('[') {
                return rest
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .split(',')
                    .any(|x| x.trim() == item);
            }
            if rest == item {
                return true;
            }
            continue;
        }
        if in_disable {
            if let Some(v) = t.strip_prefix('-') {
                if v.split('#').next().unwrap_or("").trim() == item {
                    return true;
                }
            } else if !t.is_empty() {
                in_disable = false;
            }
        }
    }
    false
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
    let flannel_none =
        content.contains("flannel-backend: \"none\"") || content.contains("flannel-backend: none");
    let kube_proxy_disabled = content.contains("disable-kube-proxy: true")
        || content.contains("disable-kube-proxy: \"true\"");
    let traefik_disabled = disable_list_contains(content, "traefik");

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
            bail!(
                "Superuser privileges are required for production server setup. Run: sudo ami init"
            );
        }

        let report = run_preflight();
        if report.is_workstation {
            Ui::step_warn(
                "Workstation indicators detected: server kernel sysctl may disrupt Wi-Fi or Swap on a laptop.",
            );
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

                // Ensure platform prep and amiterra daemon are running
                crate::tune::apply_platform_prep()?;
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
                    let service_name =
                        if Path::new("/etc/systemd/system/k3s-agent.service").exists() {
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
                wait_for_node_readiness(NODE_READY_TIMEOUT_SECS)?;

                let cfg = AmiterraConfig {
                    mode: EnvironmentMode::Server,
                    cluster: crate::context::ClusterConfig {
                        runtime: "k3s".to_string(),
                        networking: "cilium-ebpf (kube-proxy replacement)".to_string(),
                        ..Default::default()
                    },
                };
                let _ = ctx.save_config(&cfg);

                Ui::step_done("Host is aligned with cluster state.", None);
                Ui::next_steps(
                    "Verify status:",
                    &["$ ami status", "$ journalctl -u amiterra -f"],
                );
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
                    println!(
                        "    • Kube-Proxy is active (Conflicts with Cilium eBPF Host-Routing)"
                    );
                }
                if *traefik_active {
                    println!(
                        "    • Traefik ingress is active (Conflicts with Amiterra API Gateway)"
                    );
                }

                if dry_run {
                    Ui::step_info(
                        "Dry-run preview",
                        "Would offer Safe Migration (backup & align) or Clean Reinstall.",
                    );
                } else {
                    use std::io::IsTerminal;
                    let remediation = if init_args.yes || !std::io::stdin().is_terminal() {
                        RemediationChoice::SafeMigration // explicit non-interactive default
                    } else {
                        use std::io::Write;
                        println!("\n  Recommended Remediation Options:");
                        println!(
                            "    1. Safe Migration (Recommended) — Back up config and reconfigure to Amiterra eBPF"
                        );
                        println!(
                            "    2. Clean Reinstall              — Run k3s-uninstall.sh and perform fresh bootstrap"
                        );
                        println!(
                            "    3. Abort                        — Exit without modifying host"
                        );
                        loop {
                            print!(
                                "\n  {} Select remediation option [1-3, Enter=1]: ",
                                crate::ui::Palette::cyan("?")
                            );
                            std::io::stdout().flush()?;
                            let mut input = String::new();
                            std::io::stdin().read_line(&mut input)?;
                            match parse_remediation_choice(input.trim()) {
                                Some(choice) => break choice,
                                None => {
                                    crate::ui::Ui::step_warn(
                                        "Invalid selection. Enter 1 (Safe Migration), 2 (Clean Reinstall), 3 (Abort), or press Enter for 1.",
                                    );
                                }
                            }
                        }
                    };

                    match remediation {
                        RemediationChoice::Abort => {
                            bail!(
                                "Installation aborted by user to resolve K3s configuration conflicts."
                            );
                        }
                        RemediationChoice::CleanReinstall => {
                            let s_clean = Ui::spinner("Running K3s uninstaller for clean reset...");
                            let r = crate::cleanup::run_k3s_uninstaller(
                                "/usr/local/bin/k3s-uninstall.sh",
                            );
                            let _ = fs::remove_dir_all("/etc/rancher/k3s");
                            // Same leftovers as `ami uninstall` would leave: the k3s
                            // script knows nothing about Cilium, and stale datapath
                            // state makes the next install's CIDR detector drift.
                            let report = crate::cleanup::cleanup_cilium_datapath();
                            if report.removed.is_empty() && report.failed.is_empty() {
                                s_clean.success("Existing K3s cleanly uninstalled");
                            } else {
                                s_clean.success(&format!(
                                    "Existing K3s cleanly uninstalled (+{} Cilium leftover(s))",
                                    report.removed.len()
                                ));
                            }
                            for f in &report.failed {
                                Ui::step_warn(&format!("could not remove {f}"));
                            }
                            if let Err(e) = r {
                                Ui::step_warn(&format!("k3s uninstaller reported: {e:#}"));
                            }
                        }
                        RemediationChoice::SafeMigration => {
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

            Ui::card(
                "Planned Node Configuration (Dry-Run Preview)",
                &preview_items,
            );

            println!(
                "  {}",
                crate::ui::Palette::bold("Planned Host Modifications:")
            );
            println!(
                "    {} 1. Platform prep (opt-out of perf tuning): {}",
                crate::ui::Palette::cyan("›"),
                crate::ui::Palette::dim(
                    "/etc/sysctl.d/98-amiterra-platform.conf (ip_forward only)"
                )
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
            println!(
                "    {} 5. Storage optimization:        {}",
                crate::ui::Palette::cyan("›"),
                match &node_config.storage {
                    crate::features::StoragePlan::Skip => {
                        crate::ui::Palette::dim("SKIPPED — later: ami storage prepare")
                    }
                    crate::features::StoragePlan::Activate => {
                        crate::ui::Palette::dim("activate dedicated VG")
                    }
                    crate::features::StoragePlan::Prepare(d) => {
                        crate::ui::Palette::dim(&format!("prepare /dev/{d} (LVM)"))
                    }
                }
            );
            println!(
                "    {} 6. Performance tuning:          {}",
                crate::ui::Palette::cyan("›"),
                if node_config.apply_performance_tuning {
                    crate::ui::Palette::dim("ami tune apply")
                } else {
                    crate::ui::Palette::dim("SKIPPED — later: ami tune apply")
                }
            );
            println!(
                "    {} 7. GitOps bootstrap:            {}",
                crate::ui::Palette::cyan("›"),
                if node_config.gitops_bootstrap {
                    crate::ui::Palette::dim("ami gitops bootstrap")
                } else {
                    crate::ui::Palette::dim("SKIPPED — later: ami gitops bootstrap")
                }
            );
            println!();
            Ui::step_done(
                "Dry-run preview complete · Zero system modifications applied.",
                None,
            );
            println!();
            return Ok(());
        }

        // 4. Platform prep only (pod networking). Performance tuning is opt-in via `ami tune`.
        let s1 = Ui::spinner("Applying platform prep (pod networking sysctl)...");
        let platform_changes = crate::tune::apply_platform_prep()?;
        s1.success(&format!(
            "Platform prep applied ({} networking key(s))",
            platform_changes.len().max(2)
        ));

        // 5. K3s binary check & headless install
        if !Path::new("/usr/local/bin/k3s").exists() {
            let s_k3s = Ui::spinner("Installing K3s binary (v1.37.1+k3s1, headless)...");
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
            deploy_cilium_manifest(node_config.wireguard_enabled, &api_server_host(&node_config))?;
            let enc_str = if node_config.wireguard_enabled {
                "with WireGuard WAN encryption"
            } else {
                "direct host routing"
            };
            s3.success(&format!("Cilium eBPF manifest deployed ({})", enc_str));
        }

        // 7a. Storage feature (opt-in): dedicated LVM data disk. Runs BEFORE the
        // data root so stateful directories land on the dedicated volume and the
        // tier is classified correctly in this very run.
        match &node_config.storage {
            crate::features::StoragePlan::Skip => {}
            crate::features::StoragePlan::Activate | crate::features::StoragePlan::Prepare(_) => {
                let s_st = Ui::spinner("Preparing dedicated data disk...");
                if let crate::features::StoragePlan::Prepare(disk) = &node_config.storage {
                    let inv = crate::storage::StorageInventory::probe().unwrap_or_default();
                    let plan = crate::storage::prepare::plan_prepare(
                        &inv,
                        disk,
                        crate::storage::prepare::DEFAULT_VG,
                    )?;
                    crate::storage::prepare::execute_prepare(&plan, false, true)?;
                }
                let done = crate::storage::prepare::activate_data_root(
                    crate::storage::prepare::DEFAULT_VG,
                    false,
                )?;
                s_st.success(&format!(
                    "Dedicated data disk active ({} step(s))",
                    done.len().max(1)
                ));
            }
        }

        // 7b. Universal storage: data-root + StorageClass (control plane).
        {
            let s_st = Ui::spinner("Preparing universal stateful data root...");
            crate::storage::cli::apply_universal_data_root()?;
            if node_config.role.is_control_plane() {
                let manifests = Path::new("/var/lib/rancher/k3s/server/manifests");
                let _ = fs::create_dir_all(manifests);
                let sc_path = manifests.join("amiterra-storage-class.yaml");
                fs::write(
                    &sc_path,
                    crate::storage::local_storageclass_yaml(crate::storage::DATA_ROOT),
                )?;
            }
            s_st.success("Data root ready (tier s0 shared-root until dedicated disk)");
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
            bail!(
                "Failed to start systemd service '{}': {}",
                service_name,
                err.trim()
            );
        }
        install_systemd_unit()?;
        s4.success("Systemd services enabled and running");

        // 9. Active readiness probe
        if node_config.role.is_control_plane() {
            let s_ready = Ui::spinner("Waiting for control-plane readiness in cluster...");
            wait_for_node_readiness(NODE_READY_TIMEOUT_SECS)?;
            s_ready.success("Control-plane node registered and active");
        }

        // 9b. Storage tier card + node labels (best-effort kubectl).
        let storage_summary = {
            let inv = crate::storage::StorageInventory::probe().unwrap_or_default();
            let summary = crate::storage::classify(&inv);
            println!();
            println!("  {}", crate::ui::Palette::bold("Storage (universal node)"));
            println!(
                "    tier={} class={} policy={}",
                summary.tier.as_str(),
                summary.storage_class.as_str(),
                summary.policy_label()
            );
            for n in &summary.notes {
                println!("     {} {}", crate::ui::Palette::yellow("!"), n);
            }
            let _ = apply_storage_node_labels(&summary);
            // The upgrade hint is a dead end when nothing can be prepared.
            if summary.free_disk_names.is_empty() {
                println!(
                    "     {}",
                    crate::ui::Palette::dim("Details: ami storage plan")
                );
            } else {
                println!(
                    "     {}",
                    crate::ui::Palette::dim(
                        "Details: ami storage plan   |  upgrade: ami storage prepare"
                    )
                );
            }
            summary
        };

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
        };
        let _ = ctx.save_config(&cfg);

        // Optional performance tuning. The wizard's feature plan is the single
        // source of truth (flags / --all-features / prompts already resolved).
        let tune_apply = node_config.apply_performance_tuning;
        if tune_apply {
            // `tune::apply` owns its UI (header/plan/report) — no outer spinner
            // and no repeated success line; the inner report is the step output.
            if let Err(e) = crate::tune::apply(true, false) {
                Ui::step_warn(&format!("Performance profile failed: {e:#}"));
                Ui::step_warn("Cluster is up; tune later with `sudo ami tune apply`");
            }
        }

        // Optional GitOps bootstrap. The feature plan is authoritative; the C1
        // role gate stays as defense in depth (cluster-init only).
        let gitops_bootstrap =
            node_config.gitops_bootstrap && node_config.role == NodeRole::ControlPlaneInit;
        if node_config.gitops_bootstrap && node_config.role != NodeRole::ControlPlaneInit {
            Ui::step_warn(
                "GitOps bootstrap skipped: only the control-plane-init node may bind \
                 the cluster Git repository",
            );
        }
        // Some(true) = converged, Some(false) = attempted but failed, None = not requested.
        let mut gitops_outcome: Option<bool> = None;
        if gitops_bootstrap {
            let opts = crate::gitops::BootstrapOptions {
                node_ip: node_config.node_ip.clone(),
                yes: true,
                wait_ready: true,
                ..Default::default()
            };
            match crate::gitops::bootstrap(&opts) {
                Ok(_) => {
                    Ui::step_done("GitOps bootstrapped (Flux bound to Git)", None);
                    gitops_outcome = Some(true);
                }
                Err(e) => {
                    Ui::step_warn(&format!("GitOps bootstrap failed: {e:#}"));
                    Ui::step_warn(
                        "Cluster is up; bootstrap later with `sudo ami gitops bootstrap`",
                    );
                    gitops_outcome = Some(false);
                }
            }
        }

        if node_config.role == NodeRole::ControlPlaneInit {
            let ready_items = [
                ("Cluster State", "● healthy (control plane online)"),
                (
                    "Kubernetes API",
                    &format!("https://{}:6443 (mTLS secured)", node_config.node_ip),
                ),
                ("Networking Stack", "Cilium eBPF (Host-Routing)"),
                (
                    "Performance Profile",
                    if tune_apply {
                        "● applied"
                    } else {
                        "○ skipped (safe default)"
                    },
                ),
                (
                    "GitOps (Flux)",
                    match gitops_outcome {
                        Some(true) => "● bootstrapped",
                        Some(false) => "○ failed (retry: sudo ami gitops bootstrap)",
                        None => "○ skipped (safe default)",
                    },
                ),
                (
                    "Storage",
                    &format!(
                        "{} {} · policy {}",
                        storage_summary.tier.as_str(),
                        storage_summary.storage_class.as_str(),
                        storage_summary.policy_label()
                    ),
                ),
                (
                    "WireGuard Mesh",
                    if node_config.wireguard_enabled {
                        "● Active (Transparent WAN encryption)"
                    } else {
                        "○ Disabled (Private network)"
                    },
                ),
            ];
            Ui::card("Amiterra Production Cluster Initialized", &ready_items);

            // The join token is a secret (C2): never print it here. Show the
            // lookup commands instead — highlighted, copy-paste ready.
            println!(
                "  {}",
                crate::ui::Palette::bold(
                    "To join additional nodes to this cluster, get the join command here:"
                )
            );
            println!();
            println!("  {} Worker node:", crate::ui::Palette::cyan("›"));
            println!(
                "    {} {}",
                crate::ui::Palette::dim("$"),
                crate::ui::Palette::bold_blue("ami join-command worker")
            );
            println!();
            println!(
                "  {} Control Plane node (HA):",
                crate::ui::Palette::cyan("›")
            );
            println!(
                "    {} {}",
                crate::ui::Palette::dim("$"),
                crate::ui::Palette::bold_blue("ami join-command control-plane")
            );
            println!();
            println!(
                "  {} Each command prints the full join string (embeds the cluster token).",
                crate::ui::Palette::dim("→")
            );
            println!(
                "  {} Run it on this node, then execute the printed line on the joining node.",
                crate::ui::Palette::dim("→")
            );
            println!();

            let mut steps = vec![
                "$ ami status".to_string(),
                "$ kubectl get nodes -o wide".to_string(),
            ];
            if !tune_apply {
                steps.push(
                    "$ sudo ami tune apply   # optional performance profile (BBR, limits)"
                        .to_string(),
                );
            }
            if gitops_outcome != Some(true) {
                steps.push(
                    "$ sudo ami gitops bootstrap   # optional GitOps (Flux + Git binding)"
                        .to_string(),
                );
            }
            let step_refs: Vec<&str> = steps.iter().map(String::as_str).collect();
            Ui::next_steps("Inspect cluster status:", &step_refs);
        } else {
            // Agent service is running (verified in the systemd step), but
            // cluster registration is only visible from the control plane.
            println!();
            Ui::step_done("Node join complete (k3s service running)", None);
            let mut steps = vec![
                "$ ami status".to_string(),
                "$ kubectl get nodes   # on the control plane — confirm node is Ready".to_string(),
            ];
            if !tune_apply {
                steps.push("$ sudo ami tune apply   # optional performance profile".to_string());
            }
            let step_refs: Vec<&str> = steps.iter().map(String::as_str).collect();
            Ui::next_steps("Verify node status:", &step_refs);
        }

        Ok(())
    }

    fn up(&self, ctx: &ExecutionContext, dry_run: bool) -> Result<()> {
        if !Path::new("/etc/systemd/system/amiterra.service").exists() {
            return self.init(ctx, dry_run);
        }
        if dry_run {
            Ui::step_info(
                "Dry-run preview",
                "Would start k3s.service and amiterra.service",
            );
            return Ok(());
        }
        let sp = Ui::spinner("Starting Amiterra Production Server services...");
        let mut failed = Vec::new();
        for svc in ["k3s", "amiterra"] {
            let out = Command::new("systemctl").args(["start", svc]).output();
            match out {
                Ok(o) if o.status.success() => {}
                Ok(o) => failed.push(format!(
                    "{svc}: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                )),
                Err(e) => failed.push(format!("{svc}: {e}")),
            }
        }
        if !failed.is_empty() {
            sp.fail("Failed to start production server services");
            bail!("service start failed:\n  {}", failed.join("\n  "));
        }
        sp.success("Production server services started");
        Ui::next_steps("Verify health:", &["$ ami status"]);
        Ok(())
    }

    fn down(&self, _ctx: &ExecutionContext) -> Result<()> {
        let sp = Ui::spinner("Stopping Amiterra Production Server services...");
        let mut failed = Vec::new();
        for svc in ["amiterra", "k3s"] {
            let out = Command::new("systemctl").args(["stop", svc]).output();
            match out {
                Ok(o) if o.status.success() => {}
                Ok(o) => failed.push(format!(
                    "{svc}: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                )),
                Err(e) => failed.push(format!("{svc}: {e}")),
            }
        }
        if !failed.is_empty() {
            sp.fail("Failed to stop some services");
            bail!("service stop failed:\n  {}", failed.join("\n  "));
        }
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

        // Feature states (opt-in features report their own durable state).
        match crate::tune::status() {
            Ok(t) => metrics.push(StatusMetric {
                label: "Performance Profile".to_string(),
                value: if t.performance_applied {
                    "● applied (BBR, limits, swappiness)".to_string()
                } else if t.platform_applied {
                    "◐ platform prep only (run `sudo ami tune apply`)".to_string()
                } else {
                    "○ not applied (run `sudo ami tune apply`)".to_string()
                },
            }),
            Err(_) => metrics.push(StatusMetric {
                label: "Performance Profile".to_string(),
                value: "○ unknown (tune state unreadable)".to_string(),
            }),
        }
        match crate::gitops::status() {
            Ok(g) => metrics.push(StatusMetric {
                label: "GitOps (Flux)".to_string(),
                value: if g.installed {
                    // M1: report live sync state, not just "state.yaml says bootstrapped".
                    let sync = match g.sync {
                        crate::gitops::flux::SyncHealth::Ready => "synced",
                        crate::gitops::flux::SyncHealth::Degraded => "sync degraded",
                        crate::gitops::flux::SyncHealth::NotInstalled => "flux missing",
                        crate::gitops::flux::SyncHealth::Unknown => "sync unknown",
                    };
                    match &g.state {
                        Some(s) => format!("● bootstrapped (branch {}, {sync})", s.branch),
                        None => format!("● bootstrapped ({sync})"),
                    }
                } else if g.private_key_present {
                    "◐ deploy key present — not bootstrapped (run `sudo ami gitops bootstrap`)"
                        .to_string()
                } else {
                    "○ not bootstrapped (run `sudo ami gitops bootstrap`)".to_string()
                },
            }),
            Err(_) => metrics.push(StatusMetric {
                label: "GitOps (Flux)".to_string(),
                value: "○ unknown (gitops state unreadable)".to_string(),
            }),
        }
        {
            let inv = crate::storage::inventory::StorageInventory::probe().unwrap_or_default();
            let summary = crate::storage::classify(&inv);
            let vg_note = if crate::storage::prepare::dedicated_vg_present(
                crate::storage::prepare::DEFAULT_VG,
            ) {
                " · VG amiterra-data ready"
            } else {
                ""
            };
            metrics.push(StatusMetric {
                label: "Storage".to_string(),
                value: format!(
                    "{} {} · policy {}{vg_note}",
                    summary.tier.as_str(),
                    summary.storage_class.as_str(),
                    summary.policy_label()
                ),
            });
        }
        {
            let wg =
                fs::read_to_string("/var/lib/rancher/k3s/server/manifests/cilium-helmchart.yaml")
                    .map(|m| m.contains("type: wireguard"))
                    .unwrap_or(false);
            metrics.push(StatusMetric {
                label: "WireGuard Mesh".to_string(),
                value: if wg {
                    "● Active (Transparent WAN encryption)".to_string()
                } else {
                    "○ Disabled (Private network)".to_string()
                },
            });
        }

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

    fn uninstall(&self, _ctx: &ExecutionContext, purge: bool) -> Result<()> {
        let mut failures = Vec::new();

        if Path::new("/etc/systemd/system/amiterra.service").exists() {
            for act in [
                ["stop", "amiterra"].as_slice(),
                ["disable", "amiterra"].as_slice(),
            ] {
                if let Ok(o) = Command::new("systemctl").args(act).output()
                    && !o.status.success()
                {
                    failures.push(format!(
                        "systemctl {} amiterra: {}",
                        act[0],
                        String::from_utf8_lossy(&o.stderr).trim()
                    ));
                }
            }
            if let Err(e) = fs::remove_file("/etc/systemd/system/amiterra.service") {
                failures.push(format!("remove amiterra.service: {e}"));
            } else {
                Ui::step_done("Removed systemd service amiterra.service", None);
            }
        }

        // k3s uninstallers are verbose by design (xtrace, umount listings) —
        // capture their output; noise is surfaced only when a script fails.
        for (script, label) in [
            ("/usr/local/bin/k3s-uninstall.sh", "K3s cluster"),
            ("/usr/local/bin/k3s-agent-uninstall.sh", "K3s agent"),
        ] {
            if Path::new(script).exists() {
                let sp = Ui::spinner(format!("Running {} uninstaller...", label));
                match crate::cleanup::run_k3s_uninstaller(script) {
                    Ok(()) => sp.success(&format!("{label} uninstalled")),
                    Err(e) => {
                        sp.fail(&format!("{label} uninstaller failed"));
                        failures.push(format!("{label} uninstaller: {e:#}"));
                    }
                }
            }
        }

        // Cilium datapath cleanup: the k3s uninstaller knows only its own
        // stack (flannel/cni0); our CNI leaves interfaces, routes and
        // netfilter chains behind — they pollute the host and confuse the
        // next install's CIDR auto-detection.
        let sp = Ui::spinner("Cleaning Cilium datapath leftovers...");
        let report = crate::cleanup::cleanup_cilium_datapath();
        if report.removed.is_empty() && report.failed.is_empty() {
            sp.success("No Cilium datapath leftovers");
        } else {
            sp.success(&format!(
                "Removed {} Cilium leftover(s)",
                report.removed.len()
            ));
        }
        for f in &report.failed {
            Ui::step_warn(&format!("could not remove {f}"));
        }

        // GitOps system account (the repository itself is data — purge's job).
        for desc in crate::cleanup::remove_git_user(crate::gitops::local_bare::GIT_USER) {
            Ui::step_done(&format!("Removed {desc}"), None);
        }

        // Restore tuned host state (performance profile + platform prep + legacy).
        if let Err(e) = crate::tune::rollback(true) {
            Ui::step_warn(&format!("tune rollback during uninstall failed: {e:#}"));
        }
        let mut removed_any = false;
        for path in [
            crate::tune::LEGACY_SYSCTL_PATH,
            crate::tune::PLATFORM_SYSCTL_PATH,
            crate::tune::TUNE_SYSCTL_PATH,
            crate::tune::TUNE_LIMITS_PATH,
        ] {
            if Path::new(path).exists() {
                let _ = fs::remove_file(path);
                removed_any = true;
                Ui::step_done(&format!("Removed {path}"), None);
            }
        }
        // Only reload on Linux when drop-ins changed (macOS `sysctl` has no --system).
        if removed_any && let Err(e) = crate::tune::reload_sysctl() {
            Ui::step_warn(&format!("sysctl reload after cleanup failed: {e:#}"));
        }

        if purge {
            for dir in ["/etc/amiterra", "/var/lib/amiterra"] {
                if !Path::new(dir).exists() {
                    continue;
                }
                match fs::remove_dir_all(dir) {
                    Ok(()) => Ui::step_done(&format!("Removed {dir}"), None),
                    Err(e) => failures.push(format!("purge {dir}: {e}")),
                }
            }
        }

        if !failures.is_empty() {
            bail!(
                "uninstall incomplete — host may be partially restored:\n  {}",
                failures.join("\n  ")
            );
        }
        Ok(())
    }
}

/// Escape a scalar for a double-quoted YAML string: prevents structure
/// injection when values arrive from discovery, wizard or CLI input.
fn yaml_dq(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn render_k3s_config(config: &ClusterNodeConfig) -> String {
    let mut yaml = String::new();
    yaml.push_str("# Amiterra Production Headless K3s Configuration\n");
    yaml.push_str(&format!("node-ip: \"{}\"\n", yaml_dq(&config.node_ip)));
    if let Some(ext) = &config.node_external_ip {
        yaml.push_str(&format!("node-external-ip: \"{}\"\n", yaml_dq(ext)));
    }
    if config.role.is_control_plane() {
        yaml.push_str("flannel-backend: \"none\"\n");
        yaml.push_str("disable-network-policy: true\n");
        yaml.push_str("disable-kube-proxy: true\n");
        yaml.push_str("disable:\n  - traefik\n  - servicelb\n  - local-storage\n");
        // Без явного advertise-address k3s выбирает node-external-ip (auto-
        // detected egress IP) — это отравляет endpoints сервиса `kubernetes`:
        // поды внутри кластера не могут достучаться до API. Всегда рекламируем
        // приватный cluster IP узла.
        yaml.push_str(&format!(
            "advertise-address: \"{}\"\n",
            yaml_dq(&config.node_ip)
        ));
        yaml.push_str(&format!(
            "cluster-cidr: \"{}\"\n",
            yaml_dq(&config.pod_cidr)
        ));
        yaml.push_str(&format!(
            "service-cidr: \"{}\"\n",
            yaml_dq(&config.service_cidr)
        ));

        if !config.tls_sans.is_empty() {
            yaml.push_str("tls-san:\n");
            for san in &config.tls_sans {
                yaml.push_str(&format!("  - \"{}\"\n", yaml_dq(san)));
            }
        }

        if config.role == NodeRole::ControlPlaneInit {
            yaml.push_str("cluster-init: true\n");
        }
    }

    if let Some(url) = &config.server_url {
        yaml.push_str(&format!("server: \"{}\"\n", yaml_dq(url)));
    }
    if let Some(tok) = &config.cluster_token {
        yaml.push_str(&format!("token: \"{}\"\n", yaml_dq(tok)));
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
    // The config holds the cluster join token — 0600, owner-only.
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(config_path)
            .with_context(|| format!("failed to write {}", config_path.display()))?;
        f.write_all(content.as_bytes())
            .with_context(|| format!("failed to write {}", config_path.display()))?;
    }
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(config_path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to chmod {}", config_path.display()))?;
    Ok(())
}

/// Host (IP or DNS) of the cluster API endpoint that every node can reach.
///
/// `127.0.0.1` is only valid on the node that runs the apiserver itself;
/// worker nodes must use the real cluster endpoint (server-url host or node-ip).
pub fn api_server_host(config: &ClusterNodeConfig) -> String {
    if let Some(url) = &config.server_url {
        let trimmed = url
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        if let Some(host) = trimmed.split(':').next() {
            if !host.is_empty() {
                return host.to_string();
            }
        }
    }
    config.node_ip.clone()
}

pub fn render_cilium_manifest(wireguard_enabled: bool, k8s_host: &str) -> String {
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
  version: "1.20.2"
  targetNamespace: kube-system
  bootstrap: true
  valuesContent: |-
    kubeProxyReplacement: true
    k8sServiceHost: {k8s_host}
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

fn deploy_cilium_manifest(wireguard_enabled: bool, k8s_host: &str) -> Result<()> {
    let manifest_content = render_cilium_manifest(wireguard_enabled, k8s_host);
    let manifest_dir = Path::new("/var/lib/rancher/k3s/server/manifests");
    let manifest_path = manifest_dir.join("cilium.yaml");
    if let Some(parent) = manifest_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&manifest_path, manifest_content)?;
    // Старое имя файла могло оставить после себя прежний манифест с
    // 127.0.0.1 — удаляем, чтобы не создавать два конфликтующих HelmChart.
    let stale = manifest_dir.join("cilium-helmchart.yaml");
    if stale.exists() {
        let _ = fs::remove_file(stale);
    }
    Ok(())
}

fn install_k3s_binary(config: &ClusterNodeConfig) -> Result<()> {
    let has_curl = Command::new("curl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !has_curl {
        bail!(
            "'curl' command is required to install K3s. Please install curl (e.g. apt-get install -y curl)."
        );
    }

    let exec_type = if config.role == NodeRole::Worker {
        "agent"
    } else {
        "server"
    };
    // Timeouts bound the supply-chain window and prevent a hung mirror from
    // stalling init forever; `pipefail` surfaces curl failures to the exit code.
    let cmd = format!(
        "set -e -o pipefail; curl -sfL --connect-timeout 30 --max-time 300 https://get.k3s.io | INSTALL_K3S_SKIP_START=true INSTALL_K3S_VERSION=\"v1.37.1+k3s1\" INSTALL_K3S_EXEC=\"{}\" sh -s -",
        exec_type
    );
    let output = Command::new("sh").arg("-c").arg(&cmd).output();
    match output {
        Ok(out) if out.status.success() => {
            if !Path::new("/usr/local/bin/k3s").exists() {
                bail!(
                    "K3s installer completed with status 0, but /usr/local/bin/k3s was not created on disk."
                );
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

/// Best-effort node labeling for the placement advisor.
fn apply_storage_node_labels(_summary: &crate::storage::StoragePlanSummary) -> Result<()> {
    // Shared implementation lives in the storage module (also used by
    // `ami storage prepare` so tier labels refresh in the same run).
    crate::storage::refresh_node_labels();
    Ok(())
}

/// Бюджет ожидания Ready-состояния ноды. Холодная загрузка образов CNI
/// (Cilium ~200 МБ с quay.io) укладывается не всегда — 60с оказывалось мало.
const NODE_READY_TIMEOUT_SECS: u64 = 300;

fn wait_for_node_readiness(timeout_secs: u64) -> Result<()> {
    let start = std::time::Instant::now();
    while start.elapsed().as_secs() < timeout_secs {
        let out = Command::new("k3s")
            .args(["kubectl", "get", "nodes", "--no-headers"])
            .output();
        if let Ok(o) = out {
            // STATUS is the second whitespace-separated column; `NotReady`
            // must not match a naive substring search for "Ready".
            let ready = String::from_utf8_lossy(&o.stdout).lines().any(|l| {
                l.split_whitespace()
                    .nth(1)
                    .map(|s| s == "Ready")
                    .unwrap_or(false)
            });
            if ready {
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

    let reload = Command::new("systemctl")
        .arg("daemon-reload")
        .output()
        .context("failed to run systemctl daemon-reload")?;
    if !reload.status.success() {
        bail!(
            "systemctl daemon-reload failed: {}",
            String::from_utf8_lossy(&reload.stderr).trim()
        );
    }
    let enable = Command::new("systemctl")
        .args(["enable", "--now", "amiterra"])
        .output()
        .context("failed to run systemctl enable")?;
    if !enable.status.success() {
        bail!(
            "failed to enable amiterra.service: {}",
            String::from_utf8_lossy(&enable.stderr).trim()
        );
    }
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
    fn test_traefik_mention_in_comment_is_not_disabled() {
        // Regression: substring "traefik" must not mean "traefik disabled".
        let sample = r#"
flannel-backend: "none"
disable-kube-proxy: true
# traefik is kept enabled here
"#;
        let res = analyze_k3s_config(true, Some(sample), true);
        match res {
            K3sInspection::ConflictingInstance { traefik_active, .. } => assert!(traefik_active),
            other => panic!("expected ConflictingInstance, got {other:?}"),
        }
    }

    #[test]
    fn test_disable_list_inline_form() {
        let sample = r#"
flannel-backend: none
disable-kube-proxy: true
disable: [traefik, servicelb]
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
            apply_performance_tuning: false,
            gitops_bootstrap: false,
            storage: crate::features::StoragePlan::Skip,
        };

        let yaml = render_k3s_config(&config);
        assert!(yaml.contains("node-ip: \"65.109.10.20\""));
        // Regression: advertise-address обязан быть приватным cluster IP,
        // иначе endpoints сервиса `kubernetes` отравляются external-ip.
        assert!(yaml.contains("advertise-address: \"65.109.10.20\""));
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
            apply_performance_tuning: false,
            gitops_bootstrap: false,
            storage: crate::features::StoragePlan::Skip,
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
        assert!(!yaml.contains("advertise-address"));
    }

    #[test]
    fn test_render_cilium_manifest_encryption() {
        let manifest_wg = render_cilium_manifest(true, "192.168.100.10");
        assert!(manifest_wg.contains("encryption:\n      enabled: true\n      type: wireguard"));

        let manifest_no_wg = render_cilium_manifest(false, "192.168.100.10");
        assert!(manifest_no_wg.contains("encryption:\n      enabled: false"));
        assert!(!manifest_no_wg.contains("type: wireguard"));
    }

    #[test]
    fn test_cilium_manifest_uses_reachable_api_host() {
        // 127.0.0.1 ломает worker-ноды: у них нет локального apiserver.
        let manifest = render_cilium_manifest(false, "192.168.100.10");
        assert!(manifest.contains("k8sServiceHost: 192.168.100.10"));
        assert!(!manifest.contains("k8sServiceHost: 127.0.0.1"));

        let init = ClusterNodeConfig {
            role: NodeRole::ControlPlaneInit,
            node_ip: "10.0.0.5".into(),
            node_external_ip: None,
            wireguard_enabled: false,
            pod_cidr: "10.42.0.0/16".into(),
            service_cidr: "10.43.0.0/16".into(),
            tls_sans: vec![],
            server_url: None,
            cluster_token: None,
            isolate_control_plane: false,
            apply_performance_tuning: false,
            gitops_bootstrap: false,
            storage: crate::features::StoragePlan::default(),
        };
        assert_eq!(api_server_host(&init), "10.0.0.5");

        let join = ClusterNodeConfig {
            role: NodeRole::Worker,
            node_ip: "10.0.0.6".into(),
            server_url: Some("https://10.0.0.5:6443".into()),
            ..init
        };
        assert_eq!(api_server_host(&join), "10.0.0.5");
    }

    #[test]
    fn test_parse_remediation_choice_rejects_garbage() {
        assert_eq!(
            parse_remediation_choice(""),
            Some(RemediationChoice::SafeMigration)
        );
        assert_eq!(
            parse_remediation_choice("1"),
            Some(RemediationChoice::SafeMigration)
        );
        assert_eq!(
            parse_remediation_choice("2"),
            Some(RemediationChoice::CleanReinstall)
        );
        assert_eq!(
            parse_remediation_choice("3"),
            Some(RemediationChoice::Abort)
        );
        assert_eq!(
            parse_remediation_choice("q"),
            Some(RemediationChoice::Abort)
        );
        // Regression: garbage must NOT become SafeMigration (host-modifying default).
        assert_eq!(parse_remediation_choice("4"), None);
        assert_eq!(parse_remediation_choice("yes"), None);
        assert_eq!(parse_remediation_choice("22"), None);
        assert_eq!(parse_remediation_choice("clean"), None);
    }
}
