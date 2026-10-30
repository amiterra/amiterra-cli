use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::io::{IsTerminal, Write, stdin, stdout};

use crate::cli::InitArgs;
use crate::discovery::{DiscoveryReport, HostTopology};
use crate::features::{FeatureContext, FeatureRequest, StoragePlan};
use crate::ui::{Palette, Ui};

/// Target role of the node within the Kubernetes cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NodeRole {
    #[default]
    ControlPlaneInit,
    ControlPlane,
    Worker,
}

impl NodeRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeRole::ControlPlaneInit => "control-plane-init",
            NodeRole::ControlPlane => "control-plane",
            NodeRole::Worker => "worker",
        }
    }

    pub fn display_title(&self) -> &'static str {
        match self {
            NodeRole::ControlPlaneInit => "Control Plane (Cluster Init)",
            NodeRole::ControlPlane => "Control Plane (Join HA)",
            NodeRole::Worker => "Worker",
        }
    }

    pub fn is_control_plane(&self) -> bool {
        matches!(self, NodeRole::ControlPlaneInit | NodeRole::ControlPlane)
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().trim() {
            "control-plane-init" | "init" | "primary" | "first-master" => {
                Some(NodeRole::ControlPlaneInit)
            }
            "control-plane" | "server" | "ha" | "master" => Some(NodeRole::ControlPlane),
            "worker" | "agent" | "compute" => Some(NodeRole::Worker),
            _ => None,
        }
    }
}

/// Fully resolved, validated configuration for initializing or joining a cluster node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNodeConfig {
    pub role: NodeRole,
    pub node_ip: String,
    pub node_external_ip: Option<String>,
    pub wireguard_enabled: bool,
    pub pod_cidr: String,
    pub service_cidr: String,
    pub tls_sans: Vec<String>,
    pub server_url: Option<String>,
    pub cluster_token: Option<String>,
    pub isolate_control_plane: bool,
    /// Opt-in performance profile (`ami tune apply`) after install.
    #[serde(default)]
    pub apply_performance_tuning: bool,
    /// Opt-in GitOps bootstrap (`ami gitops bootstrap`) after install.
    #[serde(default)]
    pub gitops_bootstrap: bool,
    /// Dedicated data disk feature (skip / activate existing VG / prepare disk).
    #[serde(default)]
    pub storage: crate::features::StoragePlan,
}

/// Outcome of parsing the node-role menu input.
#[derive(Debug, PartialEq, Eq)]
pub enum RoleChoice {
    Role(NodeRole),
    Custom,
    Quit,
    /// Unknown input — caller must re-prompt, never silently pick a role.
    Invalid,
}

/// Pure parser for `prompt_node_role_and_action` (unit-testable).
pub fn parse_role_choice(raw: &str) -> RoleChoice {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "1" => RoleChoice::Role(NodeRole::ControlPlaneInit),
        "2" => RoleChoice::Role(NodeRole::ControlPlane),
        "3" => RoleChoice::Role(NodeRole::Worker),
        "c" | "custom" => RoleChoice::Custom,
        "q" | "quit" | "abort" => RoleChoice::Quit,
        _ => RoleChoice::Invalid,
    }
}

/// Outcome of parsing the performance-tuning menu input.
#[derive(Debug, PartialEq, Eq)]
pub enum TuningChoice {
    Skip,
    Apply,
    Preview,
    /// Unknown input — caller must re-prompt.
    Invalid,
}

/// Outcome of parsing the storage-optimization menu input.
#[derive(Debug, PartialEq, Eq)]
pub enum StorageChoice {
    Skip,
    Apply,
    Preview,
    /// Unknown input — caller must re-prompt.
    Invalid,
}

/// Pure parser for `prompt_storage` (unit-testable).
/// Empty input = safe default (Skip). Never silently Apply.
pub fn parse_storage_choice(raw: &str) -> StorageChoice {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "n" | "no" | "skip" => StorageChoice::Skip,
        "2" | "y" | "yes" | "apply" | "prepare" => StorageChoice::Apply,
        "3" | "p" | "plan" | "preview" => StorageChoice::Preview,
        _ => StorageChoice::Invalid,
    }
}

/// Pure parser for `prompt_performance_tuning` (unit-testable).
/// Empty input = safe default (Skip). Never silently Apply.
pub fn parse_tuning_choice(raw: &str) -> TuningChoice {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "n" | "no" | "skip" => TuningChoice::Skip,
        "2" | "y" | "yes" | "apply" => TuningChoice::Apply,
        "3" | "p" | "plan" | "preview" => TuningChoice::Preview,
        _ => TuningChoice::Invalid,
    }
}

/// Outcome of parsing the GitOps bootstrap menu input.
#[derive(Debug, PartialEq, Eq)]
pub enum GitopsChoice {
    Skip,
    Apply,
    Preview,
    /// Unknown input — caller must re-prompt.
    Invalid,
}

/// Pure parser for `prompt_gitops_bootstrap` (unit-testable).
/// Empty input = safe default (Skip). Never silently Bootstrap.
pub fn parse_gitops_choice(raw: &str) -> GitopsChoice {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "n" | "no" | "skip" => GitopsChoice::Skip,
        "2" | "y" | "yes" | "apply" | "bootstrap" => GitopsChoice::Apply,
        "3" | "p" | "plan" | "preview" => GitopsChoice::Preview,
        _ => GitopsChoice::Invalid,
    }
}

pub struct TerminalWizard;

/// Announce a storage layer that has nothing to act on (no free disks, no
/// existing VG) exactly where its prompt would appear — a silent skip is an
/// answer the operator cannot see. Never fires for an explicit
/// `--storage-disk` (that path validates the name and errors instead).
fn note_storage_na(req: &FeatureRequest, ctx: &FeatureContext) {
    if req.storage_disk.is_none() && ctx.server && !ctx.vg_present && ctx.free_disks.is_empty() {
        Ui::step_info(
            "Storage",
            "Optimization skipped — no unallocated disks on this node (tier s0)",
        );
    }
}

/// [`crate::features::FeaturePrompts`] backed by terminal dialogs. Feature
/// resolution stays in `features::plan_features`; this struct only collects
/// answers for what is still undecided.
struct WizardPrompts {
    node_ip: String,
}

impl crate::features::FeaturePrompts for WizardPrompts {
    fn storage(&mut self, ctx: &crate::features::FeatureContext) -> Result<StoragePlan> {
        TerminalWizard::prompt_storage(ctx)
    }
    fn disk(&mut self, candidates: &[String]) -> Result<String> {
        TerminalWizard::prompt_disk_choice(candidates)
    }
    fn tune(&mut self) -> Result<bool> {
        TerminalWizard::prompt_performance_tuning()
    }
    fn gitops(&mut self) -> Result<bool> {
        TerminalWizard::prompt_gitops_bootstrap(&self.node_ip)
    }
}

impl TerminalWizard {
    /// Runs the Scenario B terminal wizard. If `args.yes` is provided or standard input
    /// is non-interactive, smart defaults are used automatically without waiting for input.
    pub fn run(report: &DiscoveryReport, args: &InitArgs) -> Result<ClusterNodeConfig> {
        // Explicit --role must be valid; never silently fall back to ControlPlaneInit.
        let cli_role = match args.role.as_deref() {
            None => None,
            Some(raw) => Some(NodeRole::parse(raw).ok_or_else(|| {
                anyhow::anyhow!(
                    "Invalid --role '{raw}'. Use control-plane-init | control-plane | worker \
                     (or init/primary, server/ha/master, agent/compute)."
                )
            })?),
        };

        // Render the discovery card
        Self::render_discovery_card(report);

        // If headless or auto-confirm flag is passed, no prompts run: flags and
        // `--all-features` decide, everything else stays off (safe defaults).
        if args.yes || !stdin().is_terminal() {
            let role = cli_role.unwrap_or(NodeRole::ControlPlaneInit);
            crate::ui::Ui::step_info(
                "Auto-confirming",
                "Using verified defaults (non-interactive session)",
            );
            let mut config =
                Self::build_default_config(report, role, args, args.server_url.as_deref());
            let req = FeatureRequest {
                all_features: args.all_features,
                storage_disk: args.storage_disk.clone(),
                tune_apply: args.tune_apply,
                gitops_bootstrap: args.gitops_bootstrap,
            };
            let inv = crate::storage::StorageInventory::probe().unwrap_or_default();
            let ctx = FeatureContext {
                cluster_init: role == NodeRole::ControlPlaneInit,
                server: true,
                free_disks: inv.free_disks().iter().map(|d| d.name.clone()).collect(),
                vg_present: crate::storage::prepare::dedicated_vg_present(
                    crate::storage::prepare::DEFAULT_VG,
                ),
                interactive: false,
            };
            let mut prompts = WizardPrompts {
                node_ip: config.node_ip.clone(),
            };
            // Printed before the prompt sequence so the note lands exactly
            // where the storage question would have been (storage → tune → gitops).
            note_storage_na(&req, &ctx);
            let plan = crate::features::plan_features(&req, &ctx, &mut prompts)?;
            config.apply_performance_tuning = plan.tune.enabled;
            config.gitops_bootstrap = plan.gitops.enabled;
            config.storage = plan.storage;
            if req.gitops_bootstrap && role != NodeRole::ControlPlaneInit {
                config.gitops_bootstrap = false;
                Ui::step_warn(
                    "GitOps bootstrap ignored: only the control-plane-init node may bind \
                     the cluster Git repository",
                );
            }
            return Ok(config);
        }

        // 1. Role Selection & Confirmation (One-touch UX)
        let (role, customize) = if let Some(r) = cli_role {
            (r, false)
        } else {
            Self::prompt_node_role_and_action()?
        };

        // 2. Additional prompts for join roles
        let mut server_url = args.server_url.clone();
        let mut cluster_token = args.token.clone();

        if role != NodeRole::ControlPlaneInit {
            if server_url.is_none() {
                print!(
                    "  {} Control Plane Server URL (e.g. https://10.0.1.5:6443): ",
                    Palette::cyan("?")
                );
                stdout().flush()?;
                let mut input = String::new();
                stdin().read_line(&mut input)?;
                let trimmed = input.trim();
                if !trimmed.is_empty() {
                    server_url = Some(trimmed.to_string());
                } else {
                    bail!("Control Plane Server URL is required to join an existing cluster");
                }
            }

            if cluster_token.is_none() {
                print!("  {} Cluster Join Token: ", Palette::cyan("?"));
                stdout().flush()?;
                let mut input = String::new();
                stdin().read_line(&mut input)?;
                let trimmed = input.trim();
                if !trimmed.is_empty() {
                    cluster_token = Some(trimmed.to_string());
                } else {
                    bail!("Cluster token is required to join an existing cluster");
                }
            }
        }

        let mut config = Self::build_default_config(report, role, args, server_url.as_deref());
        config.server_url = server_url;
        config.cluster_token = cluster_token;

        if customize {
            Self::prompt_customization(report, &mut config)?;
        }

        // Optional feature layers — one resolution pipeline (flags beat
        // prompts; `--yes` keeps everything off; `--all-features` turns all
        // applicable layers on). Prompts run only for what is undecided.
        let req = FeatureRequest {
            all_features: args.all_features,
            storage_disk: args.storage_disk.clone(),
            tune_apply: args.tune_apply,
            gitops_bootstrap: args.gitops_bootstrap,
        };
        let inv = crate::storage::StorageInventory::probe().unwrap_or_default();
        let ctx = FeatureContext {
            cluster_init: role == NodeRole::ControlPlaneInit,
            server: true,
            free_disks: inv.free_disks().iter().map(|d| d.name.clone()).collect(),
            vg_present: crate::storage::prepare::dedicated_vg_present(
                crate::storage::prepare::DEFAULT_VG,
            ),
            interactive: !args.yes,
        };
        let mut prompts = WizardPrompts {
            node_ip: config.node_ip.clone(),
        };
        // Printed before the prompt sequence so the note lands exactly
        // where the storage question would have been (storage → tune → gitops).
        note_storage_na(&req, &ctx);
        let plan = crate::features::plan_features(&req, &ctx, &mut prompts)?;
        config.apply_performance_tuning = plan.tune.enabled;
        config.gitops_bootstrap = plan.gitops.enabled;
        config.storage = plan.storage;

        // C1: joining nodes must never rebind the cluster's Flux repository.
        if req.gitops_bootstrap && role != NodeRole::ControlPlaneInit {
            config.gitops_bootstrap = false;
            Ui::step_warn(
                "GitOps bootstrap ignored: only the control-plane-init node may bind \
                 the cluster Git repository (run `ami gitops bootstrap` there)",
            );
        }

        Ok(config)
    }

    fn build_default_config(
        report: &DiscoveryReport,
        role: NodeRole,
        args: &InitArgs,
        server_url: Option<&str>,
    ) -> ClusterNodeConfig {
        // Smart kernel route matching: if joining an existing cluster and node_ip was not explicitly provided,
        // use 'ip route get <server_ip>' to select the exact local interface and IP communicating with the control plane.
        let mut auto_node_ip = None;
        if let Some(s_url) = server_url.or(args.server_url.as_deref())
            && let Some(target_host) = crate::discovery::network::extract_host_from_url(s_url)
            && let Some((_iface, src_ip)) =
                crate::discovery::network::find_route_to_target(&target_host)
        {
            auto_node_ip = Some(src_ip);
        }

        let node_ip = args
            .node_ip
            .clone()
            .or(auto_node_ip)
            .unwrap_or_else(|| report.topology.primary_node_ip().to_string());

        let node_external_ip = args
            .node_external_ip
            .clone()
            .or_else(|| report.topology.primary_external_ip().map(String::from));

        let wireguard_enabled = report.topology.is_wireguard_required();

        let pod_cidr = args
            .pod_cidr
            .clone()
            .unwrap_or_else(|| report.pod_cidr.clone());

        let service_cidr = args
            .service_cidr
            .clone()
            .unwrap_or_else(|| report.service_cidr.clone());

        let mut tls_sans = report.tls_sans.clone();
        for domain in &args.tls_san {
            if !tls_sans.contains(domain) {
                tls_sans.push(domain.clone());
            }
        }

        ClusterNodeConfig {
            role,
            node_ip,
            node_external_ip,
            wireguard_enabled,
            pod_cidr,
            service_cidr,
            tls_sans,
            storage: StoragePlan::Skip,
            server_url: args.server_url.clone(),
            cluster_token: args.token.clone(),
            isolate_control_plane: args.isolate_control_plane,
            apply_performance_tuning: args.tune_apply,
            gitops_bootstrap: args.gitops_bootstrap,
        }
    }

    fn render_discovery_card(report: &DiscoveryReport) {
        let mut items: Vec<(&str, String)> = Vec::new();

        let topo_label = match &report.topology {
            HostTopology::SinglePublicIp { .. } => "● Single Public IP (Direct Internet VPS)",
            HostTopology::MultiNic { .. } => "● Multi-NIC Hybrid (WAN + Private Mesh)",
            HostTopology::PrivateNat { public_nat_ip, .. } => {
                if public_nat_ip.is_some() {
                    "● Private NAT (1:1 Cloud / Edge Gateway)"
                } else {
                    "● Private Isolated (VPC / Air-Gapped Network)"
                }
            }
        };
        items.push(("Network Topology", topo_label.to_string()));

        let node_ip_detail = match &report.topology {
            HostTopology::SinglePublicIp {
                interface,
                public_ip,
            } => {
                format!("{} ({})", public_ip, interface)
            }
            HostTopology::MultiNic {
                private_ip,
                private_interface,
                ..
            } => {
                format!("{} ({})", private_ip, private_interface)
            }
            HostTopology::PrivateNat {
                private_ip,
                interface,
                ..
            } => {
                format!("{} ({})", private_ip, interface)
            }
        };
        items.push(("Cluster Node IP", node_ip_detail));

        if let Some(ext) = report.topology.primary_external_ip()
            && ext != report.topology.primary_node_ip()
        {
            items.push((
                "External Ingress IP",
                format!("{} (Egress auto-detected)", ext),
            ));
        }

        let wg_label = if report.topology.is_wireguard_required() {
            "● Required (Transparent eBPF WAN mesh)".to_string()
        } else {
            "○ Optional (Private L2 mesh isolated)".to_string()
        };
        items.push(("WireGuard Mesh", wg_label));

        let cidr_badge = if report.cidr_collision_prevented {
            format!("{} (Collision-free alternative selected)", report.pod_cidr)
        } else {
            format!("{} (Collision-free verified)", report.pod_cidr)
        };
        items.push(("Pod Subnet", cidr_badge));
        items.push(("Service Subnet", report.service_cidr.clone()));

        let sans_preview = if report.tls_sans.len() > 4 {
            format!(
                "{}, ... (+{} more)",
                report.tls_sans[..3].join(", "),
                report.tls_sans.len() - 3
            )
        } else {
            report.tls_sans.join(", ")
        };
        items.push(("TLS SANs", sans_preview));

        let item_refs: Vec<(&str, &str)> = items.iter().map(|(k, v)| (*k, v.as_str())).collect();

        Ui::card("Amiterra Network Auto-Discovery", &item_refs);
    }

    fn prompt_node_role_and_action() -> Result<(NodeRole, bool)> {
        println!("  Select Node Role:");
        println!(
            "    1. Control Plane (Cluster Init)  {} {} First management node, bootstraps etcd & cluster",
            Palette::cyan("[Default]"),
            Palette::dim("—")
        );
        println!(
            "    2. Control Plane (Join HA)                 {} Additional management node for High Availability",
            Palette::dim("—")
        );
        println!(
            "    3. Worker                                  {} Application compute node, executes container workloads",
            Palette::dim("—")
        );
        println!();

        loop {
            print!(
                "  {} Press {} to launch with verified defaults, {} to select role, {} to customize, or {} to quit: ",
                Palette::cyan("?"),
                Palette::bold("[Enter]"),
                Palette::bold("[1-3]"),
                Palette::bold("[c]"),
                Palette::bold("[q]")
            );
            stdout().flush()?;

            let mut input = String::new();
            stdin().read_line(&mut input)?;
            let choice = input.trim().to_lowercase();

            match parse_role_choice(&choice) {
                RoleChoice::Quit => bail!("Installation aborted by user."),
                RoleChoice::Custom => return Ok((NodeRole::ControlPlaneInit, true)),
                RoleChoice::Role(role) => return Ok((role, false)),
                RoleChoice::Invalid => {
                    Ui::step_warn(&format!(
                        "Invalid selection '{choice}'. Enter 1-3, c, q, or press Enter for default."
                    ));
                }
            }
        }
    }

    /// Optional storage-optimization step (dedicated LVM data disk).
    /// Safe default is **skip**. Returns the chosen plan.
    fn prompt_storage(ctx: &FeatureContext) -> Result<StoragePlan> {
        println!("\n  ── Storage Optimization (optional) ────────────────────────");
        println!(
            "     {} Moves stateful data to a dedicated disk (tier s1, I/O isolation).",
            Palette::dim("Destructive only to the disk you select — system RAID is never touched.")
        );
        if ctx.vg_present {
            println!(
                "     {} Dedicated VG already present — activation only (no new disk).",
                Palette::dim("Re-run detected:")
            );
        } else {
            println!(
                "     {} Free disks: {}",
                Palette::dim("Available:"),
                if ctx.free_disks.is_empty() {
                    "none (node stays on shared root, tier s0)".to_string()
                } else {
                    ctx.free_disks.join(", ")
                }
            );
        }
        println!(
            "     {} Skip — safe default (shared root)",
            Palette::bold("[1]")
        );
        println!(
            "     {} {}",
            Palette::bold("[2]"),
            if ctx.vg_present {
                "Activate dedicated disk now"
            } else {
                "Prepare dedicated disk now (LVM + mount)"
            }
        );
        println!(
            "     {} Preview only (`ami storage plan`)",
            Palette::bold("[3]")
        );
        println!();

        loop {
            print!(
                "  {} Select [1-3, press Enter for 1 (Skip)]: ",
                Palette::cyan("?")
            );
            stdout().flush()?;
            let mut input = String::new();
            stdin().read_line(&mut input)?;
            let raw = input.trim();

            match parse_storage_choice(raw) {
                StorageChoice::Apply => {
                    if ctx.vg_present {
                        Ui::step_done("Dedicated disk will be activated after install", None);
                        return Ok(StoragePlan::Activate);
                    }
                    let disk = if ctx.free_disks.len() == 1 {
                        let d = ctx.free_disks[0].clone();
                        Ui::step_done(&format!("Selected disk: {d}"), None);
                        d
                    } else {
                        Self::prompt_disk_choice(&ctx.free_disks)?
                    };
                    Ui::step_done("Dedicated disk will be prepared after install", None);
                    return Ok(StoragePlan::Prepare(disk));
                }
                StorageChoice::Preview => {
                    // Real preview (same contract as tune's Preview): show the
                    // actual plan output, not a command hint.
                    let inv = crate::storage::StorageInventory::probe().unwrap_or_default();
                    let summary = crate::storage::classify(&inv);
                    let doc = crate::storage::plan::build_plan(&inv, &summary, false);
                    println!(
                        "     {} tier={} · free disks: {}",
                        Palette::dim("Storage plan:"),
                        summary.tier.as_str(),
                        if summary.free_disk_names.is_empty() {
                            "none".to_string()
                        } else {
                            summary.free_disk_names.join(", ")
                        }
                    );
                    for step in &doc.improve_guide {
                        println!(
                            "       {} {}",
                            Palette::cyan(crate::ui::Glyphs::CHEVRON),
                            step
                        );
                    }
                    println!("     (re-run the question — Enter = Skip, 2 = Apply now)");
                    continue;
                }
                StorageChoice::Skip => {
                    Ui::step_info(
                        "Storage",
                        "Skipped — run `sudo ami storage prepare --disk <disk>` when ready.",
                    );
                    return Ok(StoragePlan::Skip);
                }
                StorageChoice::Invalid => {
                    Ui::step_warn(&format!(
                        "Invalid selection '{raw}'. Enter 1 (Skip), 2 (Apply), 3 (Preview), or press Enter for Skip."
                    ));
                }
            }
        }
    }

    /// Disk picker for multiple candidates (feature already ON; this collects
    /// the *parameter*, it does not re-decide the feature).
    fn prompt_disk_choice(candidates: &[String]) -> Result<String> {
        if candidates.is_empty() {
            bail!("no free disks available for storage prepare");
        }
        println!("\n  Available unallocated disks:");
        for (idx, name) in candidates.iter().enumerate() {
            let label = format!("[{}]", idx + 1);
            println!("     {} {}", Palette::bold(&label), name);
        }
        loop {
            print!(
                "  {} Select disk [1-{}, q=cancel]: ",
                Palette::cyan("?"),
                candidates.len()
            );
            stdout().flush()?;
            let mut input = String::new();
            stdin().read_line(&mut input)?;
            let raw = input.trim();
            if matches!(raw, "q" | "Q" | "quit" | "cancel") {
                bail!("storage preparation cancelled — nothing was modified");
            }
            match raw.parse::<usize>() {
                Ok(n) if (1..=candidates.len()).contains(&n) => {
                    let d = candidates[n - 1].clone();
                    Ui::step_done(&format!("Selected disk: {d}"), None);
                    return Ok(d);
                }
                _ => {
                    Ui::step_warn(&format!(
                        "Invalid selection '{raw}'. Enter 1-{}, or q to cancel.",
                        candidates.len()
                    ));
                }
            }
        }
    }

    /// Optional performance-tuning step. Safe default is **skip**.
    /// Returns true only when the operator explicitly opts in.
    fn prompt_performance_tuning() -> Result<bool> {
        use crate::tune::profile::TUNING_DOCS_URL;

        println!("\n  ── Performance Tuning (optional) ───────────────────────────");
        // Subsystem warning + source-of-truth docs (same contract as `ami tune apply`).
        crate::tune::print_tuning_scope_warning();
        println!(
            "     {} Skip — safe default, no host tuning",
            Palette::bold("[1]")
        );
        println!(
            "     {} Apply performance profile now",
            Palette::bold("[2]")
        );
        println!(
            "     {} Preview only (`ami tune plan`)",
            Palette::bold("[3]")
        );
        println!();

        loop {
            print!(
                "  {} Select [1-3, press Enter for 1 (Skip)]: ",
                Palette::cyan("?")
            );
            stdout().flush()?;
            let mut input = String::new();
            stdin().read_line(&mut input)?;
            let raw = input.trim();

            match parse_tuning_choice(raw) {
                TuningChoice::Apply => {
                    Ui::step_done("Performance profile will be applied after install", None);
                    return Ok(true);
                }
                TuningChoice::Preview => {
                    let changes = crate::tune::plan().unwrap_or_default();
                    let perf: Vec<_> = changes
                        .into_iter()
                        .filter(|c| c.layer == "performance")
                        .collect();
                    crate::tune::print_plan(&perf, "performance");
                    println!(
                        "  (Parameter sources: {TUNING_DOCS_URL} — re-run `ami tune apply` when ready.)"
                    );
                    // Preview is not a terminal answer — ask again (Skip / Apply / Preview).
                    continue;
                }
                TuningChoice::Skip => {
                    Ui::step_info(
                        "Tuning",
                        &format!(
                            "Skipped — sources & docs: {TUNING_DOCS_URL}. Run `sudo ami tune apply` when needed."
                        ),
                    );
                    return Ok(false);
                }
                TuningChoice::Invalid => {
                    Ui::step_warn(&format!(
                        "Invalid selection '{raw}'. Enter 1 (Skip), 2 (Apply), 3 (Preview), or press Enter for Skip."
                    ));
                }
            }
        }
    }

    /// Optional GitOps bootstrap step. Safe default is **skip**.
    /// Returns true only when the operator explicitly opts in.
    fn prompt_gitops_bootstrap(node_ip: &str) -> Result<bool> {
        println!("\n  ── GitOps Bootstrap (optional) ─────────────────────────────");
        println!(
            "     {} Deploys Flux controllers and binds the cluster to a Git repository.",
            Palette::dim("Infrastructure as Code, single source of truth.")
        );
        println!(
            "     {} Skip — safe default, no GitOps on this node",
            Palette::bold("[1]")
        );
        println!(
            "     {} Bootstrap Flux + Git binding now",
            Palette::bold("[2]")
        );
        println!(
            "     {} Preview only (same output as `ami gitops bootstrap --dry-run`)",
            Palette::bold("[3]")
        );
        println!();

        loop {
            print!(
                "  {} Select [1-3, press Enter for 1 (Skip)]: ",
                Palette::cyan("?")
            );
            stdout().flush()?;
            let mut input = String::new();
            stdin().read_line(&mut input)?;
            let raw = input.trim();

            match parse_gitops_choice(raw) {
                GitopsChoice::Apply => {
                    Ui::step_done("GitOps bootstrap will run after install", None);
                    return Ok(true);
                }
                GitopsChoice::Preview => {
                    // M4: run the real dry-run plan (like tune's Preview runs `tune plan`),
                    // with the detected node IP — no placeholder strings to copy-paste.
                    let opts = crate::gitops::BootstrapOptions {
                        node_ip: node_ip.to_string(),
                        dry_run: true,
                        ..Default::default()
                    };
                    if let Err(e) = crate::gitops::bootstrap(&opts) {
                        Ui::step_warn(&format!("Preview failed: {e:#}"));
                    }
                    println!("     (re-run the question — Enter = Skip, 2 = Bootstrap now)");
                    continue;
                }
                GitopsChoice::Skip => {
                    Ui::step_info(
                        "GitOps",
                        "Skipped — run `sudo ami gitops bootstrap` when ready.",
                    );
                    return Ok(false);
                }
                GitopsChoice::Invalid => {
                    Ui::step_warn(&format!(
                        "Invalid selection '{raw}'. Enter 1 (Skip), 2 (Bootstrap), 3 (Preview), or press Enter for Skip."
                    ));
                }
            }
        }
    }

    fn prompt_customization(
        report: &DiscoveryReport,
        config: &mut ClusterNodeConfig,
    ) -> Result<()> {
        println!("\n  ── Interactive Customization ──────────────────────────────");

        // 1. Interface selection
        if report.interfaces.len() > 1 {
            println!("  Available Network Interfaces:");
            for (idx, iface) in report.interfaces.iter().enumerate() {
                let note = if iface.is_storage {
                    " [Storage/SAN]"
                } else if iface.is_default {
                    " [Default Gateway]"
                } else {
                    ""
                };
                println!(
                    "    [{}] {} (IP: {}, MTU: {}){}",
                    idx + 1,
                    iface.name,
                    iface.ip,
                    iface.mtu,
                    Palette::dim(note)
                );
            }
            print!(
                "  Select interface for cluster traffic [1-{}, press Enter to keep {}]: ",
                report.interfaces.len(),
                config.node_ip
            );
            stdout().flush()?;
            let mut if_choice = String::new();
            stdin().read_line(&mut if_choice)?;
            let raw = if_choice.trim();
            if raw.is_empty() {
                // Explicit keep — fine.
            } else if let Ok(idx) = raw.parse::<usize>()
                && (1..=report.interfaces.len()).contains(&idx)
            {
                config.node_ip = report.interfaces[idx - 1].ip.clone();
                Ui::step_done(&format!("Selected node-ip: {}", config.node_ip), None);
            } else {
                // Do not silently keep the old value on garbage input.
                anyhow::bail!(
                    "invalid interface selection '{raw}' — re-run `ami init` and pick a listed index"
                );
            }
        }

        // 2. Extra domain name
        print!("  Enter custom DNS domain name for TLS SANs (or press Enter to skip): ");
        stdout().flush()?;
        let mut domain_input = String::new();
        stdin().read_line(&mut domain_input)?;
        let trimmed_domain = domain_input.trim();
        if !trimmed_domain.is_empty() && !config.tls_sans.contains(&trimmed_domain.to_string()) {
            config.tls_sans.push(trimmed_domain.to_string());
            Ui::step_done(
                &format!("Added custom domain to TLS SANs: {}", trimmed_domain),
                None,
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_default_config_for_single_public_ip() {
        let report = DiscoveryReport {
            hostname: "vps-01".to_string(),
            interfaces: vec![],
            topology: HostTopology::SinglePublicIp {
                interface: "eth0".to_string(),
                public_ip: "95.217.142.10".to_string(),
            },
            public_probed_ip: None,
            pod_cidr: "10.42.0.0/16".to_string(),
            service_cidr: "10.43.0.0/16".to_string(),
            cidr_collision_prevented: false,
            tls_sans: vec!["127.0.0.1".to_string(), "95.217.142.10".to_string()],
        };

        let args = InitArgs {
            yes: true,
            ..Default::default()
        };

        let cfg =
            TerminalWizard::build_default_config(&report, NodeRole::ControlPlaneInit, &args, None);
        assert_eq!(cfg.role, NodeRole::ControlPlaneInit);
        assert_eq!(cfg.node_ip, "95.217.142.10");
        assert_eq!(cfg.node_external_ip, Some("95.217.142.10".to_string()));
        assert!(cfg.wireguard_enabled);
        assert_eq!(cfg.pod_cidr, "10.42.0.0/16");
    }

    #[test]
    fn test_extract_host_from_url() {
        use crate::discovery::network::extract_host_from_url;
        assert_eq!(
            extract_host_from_url("https://10.20.30.5:6443"),
            Some("10.20.30.5".to_string())
        );
        assert_eq!(
            extract_host_from_url("http://cluster.internal:6443/api"),
            Some("cluster.internal".to_string())
        );
        assert_eq!(
            extract_host_from_url("192.168.1.100:6443"),
            Some("192.168.1.100".to_string())
        );
        assert_eq!(
            extract_host_from_url("192.168.1.100"),
            Some("192.168.1.100".to_string())
        );
    }

    #[test]
    fn test_render_discovery_card_runs() {
        let report = DiscoveryReport {
            hostname: "Evgenys-MacBook-Pro.local".to_string(),
            interfaces: vec![],
            topology: HostTopology::PrivateNat {
                private_ip: "192.168.1.165".to_string(),
                public_nat_ip: Some("197.151.129.214".to_string()),
                interface: "en0".to_string(),
            },
            public_probed_ip: Some("197.151.129.214".to_string()),
            pod_cidr: "10.42.0.0/16".to_string(),
            service_cidr: "10.43.0.0/16".to_string(),
            cidr_collision_prevented: false,
            tls_sans: vec![
                "127.0.0.1".to_string(),
                "localhost".to_string(),
                "kubernetes".to_string(),
                "kubernetes.default".to_string(),
                "192.168.1.165".to_string(),
                "197.151.129.214".to_string(),
                "Evgenys-MacBook-Pro.local".to_string(),
            ],
        };

        TerminalWizard::render_discovery_card(&report);
    }

    #[test]
    fn test_parse_role_choice_accepts_valid_and_rejects_garbage() {
        assert_eq!(
            parse_role_choice(""),
            RoleChoice::Role(NodeRole::ControlPlaneInit)
        );
        assert_eq!(
            parse_role_choice("1"),
            RoleChoice::Role(NodeRole::ControlPlaneInit)
        );
        assert_eq!(
            parse_role_choice("2"),
            RoleChoice::Role(NodeRole::ControlPlane)
        );
        assert_eq!(parse_role_choice("3"), RoleChoice::Role(NodeRole::Worker));
        assert_eq!(parse_role_choice("C"), RoleChoice::Custom);
        assert_eq!(parse_role_choice("q"), RoleChoice::Quit);
        // Regression: garbage must NOT become ControlPlaneInit.
        assert_eq!(parse_role_choice("4"), RoleChoice::Invalid);
        assert_eq!(parse_role_choice("abc"), RoleChoice::Invalid);
        assert_eq!(parse_role_choice("1x"), RoleChoice::Invalid);
        assert_eq!(parse_role_choice("-1"), RoleChoice::Invalid);
    }

    #[test]
    fn test_parse_tuning_choice_never_silently_applies() {
        assert_eq!(parse_tuning_choice(""), TuningChoice::Skip);
        assert_eq!(parse_tuning_choice("1"), TuningChoice::Skip);
        assert_eq!(parse_tuning_choice("2"), TuningChoice::Apply);
        assert_eq!(parse_tuning_choice("apply"), TuningChoice::Apply);
        assert_eq!(parse_tuning_choice("3"), TuningChoice::Preview);
        // Regression: garbage must NOT become Apply (or silent Skip without feedback path).
        assert_eq!(parse_tuning_choice("4"), TuningChoice::Invalid);
        assert_eq!(parse_tuning_choice("maybe"), TuningChoice::Invalid);
        assert_eq!(parse_tuning_choice("22"), TuningChoice::Invalid);
    }

    #[test]
    fn test_parse_gitops_choice_never_silently_bootstraps() {
        assert_eq!(parse_gitops_choice(""), GitopsChoice::Skip);
        assert_eq!(parse_gitops_choice("1"), GitopsChoice::Skip);
        assert_eq!(parse_gitops_choice("2"), GitopsChoice::Apply);
        assert_eq!(parse_gitops_choice("bootstrap"), GitopsChoice::Apply);
        assert_eq!(parse_gitops_choice("3"), GitopsChoice::Preview);
        // Regression: garbage must NOT become Bootstrap.
        assert_eq!(parse_gitops_choice("4"), GitopsChoice::Invalid);
        assert_eq!(parse_gitops_choice("maybe"), GitopsChoice::Invalid);
        assert_eq!(parse_gitops_choice("22"), GitopsChoice::Invalid);
    }

    #[test]
    fn test_parse_storage_choice_never_silently_prepares() {
        assert_eq!(parse_storage_choice(""), StorageChoice::Skip);
        assert_eq!(parse_storage_choice("1"), StorageChoice::Skip);
        assert_eq!(parse_storage_choice("2"), StorageChoice::Apply);
        assert_eq!(parse_storage_choice("prepare"), StorageChoice::Apply);
        assert_eq!(parse_storage_choice("3"), StorageChoice::Preview);
        // Regression: garbage must NOT become Apply.
        assert_eq!(parse_storage_choice("4"), StorageChoice::Invalid);
        assert_eq!(parse_storage_choice("maybe"), StorageChoice::Invalid);
    }

    #[test]
    fn test_node_role_parse_rejects_unknown() {
        assert!(NodeRole::parse("worker").is_some());
        assert!(NodeRole::parse("master").is_some());
        // Must be None so run() can hard-error --role typos (no silent ControlPlaneInit).
        assert_eq!(NodeRole::parse("foo"), None);
        assert_eq!(NodeRole::parse("4"), None);
        assert_eq!(NodeRole::parse(""), None);
    }
}
