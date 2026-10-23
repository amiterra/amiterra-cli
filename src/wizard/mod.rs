use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::io::{stdin, stdout, IsTerminal, Write};

use crate::cli::InitArgs;
use crate::discovery::{DiscoveryReport, HostTopology};
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

pub struct TerminalWizard;

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

        // Render Scenario B Discovery Card (Design Doc 0014 format)
        Self::render_discovery_card(report);

        // If headless or auto-confirm flag is passed, construct directly from smart defaults
        if args.yes || !stdin().is_terminal() {
            let role = cli_role.unwrap_or(NodeRole::ControlPlaneInit);
            crate::ui::Ui::step_info("Auto-confirming", "Using verified defaults (non-interactive session)");
            return Ok(Self::build_default_config(
                report,
                role,
                args,
                args.server_url.as_deref(),
            ));
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
        config.apply_performance_tuning = args.tune_apply;

        if customize {
            Self::prompt_customization(report, &mut config)?;
        }

        // Tuning is a first-class optional step — never implicit.
        if !args.tune_apply && !args.yes {
            config.apply_performance_tuning = Self::prompt_performance_tuning()?;
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
            && let Some((_iface, src_ip)) = crate::discovery::network::find_route_to_target(&target_host)
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
            server_url: args.server_url.clone(),
            cluster_token: args.token.clone(),
            isolate_control_plane: args.isolate_control_plane,
            apply_performance_tuning: args.tune_apply,
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
            HostTopology::SinglePublicIp { interface, public_ip } => {
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
            items.push(("External Ingress IP", format!("{} (Egress auto-detected)", ext)));
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

        let item_refs: Vec<(&str, &str)> = items
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect();

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

    /// Optional performance-tuning step. Safe default is **skip**.
    /// Returns true only when the operator explicitly opts in.
    fn prompt_performance_tuning() -> Result<bool> {
        use crate::tune::profile::TUNING_DOCS_URL;

        println!("\n  ── Performance Tuning (optional) ───────────────────────────");
        // Subsystem warning + source-of-truth docs (same contract as `ami tune apply`).
        crate::tune::print_tuning_scope_warning();
        println!("     {} Skip — safe default, no host tuning", Palette::bold("[1]"));
        println!("     {} Apply performance profile now", Palette::bold("[2]"));
        println!("     {} Preview only (`ami tune plan`)", Palette::bold("[3]"));
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

    fn prompt_customization(report: &DiscoveryReport, config: &mut ClusterNodeConfig) -> Result<()> {
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
            print!("  Select interface for cluster traffic [1-{}, press Enter to keep {}]: ", report.interfaces.len(), config.node_ip);
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
                Ui::step_warn(&format!(
                    "Invalid interface selection '{raw}'. Keeping node-ip {}.",
                    config.node_ip
                ));
            }
        }

        // 2. Extra domain name
        print!("  Enter custom DNS domain name for TLS SANs (or press Enter to skip): ");
        stdout().flush()?;
        let mut domain_input = String::new();
        stdin().read_line(&mut domain_input)?;
        let trimmed_domain = domain_input.trim();
        if !trimmed_domain.is_empty()
            && !config.tls_sans.contains(&trimmed_domain.to_string())
        {
            config.tls_sans.push(trimmed_domain.to_string());
            Ui::step_done(&format!("Added custom domain to TLS SANs: {}", trimmed_domain), None);
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

        let cfg = TerminalWizard::build_default_config(&report, NodeRole::ControlPlaneInit, &args, None);
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
        assert_eq!(parse_role_choice(""), RoleChoice::Role(NodeRole::ControlPlaneInit));
        assert_eq!(parse_role_choice("1"), RoleChoice::Role(NodeRole::ControlPlaneInit));
        assert_eq!(parse_role_choice("2"), RoleChoice::Role(NodeRole::ControlPlane));
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
    fn test_node_role_parse_rejects_unknown() {
        assert!(NodeRole::parse("worker").is_some());
        assert!(NodeRole::parse("master").is_some());
        // Must be None so run() can hard-error --role typos (no silent ControlPlaneInit).
        assert_eq!(NodeRole::parse("foo"), None);
        assert_eq!(NodeRole::parse("4"), None);
        assert_eq!(NodeRole::parse(""), None);
    }
}
