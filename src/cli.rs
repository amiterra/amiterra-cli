use clap::{Args, Parser, Subcommand};

use crate::storage::cli::StorageArgs;
use crate::tune::cli::TuneArgs;

#[derive(Parser)]
#[command(name = "amiterra")]
#[command(author = "Amiterra Architecture Team")]
#[command(version = "0.1.0")]
#[command(about = "Amiterra (ami): Universal Private Cloud & Autonomous Infrastructure Engine", long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Initialize Amiterra environment (interactive Dev Workstation or Production Server setup)
    #[command(alias = "install")]
    Init(InitArgs),

    /// Join an existing Amiterra cluster as a Control-Plane or Worker node
    Join(JoinArgs),

    /// Start the Amiterra environment (local sandbox cluster or server node services)
    #[command(alias = "start")]
    Up(UpArgs),

    /// Stop the running Amiterra environment and release resources
    #[command(alias = "stop")]
    Down(DownArgs),

    /// Display context-aware health and status of the active environment
    Status(StatusArgs),

    /// Run system diagnostics and capability checks (alias: preflight)
    #[command(visible_alias = "preflight")]
    Doctor(DoctorArgs),

    /// Inspect, apply, or roll back host performance tuning (opt-in, reversible)
    Tune(TuneArgs),

    /// Storage inventory, tier plan, and opt-in LVM prepare for stateful workloads
    Storage(StorageArgs),

    /// Completely remove Amiterra, stop clusters, and restore host state
    Uninstall(UninstallArgs),

    /// Run background Kubelet monitoring and eBPF host tuning daemon (Day 2 systemd internal)
    #[command(hide = true)]
    Daemon(DaemonArgs),
}

#[derive(Args, Debug, Clone, Default)]
pub struct InitArgs {
    /// Local development workstation mode (rootless, zero host sysctl modifications)
    #[arg(long, visible_alias = "local")]
    pub dev: bool,

    /// Production server node mode (requires root, configures K3s, Cilium eBPF, sysctl)
    #[arg(long)]
    pub server: bool,

    /// Node role in cluster: "control-plane-init", "control-plane", or "worker"
    #[arg(long)]
    pub role: Option<String>,

    /// Node internal IP address for cluster mesh (overrides auto-detection)
    #[arg(long)]
    pub node_ip: Option<String>,

    /// Node external IP address for WAN/NAT ingress
    #[arg(long)]
    pub node_external_ip: Option<String>,

    /// Pod network CIDR (defaults to collision-free candidate e.g., 10.42.0.0/16)
    #[arg(long)]
    pub pod_cidr: Option<String>,

    /// Service network CIDR (defaults to collision-free candidate e.g., 10.43.0.0/16)
    #[arg(long)]
    pub service_cidr: Option<String>,

    /// Cluster control-plane endpoint to join (e.g. https://<first-control-plane>:6443)
    #[arg(long)]
    pub server_url: Option<String>,

    /// Cluster join token
    #[arg(short = 't', long)]
    pub token: Option<String>,

    /// Platform claim token for Amiterra Cloud auto-registration
    #[arg(long)]
    pub claim_token: Option<String>,

    /// Additional Subject Alternative Names (SANs) for the K3s API server certificate
    #[arg(long, value_delimiter = ',')]
    pub tls_san: Vec<String>,

    /// Prevent regular workloads from scheduling on control-plane nodes
    #[arg(long)]
    pub isolate_control_plane: bool,

    /// Skip interactive prompts and accept default options
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Apply the performance tuning profile after initialization (otherwise opt-in via `ami tune apply`)
    #[arg(long)]
    pub tune_apply: bool,

    /// Preview planned actions without applying any system modifications
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct JoinArgs {
    /// Cluster control-plane API endpoint (e.g., https://192.168.1.10:6443)
    pub server_url: Option<String>,

    /// Node join token or path to token file
    #[arg(short = 't', long)]
    pub token: Option<String>,

    /// Join as control-plane management node rather than worker
    #[arg(long, visible_alias = "master")]
    pub control_plane: bool,

    /// Node internal IP address for cluster mesh (overrides auto-detection)
    #[arg(long)]
    pub node_ip: Option<String>,

    /// Node external IP address for WAN/NAT ingress
    #[arg(long)]
    pub node_external_ip: Option<String>,

    /// Additional Subject Alternative Names (SANs) for the node certificate
    #[arg(long, value_delimiter = ',')]
    pub tls_san: Vec<String>,

    /// Skip interactive prompts and accept default options
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Apply the performance tuning profile after joining
    #[arg(long)]
    pub tune_apply: bool,

    /// Preview planned actions without applying any system modifications
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct UpArgs {
    /// Force local development workstation mode
    #[arg(long)]
    pub dev: bool,

    /// Force production server node mode
    #[arg(long)]
    pub server: bool,

    /// Preview planned actions without applying any system modifications
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct DownArgs {
    /// Force local development workstation mode
    #[arg(long)]
    pub dev: bool,

    /// Force production server node mode
    #[arg(long)]
    pub server: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct StatusArgs {
    /// Output status report in machine-readable JSON format
    #[arg(long)]
    pub json: bool,

    /// Inspect status in local development workstation mode
    #[arg(long)]
    pub dev: bool,

    /// Inspect status in production server node mode
    #[arg(long)]
    pub server: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct DoctorArgs {
    /// Output diagnostics report in machine-readable JSON format
    #[arg(long)]
    pub json: bool,

    /// Check requirements specifically for a production server node
    #[arg(long)]
    pub server: bool,

    /// Storage inventory / tier / Order-Improve plan (alias of `ami storage plan`)
    #[arg(long)]
    pub storage: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct DaemonArgs {
    /// Path to the workload tuning rules YAML configuration file
    #[arg(long, default_value = "/etc/amiterra/tuning_rules.yaml")]
    pub config: String,
}

#[derive(Args, Debug, Clone, Default)]
pub struct UninstallArgs {
    /// Automatically confirm uninstallation without prompting
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Purge all data directories and logs
    #[arg(long)]
    pub purge: bool,
}
