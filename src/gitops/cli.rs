//! CLI surface for `ami gitops`.

use anyhow::Result;
use clap::{Args, Subcommand};

use super::{BootstrapOptions, DEFAULT_BRANCH, DEFAULT_CLUSTER_ID, bootstrap, print_status};
use crate::delivery::cli::IntentServeArgs;

#[derive(Args, Debug, Clone, Default)]
pub struct GitopsArgs {
    #[command(subcommand)]
    pub command: Option<GitopsCommand>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GitopsCommand {
    /// Bootstrap Flux and bind it to the Git repository (idempotent converge)
    Bootstrap {
        /// Remote URL (default: local bare repository on this node)
        #[arg(long)]
        git: Option<String>,
        /// Branch tracked by Flux
        #[arg(long, default_value = DEFAULT_BRANCH)]
        branch: String,
        /// Cluster id used in the `clusters/<id>/` layout
        #[arg(long, default_value = DEFAULT_CLUSTER_ID)]
        cluster_id: String,
        /// Node IP used in the LocalBare SSH remote (required for local provider)
        #[arg(long)]
        node_ip: Option<String>,
        /// Skip interactive confirmation
        #[arg(short = 'y', long)]
        yes: bool,
        /// Show planned steps only
        #[arg(long)]
        dry_run: bool,
        /// Do not wait for the root Kustomization to become Ready
        #[arg(long)]
        no_wait: bool,
    },
    /// Show bootstrap state, deploy key fingerprint and remote (read-only)
    Status {
        /// Machine-readable JSON report
        #[arg(long)]
        json: bool,
    },
    /// Run the gitops-agent intent channel (signed TopologyChange → commit)
    IntentServe(IntentServeArgs),
}

pub fn handle_gitops(args: GitopsArgs) -> Result<()> {
    match args
        .command
        .unwrap_or(GitopsCommand::Status { json: false })
    {
        GitopsCommand::Bootstrap {
            git,
            branch,
            cluster_id,
            node_ip,
            yes,
            dry_run,
            no_wait,
        } => {
            let node_ip = node_ip.unwrap_or_else(detect_node_ip);
            let opts = BootstrapOptions {
                git,
                branch,
                cluster_id,
                node_ip,
                yes,
                dry_run,
                wait_ready: !no_wait,
            };
            bootstrap(&opts)?;
            Ok(())
        }
        GitopsCommand::Status { json } => print_status(json),
        GitopsCommand::IntentServe(args) => crate::delivery::cli::handle_intent_serve(args),
    }
}

/// Best-effort primary node IP for the LocalBare SSH remote.
fn detect_node_ip() -> String {
    // Route-based detection: the source IP of the default route.
    if let Ok(out) = std::process::Command::new("ip")
        .args(["-4", "route", "get", "1.1.1.1"])
        .output()
        && out.status.success()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some(pos) = text.find(" src ") {
            let rest = &text[pos + 5..];
            if let Some(ip) = rest.split_whitespace().next() {
                return ip.to_string();
            }
        }
    }
    String::new()
}
