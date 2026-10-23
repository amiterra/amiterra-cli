pub mod capabilities;
mod cli;
mod context;
mod daemon;
pub mod discovery;
pub mod guardrails;
mod installer;
mod mcp;
mod preflight;
mod providers;
pub mod tune;
pub mod ui;
pub mod wizard;

use clap::Parser;
use cli::{Cli, Commands, InitArgs};
use tracing_subscriber::EnvFilter;

/// Ensures that when launched via the `ami` symlink/alias, the process re-executes
/// the canonical `amiterra` binary in-place (same PID) before spawning threads,
/// so `ps`, `top`, `htop`, and `/proc/<pid>/comm` unambiguously show `amiterra`.
#[cfg(unix)]
fn ensure_canonical_process_name() {
    if let Some(arg0) = std::env::args_os().next() {
        let invoked_name = std::path::Path::new(&arg0)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if invoked_name != "amiterra"
            && let Ok(real_exe) = std::env::current_exe().and_then(|p| p.canonicalize())
            && real_exe.file_name().and_then(|n| n.to_str()) == Some("amiterra")
        {
            use std::os::unix::process::CommandExt;
            let _ = std::process::Command::new(&real_exe)
                .args(std::env::args_os().skip(1))
                .exec();
        }
    }
}

fn main() -> anyhow::Result<()> {
    #[cfg(unix)]
    ensure_canonical_process_name();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let default_level = match &cli.command {
        Some(Commands::Daemon(_)) => "info",
        _ => "warn",
    };

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    match cli.command {
        Some(Commands::Init(args)) => {
            installer::handle_init(args).await?;
        }
        Some(Commands::Join(args)) => {
            installer::handle_join(args).await?;
        }
        Some(Commands::Up(args)) => {
            installer::handle_up(args).await?;
        }
        Some(Commands::Down(args)) => {
            installer::handle_down(args).await?;
        }
        Some(Commands::Status(args)) => {
            installer::handle_status(args).await?;
        }
        Some(Commands::Doctor(args)) => {
            let report = preflight::run_preflight(args.server);
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                preflight::print_preflight_report(&report);
            }
        }
        Some(Commands::Tune(args)) => {
            tune::cli::handle_tune(args)?;
        }
        Some(Commands::Mcp(args)) => {
            mcp::run_mcp_server(args).await?;
        }
        Some(Commands::Uninstall(args)) => {
            installer::handle_uninstall(args).await?;
        }
        Some(Commands::Daemon(_args)) => {
            tracing::info!("Starting Amiterra Daemon (Day 2)...");
            daemon::run().await?;
        }
        None => {
            installer::handle_init(InitArgs::default()).await?;
        }
    }

    Ok(())
}
