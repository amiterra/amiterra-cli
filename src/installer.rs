use anyhow::Result;
use std::io::{self, Write};

use crate::cli::{
    DownArgs, InitArgs, JoinArgs, StatusArgs, UninstallArgs, UpArgs,
};
use crate::context::{EnvironmentMode, ExecutionContext};
use crate::providers::resolve_backend;
use crate::ui::{Glyphs, Palette, Ui};

pub async fn handle_init(args: InitArgs) -> Result<()> {
    let mode = if args.server
        || args.role.is_some()
        || args.server_url.is_some()
        || args.token.is_some()
    {
        EnvironmentMode::Server
    } else if args.dev || args.yes {
        EnvironmentMode::Workstation
    } else {
        Ui::header(
            "Welcome to Amiterra",
            "Private Cloud & Autonomous Infrastructure Engine",
        );
        prompt_user_mode()?
    };

    let mut ctx = ExecutionContext::resolve(
        mode == EnvironmentMode::Workstation,
        mode == EnvironmentMode::Server,
    );
    ctx.init_args = Some(args.clone());
    let backend = resolve_backend(ctx.mode);

    tracing::debug!("Initializing environment via backend: {}", backend.name());
    backend.init(&ctx, args.dry_run)
}

pub async fn handle_join(args: JoinArgs) -> Result<()> {
    let init_args = InitArgs {
        server: true,
        role: Some(if args.control_plane {
            "control-plane".to_string()
        } else {
            "worker".to_string()
        }),
        server_url: args.server_url,
        token: args.token,
        node_ip: args.node_ip,
        node_external_ip: args.node_external_ip,
        tls_san: args.tls_san,
        yes: args.yes,
        dry_run: args.dry_run,
        ..Default::default()
    };
    handle_init(init_args).await
}

pub async fn handle_up(args: UpArgs) -> Result<()> {
    let ctx = ExecutionContext::resolve(args.dev, args.server);
    let backend = resolve_backend(ctx.mode);
    backend.up(&ctx, args.dry_run)
}

pub async fn handle_down(args: DownArgs) -> Result<()> {
    let ctx = ExecutionContext::resolve(args.dev, args.server);
    let backend = resolve_backend(ctx.mode);
    backend.down(&ctx)
}

pub async fn handle_status(args: StatusArgs) -> Result<()> {
    let ctx = ExecutionContext::resolve(args.dev, args.server);
    let backend = resolve_backend(ctx.mode);
    let report = backend.status(&ctx)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let items: Vec<(&str, &str)> = report
        .metrics
        .iter()
        .map(|m| (m.label.as_str(), m.value.as_str()))
        .collect();

    Ui::card("Amiterra Environment Status", &items);

    if let Some(hint) = &report.next_hint {
        Ui::next_steps("Recommended next step:", &[hint.as_str()]);
    }
    println!();
    Ok(())
}

pub async fn handle_uninstall(args: UninstallArgs) -> Result<()> {
    Ui::header(
        "Uninstall Amiterra",
        "Restoring system state and removing components",
    );

    if !args.yes {
        print!(
            "{} Are you sure you want to uninstall Amiterra and revert settings? [y/N]: ",
            Palette::yellow(Glyphs::WARN)
        );
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim().to_lowercase() != "y" {
            println!("Aborted.");
            return Ok(());
        }
    }

    let ctx = ExecutionContext::resolve(false, false);
    // Clean up both server and workstation artifacts safely
    let server_backend = resolve_backend(EnvironmentMode::Server);
    let _ = server_backend.uninstall(&ctx, args.purge);

    let workstation_backend = resolve_backend(EnvironmentMode::Workstation);
    workstation_backend.uninstall(&ctx, args.purge)?;

    Ui::step_done(
        "All Amiterra components cleanly uninstalled. Host state restored.",
        None,
    );
    println!();
    Ok(())
}

fn prompt_user_mode() -> Result<EnvironmentMode> {
    Ui::header(
        "Choose Environment Mode",
        "Select installation profile for this node",
    );
    println!(
        "  {} {} Local Development (Workstation Sandbox) {}",
        Palette::cyan(Glyphs::CHEVRON),
        Palette::bold("1)"),
        Palette::dim("[Default]")
    );
    println!(
        "     {} Deploys an isolated container sandbox for testing and AI agents",
        Palette::dim(Glyphs::BULLET)
    );
    println!(
        "     {} ZERO Host Pollution (host system files and kernel untouched)",
        Palette::dim(Glyphs::BULLET)
    );
    println!(
        "     {} Rootless: NO host eBPF, NO sysctl tuning, NO sudo required",
        Palette::dim(Glyphs::BULLET)
    );
    println!(
        "     {} Recommended for macOS, Linux Desktop, and laptops\n",
        Palette::dim(Glyphs::BULLET)
    );

    println!(
        "     {} Production Server Node",
        Palette::bold("2)")
    );
    println!(
        "     {} Dedicated bare-metal or Cloud VPS (Ubuntu / Debian)",
        Palette::dim(Glyphs::BULLET)
    );
    println!(
        "     {} Autonomous host kernel tuning (BBR, Somaxconn, limits)",
        Palette::dim(Glyphs::BULLET)
    );
    println!(
        "     {} High-performance Cilium eBPF Host-Routing networking stack",
        Palette::dim(Glyphs::BULLET)
    );
    println!(
        "     {} Requires superuser privileges (root / sudo)\n",
        Palette::dim(Glyphs::BULLET)
    );

    print!("Select an option [1-2, press Enter for 1]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice = input.trim();

    if choice == "2" {
        Ok(EnvironmentMode::Server)
    } else {
        Ok(EnvironmentMode::Workstation)
    }
}
