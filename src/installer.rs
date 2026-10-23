use anyhow::{bail, Result};
use std::io::{self, Write};

use crate::capabilities::{env_choices, HostCapabilities, InitTarget};
use crate::cli::{
    DownArgs, InitArgs, JoinArgs, StatusArgs, UninstallArgs, UpArgs,
};
use crate::context::{EnvironmentMode, ExecutionContext};
use crate::providers::resolve_backend;
use crate::ui::{Glyphs, Palette, Ui};

pub async fn handle_init(args: InitArgs) -> Result<()> {
    // Fast paths from explicit flags (CI / scripts). Interactive path is the
    // single unified wizard — same questions, capability-gated choices.
    let (mode, sandbox_engine) = if args.server
        || args.role.is_some()
        || args.server_url.is_some()
        || args.token.is_some()
    {
        (EnvironmentMode::Server, None)
    } else if args.dev {
        (EnvironmentMode::Workstation, Some("container".to_string()))
    } else if args.yes {
        (EnvironmentMode::Workstation, None)
    } else {
        Ui::header(
            "Welcome to Amiterra",
            "Private Cloud & Autonomous Infrastructure Engine",
        );
        prompt_target_environment()?
    };

    let mut ctx = ExecutionContext::resolve(
        mode == EnvironmentMode::Workstation,
        mode == EnvironmentMode::Server,
    );
    ctx.init_args = Some(args.clone());
    ctx.sandbox_engine = sandbox_engine;
    let backend = resolve_backend(ctx.mode);

    tracing::debug!("Initializing environment via backend: {}", backend.name());
    backend.init(&ctx, args.dry_run)
}

/// Unified environment picker: every option is listed; unavailable ones are
/// disabled with a one-line reason and **cannot be selected** — the wizard
/// re-prompts instead of silently installing something else.
/// Returns `(mode, preferred sandbox engine family)`.
fn prompt_target_environment() -> Result<(EnvironmentMode, Option<String>)> {
    let caps = HostCapabilities::probe();
    let choices = env_choices(&caps);

    let default_idx = choices
        .iter()
        .position(|c| c.available && c.recommended)
        .or_else(|| choices.iter().position(|c| c.available))
        .map(|i| i + 1);

    // Hard stop when this host cannot run any target.
    let Some(default_idx) = default_idx else {
        bail!(
            "No install target is available on this host.\n\
             Install a container runtime (Docker/OrbStack/Podman), QEMU, or run on Ubuntu 22.04/24.04 / Debian 12 as root."
        );
    };

    println!(
        "  {}  Host: {} · root: {} · runtime: {} · QEMU: {}\n",
        Palette::dim(Glyphs::BULLET),
        caps.os_label,
        if caps.is_root { "yes" } else { "no" },
        caps.container_runtime.as_deref().unwrap_or("none"),
        if caps.qemu_available { "yes" } else { "no" },
    );

    loop {
        render_env_menu(&choices, default_idx);
        print!(
            "  {} Select [1-{}, Enter={}, q=quit]: ",
            Palette::cyan("?"),
            choices.len(),
            default_idx
        );
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let raw = input.trim();

        if matches!(raw, "q" | "Q" | "quit" | "abort") {
            bail!("Installation aborted by user.");
        }

        match resolve_env_selection(&choices, raw, default_idx)? {
            EnvSelection::Chosen(idx) => {
                let choice = &choices[idx];
                Ui::step_done(
                    &format!("Selected target: {}", choice.target.title()),
                    None,
                );
                return Ok(target_to_mode(choice.target));
            }
            EnvSelection::Unavailable { index, reason } => {
                Ui::step_warn(&format!(
                    "{} is not available on this host: {}",
                    choices[index].target.title(),
                    reason
                ));
                println!(
                    "  {}",
                    Palette::dim("Pick a different target. Unavailable options cannot be installed.")
                );
                println!();
                // Re-render menu and ask again — never continue with another target.
            }
            EnvSelection::Invalid { message } => {
                Ui::step_warn(&message);
                println!();
            }
        }
    }
}

/// Result of interpreting one line of target-environment input.
#[derive(Debug, PartialEq, Eq)]
enum EnvSelection {
    /// 0-based index of an available target.
    Chosen(usize),
    /// User picked a listed but unavailable target — must re-prompt, not fall back.
    Unavailable { index: usize, reason: String },
    /// Unparseable / out-of-range input — must re-prompt.
    Invalid { message: String },
}

/// Pure selection logic (unit-testable). `raw` is trimmed user input;
/// empty input means "accept default".
fn resolve_env_selection(
    choices: &[crate::capabilities::EnvChoice],
    raw: &str,
    default_idx: usize,
) -> Result<EnvSelection> {
    let selected = if raw.is_empty() {
        default_idx
    } else {
        match raw.parse::<usize>() {
            Ok(n) if n >= 1 && n <= choices.len() => n,
            _ => {
                return Ok(EnvSelection::Invalid {
                    message: format!(
                        "Invalid selection '{raw}'. Enter 1-{}, Enter for {}, or q to quit.",
                        choices.len(),
                        default_idx
                    ),
                });
            }
        }
    };

    let index = selected - 1;
    let Some(choice) = choices.get(index) else {
        return Ok(EnvSelection::Invalid {
            message: format!("Selection {selected} is out of range."),
        });
    };

    if !choice.available {
        return Ok(EnvSelection::Unavailable {
            index,
            reason: choice.reason.clone(),
        });
    }

    Ok(EnvSelection::Chosen(index))
}

fn render_env_menu(choices: &[crate::capabilities::EnvChoice], default_idx: usize) {
    println!("  {}", Palette::bold("Select target environment:"));
    for (idx, choice) in choices.iter().enumerate() {
        let n = idx + 1;
        if choice.available {
            let rec = if choice.recommended {
                Palette::cyan(" [Recommended]")
            } else {
                String::new()
            };
            let def = if n == default_idx {
                Palette::cyan(" [Default]")
            } else {
                String::new()
            };
            println!(
                "    {} {}{}{}",
                Palette::bold(format!("{n})").as_str()),
                Palette::bold(choice.target.title()),
                rec,
                def
            );
            println!("       {}", Palette::dim(choice.target.summary()));
            println!("       {}", Palette::dim(&format!("— {}", choice.reason)));
        } else {
            println!(
                "    {} {}  {}",
                Palette::bold(format!("{n})").as_str()),
                Palette::dim(choice.target.title()),
                Palette::yellow("(unavailable — cannot be selected)")
            );
            println!("       {}", Palette::dim(choice.target.summary()));
            println!(
                "       {}",
                Palette::yellow(&format!("— {}", choice.reason))
            );
        }
        println!();
    }
}

fn target_to_mode(target: InitTarget) -> (EnvironmentMode, Option<String>) {
    match target {
        InitTarget::SandboxContainer => {
            (EnvironmentMode::Workstation, Some("container".to_string()))
        }
        InitTarget::SandboxQemu => (EnvironmentMode::Workstation, Some("qemu".to_string())),
        InitTarget::ProductionServer => (EnvironmentMode::Server, None),
    }
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
        tune_apply: args.tune_apply,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::EnvChoice;

    fn sample_choices() -> Vec<EnvChoice> {
        vec![
            EnvChoice {
                target: InitTarget::SandboxContainer,
                available: false,
                reason: "No container runtime".into(),
                recommended: false,
            },
            EnvChoice {
                target: InitTarget::SandboxQemu,
                available: false,
                reason: "QEMU not installed".into(),
                recommended: false,
            },
            EnvChoice {
                target: InitTarget::ProductionServer,
                available: true,
                reason: "Root privileges detected".into(),
                recommended: true,
            },
        ]
    }

    #[test]
    fn unavailable_selection_is_rejected_not_fallback() {
        // Regression: user picks option 1 (unavailable) — must NOT continue install.
        let choices = sample_choices();
        let sel = resolve_env_selection(&choices, "1", 3).unwrap();
        assert!(matches!(
            sel,
            EnvSelection::Unavailable { index: 0, .. }
        ));
    }

    #[test]
    fn available_selection_is_accepted() {
        let choices = sample_choices();
        let sel = resolve_env_selection(&choices, "3", 3).unwrap();
        assert_eq!(sel, EnvSelection::Chosen(2));
    }

    #[test]
    fn empty_input_uses_default() {
        let choices = sample_choices();
        let sel = resolve_env_selection(&choices, "", 3).unwrap();
        assert_eq!(sel, EnvSelection::Chosen(2));
    }

    #[test]
    fn invalid_input_is_rejected() {
        let choices = sample_choices();
        assert!(matches!(
            resolve_env_selection(&choices, "9", 3).unwrap(),
            EnvSelection::Invalid { .. }
        ));
        assert!(matches!(
            resolve_env_selection(&choices, "abc", 3).unwrap(),
            EnvSelection::Invalid { .. }
        ));
        assert!(matches!(
            resolve_env_selection(&choices, "0", 3).unwrap(),
            EnvSelection::Invalid { .. }
        ));
    }

    #[test]
    fn unavailable_default_cannot_mask_error() {
        // If someone forces default_idx onto an unavailable row, selection must still refuse.
        let choices = sample_choices();
        let sel = resolve_env_selection(&choices, "", 1).unwrap();
        assert!(matches!(sel, EnvSelection::Unavailable { index: 0, .. }));
    }
}
