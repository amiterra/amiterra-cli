//! CLI surface for `ami tune`.

use anyhow::Result;
use clap::{Args, Subcommand};

use super::{apply, apply_platform_prep, plan, print_plan, rollback, status};

#[derive(Args, Debug, Clone, Default)]
pub struct TuneArgs {
    #[command(subcommand)]
    pub command: Option<TuneCommand>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TuneCommand {
    /// Preview the performance profile without changing the host
    Plan,
    /// Apply the performance profile (baseline + sysctl + limits)
    Apply {
        /// Skip interactive confirmation
        #[arg(short = 'y', long)]
        yes: bool,
        /// Show planned changes only
        #[arg(long)]
        dry_run: bool,
    },
    /// Restore host values captured before `tune apply`
    Rollback {
        /// Skip interactive confirmation
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Show whether platform prep / performance profile are applied
    Status {
        /// Machine-readable JSON report
        #[arg(long)]
        json: bool,
    },
    /// Apply minimal platform prep only (same as init; useful to repair)
    Platform {
        /// Skip interactive confirmation
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

pub fn handle_tune(args: TuneArgs) -> Result<()> {
    match args.command.unwrap_or(TuneCommand::Status { json: false }) {
        TuneCommand::Plan => {
            let changes = plan()?;
            let perf: Vec<_> = changes
                .into_iter()
                .filter(|c| c.layer == "performance")
                .collect();
            print_plan(&perf, "performance");
            crate::tune::print_tuning_scope_warning();
            Ok(())
        }
        TuneCommand::Apply { yes, dry_run } => apply(yes, dry_run),
        TuneCommand::Rollback { yes } => rollback(yes),
        TuneCommand::Status { json } => {
            let st = status()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&st)?);
            } else {
                crate::ui::Ui::header("Amiterra Tune Status", "Host tuning layers");
                println!(
                    "  Platform prep (init)     : {}",
                    if st.platform_applied {
                        "● applied"
                    } else {
                        "○ not applied"
                    }
                );
                println!(
                    "  Performance profile     : {}",
                    if st.performance_applied {
                        "● applied"
                    } else {
                        "○ not applied"
                    }
                );
                println!(
                    "  Baseline for rollback   : {}",
                    if st.baseline_present {
                        "● present"
                    } else {
                        "○ absent"
                    }
                );
                for n in &st.notes {
                    println!("  {} {}", crate::ui::Palette::yellow("!"), n);
                }
                println!();
            }
            Ok(())
        }
        TuneCommand::Platform { yes } => {
            let changes = {
                // Show what platform prep would change.
                let mut out = Vec::new();
                for e in crate::tune::PlatformPrep.sysctl() {
                    let cur = crate::tune::read_sysctl(&e.key).ok();
                    if cur.as_deref() != Some(e.value.as_str()) {
                        out.push(crate::tune::PlannedChange {
                            key: e.key.clone(),
                            current: cur,
                            target: e.value.clone(),
                            layer: "platform".into(),
                        });
                    }
                }
                out
            };
            print_plan(&changes, "platform");
            if changes.is_empty() {
                crate::ui::Ui::step_done("Platform prep already applied", None);
                return Ok(());
            }
            if !yes {
                use std::io::{stdin, stdout, IsTerminal, Write};
                if stdin().is_terminal() {
                    print!("  Apply platform prep? [y/N]: ");
                    stdout().flush()?;
                    let mut input = String::new();
                    stdin().read_line(&mut input)?;
                    if !input.trim().eq_ignore_ascii_case("y") {
                        println!("  Aborted.");
                        return Ok(());
                    }
                }
            }
            if !crate::preflight::is_root() {
                anyhow::bail!("Superuser privileges required. Re-run with sudo.");
            }
            let applied = apply_platform_prep()?;
            crate::ui::Ui::step_done(
                &format!("Platform prep applied ({} change(s))", applied.len()),
                None,
            );
            Ok(())
        }
    }
}
