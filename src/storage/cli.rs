//! CLI surface: `ami storage …`.

use anyhow::Result;
use clap::{Args, Subcommand};

use super::{DATA_ROOT, classify, ensure_data_root, inventory::StorageInventory, plan, prepare};

#[derive(Args, Debug, Clone, Default)]
pub struct StorageArgs {
    #[command(subcommand)]
    pub command: Option<StorageCommand>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum StorageCommand {
    /// Show storage tier, labels, and next steps
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Order/Improve guide + machine-readable plan (read-only)
    Plan {
        /// Emit JSON document for placement Advisor / UI
        #[arg(long)]
        json: bool,
        /// Include full device/RAID inventory (debug / storage prepare)
        #[arg(long)]
        full: bool,
    },
    /// Prepare a dedicated data disk: LVM volume + filesystem + mount at the
    /// data root (opt-in; destructive only to the selected unallocated disk)
    Prepare {
        /// Whole-disk name (e.g. nvme2n1) — must be unallocated/unmounted
        #[arg(long)]
        disk: String,
        /// Volume group name (default: amiterra-data)
        #[arg(long, default_value = prepare::DEFAULT_VG)]
        vg: String,
        /// Skip interactive confirmation
        #[arg(short = 'y', long)]
        yes: bool,
        /// Show planned commands only
        #[arg(long)]
        dry_run: bool,
    },
    /// Undo prepare: unmount, drop fstab entry, remove the data LV and VG (requires --yes)
    Rollback {
        #[arg(long, default_value = prepare::DEFAULT_VG)]
        vg: String,
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

/// Format optional byte count without `Some(..)` debug noise.
pub(crate) fn format_bytes(v: Option<u64>) -> String {
    v.map(|n| format!("{n} bytes"))
        .unwrap_or_else(|| "—".to_string())
}

pub fn handle_storage(args: StorageArgs) -> Result<()> {
    match args
        .command
        .unwrap_or(StorageCommand::Status { json: false })
    {
        StorageCommand::Status { json } => {
            let inv = StorageInventory::probe().unwrap_or_default();
            let summary = classify(&inv);
            if json {
                let doc = plan::build_plan(&inv, &summary, false);
                println!("{}", serde_json::to_string_pretty(&doc)?);
                return Ok(());
            }
            crate::ui::Ui::header("Amiterra Storage", "Universal node storage tier");
            println!(
                "  Tier            : {} ({})",
                summary.tier.as_str(),
                summary.storage_class.as_str()
            );
            println!("  Data root       : {DATA_ROOT}");
            println!("  Local SC        : {}", super::LOCAL_SC_NAME);
            println!("  Policy          : {}", summary.policy_label());
            let vg_ready = prepare::dedicated_vg_present(prepare::DEFAULT_VG);
            println!(
                "  Dedicated VG    : {}",
                if vg_ready {
                    crate::ui::Palette::green(&format!(
                        "{} present — s1 path ready",
                        prepare::DEFAULT_VG
                    ))
                } else {
                    crate::ui::Palette::dim(&format!("{} absent", prepare::DEFAULT_VG))
                }
            );
            println!(
                "  Free disks      : {}",
                if summary.free_disk_names.is_empty() {
                    "—".into()
                } else {
                    summary.free_disk_names.join(", ")
                }
            );
            for n in &summary.notes {
                println!("  {} {}", crate::ui::Palette::yellow("!"), n);
            }
            println!();
            crate::ui::Ui::next_steps(
                "Next:",
                &[
                    "ami storage plan          Order/Improve checklist",
                    "ami storage plan --json   Machine-readable plan",
                ],
            );
            Ok(())
        }
        StorageCommand::Plan { json, full } => {
            let inv = StorageInventory::probe().unwrap_or_default();
            let summary = classify(&inv);
            let doc = plan::build_plan(&inv, &summary, full);
            if json {
                println!("{}", serde_json::to_string_pretty(&doc)?);
                return Ok(());
            }
            // Text mode: compact facts (same as slim JSON).
            crate::ui::Ui::header(
                "Storage Plan",
                "Machine-readable facts (no recommendations)",
            );
            println!("  tier             : {}", doc.tier);
            println!("  storage_class    : {}", doc.storage_class);
            println!("  policy           : {}", doc.policy.join(","));
            println!("  data_root        : {}", doc.data_root);
            println!(
                "  isolation        : {}",
                doc.node_profile.isolation.as_str()
            );
            println!(
                "  redundancy       : {}",
                doc.node_profile.redundancy.as_str()
            );
            println!(
                "  performance      : {}",
                doc.node_profile.performance_class.as_str()
            );
            println!(
                "  media            : {}",
                doc.node_profile.media_classes.join(",")
            );
            let free = format_bytes(doc.node_profile.capacity.free_bytes);
            let budget = format_bytes(doc.node_profile.capacity.stateful_budget_bytes);
            println!(
                "  root             : {} ({free} free)",
                doc.node_profile
                    .capacity
                    .root_device
                    .clone()
                    .unwrap_or_else(|| "—".into()),
            );
            println!("  stateful_budget  : {budget}");
            println!(
                "  raid_summary     : {}",
                doc.node_profile
                    .raid_summary
                    .iter()
                    .map(|r| format!("{}({},{})", r.name, r.level, r.used_for))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            println!(
                "  free_disks       : {}",
                if doc.node_profile.free_disks.is_empty() {
                    "—".into()
                } else {
                    doc.node_profile.free_disks.join(", ")
                }
            );
            println!("  forbidden        : {}", doc.forbidden.join(","));
            println!("  order_guide      : {}", doc.order_guide.join(" | "));
            println!("  improve_guide    : {}", doc.improve_guide.join(" | "));
            if let Some(i) = &doc.inventory {
                println!(
                    "  inventory        : {} device(s) [--full]",
                    i.devices.len()
                );
            }
            println!();
            Ok(())
        }
        StorageCommand::Prepare {
            disk,
            vg,
            yes,
            dry_run,
        } => {
            let inv = StorageInventory::probe().unwrap_or_default();
            let plan = prepare::plan_prepare(&inv, &disk, &vg)?;
            crate::ui::Ui::header("Storage Prepare", "Dedicated data disk (LVM + mount)");
            println!("  Disk: /dev/{}", plan.disk);
            println!("  VG  : {}", plan.vg_name);
            println!("  Planned:");
            for a in &plan.actions {
                println!("    • {a}");
            }
            println!();
            println!(
                "  {}",
                crate::ui::Palette::yellow(
                    "This will write an LVM label to the selected disk (not system RAID)."
                )
            );
            if dry_run {
                crate::ui::Ui::step_info("Dry-run", "No host modifications applied.");
                return Ok(());
            }
            if !yes {
                anyhow::bail!(
                    "Refusing to modify disks without --yes. Review `ami storage plan` first."
                );
            }
            prepare::execute_prepare(&plan, false, true)?;
            let done = prepare::activate_data_root(&plan.vg_name, false)?;
            // Tier labels refresh in the same run (no "next init" lag).
            super::refresh_node_labels();
            crate::ui::Ui::step_done(
                &format!(
                    "Dedicated data volume ready ({} step(s)) — tier s1 on next status",
                    done.len().max(1)
                ),
                None,
            );
            crate::ui::Ui::next_steps(
                "Verify:",
                &[
                    "ami storage status          VG/LV readiness and tier",
                    "ami storage status --json   Machine-readable summary",
                ],
            );
            Ok(())
        }
        StorageCommand::Rollback { vg, yes } => {
            prepare::rollback_prepare(&vg, yes)?;
            crate::ui::Ui::step_done(&format!("VG {vg} removed"), None);
            Ok(())
        }
    }
}

/// Called from server init (Phase A): ensure data-root + print tier card.
pub fn apply_universal_data_root() -> Result<()> {
    let root = std::path::Path::new(DATA_ROOT);
    ensure_data_root(root)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_never_prints_some() {
        assert_eq!(format_bytes(Some(42)), "42 bytes");
        assert_eq!(format_bytes(None), "—");
        assert!(!format_bytes(Some(1)).contains("Some"));
    }
}
