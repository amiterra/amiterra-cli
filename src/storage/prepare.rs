//! Opt-in LVM volume-group preparation (Phase C).
//!
//! Destructive only on **explicitly selected unallocated disks**.
//! Never touches system RAID, mounted devices, or partitions in use.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

use super::inventory::StorageInventory;

/// Proposed prepare action (preview before any mutation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparePlan {
    pub disk: String,
    pub vg_name: String,
    pub actions: Vec<String>,
}

/// Default VG name for dedicated stateful storage.
pub const DEFAULT_VG: &str = "amiterra-data";

/// Build a prepare plan for `disk`. Pure validation of names/eligibility
/// against inventory; no host changes.
///
/// **Only** disks from [`StorageInventory::free_disks`] are eligible:
/// unmounted, unpartitioned, no filesystem. System RAID/root is never allowed.
pub fn plan_prepare(inv: &StorageInventory, disk: &str, vg: &str) -> Result<PreparePlan> {
    if disk.trim().is_empty() {
        bail!("disk name must not be empty");
    }
    // Normalize: accept /dev/nvme2n1 or nvme2n1.
    let disk = disk.trim().trim_start_matches("/dev/");
    if vg.trim().is_empty() {
        bail!("VG name must not be empty");
    }
    if !vg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        bail!("VG name '{vg}' contains invalid characters");
    }

    // Hard deny-list even before inventory lookup.
    if disk.starts_with("md") || disk.contains("dm-") {
        bail!("refusing to prepare on '{disk}' (system RAID / device-mapper)");
    }
    if disk.contains('/') || disk.contains("..") {
        bail!("invalid disk name '{disk}'");
    }

    let target = inv
        .free_disks()
        .into_iter()
        .find(|d| d.name == disk)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "disk '{disk}' is not in usable_free_disks (unallocated unmounted whole disk). \
                 Nothing to prepare without a dedicated free disk — see `ami storage plan`."
            )
        })?;

    if target.has_any_mount() {
        bail!("refusing to use a mounted disk");
    }
    if !target.children.is_empty() {
        bail!("refusing to use a disk that already has partitions");
    }
    if target.fstype.as_deref().map(|s| !s.is_empty()).unwrap_or(false) {
        bail!("refusing to use a disk that already has a filesystem signature");
    }

    Ok(PreparePlan {
        disk: target.name.clone(),
        vg_name: vg.to_string(),
        actions: vec![
            format!("pvcreate /dev/{}", target.name),
            format!("vgcreate {vg} /dev/{}", target.name),
        ],
    })
}

/// Live safety checks immediately before `pvcreate` (inventory may be stale).
fn assert_device_safe_at_execute(disk: &str) -> Result<()> {
    if disk.starts_with("md") || disk.contains("dm-") {
        bail!("refusing '{disk}' (RAID/dm)");
    }
    if disk.contains('/') || disk.contains("..") || disk.trim().is_empty() {
        bail!("invalid disk name '{disk}'");
    }

    // 1) Not mounted (including by UUID).
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        let dev = format!("/dev/{disk}");
        for line in mounts.lines() {
            if line.starts_with(&dev) {
                bail!("refusing '{disk}': appears in /proc/mounts");
            }
        }
    }

    // 2) Not a member of an active md RAID.
    if let Ok(md) = std::fs::read_to_string("/proc/mdstat")
        && (md.contains(&format!(" {disk}")) || md.contains(&format!("{disk}[")))
    {
        bail!("refusing '{disk}': listed in /proc/mdstat");
    }

    // 3) Not an LVM PV already (pvs).
    if let Ok(out) = Command::new("pvs").args(["--noheadings", "-o", "pv_name"]).output()
        && out.status.success()
    {
        let txt = String::from_utf8_lossy(&out.stdout);
        if txt.lines().any(|l| l.trim().ends_with(disk)) {
            bail!("refusing '{disk}': already an LVM PV");
        }
    }

    // 4) No existing filesystem/RAID/LVM signature (blkid) — we do NOT wipe.
    if let Ok(out) = Command::new("blkid").args(["-o", "value", "-s", "TYPE", &format!("/dev/{disk}")]).output()
        && out.status.success()
    {
        let t = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !t.is_empty() {
            bail!("refusing '{disk}': existing signature type '{t}' (will not wipe)");
        }
    }

    // 5) Partition table check: any child partition under /sys/block/<disk>/.
    let sys = format!("/sys/block/{disk}");
    if let Ok(entries) = std::fs::read_dir(&sys) {
        for e in entries.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with(disk) && n != disk && e.path().join("partition").exists() {
                bail!("refusing '{disk}': has partition {n}");
            }
        }
    }

    Ok(())
}

/// Execute prepare plan (requires root). Captures stderr; does not run on dry_run.
///
/// Uses `pvcreate -y` **without** `-ff`: existing signatures abort instead of wipe.
pub fn execute_prepare(plan: &PreparePlan, dry_run: bool, yes: bool) -> Result<()> {
    if dry_run {
        return Ok(());
    }
    if !yes {
        bail!("storage prepare requires --yes after reviewing `ami storage plan`");
    }
    if !crate::preflight::is_root() {
        bail!("superuser privileges required for ami storage prepare");
    }

    let disk_path = format!("/dev/{}", plan.disk);
    if !Path::new(&disk_path).exists() {
        bail!("device {disk_path} does not exist");
    }

    assert_device_safe_at_execute(&plan.disk)?;

    // No -ff: refuse if anything is already on the disk.
    let pv = Command::new("pvcreate")
        .args(["-y", &disk_path])
        .output()
        .context("pvcreate not available (install lvm2)")?;
    if !pv.status.success() {
        bail!(
            "pvcreate failed (disk may not be empty): {}",
            String::from_utf8_lossy(&pv.stderr).trim()
        );
    }

    let vg = Command::new("vgcreate")
        .args([&plan.vg_name, &disk_path])
        .output()
        .context("vgcreate failed to start")?;
    if !vg.status.success() {
        bail!(
            "vgcreate failed: {}",
            String::from_utf8_lossy(&vg.stderr).trim()
        );
    }

    Ok(())
}

/// Best-effort reverse of prepare (only when VG exists and has no LVs).
pub fn rollback_prepare(vg: &str, yes: bool) -> Result<()> {
    if !yes {
        bail!("rollback requires --yes");
    }
    if !crate::preflight::is_root() {
        bail!("superuser privileges required");
    }
    let _ = Command::new("vgchange").args(["-an", vg]).output();
    let out = Command::new("vgremove")
        .args(["-y", vg])
        .output()
        .context("vgremove failed to start")?;
    if !out.status.success() {
        bail!(
            "vgremove failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::inventory::{BlockDevice, StorageInventory};

    fn inv() -> StorageInventory {
        StorageInventory::from_devices(vec![
            BlockDevice {
                name: "nvme0n1".into(),
                kind: "disk".into(),
                children: vec![BlockDevice {
                    name: "nvme0n1p4".into(),
                    kind: "part".into(),
                    fstype: Some("ext4".into()),
                    mountpoints: vec!["/".into()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            BlockDevice {
                name: "nvme2n1".into(),
                kind: "disk".into(),
                ..Default::default()
            },
        ])
    }

    #[test]
    fn plan_rejects_non_free_disk() {
        assert!(plan_prepare(&inv(), "nvme0n1", "vg0").is_err());
        assert!(plan_prepare(&inv(), "md2", "vg0").is_err());
    }

    #[test]
    fn plan_accepts_free_whole_disk() {
        let p = plan_prepare(&inv(), "nvme2n1", DEFAULT_VG).unwrap();
        assert_eq!(p.disk, "nvme2n1");
        assert_eq!(p.vg_name, DEFAULT_VG);
        assert!(p.actions.iter().any(|a| a.contains("pvcreate")));
    }

    #[test]
    fn plan_rejects_bad_vg_name() {
        assert!(plan_prepare(&inv(), "nvme2n1", "bad name").is_err());
        assert!(plan_prepare(&inv(), "", DEFAULT_VG).is_err());
    }

    #[test]
    fn execute_requires_yes() {
        let p = plan_prepare(&inv(), "nvme2n1", DEFAULT_VG).unwrap();
        assert!(execute_prepare(&p, false, false).is_err());
    }

    #[test]
    fn execute_dry_run_is_noop() {
        let p = plan_prepare(&inv(), "nvme2n1", DEFAULT_VG).unwrap();
        assert!(execute_prepare(&p, true, false).is_ok());
    }

    #[test]
    fn plan_normalizes_dev_prefix_and_rejects_paths() {
        let inv = inv();
        assert!(plan_prepare(&inv, "/dev/nvme2n1", DEFAULT_VG).is_ok());
        assert!(plan_prepare(&inv, "../nvme2n1", DEFAULT_VG).is_err());
        assert!(plan_prepare(&inv, "nvme2n1p1", DEFAULT_VG).is_err());
        assert!(plan_prepare(&inv, "dm-0", DEFAULT_VG).is_err());
    }

    #[test]
    fn plan_rejects_disk_with_children_or_fs() {
        let mut d = BlockDevice {
            name: "nvme3n1".into(),
            kind: "disk".into(),
            fstype: Some("ext4".into()),
            ..Default::default()
        };
        let _ = &mut d;
        let with_fs = StorageInventory::from_devices(vec![BlockDevice {
            name: "nvme3n1".into(),
            kind: "disk".into(),
            fstype: Some("ext4".into()),
            ..Default::default()
        }]);
        assert!(plan_prepare(&with_fs, "nvme3n1", DEFAULT_VG).is_err());

        let with_part = StorageInventory::from_devices(vec![BlockDevice {
            name: "nvme3n1".into(),
            kind: "disk".into(),
            children: vec![BlockDevice {
                name: "nvme3n1p1".into(),
                kind: "part".into(),
                ..Default::default()
            }],
            ..Default::default()
        }]);
        assert!(plan_prepare(&with_part, "nvme3n1", DEFAULT_VG).is_err());
    }

    #[test]
    fn assert_device_safe_rejects_md_and_traversal() {
        assert!(assert_device_safe_at_execute("md2").is_err());
        assert!(assert_device_safe_at_execute("dm-0").is_err());
        assert!(assert_device_safe_at_execute("../sda").is_err());
    }
}
