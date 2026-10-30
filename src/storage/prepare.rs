//! Opt-in LVM volume-group preparation (Phase C).
//!
//! Destructive only on **explicitly selected unallocated disks**.
//! Never touches system RAID, mounted devices, or partitions in use.

use anyhow::{Context, Result, bail};
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

/// True when the dedicated VG from [`DEFAULT_VG`] (or `vg`) exists on this host.
///
/// Phase C readiness signal: after `ami storage prepare`
/// the node has a dedicated data path even before the first mount/PVC.
/// Best-effort — `vgs` missing simply reports `false`.
pub fn dedicated_vg_present(vg: &str) -> bool {
    Command::new("vgs")
        .args(["--noheadings", "-o", "vg_name", vg])
        .output()
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|l| l.trim() == vg)
        })
        .unwrap_or(false)
}

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
    if target
        .fstype
        .as_deref()
        .map(|s| !s.is_empty())
        .unwrap_or(false)
    {
        bail!("refusing to use a disk that already has a filesystem signature");
    }

    Ok(PreparePlan {
        disk: target.name.clone(),
        vg_name: vg.to_string(),
        actions: vec![
            format!("pvcreate /dev/{}", target.name),
            format!("vgcreate {vg} /dev/{}", target.name),
            format!("lvcreate -y -l 100%FREE -n data {vg}"),
            format!("mkfs.ext4 /dev/{vg}/data"),
            format!("mount /dev/{vg}/data {}", super::DATA_ROOT),
            format!("add /etc/fstab entry ({vg}/data → {})", super::DATA_ROOT),
        ],
    })
}

/// Name of the logical volume created by [`activate_data_root`].
pub const DATA_LV: &str = "data";

/// fstab line for the dedicated data volume (pure, unit-tested).
pub fn fstab_line(vg: &str) -> String {
    format!(
        "/dev/{vg}/{DATA_LV} {} ext4 defaults,nofail 0 2  # amiterra-data",
        super::DATA_ROOT
    )
}

/// Activate the dedicated data volume: create LV, format, mount at the data
/// root, persist in fstab. Idempotent — converges and reports what changed.
///
/// Runs after [`execute_prepare`]; also used standalone when the VG already
/// exists (re-run / `--all-features` converge path).
pub fn activate_data_root(vg: &str, dry_run: bool) -> Result<Vec<String>> {
    if vg.trim().is_empty() {
        bail!("VG name must not be empty");
    }
    if !dedicated_vg_present(vg) {
        bail!("VG '{vg}' does not exist — run prepare first");
    }
    if !crate::preflight::is_root() {
        bail!("superuser privileges required for storage activation");
    }

    let dev = format!("/dev/{vg}/{DATA_LV}");
    let mountpoint = super::DATA_ROOT;
    let mut done = Vec::new();

    // 1. LV (idempotent).
    let lv_exists = Command::new("lvs")
        .args(["--noheadings", "-o", "lv_name", &format!("{vg}/{DATA_LV}")])
        .output()
        .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false);
    if !lv_exists {
        if dry_run {
            done.push(format!("lvcreate -y -l 100%FREE -n {DATA_LV} {vg}"));
        } else {
            let out = Command::new("lvcreate")
                .args(["-y", "-l", "100%FREE", "-n", DATA_LV, vg])
                .output()
                .context("lvcreate failed to start (install lvm2)")?;
            if !out.status.success() {
                bail!(
                    "lvcreate failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            done.push(format!("LV {vg}/{DATA_LV} created"));
        }
    }

    // 2. Filesystem (only when absent — never overwrite an existing fs).
    if dry_run {
        done.push(format!("mkfs.ext4 {dev} (if unformatted)"));
    } else {
        let has_fs = Command::new("blkid")
            .args(["-o", "value", "-s", "TYPE", &dev])
            .output()
            .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
            .unwrap_or(false);
        if !has_fs {
            let out = Command::new("mkfs.ext4")
                .arg(&dev)
                .output()
                .context("mkfs.ext4 failed to start")?;
            if !out.status.success() {
                bail!(
                    "mkfs.ext4 failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            done.push(format!("ext4 formatted on {dev}"));
        }
    }

    // 3. Mount (idempotent).
    let mounted = std::fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .any(|l| l.split_whitespace().nth(1) == Some(mountpoint));
    if !mounted {
        if dry_run {
            done.push(format!("mount {dev} {mountpoint}"));
        } else {
            std::fs::create_dir_all(mountpoint)
                .with_context(|| format!("failed to create {mountpoint}"))?;
            let out = Command::new("mount")
                .args([&dev, mountpoint])
                .output()
                .context("mount failed to start")?;
            if !out.status.success() {
                bail!(
                    "mount failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            done.push(format!("mounted {dev} at {mountpoint}"));
        }
    }

    // 4. Persist across reboot (idempotent).
    let line = fstab_line(vg);
    let fstab = std::fs::read_to_string("/etc/fstab").unwrap_or_default();
    if !fstab.lines().any(|l| l.trim() == line.trim()) {
        if dry_run {
            done.push("add /etc/fstab entry (amiterra-data)".into());
        } else {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open("/etc/fstab")
                .context("failed to open /etc/fstab")?;
            use std::io::Write;
            writeln!(f, "{line}").context("failed to write /etc/fstab")?;
            done.push("fstab entry added".into());
        }
    }

    Ok(done)
}

/// Live safety checks immediately before `pvcreate` (inventory may be stale).
///
/// Fail-closed: if a checker cannot run (missing tool / unreadable proc file),
/// the prepare aborts — a skipped check must never equal a passed check.
fn assert_device_safe_at_execute(disk: &str) -> Result<()> {
    if disk.starts_with("md") || disk.contains("dm-") {
        bail!("refusing '{disk}' (RAID/dm)");
    }
    if disk.contains('/') || disk.contains("..") || disk.trim().is_empty() {
        bail!("invalid disk name '{disk}'");
    }

    // 1) Not mounted (including by UUID).
    let mounts = std::fs::read_to_string("/proc/mounts")
        .context("cannot read /proc/mounts — refusing to proceed unverified")?;
    let dev = format!("/dev/{disk}");
    for line in mounts.lines() {
        if line.starts_with(&dev) {
            bail!("refusing '{disk}': appears in /proc/mounts");
        }
    }

    // 2) Not a member of an active md RAID.
    let md = std::fs::read_to_string("/proc/mdstat")
        .context("cannot read /proc/mdstat — refusing to proceed unverified")?;
    if md.contains(&format!(" {disk}")) || md.contains(&format!("{disk}[")) {
        bail!("refusing '{disk}': listed in /proc/mdstat");
    }

    // 3) Not an LVM PV already (pvs).
    let pvs = Command::new("pvs")
        .args(["--noheadings", "-o", "pv_name"])
        .output()
        .context("pvs not available (install lvm2)")?;
    if !pvs.status.success() {
        bail!(
            "pvs failed — refusing to proceed unverified: {}",
            String::from_utf8_lossy(&pvs.stderr).trim()
        );
    }
    if String::from_utf8_lossy(&pvs.stdout)
        .lines()
        .any(|l| l.trim().ends_with(disk))
    {
        bail!("refusing '{disk}': already an LVM PV");
    }

    // 4) No existing filesystem/RAID/LVM signature (blkid) — we do NOT wipe.
    let blkid = Command::new("blkid")
        .args(["-o", "value", "-s", "TYPE", &format!("/dev/{disk}")])
        .output()
        .context("blkid not available (install util-linux)")?;
    if !blkid.status.success() {
        // blkid exits non-zero when no signature is present — that is safe.
        // Any other failure (missing device) is already guarded above; treat
        // empty output as "no signature", non-empty as evidence.
    }
    let t = String::from_utf8_lossy(&blkid.stdout).trim().to_string();
    if !t.is_empty() {
        bail!("refusing '{disk}': existing signature type '{t}' (will not wipe)");
    }

    // 5) Partition table check: any child partition under /sys/block/<disk>/.
    let sys = format!("/sys/block/{disk}");
    let entries = std::fs::read_dir(&sys).context(
        "cannot read /sys/block — refusing to proceed unverified (device may not exist)",
    )?;
    for e in entries.flatten() {
        let n = e.file_name().to_string_lossy().to_string();
        if n.starts_with(disk) && n != disk && e.path().join("partition").exists() {
            bail!("refusing '{disk}': has partition {n}");
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

/// Best-effort reverse of prepare (only when the VG exists and has no LVs).
///
/// The VG name is strictly validated: it flows into `vgchange`/`vgremove`
/// argv and must never be parsed as an option or escape LVM's namespace.
/// Reverse of prepare+activate: unmount, drop fstab entry, remove the standard
/// LV, then the VG. Only the volumes we created are touched — a VG carrying any
/// other logical volume is still refused.
pub fn rollback_prepare(vg: &str, yes: bool) -> Result<()> {
    if !yes {
        bail!("rollback requires --yes");
    }
    if !crate::preflight::is_root() {
        bail!("superuser privileges required");
    }
    let name_ok = !vg.is_empty()
        && vg.len() <= 64
        && !vg.starts_with('-')
        && !vg.contains("..")
        && vg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '_' | '.' | '-'));
    if !name_ok {
        bail!("invalid VG name '{vg}'");
    }

    // Only the standard `data` LV (created by activate) may be present; anything
    // else is live state and is never touched.
    let lvs = Command::new("lvs")
        .args(["--noheadings", "-o", "lv_name", vg])
        .output()
        .context("lvs not available (install lvm2)")?;
    if !lvs.status.success() {
        bail!(
            "cannot inspect VG '{vg}' — refusing to remove unverified: {}",
            String::from_utf8_lossy(&lvs.stderr).trim()
        );
    }
    let lv_raw = String::from_utf8_lossy(&lvs.stdout).into_owned();
    let lv_names: Vec<&str> = lv_raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lv_names.iter().any(|l| *l != DATA_LV) {
        bail!(
            "VG '{vg}' has logical volumes other than '{DATA_LV}' — refusing to remove. \
             Delete/backup those LVs first."
        );
    }

    // Unmount our data volume if it is live.
    if lv_names.contains(&DATA_LV) {
        let out = Command::new("umount")
            .arg(super::DATA_ROOT)
            .output()
            .context("umount failed to start")?;
        // ENXBT ("not mounted") is fine — everything else aborts.
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            if !err.contains("not mounted") && !err.contains("no mount point") {
                bail!("umount {} failed: {}", super::DATA_ROOT, err.trim());
            }
        }
        // Drop our fstab marker line (idempotent).
        if let Ok(fstab) = std::fs::read_to_string("/etc/fstab") {
            let kept: Vec<&str> = fstab
                .lines()
                .filter(|l| !l.contains("# amiterra-data"))
                .collect();
            let _ = std::fs::write("/etc/fstab", format!("{}\n", kept.join("\n")));
        }
        let out = Command::new("lvremove")
            .args(["-y", &format!("{vg}/{DATA_LV}")])
            .output()
            .context("lvremove failed to start")?;
        if !out.status.success() {
            bail!(
                "lvremove failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
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

    #[test]
    fn fstab_line_targets_data_root_with_marker() {
        let line = fstab_line("amiterra-data");
        assert!(line.starts_with("/dev/amiterra-data/data "));
        assert!(line.contains(super::super::DATA_ROOT));
        assert!(
            line.contains("# amiterra-data"),
            "rollback needs the marker"
        );
        assert!(line.contains("nofail"), "node must boot without the disk");
    }

    #[test]
    fn activate_rejects_unknown_vg_name() {
        assert!(activate_data_root("", true).is_err());
    }

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
