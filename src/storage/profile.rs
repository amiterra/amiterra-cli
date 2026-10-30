//! Node storage profile — **compact facts for Placement Advisor**.
//!
//! Pure derivation from [`StorageInventory`] / classification.
//! No placement recommendations (commercial Advisor owns those).

use serde::{Deserialize, Serialize};

use super::classify::{StorageClass, StoragePlanSummary, StorageTier};
use super::inventory::StorageInventory;

/// Estimated performance class of the node's storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PerformanceClass {
    P3Hdd,
    P2Ssd,
    P1Nvme,
    P0NvmeRaid,
}

impl PerformanceClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            PerformanceClass::P3Hdd => "p3-hdd",
            PerformanceClass::P2Ssd => "p2-ssd",
            PerformanceClass::P1Nvme => "p1-nvme",
            PerformanceClass::P0NvmeRaid => "p0-nvme-raid",
        }
    }

    pub fn score(&self) -> u8 {
        match self {
            PerformanceClass::P3Hdd => 1,
            PerformanceClass::P2Ssd => 2,
            PerformanceClass::P1Nvme => 3,
            PerformanceClass::P0NvmeRaid => 4,
        }
    }
}

/// Redundancy of the storage that holds stateful data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Redundancy {
    None,
    Mirror,
    Parity,
}

impl Redundancy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Redundancy::None => "none",
            Redundancy::Mirror => "mirror",
            Redundancy::Parity => "parity",
        }
    }
}

/// Isolation of stateful volumes from the OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Isolation {
    SharedRoot,
    DedicatedVolume,
    DedicatedDisk,
}

impl Isolation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Isolation::SharedRoot => "shared-root",
            Isolation::DedicatedVolume => "dedicated-volume",
            Isolation::DedicatedDisk => "dedicated-disk",
        }
    }
}

/// Capacity of the volume that will hold stateful data (bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CapacityProfile {
    /// Device/array that backs the data path (usually system root on s0).
    pub root_device: Option<String>,
    pub root_fs: Option<String>,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    /// Conservative budget for stateful data (60% of free on shared-root).
    pub stateful_budget_bytes: Option<u64>,
}

/// One software-RAID set relevant to placement (no partition spam).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaidSummary {
    pub name: String,
    pub level: String,
    pub member_count: usize,
    /// root | boot | swap | other
    pub used_for: String,
}

/// Compact node profile — sufficient to score PG/CH/Redis placement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStorageProfile {
    pub isolation: Isolation,
    pub redundancy: Redundancy,
    pub performance_class: PerformanceClass,
    /// Distinct physical media classes seen (e.g. ["nvme"]).
    pub media_classes: Vec<String>,
    pub capacity: CapacityProfile,
    pub raid_summary: Vec<RaidSummary>,
    /// Whole disks safe for `ami storage prepare` (upgrade path).
    pub free_disks: Vec<String>,
}

const SHARED_ROOT_STATEFUL_BUDGET_RATIO: u64 = 60; // percent of free

/// Build node profile from inventory + tier classification (pure).
pub fn build_node_profile(
    inv: &StorageInventory,
    summary: &StoragePlanSummary,
) -> NodeStorageProfile {
    let empty = NodeStorageProfile {
        isolation: Isolation::SharedRoot,
        redundancy: Redundancy::None,
        performance_class: PerformanceClass::P3Hdd,
        media_classes: Vec::new(),
        capacity: CapacityProfile::default(),
        raid_summary: Vec::new(),
        free_disks: Vec::new(),
    };
    if !inv.probe_ok || inv.unique_devices().is_empty() {
        return empty;
    }

    let root = inv.root_devices().into_iter().next();
    let capacity = CapacityProfile {
        root_device: root.map(|r| r.name.clone()),
        root_fs: root.and_then(|r| r.fstype.clone()),
        total_bytes: root.and_then(|r| r.size_bytes),
        free_bytes: root.and_then(|r| r.fsavail_bytes),
        stateful_budget_bytes: match (summary.tier, root.and_then(|r| r.fsavail_bytes)) {
            (StorageTier::S0, Some(free)) => Some(free * SHARED_ROOT_STATEFUL_BUDGET_RATIO / 100),
            (_, Some(free)) => Some(free),
            (_, None) => None,
        },
    };

    // Redundancy: prefer RAID level of the root/data volume.
    let mut redundancy = Redundancy::None;
    let mut raid_summary = Vec::new();
    for rs in inv.raid_sets() {
        let used_for = if rs.mountpoints.iter().any(|m| m == "/") {
            "root"
        } else if rs.mountpoints.iter().any(|m| m == "/boot") {
            "boot"
        } else if rs.is_swap_mount() {
            "swap"
        } else {
            "other"
        };
        let level = rs.level.to_ascii_lowercase();
        if used_for == "root" {
            if level.contains("raid10") || level.contains("raid1") {
                redundancy = Redundancy::Mirror;
            } else if level.contains("raid5") || level.contains("raid6") {
                redundancy = Redundancy::Parity;
            } else if level.contains("raid0") {
                redundancy = Redundancy::None;
            }
        }
        if used_for != "swap" {
            raid_summary.push(RaidSummary {
                name: rs.name.clone(),
                level: rs.level.clone(),
                member_count: rs.members.len(),
                used_for: used_for.into(),
            });
        }
    }

    // Media classes: physical disks + raid members feeding root.
    let mut media: Vec<String> = Vec::new();
    for d in inv.unique_devices() {
        let relevant = d.is_mounted_at_root()
            || d.is_raid_or_md()
            || d.is_unmounted_disk()
            || d.fstype.as_deref() == Some("linux_raid_member");
        if !relevant {
            continue;
        }
        let m = d.media_class();
        if m == "raid" || m == "unknown" {
            continue;
        }
        if !media.iter().any(|x| x == m) {
            media.push(m.to_string());
        }
    }
    media.sort();

    let free_disks: Vec<String> = inv.free_disks().iter().map(|d| d.name.clone()).collect();
    let performance_class = derive_performance(&media, redundancy);

    NodeStorageProfile {
        isolation: match summary.storage_class {
            StorageClass::SharedRoot => Isolation::SharedRoot,
            StorageClass::LocalLvm => Isolation::DedicatedVolume,
            StorageClass::NvmeTopolvm => Isolation::DedicatedDisk,
        },
        redundancy,
        performance_class,
        media_classes: media,
        capacity,
        raid_summary,
        free_disks,
    }
}

fn derive_performance(media: &[String], redundancy: Redundancy) -> PerformanceClass {
    let has_nvme = media.iter().any(|m| m == "nvme");
    let has_ssd = media.iter().any(|m| m == "ssd");
    let has_hdd = media.iter().any(|m| m == "hdd");
    if has_nvme && matches!(redundancy, Redundancy::Mirror | Redundancy::Parity) {
        PerformanceClass::P0NvmeRaid
    } else if has_nvme {
        PerformanceClass::P1Nvme
    } else if has_ssd {
        PerformanceClass::P2Ssd
    } else {
        let _ = has_hdd;
        PerformanceClass::P3Hdd
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::classify::classify;
    use crate::storage::inventory::{BlockDevice, StorageInventory};

    fn dual_nvme_raid1() -> StorageInventory {
        let md = BlockDevice {
            name: "md2".into(),
            kind: "raid1".into(),
            size_bytes: Some(469_123_456_000),
            fsused_bytes: Some(3_400_000_000),
            fsavail_bytes: Some(411_000_000_000),
            fstype: Some("ext4".into()),
            mountpoints: vec!["/".into()],
            ..Default::default()
        };
        let p0 = BlockDevice {
            name: "nvme0n1p4".into(),
            kind: "part".into(),
            fstype: Some("linux_raid_member".into()),
            children: vec![md.clone()],
            ..Default::default()
        };
        let p1 = BlockDevice {
            name: "nvme1n1p4".into(),
            kind: "part".into(),
            fstype: Some("linux_raid_member".into()),
            children: vec![md],
            ..Default::default()
        };
        let mut d0 = BlockDevice {
            name: "nvme0n1".into(),
            kind: "disk".into(),
            rota: Some(false),
            ..Default::default()
        };
        d0.children = vec![p0];
        let mut d1 = BlockDevice {
            name: "nvme1n1".into(),
            kind: "disk".into(),
            rota: Some(false),
            ..Default::default()
        };
        d1.children = vec![p1];
        StorageInventory::from_devices(vec![d0, d1])
    }

    #[test]
    fn dual_nvme_raid1_compact_profile() {
        let inv = dual_nvme_raid1();
        let summary = classify(&inv);
        let p = build_node_profile(&inv, &summary);
        assert_eq!(p.isolation, Isolation::SharedRoot);
        assert_eq!(p.redundancy, Redundancy::Mirror);
        assert_eq!(p.performance_class, PerformanceClass::P0NvmeRaid);
        assert_eq!(p.media_classes, vec!["nvme".to_string()]);
        assert_eq!(p.capacity.root_device.as_deref(), Some("md2"));
        assert_eq!(p.capacity.root_fs.as_deref(), Some("ext4"));
        assert!(p.capacity.stateful_budget_bytes.is_some());
        assert_eq!(p.raid_summary.len(), 1);
        assert_eq!(p.raid_summary[0].used_for, "root");
        assert_eq!(p.raid_summary[0].member_count, 2);
        assert!(p.free_disks.is_empty());
    }

    #[test]
    fn hdd_single_disk_profile() {
        let d = BlockDevice {
            name: "sda".into(),
            kind: "disk".into(),
            fstype: Some("ext4".into()),
            mountpoints: vec!["/".into()],
            rota: Some(true),
            size_bytes: Some(1024 * 1024 * 1024 * 1024),
            fsavail_bytes: Some(500 * 1024 * 1024 * 1024),
            ..Default::default()
        };
        let inv = StorageInventory::from_devices(vec![d]);
        let summary = classify(&inv);
        let p = build_node_profile(&inv, &summary);
        assert_eq!(p.performance_class, PerformanceClass::P3Hdd);
        assert_eq!(p.redundancy, Redundancy::None);
        assert_eq!(p.media_classes, vec!["hdd".to_string()]);
    }

    #[test]
    fn unknown_probe_yields_empty_compact_profile() {
        let inv = StorageInventory {
            probe_ok: false,
            ..Default::default()
        };
        let summary = classify(&inv);
        let p = build_node_profile(&inv, &summary);
        assert!(p.capacity.total_bytes.is_none());
        assert!(p.raid_summary.is_empty());
    }

    #[test]
    fn raid_summary_skips_swap() {
        let md_swap = BlockDevice {
            name: "md0".into(),
            kind: "raid1".into(),
            mountpoints: vec!["[SWAP]".into()],
            fstype: Some("swap".into()),
            ..Default::default()
        };
        let inv = StorageInventory::from_devices(vec![md_swap]);
        let summary = classify(&inv);
        let p = build_node_profile(&inv, &summary);
        assert!(p.raid_summary.is_empty());
    }
}
