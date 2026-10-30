//! Pure storage tier classification.
//!
//! Input: [`StorageInventory`]. Output: tier + class + policy.
//! No syscalls — fully unit-testable.

use serde::{Deserialize, Serialize};

use super::inventory::StorageInventory;

/// Reliability/performance tier of the node's storage for stateful workloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageTier {
    /// Shared root / system RAID — best-effort, backup required.
    S0,
    /// Dedicated LVM VG on a non-system disk.
    S1,
    /// NVMe data path ready for TopoLVM (target production).
    S2,
}

impl StorageTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            StorageTier::S0 => "s0",
            StorageTier::S1 => "s1",
            StorageTier::S2 => "s2",
        }
    }

    pub fn min_for_stateful_ha(&self) -> bool {
        matches!(self, StorageTier::S1 | StorageTier::S2)
    }
}

/// Storage class label value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageClass {
    SharedRoot,
    LocalLvm,
    NvmeTopolvm,
}

impl StorageClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            StorageClass::SharedRoot => "shared-root",
            StorageClass::LocalLvm => "local-lvm",
            StorageClass::NvmeTopolvm => "nvme-topolvm",
        }
    }
}

/// Classified node storage summary (Phase A card + labels).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoragePlanSummary {
    pub tier: StorageTier,
    pub storage_class: StorageClass,
    pub policies: Vec<String>,
    pub free_disk_names: Vec<String>,
    pub root_disk_names: Vec<String>,
    pub notes: Vec<String>,
}

impl StoragePlanSummary {
    pub fn policy_label(&self) -> String {
        if self.policies.is_empty() {
            "none".to_string()
        } else {
            self.policies.join(",")
        }
    }
}

/// Derive tier/class/policy from inventory (pure).
///
/// Classification rules:
/// 1. Free whole-disk → at least S1 path (prepare available); if any free disk
///    is non-rotational we still need `prepare` first → classify as S0 with
///    note `upgrade-ready` unless a dedicated data root already exists.
/// 2. Root-only / system RAID → S0 shared-root + `backup-required`.
/// 3. Probe failure → S0 conservative + note.
///
/// Phase A does not detect TopoLVM yet (S2 is reserved for NVMe + provisioner).
pub fn classify(inv: &StorageInventory) -> StoragePlanSummary {
    let mut notes = Vec::new();

    if !inv.probe_ok {
        notes.push("storage probe incomplete; using conservative shared-root tier".into());
    }

    let free: Vec<String> = inv.free_disks().iter().map(|d| d.name.clone()).collect();
    let roots: Vec<String> = inv.root_devices().iter().map(|d| d.name.clone()).collect();

    // Heuristic: dedicated data already in use if something other than root is
    // mounted under /var/lib/amiterra/data (Phase C refine).
    let data_root_used = inv.walk().iter().any(|d| {
        d.mountpoints
            .iter()
            .any(|m| m.starts_with("/var/lib/amiterra/data") && m != "/")
    });

    if data_root_used {
        notes.push("dedicated mount detected under data root".into());
        return StoragePlanSummary {
            tier: StorageTier::S1,
            storage_class: StorageClass::LocalLvm,
            policies: vec![],
            free_disk_names: free,
            root_disk_names: roots,
            notes,
        };
    }

    if !free.is_empty() {
        notes.push(format!(
            "unallocated disk(s) available: {} — run `ami storage prepare` to reach tier s1",
            free.join(", ")
        ));
    }

    // Default universal case: stateful lives on shared root (system RAID / single FS).
    notes.push("stateful volumes share the root filesystem (no IOPS isolation)".into());

    StoragePlanSummary {
        tier: StorageTier::S0,
        storage_class: StorageClass::SharedRoot,
        policies: vec!["backup-required".into()],
        free_disk_names: free,
        root_disk_names: roots,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::inventory::{BlockDevice, StorageInventory};

    fn raid_root_only() -> StorageInventory {
        let mut p4 = BlockDevice {
            name: "nvme0n1p4".into(),
            kind: "part".into(),
            fstype: Some("ext4".into()),
            mountpoints: vec!["/".into()],
            ..Default::default()
        };
        let mut disk = BlockDevice {
            name: "nvme0n1".into(),
            kind: "disk".into(),
            ..Default::default()
        };
        disk.children.push(p4.clone());
        p4.name = "nvme1n1p4".into();
        disk.children.push(p4);
        StorageInventory::from_devices(vec![disk])
    }

    fn root_plus_free_disk() -> StorageInventory {
        let mut sys = BlockDevice {
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
        };
        sys.children = sys.children.clone();
        let free = BlockDevice {
            name: "nvme2n1".into(),
            kind: "disk".into(),
            ..Default::default()
        };
        StorageInventory::from_devices(vec![sys, free])
    }

    #[test]
    fn system_raid_only_is_s0_with_backup_policy() {
        let s = classify(&raid_root_only());
        assert_eq!(s.tier, StorageTier::S0);
        assert_eq!(s.storage_class, StorageClass::SharedRoot);
        assert!(s.policies.iter().any(|p| p == "backup-required"));
        assert_eq!(s.policy_label(), "backup-required");
    }

    #[test]
    fn free_disk_keeps_s0_until_prepare_but_notes_upgrade() {
        let s = classify(&root_plus_free_disk());
        assert_eq!(s.tier, StorageTier::S0);
        assert_eq!(s.free_disk_names, vec!["nvme2n1"]);
        assert!(s.notes.iter().any(|n| n.contains("storage prepare")));
    }

    #[test]
    fn empty_inventory_is_conservative_s0() {
        let s = classify(&StorageInventory::from_devices(vec![]));
        assert_eq!(s.tier, StorageTier::S0);
    }

    #[test]
    fn probe_failure_is_s0_with_note() {
        let inv = StorageInventory {
            probe_ok: false,
            ..Default::default()
        };
        let s = classify(&inv);
        assert_eq!(s.tier, StorageTier::S0);
        assert!(s.notes.iter().any(|n| n.contains("conservative")));
    }

    #[test]
    fn tier_strings_are_stable_for_labels() {
        assert_eq!(StorageTier::S0.as_str(), "s0");
        assert_eq!(StorageClass::SharedRoot.as_str(), "shared-root");
        assert!(!StorageTier::S0.min_for_stateful_ha());
        assert!(StorageTier::S1.min_for_stateful_ha());
    }
}
