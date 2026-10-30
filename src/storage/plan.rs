//! Machine-readable storage plan — **data-only**, compact for Placement Advisor.
//!
//! Default JSON is a slim contract (`node_profile` + policy/constraints).
//! Full device/RAID dump is available only with `--full` (prepare/debug).

use serde::{Deserialize, Serialize};

use super::classify::{StoragePlanSummary, StorageTier};
use super::inventory::{RaidSet, StorageInventory};
use super::profile::{NodeStorageProfile, build_node_profile};
use super::{DATA_ROOT, LOCAL_SC_NAME};

/// Stable JSON payload for Placement Advisor / UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoragePlanDocument {
    pub tier: String,
    pub storage_class: String,
    pub policy: Vec<String>,
    pub data_root: String,
    pub local_storage_class: String,
    /// Compact facts sufficient for service placement scoring.
    pub node_profile: NodeStorageProfile,
    /// Machine-readable safety constraints (IDs, not prose).
    /// names this field `forbidden`.
    pub forbidden: Vec<String>,
    /// Hardware to order for better tiers (Order Guide).
    pub order_guide: Vec<String>,
    /// Steps to improve this node's tier (Improve Guide).
    pub improve_guide: Vec<String>,
    /// Full inventory (devices + raid_sets) — only when `full` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory: Option<InventoryDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InventoryDto {
    pub block_device_count: usize,
    pub root_devices: Vec<String>,
    pub usable_free_disks: Vec<String>,
    pub probe_ok: bool,
    pub devices: Vec<DeviceDto>,
    pub raid_sets: Vec<RaidSet>,
}

/// Flattened device record (debug/prepare; not required for placement).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DeviceDto {
    pub name: String,
    pub kind: String,
    pub size_bytes: Option<u64>,
    pub fsused_bytes: Option<u64>,
    pub fsavail_bytes: Option<u64>,
    pub fstype: Option<String>,
    pub mountpoints: Vec<String>,
    pub media: String,
    pub rotational: bool,
    pub role: String,
}

impl DeviceDto {
    fn from_dev(d: &super::inventory::BlockDevice) -> Self {
        let role = if d.is_mounted_at_root() {
            "system-root"
        } else if d.is_raid_or_md() {
            "raid-set"
        } else if d.is_unmounted_disk() {
            "unallocated"
        } else if d.fstype.as_deref() == Some("linux_raid_member") {
            "raid-member"
        } else {
            "other"
        };
        Self {
            name: d.name.clone(),
            kind: d.kind.clone(),
            size_bytes: d.size_bytes,
            fsused_bytes: d.fsused_bytes,
            fsavail_bytes: d.fsavail_bytes,
            fstype: d.fstype.clone(),
            mountpoints: d.mountpoints.clone(),
            media: d.media_class().to_string(),
            rotational: d.is_rotational(),
            role: role.to_string(),
        }
    }
}

/// Safety constraint IDs (no prose — Advisor owns recommendations).
pub const CONSTRAINTS: &[&str] = &[
    "do-not-shrink-system-raid",
    "do-not-repartition-live-root",
    "do-not-create-loop-lvm-on-root-file",
];

/// Order Guide: hardware to order, derived from tier facts.
fn order_guide(summary: &StoragePlanSummary) -> Vec<String> {
    let mut g = Vec::new();
    if summary.tier == StorageTier::S0 {
        g.push("order a dedicated data disk (NVMe preferred, SSD acceptable) for tier s1".into());
        g.push("order hardware RAID1 or an md-mirror if stateful redundancy is required".into());
    }
    g.push("NVMe data disks enable tier s2 (TopoLVM)".into());
    g
}

/// Improve Guide: concrete next steps for this node.
fn improve_guide(summary: &StoragePlanSummary) -> Vec<String> {
    let mut g = Vec::new();
    if let Some(first) = summary.free_disk_names.first() {
        g.push(format!(
            "run `ami storage prepare --disk {first}` to open the s1 path"
        ));
    } else if summary.tier == StorageTier::S0 {
        g.push("add a data disk, then run `ami storage prepare` to reach s1".into());
    }
    if summary.tier == StorageTier::S0 {
        g.push("stateful workloads on s0 carry backup-required policy".into());
    }
    g.push("verify each step with `ami storage status`".into());
    g
}

/// Build plan document. `full=true` attaches detailed inventory.
pub fn build_plan(
    inv: &StorageInventory,
    summary: &StoragePlanSummary,
    full: bool,
) -> StoragePlanDocument {
    let inventory = if full {
        let devices: Vec<DeviceDto> = inv
            .unique_devices()
            .iter()
            .map(|d| DeviceDto::from_dev(d))
            .collect();
        Some(InventoryDto {
            block_device_count: devices.len(),
            root_devices: inv.root_devices().iter().map(|d| d.name.clone()).collect(),
            usable_free_disks: summary.free_disk_names.clone(),
            probe_ok: inv.probe_ok,
            devices,
            raid_sets: inv.raid_sets(),
        })
    } else {
        None
    };

    StoragePlanDocument {
        tier: summary.tier.as_str().to_string(),
        storage_class: summary.storage_class.as_str().to_string(),
        policy: summary.policies.clone(),
        data_root: DATA_ROOT.to_string(),
        local_storage_class: LOCAL_SC_NAME.to_string(),
        node_profile: build_node_profile(inv, summary),
        forbidden: CONSTRAINTS.iter().map(|s| s.to_string()).collect(),
        order_guide: order_guide(summary),
        improve_guide: improve_guide(summary),
        inventory,
    }
}

/// JSON string for APIs (slim unless `full`).
pub fn plan_json(inv: &StorageInventory, summary: &StoragePlanSummary, full: bool) -> String {
    let doc = build_plan(inv, summary, full);
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into())
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
    fn slim_plan_omits_inventory_but_carries_contract_fields() {
        let inv = dual_nvme_raid1();
        let summary = classify(&inv);
        let plan = build_plan(&inv, &summary, false);
        let json = serde_json::to_string_pretty(&plan).unwrap();
        assert!(plan.inventory.is_none());
        assert!(!json.contains("\"inventory\""));
        assert!(!json.contains("placement_hints"));
        assert!(!json.contains("devices"));
        // Stable schema carries forbidden + guides.
        assert!(json.contains("\"forbidden\""));
        assert!(json.contains("do-not-shrink-system-raid"));
        assert!(json.contains("\"order_guide\""));
        assert!(json.contains("\"improve_guide\""));
        assert!(json.contains("node_profile"));
        assert!(json.contains("raid_summary"));
    }

    #[test]
    fn full_plan_includes_devices_and_raid_sets() {
        let inv = dual_nvme_raid1();
        let summary = classify(&inv);
        let plan = build_plan(&inv, &summary, true);
        let invdto = plan.inventory.expect("full plan has inventory");
        assert_eq!(invdto.root_devices, vec!["md2".to_string()]);
        assert_eq!(invdto.raid_sets.len(), 1);
        assert!(!invdto.devices.is_empty());
    }

    #[test]
    fn slim_profile_is_self_contained_for_placement() {
        let inv = dual_nvme_raid1();
        let summary = classify(&inv);
        let plan = build_plan(&inv, &summary, false);
        let p = &plan.node_profile;
        assert_eq!(p.capacity.root_device.as_deref(), Some("md2"));
        assert!(p.capacity.stateful_budget_bytes.is_some());
        assert_eq!(p.redundancy, crate::storage::profile::Redundancy::Mirror);
        assert!(!p.media_classes.is_empty());
        assert_eq!(plan.tier, "s0");
        assert!(plan.policy.iter().any(|x| x == "backup-required"));
    }
}
