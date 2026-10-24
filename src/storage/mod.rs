//! Universal storage tiers for stateful workloads (Design Doc 0019).
//!
//! Layers:
//! - [`inventory`] — read-only host probe (block devices, LVM, mounts).
//! - [`classify`] — pure tier/class derivation (unit-testable).
//! - [`plan`] — Order/Improve guides + JSON for placement Advisor.
//! - [`prepare`] — opt-in VG creation (Phase C).
//!
//! Safety: no partitioning, no system-RAID mutation. Mutations are opt-in only.

pub mod classify;
pub mod cli;
pub mod inventory;
pub mod plan;
pub mod prepare;
pub mod profile;

pub use classify::{classify, StorageClass, StoragePlanSummary, StorageTier};
pub use inventory::{BlockDevice, RaidSet, StorageInventory};
pub use profile::{build_node_profile, NodeStorageProfile};

/// Data root convention for all stateful volumes (stable across tier upgrades).
pub const DATA_ROOT: &str = "/var/lib/amiterra/data";

/// StorageClass name contract for passports (stable across provisioner swap).
pub const LOCAL_SC_NAME: &str = "amiterra-local";

/// Node label: storage class (shared-root | local-lvm | nvme-topolvm).
pub const LABEL_CLASS: &str = "amiterra.io/storage-class";
/// Node label: storage tier (s0 | s1 | s2).
pub const LABEL_TIER: &str = "amiterra.io/storage-tier";
/// Node label: policy flags (e.g. backup-required).
pub const LABEL_POLICY: &str = "amiterra.io/storage-policy";

/// Subdirectories created under [`DATA_ROOT`].
pub const DATA_SUBDIRS: &[&str] = &["postgres", "clickhouse", "redis", "scratch"];

/// Ensure the universal data root layout exists (Phase A, safe mkdir).
pub fn ensure_data_root(root: &std::path::Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut created = Vec::new();
    for sub in DATA_SUBDIRS {
        let p = root.join(sub);
        if !p.exists() {
            std::fs::create_dir_all(&p)?;
            created.push(p);
        }
    }
    Ok(created)
}

/// StorageClass manifest for K3s auto-deploy (`/var/lib/rancher/k3s/server/manifests`).
/// Name is the stable passport contract [`LOCAL_SC_NAME`]; provisioner is local-path
/// compatible (WaitForFirstConsumer) so tier upgrades can swap internals later.
pub fn local_storageclass_yaml(data_root: &str) -> String {
    format!(
        r#"# Amiterra Universal Storage (Design 0019)
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: {LOCAL_SC_NAME}
  labels:
    app.kubernetes.io/part-of: amiterra
    {LABEL_CLASS}: shared-root
provisioner: rancher.io/local-path
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Delete
parameters:
  path: {data_root}
"#
    )
}

/// Node labels to apply after cluster start (printed + applied via kubectl when possible).
pub fn node_labels(class: &classify::StorageClass, tier: &classify::StorageTier, policy: &str) -> Vec<(&'static str, String)> {
    vec![
        (LABEL_CLASS, class.as_str().to_string()),
        (LABEL_TIER, tier.as_str().to_string()),
        (LABEL_POLICY, policy.to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::classify::{StorageClass, StorageTier};

    #[test]
    fn storageclass_yaml_contains_contract_names() {
        let y = local_storageclass_yaml("/var/lib/amiterra/data");
        assert!(y.contains("name: amiterra-local"));
        assert!(y.contains("path: /var/lib/amiterra/data"));
        assert!(y.contains("WaitForFirstConsumer"));
    }

    #[test]
    fn ensure_data_root_creates_layout() {
        let dir = std::env::temp_dir().join("amiterra-storage-test-root");
        let _ = std::fs::remove_dir_all(&dir);
        let created = ensure_data_root(&dir).unwrap();
        assert!(created.len() >= 4);
        assert!(dir.join("postgres").is_dir());
        assert!(dir.join("scratch").is_dir());
        // idempotent
        assert!(ensure_data_root(&dir).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_labels_stable() {
        let labels = node_labels(&StorageClass::SharedRoot, &StorageTier::S0, "backup-required");
        assert_eq!(labels[0].1, "shared-root");
        assert_eq!(labels[1].1, "s0");
        assert_eq!(labels[2].1, "backup-required");
    }
}
