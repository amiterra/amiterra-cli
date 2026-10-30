//! Universal storage tiers for stateful workloads.
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

pub use classify::{StorageClass, StoragePlanSummary, StorageTier, classify};
pub use inventory::{BlockDevice, RaidSet, StorageInventory};
pub use profile::{NodeStorageProfile, build_node_profile};

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
        r#"# Amiterra Universal Storage
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: {LOCAL_SC_NAME}
  labels:
    app.kubernetes.io/part-of: amiterra
    {LABEL_CLASS}: shared-root
provisioner: rancher.io/local-path
volumeBindingMode: WaitForFirstConsumer
# Retain (not Delete): stateful workloads on this class carry backup-required
# policy — a deleted PVC must not silently wipe the underlying directory.
reclaimPolicy: Retain
parameters:
  path: {data_root}
"#
    )
}

/// Node labels to apply after cluster start (printed + applied via kubectl when possible).
///
/// `storage-policy` is only meaningful on s0
/// (`backup-required`); higher tiers must not carry a policy label.
pub fn node_labels(
    class: &classify::StorageClass,
    tier: &classify::StorageTier,
    policy: &str,
) -> Vec<(&'static str, String)> {
    let mut labels = vec![
        (LABEL_CLASS, class.as_str().to_string()),
        (LABEL_TIER, tier.as_str().to_string()),
    ];
    if *tier == classify::StorageTier::S0 {
        labels.push((LABEL_POLICY, policy.to_string()));
    }
    labels
}

/// Re-classify the host and push fresh tier labels to the node (best-effort).
///
/// Called after `storage prepare`/`activate` and at the end of `ami init`, so a
/// tier change is visible in the same run instead of "on next init".
pub fn refresh_node_labels() {
    let inv = inventory::StorageInventory::probe().unwrap_or_default();
    let summary = classify::classify(&inv);
    let hostname = std::process::Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "localhost".into());
    for (key, val) in node_labels(
        &summary.storage_class,
        &summary.tier,
        &summary.policy_label(),
    ) {
        let arg = format!("{key}={val}");
        let _ = std::process::Command::new("k3s")
            .args(["kubectl", "label", "node", &hostname, &arg, "--overwrite"])
            .output();
    }
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
        let labels = node_labels(
            &StorageClass::SharedRoot,
            &StorageTier::S0,
            "backup-required",
        );
        assert_eq!(labels[0].1, "shared-root");
        assert_eq!(labels[1].1, "s0");
        assert_eq!(labels[2].1, "backup-required");
    }

    #[test]
    fn node_labels_omit_policy_above_s0() {
        let labels = node_labels(&StorageClass::LocalLvm, &StorageTier::S1, "none");
        assert_eq!(labels.len(), 2, "storage-policy is s0-only");
        assert!(labels.iter().all(|(k, _)| *k != LABEL_POLICY));
    }
}
