//! Persistent GitOps bootstrap state.
//!
//! Records what converge produced so `ami gitops status` can report and so the
//! next converge run can diff desired vs actual without guessing. Never stores
//! key material — fingerprints only.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// State file for the GitOps bootstrap.
pub const STATE_PATH: &str = "/var/lib/amiterra/gitops/state.yaml";

/// Snapshot of the converged bootstrap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitopsState {
    /// Provider kind string (see `GitProviderKind`).
    pub provider: String,
    /// Unified SSH remote URL.
    pub remote_url: String,
    /// Tracked branch.
    pub branch: String,
    /// Path inside the repo synced by the root Kustomization.
    pub path_in_repo: String,
    /// Cluster id (folder name under `clusters/`).
    pub cluster_id: String,
    /// Pinned Flux version installed from vendored manifests.
    pub flux_version: String,
    /// SHA256 fingerprint of the deploy key (never the key itself).
    pub key_fingerprint: String,
    /// sha of the seed commit, when one was made.
    pub seed_sha: Option<String>,
    /// Content hash of the seed tree (idempotency marker for converge).
    pub seed_tree_hash: String,
    /// RFC3339 UTC timestamp of the last successful converge.
    pub converged_at: String,
}

impl GitopsState {
    pub fn load(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let state: Self =
            serde_yaml::from_str(&raw).context("failed to parse gitops state YAML")?;
        Ok(Some(state))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let yaml = serde_yaml::to_string(self).context("failed to serialize gitops state")?;
        // Atomic replace: a crash mid-write must never leave a torn state.yaml
        // (status() hard-errors on unparsable state).
        let tmp = path.with_extension("yaml.tmp");
        fs::write(&tmp, yaml).with_context(|| format!("failed to write {}", tmp.display()))?;
        fs::rename(&tmp, path).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }

    /// Default production state path.
    pub fn default_path() -> PathBuf {
        PathBuf::from(STATE_PATH)
    }
}

/// Current UTC timestamp in RFC3339 (second precision).
pub fn now_rfc3339() -> String {
    // Avoid a chrono dependency: format from SystemTime.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Civil-from-days conversion (Howard Hinnant's algorithm).
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GitopsState {
        GitopsState {
            provider: "local-bare".into(),
            remote_url: "ssh://git@10.0.0.5/srv/git/infra.git".into(),
            branch: "main".into(),
            path_in_repo: "clusters/c0".into(),
            cluster_id: "c0".into(),
            flux_version: "2.10.0".into(),
            key_fingerprint: "SHA256:abc".into(),
            seed_sha: Some("deadbeef".into()),
            seed_tree_hash: "cafe".into(),
            converged_at: "2026-10-29T00:00:00Z".into(),
        }
    }

    #[test]
    fn state_roundtrips_through_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.yaml");
        sample().save(&path).unwrap();
        let loaded = GitopsState::load(&path).unwrap().unwrap();
        assert_eq!(loaded, sample());
    }

    #[test]
    fn load_missing_state_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            GitopsState::load(&dir.path().join("nope.yaml"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn state_never_carries_key_material_field() {
        let yaml = serde_yaml::to_string(&sample()).unwrap();
        assert!(yaml.contains("key_fingerprint"));
        assert!(!yaml.contains("private"));
    }

    #[test]
    fn now_rfc3339_has_valid_shape() {
        let t = now_rfc3339();
        assert_eq!(t.len(), 20);
        assert!(t.ends_with('Z'));
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[10..11], "T");
    }
}
