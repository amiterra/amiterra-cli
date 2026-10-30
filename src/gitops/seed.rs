//! Seed tree of the infrastructure layer.
//!
//! Pure render functions only — no filesystem or `git` side effects here — so
//! the whole tree can be unit-tested and content-hashed for idempotent converge.
//! Commit/push lives in [`super::local_bare`] behind `git` CLI.

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

use super::provider::RepoSpec;

/// Repository-relative path → file content. BTreeMap keeps a canonical order
/// for hashing and for deterministic commits.
pub type SeedTree = BTreeMap<PathBuf, String>;

/// Content hash of a seed tree (sha256 over path + content, canonical order).
pub fn tree_hash(tree: &SeedTree) -> String {
    let mut hasher = Sha256::new();
    for (path, content) in tree {
        hasher.update(path.to_string_lossy().as_bytes());
        hasher.update(b"\0");
        hasher.update(content.as_bytes());
        hasher.update(b"\0");
    }
    to_hex(&hasher.finalize())
}

/// Hex-encode digest output (sha2 0.11 `Array` has no `LowerHex`).
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Render the full seed tree for `spec`.
///
/// Layout (0020 §3.2, poc-compatible):
/// ```text
/// clusters/<id>/
///   flux-system/{kustomization.yaml, gotk-sync.yaml}
///   infrastructure/kustomization.yaml
///   apps/kustomization.yaml
/// catalog/.gitkeep
/// ```
pub fn render_seed_tree(spec: &RepoSpec, remote_url: &str) -> SeedTree {
    let mut tree = SeedTree::new();
    let root = PathBuf::from("clusters").join(&spec.cluster_id);

    tree.insert(root.join("kustomization.yaml"), render_root_kustomization());
    tree.insert(
        root.join("flux-system/kustomization.yaml"),
        render_flux_system_kustomization(),
    );
    tree.insert(
        root.join("flux-system/gotk-sync.yaml"),
        render_gotk_sync(remote_url, &spec.branch, &spec.path_in_repo),
    );
    tree.insert(
        root.join("infrastructure/kustomization.yaml"),
        render_empty_layer("infrastructure"),
    );
    tree.insert(
        root.join("apps/kustomization.yaml"),
        render_empty_layer("apps"),
    );
    tree.insert(PathBuf::from("catalog/.gitkeep"), String::new());
    tree
}

/// Root kustomization delegating to the three layers.
fn render_root_kustomization() -> String {
    let mut s = String::new();
    s.push_str(
        "# Root entrypoint for this cluster. Layer order: flux-system → infrastructure → apps.\n",
    );
    s.push_str("apiVersion: kustomize.config.k8s.io/v1beta1\n");
    s.push_str("kind: Kustomization\n");
    s.push_str("resources:\n");
    s.push_str("  - flux-system\n");
    s.push_str("  - infrastructure\n");
    s.push_str("  - apps\n");
    s
}

fn render_flux_system_kustomization() -> String {
    let mut s = String::new();
    s.push_str("apiVersion: kustomize.config.k8s.io/v1beta1\n");
    s.push_str("kind: Kustomization\n");
    s.push_str("resources:\n");
    s.push_str("  - gotk-sync.yaml\n");
    s
}

/// Empty layer placeholder (`infrastructure`, `apps`) filled in by later steps.
fn render_empty_layer(name: &str) -> String {
    format!(
        "# {name} layer — populated by later roadmap steps.\n\
         apiVersion: kustomize.config.k8s.io/v1beta1\n\
         kind: Kustomization\n\
         resources: []\n"
    )
}

/// `gotk-sync.yaml`: GitRepository + root Kustomization, in-repo self-manage.
/// After the first Flux sync the repo owns these objects; the
/// CLI only applies them when missing or drifted.
fn render_gotk_sync(remote_url: &str, branch: &str, path_in_repo: &str) -> String {
    let mut s = String::new();
    s.push_str("# Flux sync objects (self-managed: Flux reconciles these from this repo).\n");
    s.push_str("apiVersion: source.toolkit.fluxcd.io/v1\n");
    s.push_str("kind: GitRepository\n");
    s.push_str("metadata:\n");
    s.push_str("  name: flux-system\n");
    s.push_str("  namespace: flux-system\n");
    s.push_str("spec:\n");
    s.push_str("  interval: 1m0s\n");
    s.push_str("  ref:\n");
    s.push_str(&format!("    branch: {branch}\n"));
    s.push_str(&format!("  url: {remote_url}\n"));
    s.push_str("  secretRef:\n");
    s.push_str("    name: flux-system\n");
    s.push_str("---\n");
    s.push_str("apiVersion: kustomize.toolkit.fluxcd.io/v1\n");
    s.push_str("kind: Kustomization\n");
    s.push_str("metadata:\n");
    s.push_str("  name: flux-system\n");
    s.push_str("  namespace: flux-system\n");
    s.push_str("spec:\n");
    s.push_str("  interval: 10m0s\n");
    s.push_str(&format!("  path: ./{path_in_repo}\n"));
    s.push_str("  prune: true\n");
    s.push_str("  sourceRef:\n");
    s.push_str("    kind: GitRepository\n");
    s.push_str("    name: flux-system\n");
    s.push_str("  timeout: 5m0s\n");
    s
}

/// Write the tree to a directory (used for the git worktree before commit).
pub fn write_tree_to(tree: &SeedTree, dir: &std::path::Path) -> Result<()> {
    for (rel, content) in tree {
        let abs = dir.join(rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&abs, content)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> RepoSpec {
        RepoSpec {
            branch: "main".into(),
            path_in_repo: "clusters/c0".into(),
            cluster_id: "c0".into(),
        }
    }

    #[test]
    fn seed_tree_has_expected_layout() {
        let tree = render_seed_tree(&spec(), "ssh://git@10.0.0.5/srv/git/infra.git");
        let paths: Vec<_> = tree
            .keys()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            paths,
            vec![
                "catalog/.gitkeep",
                "clusters/c0/apps/kustomization.yaml",
                "clusters/c0/flux-system/gotk-sync.yaml",
                "clusters/c0/flux-system/kustomization.yaml",
                "clusters/c0/infrastructure/kustomization.yaml",
                "clusters/c0/kustomization.yaml",
            ]
        );
    }

    #[test]
    fn gotk_sync_contains_remote_branch_and_path() {
        let tree = render_seed_tree(&spec(), "ssh://git@10.0.0.5/srv/git/infra.git");
        let gotk = &tree[&PathBuf::from("clusters/c0/flux-system/gotk-sync.yaml")];
        assert!(gotk.contains("url: ssh://git@10.0.0.5/srv/git/infra.git"));
        assert!(gotk.contains("branch: main"));
        assert!(gotk.contains("path: ./clusters/c0"));
        assert!(gotk.contains("kind: GitRepository"));
        assert!(gotk.contains("kind: Kustomization"));
        assert!(gotk.contains("secretRef:\n    name: flux-system"));
    }

    #[test]
    fn tree_hash_is_stable_and_content_sensitive() {
        let a = render_seed_tree(&spec(), "ssh://git@10.0.0.5/srv/git/infra.git");
        let b = render_seed_tree(&spec(), "ssh://git@10.0.0.5/srv/git/infra.git");
        let c = render_seed_tree(&spec(), "ssh://git@10.0.0.6/srv/git/infra.git");
        assert_eq!(tree_hash(&a), tree_hash(&b));
        assert_ne!(tree_hash(&a), tree_hash(&c));
    }

    #[test]
    fn write_tree_creates_nested_paths() {
        let dir = tempfile::tempdir().unwrap();
        let tree = render_seed_tree(&spec(), "ssh://git@10.0.0.5/srv/git/infra.git");
        write_tree_to(&tree, dir.path()).unwrap();
        assert!(
            dir.path()
                .join("clusters/c0/flux-system/gotk-sync.yaml")
                .exists()
        );
        assert!(dir.path().join("catalog/.gitkeep").exists());
    }
}
