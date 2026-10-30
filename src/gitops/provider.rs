//! Git provider abstraction (anti-corruption layer).
//!
//! One write-path contract for every Git topology — local bare repo on the node,
//! GitHub, GitLab.com, self-hosted GitLab/Gitea, private git. The providers
//! differ only in remote URL and in how the read-only deploy key is registered;
//! Flux binding code is provider-independent.
//!
//! `LocalBare` is fully implemented today. GitHub / GitLab / self-hosted are
//! extension points for `amiterra git connect` (planned) — same trait, new impls.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::keys::DeployKey;
use super::seed::SeedTree;

/// Which Git topology backs the cluster's infrastructure repo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitProviderKind {
    /// Bare repository on the node itself (default).
    LocalBare,
    /// github.com (planned).
    GitHub,
    /// gitlab.com (planned).
    GitLab,
    /// Self-hosted GitLab / Gitea / private git (planned).
    SelfHosted,
}

impl std::fmt::Display for GitProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            GitProviderKind::LocalBare => "local-bare",
            GitProviderKind::GitHub => "github",
            GitProviderKind::GitLab => "gitlab",
            GitProviderKind::SelfHosted => "self-hosted",
        };
        f.write_str(s)
    }
}

/// Privilege level of a registered key. `ReadOnly` is the only level handed to
/// Flux; `ReadWrite` is reserved for the future gitops-agent and is never
/// issued by the bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAccess {
    ReadOnly,
    #[allow(dead_code)] // Reserved for the future gitops-agent write path.
    ReadWrite,
}

/// Provider-agnostic description of the target repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSpec {
    /// Branch tracked by Flux.
    pub branch: String,
    /// Path inside the repo synced by the root Kustomization (e.g. `clusters/c0`).
    pub path_in_repo: String,
    /// Cluster identifier used for `clusters/<id>/` layout.
    pub cluster_id: String,
}

/// Result of provisioning the repository.
#[derive(Debug, Clone)]
pub struct ProvisionedRepo {
    /// Unified SSH remote URL.
    pub remote_url: String,
    /// True when this call created the repository, false when it already existed.
    pub created: bool,
}

/// Result of a seed commit.
#[derive(Debug, Clone)]
pub struct SeedCommit {
    /// Commit sha of the seed commit.
    pub sha: String,
    /// True when the desired tree was already present and no commit was made.
    pub skipped: bool,
}

/// Machine-readable provider status for `ami gitops status --json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderStatus {
    pub kind: GitProviderKind,
    pub remote_url: String,
    /// Local filesystem path of the repo, when applicable.
    pub repo_path: Option<String>,
    /// Deploy key fingerprint (SHA256:…), never key material.
    pub key_fingerprint: Option<String>,
}

/// Contract every Git topology must implement.
///
/// Narrower than `GitRemote` in 0021 §7.1 (read path / PR API / webhooks): the
/// bootstrap needs provision, key registration, a remote URL, known-hosts
/// material and one seed commit. The future gitops-agent widens this same seam.
pub trait GitProvider {
    fn kind(&self) -> GitProviderKind;

    /// Ensure the repository exists (create bare / verify remote reachable).
    fn provision(&mut self) -> Result<ProvisionedRepo>;

    /// Register the public key with least privilege (read-only deploy key).
    fn register_key(&mut self, key: &DeployKey, access: KeyAccess) -> Result<()>;

    /// Remote URL in the unified SSH form.
    fn remote_url(&self) -> String;

    /// known_hosts entry material (zero-TOFU source).
    fn known_hosts(&self) -> Result<String>;

    /// Seed commit of the infrastructure layer.
    fn seed_commit(&mut self, tree: &SeedTree, spec: &RepoSpec) -> Result<SeedCommit>;

    /// Machine-readable provider status.
    fn describe(&self) -> ProviderStatus;
}
