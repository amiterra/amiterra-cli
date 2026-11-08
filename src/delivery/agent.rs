//! Agent apply path: verify → recompile → verify `tree_hash` → commit
//! (Design Doc 0026 §1.2/§1.4, Design 0020 §4.3).
//!
//! Verify-don't-trust: the agent never commits SaaS- or door-supplied
//! artifacts. It rebuilds `catalog + topology` with its **own** `amispec-compile`
//! and only writes to the fleet repository when the recomputed `tree_hash`
//! equals the reviewed `expectedTreeHash`. The commit goes through the single
//! write channel (ADR-0014) with `Change-Id` trailers and an `_intent/` audit
//! record.

use anyhow::{Context, Result, anyhow};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use amispec_compile::{PassportIndex, build_bundle};

use super::intent::{
    TopologyChange, TopologyChangeRecord, is_fresh, load_allowlist, verify_intent,
};

/// Everything the agent needs to apply one intent (all injectable for tests).
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Cluster this agent serves (intents for other clusters are refused).
    pub cluster_id: String,
    /// Fleet repository (bare for the local-bare provider).
    pub repo_path: PathBuf,
    /// Tracked branch (Flux pulls this).
    pub branch: String,
    /// `git` binary (test seam).
    pub git_bin: String,
    /// Directory of allowlisted intent public keys (`*.pub`).
    pub allowlist_dir: PathBuf,
    /// `path_in_repo` Flux actually syncs (from the gitops bootstrap state).
    /// The agent refuses intents whose cluster would land outside that path —
    /// delivery to `clusters/c0` while Flux watches `clusters/cluster-0`
    /// looks successful and does nothing (silent misdelivery).
    pub flux_path_in_repo: Option<String>,
    /// Clock override (unix seconds) for TTL checks in tests.
    /// `None` = read the live clock **at verification time** — capturing a
    /// timestamp at startup makes every later intent look "from the future".
    pub now_epoch: Option<i64>,
}

impl AgentConfig {
    /// Production defaults for the local-bare fleet repo.
    pub fn production(cluster_id: impl Into<String>) -> Self {
        Self {
            cluster_id: cluster_id.into(),
            repo_path: PathBuf::from(crate::gitops::local_bare::REPO_PATH),
            branch: crate::gitops::DEFAULT_BRANCH.to_string(),
            git_bin: "git".to_string(),
            allowlist_dir: PathBuf::from(crate::gitops::keys::GITOPS_DIR).join("allowlist.d"),
            flux_path_in_repo: crate::gitops::state::GitopsState::load(
                &crate::gitops::state::GitopsState::default_path(),
            )
            .ok()
            .flatten()
            .map(|s| s.path_in_repo),
            now_epoch: None,
        }
    }
}

/// Result of an apply (Design Doc 0020 §4.1 lifecycle points).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Bundle compiled, verified and committed.
    Applied {
        change_id: String,
        commit_sha: String,
        tree_hash: String,
        journal_path: String,
        /// Non-fatal honesty notes (preserved foreign files, gaps…).
        warnings: Vec<String>,
    },
    /// Same `change_id` was already journaled — delivery retried (at-least-once).
    Noop { change_id: String },
}

/// Apply failure. `TreeHashMismatch` is the verify-don't-trust gate: nothing
/// was committed.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("intent rejected: {0}")]
    Intent(String),
    #[error("signature rejected: {0}")]
    Signature(String),
    #[error("intent rejected: {0}")]
    Freshness(String),
    #[error("cluster mismatch: intent for `{intent}`, agent serves `{local}`")]
    ClusterMismatch { intent: String, local: String },
    #[error(
        "version skew: intent compiled with `{intent}`, agent runs `{local}` \
         (refusing to commit — align amispec-core versions)"
    )]
    VersionSkew { intent: String, local: String },
    #[error(
        "compile mismatch: reviewed tree_hash `{expected}`, agent computed \
         `{actual}` — refusing to commit (tampered bundle or compiler drift)"
    )]
    TreeHashMismatch { expected: String, actual: String },
    #[error(
        "flux path mismatch: Flux syncs `{flux}`, intent delivers `{intent}` — \
         refusing to commit (the bundle would never be applied; re-run \
         `ami gitops bootstrap --cluster-id` consistently)"
    )]
    FluxPathMismatch { flux: String, intent: String },
    #[error("git error: {0}")]
    Git(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Minimal git seam over the fleet repository (local-bare write channel).
///
/// Writes always go through a temporary worktree + push — the same protected
/// channel `--receive-pack` override used by the seed (the spawned
/// `git receive-pack` child needs its own `safe.directory`).
#[derive(Debug, Clone)]
pub struct RepoWriter {
    pub repo_path: PathBuf,
    pub branch: String,
    pub git_bin: String,
    /// `--receive-pack` override value (local-bare safe.directory protection).
    pub receive_pack: Option<String>,
}

impl RepoWriter {
    pub fn new(repo_path: PathBuf, branch: String) -> Self {
        let receive_pack = crate::gitops::local_bare::receive_pack_override(&repo_path);
        Self {
            repo_path,
            branch,
            git_bin: "git".to_string(),
            receive_pack: Some(receive_pack),
        }
    }

    fn git(&self, args: &[&str]) -> Result<String> {
        let out = Command::new(&self.git_bin)
            .args(args)
            .output()
            .with_context(|| format!("spawn {}", self.git_bin))?;
        if !out.status.success() {
            return Err(anyhow!(
                "git {} failed: {}",
                args.first().copied().unwrap_or(""),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// HEAD of the tracked branch, if the repository has history.
    pub fn head(&self) -> Result<Option<String>> {
        let git_dir = self.repo_path.to_string_lossy().to_string();
        match self.git(&["--git-dir", &git_dir, "rev-parse", &self.branch]) {
            Ok(sha) if !sha.is_empty() => Ok(Some(sha)),
            _ => Ok(None),
        }
    }

    /// Read a file at HEAD (None when absent).
    pub fn read_file(&self, rel: &str) -> Result<Option<String>> {
        let git_dir = self.repo_path.to_string_lossy().to_string();
        let spec = format!("HEAD:{rel}");
        match self.git(&["--git-dir", &git_dir, "show", &spec]) {
            Ok(content) => Ok(Some(content)),
            _ => Ok(None),
        }
    }

    /// True when the path exists at HEAD.
    pub fn exists(&self, rel: &str) -> Result<bool> {
        Ok(self.read_file(rel)?.is_some())
    }

    /// List tracked files at HEAD under `prefix` (sorted).
    pub fn list_files(&self, prefix: &str) -> Result<Vec<String>> {
        let git_dir = self.repo_path.to_string_lossy().to_string();
        let out = self.git(&[
            "--git-dir",
            &git_dir,
            "ls-tree",
            "-r",
            "--name-only",
            "HEAD",
        ])?;
        let mut files: Vec<String> = out
            .lines()
            .filter(|l| l.starts_with(prefix))
            .map(|l| l.to_string())
            .collect();
        files.sort();
        Ok(files)
    }

    /// Commit `files` (path → content).
    ///
    /// Under `root` (`clusters/<id>`) exactly the **owned** entries are
    /// replaced by the bundle's content; everything else survives:
    /// * `flux-system/` — seed-owned (gotk-sync), never touched (Design 0026 §1.3);
    /// * any other foreign file/dir — preserved and **reported**, not silently
    ///   deleted (zero-step review: replace must not destroy operator data).
    ///
    /// Outside `root` writes are additive (catalog pins and the `_intent/`
    /// journal accumulate, §2.2).
    pub fn commit(
        &self,
        files: &BTreeMap<String, String>,
        root: &str,
        owned_entries: &[String],
        message: &str,
    ) -> Result<CommitOutcome> {
        let head = self.head()?.ok_or_else(|| {
            anyhow!("fleet repository has no history — run `ami gitops bootstrap` first")
        })?;

        let work = tempfile::tempdir().context("temp worktree")?;
        let work_s = work.path().to_string_lossy().to_string();
        let repo_s = self.repo_path.to_string_lossy().to_string();
        self.git(&[
            "clone",
            "--quiet",
            "--branch",
            &self.branch,
            "--single-branch",
            &repo_s,
            &work_s,
        ])
        .context("clone fleet repository")?;

        let mut foreign_files: Vec<String> = Vec::new();
        let target = work.path().join(root);
        if target.is_dir() {
            for entry in
                std::fs::read_dir(&target).with_context(|| format!("scan {}", target.display()))?
            {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name == "flux-system" || owned_entries.contains(&name) {
                    continue; // seed-owned or bundle-owned (rewritten below)
                }
                foreign_files.push(format!("{root}/{name}"));
            }
        }
        for name in owned_entries {
            let path = target.join(name);
            if path.is_dir() {
                std::fs::remove_dir_all(&path)
                    .with_context(|| format!("replace {}", path.display()))?;
            } else if path.is_file() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("replace {}", path.display()))?;
            }
        }
        for (rel, content) in files {
            let abs = work.path().join(rel);
            if let Some(parent) = abs.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
            std::fs::write(&abs, content).with_context(|| format!("write {}", abs.display()))?;
        }

        self.git(&["-C", &work_s, "add", "-A"])?;
        self.git(&[
            "-C",
            &work_s,
            "-c",
            "user.name=amiterra",
            "-c",
            "user.email=gitops@amiterra.local",
            "commit",
            "--quiet",
            "-m",
            message,
        ])?;
        let receive_arg = self
            .receive_pack
            .as_ref()
            .map(|rp| format!("--receive-pack={rp}"));
        let mut push = vec!["-C", &work_s, "push", "--quiet"];
        if let Some(arg) = &receive_arg {
            push.push(arg.as_str());
        }
        push.push(&repo_s);
        let refspec = format!("HEAD:{}", self.branch);
        push.push(&refspec);
        self.git(&push)
            .context("push to fleet repository (single write channel)")?;

        let sha = self.git(&["-C", &work_s, "rev-parse", "HEAD"])?;
        let _ = head;
        Ok(CommitOutcome { sha, foreign_files })
    }
}

/// Result of a bundle commit.
#[derive(Debug, Clone)]
pub struct CommitOutcome {
    pub sha: String,
    /// Preserved entries under `clusters/<id>/` that the bundle does not own.
    pub foreign_files: Vec<String>,
}

/// Commit subject + trailers (Design 0021 I10, Task 0006 step 5).
pub fn commit_message(change: &TopologyChange, tree_hash: &str) -> Result<String> {
    let canonical = change.canonical_bytes()?;
    let short_tree = tree_hash.trim_start_matches("sha256:");
    Ok(format!(
        "amiterra: apply {cid} (tree-sha256:{short_tree})\n\n\
         Change-Id: {cid}\n\
         Amispec-Schema-Hash: {sh}\n\
         Amiterra-Intent: TopologyChange v1 origin={origin} actor={actor}\n\
         Intent-Sha: {isha}\n",
        cid = change.metadata.change_id,
        sh = change.spec.schema_hash,
        origin = change.spec.origin,
        actor = change.spec.actor,
        isha = hash_text_bytes(&canonical),
    ))
}

fn hash_text_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{}", bytes_to_hex(&h.finalize()))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Major version of an `amispec-compile/X.Y.Z+…` stamp (skew gate).
fn major_of(version: &str) -> Option<u32> {
    let rest = version.split('/').nth(1)?;
    let semver = rest.split('+').next()?;
    semver.split('.').next()?.parse().ok()
}

/// Apply one signed intent (the whole agent-side contract).
pub fn apply_intent(
    intent: &TopologyChange,
    signature_pem: &str,
    cfg: &AgentConfig,
) -> Result<ApplyOutcome, ApplyError> {
    // 1. structural + payload integrity (pin hashes, grammar, TTL bounds)
    intent
        .validate_shape()
        .map_err(|e| ApplyError::Intent(e.to_string()))?;

    // 2. signature + allowlist (Design 0020 §4.3)
    let allowlist = load_allowlist(&cfg.allowlist_dir).map_err(ApplyError::Other)?;
    let signer = verify_intent(intent, signature_pem, &allowlist)
        .map_err(|e| ApplyError::Signature(e.to_string()))?;

    // 3. TTL / replay window (live clock unless a test override is set)
    let now = cfg
        .now_epoch
        .unwrap_or_else(crate::gitops::state::now_epoch);
    is_fresh(
        &intent.metadata.created_at,
        intent.metadata.ttl_seconds,
        now,
    )
    .map_err(|e| ApplyError::Freshness(e.to_string()))?;

    // 4. cluster + compiler version gates (fail-closed on skew)
    if intent.spec.cluster_id != cfg.cluster_id {
        return Err(ApplyError::ClusterMismatch {
            intent: intent.spec.cluster_id.clone(),
            local: cfg.cluster_id.clone(),
        });
    }
    let want_path = format!("clusters/{}", cfg.cluster_id);
    if let Some(flux_path) = cfg.flux_path_in_repo.as_ref().filter(|p| **p != want_path) {
        return Err(ApplyError::FluxPathMismatch {
            flux: flux_path.clone(),
            intent: want_path,
        });
    }
    let local_version = amispec_compile::bundle_version();
    match (
        major_of(&intent.spec.amispec_version),
        major_of(&local_version),
    ) {
        (Some(a), Some(b)) if a == b => {}
        _ => {
            return Err(ApplyError::VersionSkew {
                intent: intent.spec.amispec_version.clone(),
                local: local_version,
            });
        }
    }

    let writer = RepoWriter::new(cfg.repo_path.clone(), cfg.branch.clone());
    // set test/production git binary
    let writer = RepoWriter {
        git_bin: cfg.git_bin.clone(),
        ..writer
    };

    // 5. idempotency by change_id (at-least-once delivery, 0021)
    let journal_rel = intent.journal_path();
    if writer
        .exists(&journal_rel)
        .map_err(|e| ApplyError::Git(e.to_string()))?
    {
        return Ok(ApplyOutcome::Noop {
            change_id: intent.metadata.change_id.clone(),
        });
    }

    // 6. verify-don't-trust: rebuild the bundle with the agent's compiler
    let mut passports = PassportIndex::new();
    for pin in &intent.spec.catalog_pins {
        passports.insert_document(&pin.content).map_err(|e| {
            ApplyError::Intent(format!("catalog pin {}/rev{}: {e}", pin.id, pin.rev))
        })?;
    }
    let topology = amispec_schema::parse_topology(&intent.spec.topology_delta)
        .map_err(|e| ApplyError::Intent(format!("topologyDelta: {e}")))?;
    let bundle = build_bundle(&topology, &cfg.cluster_id, &passports, true)
        .map_err(|e| ApplyError::Intent(format!("bundle build: {e}")))?;

    if bundle.tree_hash != intent.spec.expected_tree_hash {
        return Err(ApplyError::TreeHashMismatch {
            expected: intent.spec.expected_tree_hash.clone(),
            actual: bundle.tree_hash.clone(),
        });
    }

    // 7. commit sources + compiled tree + journal through the write channel
    let prev_head = writer
        .head()
        .map_err(|e| ApplyError::Git(e.to_string()))?
        .unwrap_or_default();
    let record = TopologyChangeRecord::new(
        intent,
        crate::gitops::state::now_rfc3339(),
        &bundle.tree_hash,
        &signer.fingerprint,
        &prev_head,
        "applied",
    );
    let mut files = bundle.repo_tree();
    files.insert(
        journal_rel.clone(),
        record.to_yaml().map_err(ApplyError::Other)?,
    );

    let message = commit_message(intent, &bundle.tree_hash).map_err(ApplyError::Other)?;
    let replace_root = format!("clusters/{}", cfg.cluster_id);
    // Owned entries = the compiled stages + root kustomization + topology.
    let prefix = format!("{replace_root}/");
    let mut owned: Vec<String> = Vec::new();
    for f in &bundle.tree {
        if let Some(first) = f
            .relative_path
            .strip_prefix(&prefix)
            .and_then(|rest| rest.split('/').next())
            .filter(|first| !first.is_empty() && !owned.iter().any(|e| e == first))
        {
            owned.push(first.to_string());
        }
    }
    for extra in ["kustomization.yaml", "topology.yaml"] {
        if !owned.iter().any(|e| e == extra) {
            owned.push(extra.to_string());
        }
    }
    let outcome = writer
        .commit(&files, &replace_root, &owned, &message)
        .map_err(|e| ApplyError::Git(e.to_string()))?;

    let mut warnings: Vec<String> = outcome
        .foreign_files
        .iter()
        .map(|f| {
            format!(
                "preserved non-bundle file `{f}` under {replace_root} — it is                  outside the compiler's ownership and will NOT be pruned"
            )
        })
        .collect();
    if outcome
        .foreign_files
        .iter()
        .any(|f| f.ends_with("kustomization.yaml"))
    {
        warnings.push(
            "a foreign kustomization.yaml was preserved — it may reference              resources Flux prunes or conflicts with the compiled root"
                .to_string(),
        );
    }

    Ok(ApplyOutcome::Applied {
        change_id: intent.metadata.change_id.clone(),
        commit_sha: outcome.sha,
        tree_hash: bundle.tree_hash.clone(),
        journal_path: journal_rel,
        warnings,
    })
}

/// Convenience: build + sign + apply in one call (the local door path).
/// The agent-side verification still runs in full — the door is just a client.
pub fn apply_locally(
    change: &TopologyChange,
    signature_pem: &str,
    cfg: &AgentConfig,
) -> Result<ApplyOutcome, ApplyError> {
    apply_intent(change, signature_pem, cfg)
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use crate::delivery::intent::{
        IntentSpec, Origin, TopologyChange, build_intent, generate_nonce, sign_intent,
    };
    use crate::gitops::state::now_rfc3339;
    use ssh_key::{PrivateKey, PublicKey};
    use std::path::Path;

    pub const WEB_PASSPORT: &str = r#"
apiVersion: catalog.amispec.io/v1
kind: ComponentPassport
metadata: { id: stateless-app, name: Web, version: "1.0.0", passportRev: 1, category: application, archetype: stateless-app }
interfaces:
  egressDefaultMode: graph-only
  endpoints:
    - { name: web, protocol: http, containerPort: 8080, role: ui, defaultScope: public }
  provides: []
  requires: {}
"#;

    pub fn topology_yaml(host: &str) -> String {
        format!(
            r#"apiVersion: topology.amispec.io/v1
kind: TopologyBlueprint
metadata: {{ projectId: demo, organization: ex }}
clusters:
  - id: c0
    name: Demo
    domain: example.io
    security: {{ sopsRecipients: [age1abc123] }}
    cni: {{ engine: cilium-ebpf, clusterMeshId: 1 }}
    nodes:
      - id: n1
        role: control-plane-worker
        pricingTier: standard-node
        hardware: {{ cpuCores: 2, memoryMb: 4096, disks: [] }}
    loadBalancers:
      - {{ id: main-l7, layer: l7-gateway, provider: cilium-envoy }}
    components:
      - id: web
        passport: stateless-app
        version: "1.0.0"
        passportRev: 1
        zone: dmz
        topology: {{ mode: standalone }}
        resources: {{ cpuCores: 1, memoryMb: 256 }}
        expose:
          - {{ endpoint: web, viaBalancer: main-l7, scope: public, hostname: {host} }}
    bindings: []
"#
        )
    }

    pub struct World {
        pub repo: PathBuf,
        pub allow: PathBuf,
        pub key: PrivateKey,
        pub _pub_key: PublicKey,
        pub dir: tempfile::TempDir,
    }

    impl World {
        pub fn agent_config(&self) -> AgentConfig {
            AgentConfig {
                cluster_id: "c0".into(),
                repo_path: self.repo.clone(),
                branch: "main".into(),
                git_bin: "git".into(),
                allowlist_dir: self.allow.clone(),
                flux_path_in_repo: Some("clusters/c0".into()),
                now_epoch: Some(now()),
            }
        }

        pub fn writer(&self) -> RepoWriter {
            RepoWriter::new(self.repo.clone(), "main".into())
        }

        /// Build an intent for a topology with the given hostname; pass
        /// `"auto"` to bind the real computed tree_hash.
        pub fn intent(&self, host: &str, tree_hash: &str) -> TopologyChange {
            let mut idx = PassportIndex::new();
            idx.insert_document(WEB_PASSPORT).unwrap();
            let topo = amispec_schema::parse_topology(&topology_yaml(host)).unwrap();
            let bundle = build_bundle(&topo, "c0", &idx, true).unwrap();
            let th = if tree_hash == "auto" {
                bundle.tree_hash.clone()
            } else {
                tree_hash.to_string()
            };
            let spec = IntentSpec {
                cluster_id: "c0".into(),
                origin: Origin::Local,
                actor: "operator@node1".into(),
                amispec_version: amispec_compile::bundle_version(),
                expected_tree_hash: th,
                schema_hash: bundle.schema_hash.clone(),
                catalog_pins: bundle.catalog.clone(),
                topology_delta: topology_yaml(host),
            };
            build_intent(spec, generate_nonce().unwrap(), now_rfc3339(), 900).unwrap()
        }

        pub fn sign(&self, intent: &TopologyChange) -> String {
            sign_intent(intent, &self.key).unwrap()
        }

        /// Build + sign in one step.
        pub fn signed_intent(&self, host: &str, tree_hash: &str) -> (TopologyChange, String) {
            let intent = self.intent(host, tree_hash);
            let pem = self.sign(&intent);
            (intent, pem)
        }
    }

    pub fn now() -> i64 {
        crate::delivery::intent::parse_rfc3339_utc(&now_rfc3339()).unwrap()
    }

    pub fn test_world() -> World {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("infra.git");
        seed_bare(&repo, tmp.path());

        let allow = tmp.path().join("allowlist.d");
        std::fs::create_dir_all(&allow).unwrap();
        let key_dir = tmp.path().join("keys");
        std::fs::create_dir_all(&key_dir).unwrap();
        let priv_path = key_dir.join("op");
        let dk = crate::gitops::keys::generate(&priv_path).unwrap();
        std::fs::write(allow.join("operator.pub"), format!("{}\n", dk.public_line)).unwrap();
        let key = PrivateKey::read_openssh_file(&priv_path).unwrap();
        let _pub_key = PublicKey::from_openssh(&dk.public_line).unwrap();
        World {
            repo,
            allow,
            key,
            _pub_key,
            dir: tmp,
        }
    }

    /// Empty bare repo + one seed commit on `main` (what `ami gitops
    /// bootstrap` leaves behind). Pushes from a temp worktree — the only way
    /// to create the first ref on an empty repository.
    fn seed_bare(repo: &Path, parent: &Path) {
        Command::new("git")
            .args(["init", "--bare", "--initial-branch=main"])
            .arg(repo)
            .output()
            .unwrap();
        let work = parent.join("seed-work");
        let ws = work.to_string_lossy().to_string();
        Command::new("git")
            .args(["init", "--initial-branch=main", &ws])
            .output()
            .unwrap();
        std::fs::create_dir_all(work.join("catalog")).unwrap();
        std::fs::write(work.join("catalog/.gitkeep"), "").unwrap();
        std::fs::create_dir_all(work.join("clusters/c0/flux-system")).unwrap();
        std::fs::write(
            work.join("clusters/c0/flux-system/gotk-sync.yaml"),
            "# seed\n",
        )
        .unwrap();
        for args in [
            vec!["-C", &ws, "add", "-A"],
            vec![
                "-C",
                &ws,
                "-c",
                "user.name=amiterra",
                "-c",
                "user.email=gitops@amiterra.local",
                "commit",
                "--quiet",
                "-m",
                "seed",
            ],
            vec![
                "-C",
                &ws,
                "push",
                "--quiet",
                &repo.to_string_lossy(),
                "HEAD:main",
            ],
        ] {
            let out = Command::new("git").args(&args).output().unwrap();
            assert!(
                out.status.success(),
                "seed {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        std::fs::remove_dir_all(&work).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::*;
    use super::*;
    use crate::delivery::intent::{IntentSpec, Origin, build_intent, generate_nonce};
    use crate::gitops::state::now_rfc3339;
    use amispec_compile::PassportIndex;

    fn cfg(w: &World) -> AgentConfig {
        w.agent_config()
    }

    #[test]
    fn apply_commits_bundle_and_journal() {
        let w = test_world();
        let (intent, pem) = w.signed_intent("app.example.io", "auto");
        let out = apply_intent(&intent, &pem, &cfg(&w)).unwrap();
        match &out {
            ApplyOutcome::Applied {
                change_id,
                commit_sha,
                tree_hash,
                journal_path,
                warnings: _,
            } => {
                assert_eq!(change_id, &intent.metadata.change_id);
                assert!(commit_sha.len() >= 7);
                assert!(tree_hash.starts_with("sha256:"));
                assert_eq!(
                    journal_path,
                    &format!("_intent/{}.yaml", intent.metadata.change_id)
                );
            }
            ApplyOutcome::Noop { .. } => panic!("expected Applied"),
        }

        let writer = w.writer();
        // sources + compiled tree + journal landed
        assert!(writer.exists("catalog/stateless-app/rev1.yaml").unwrap());
        assert!(writer.exists("clusters/c0/topology.yaml").unwrap());
        assert!(
            writer
                .exists("clusters/c0/02-operators-and-networking/gateways.yaml")
                .unwrap(),
            "compiled stage tree committed"
        );
        let journal = writer
            .read_file(&format!("_intent/{}.yaml", intent.metadata.change_id))
            .unwrap()
            .expect("journal record");
        assert!(journal.contains("TopologyChangeRecord"));
        assert!(journal.contains("prevHead"));

        // commit carries the audit trailers
        let msg = writer
            .git(&[
                "--git-dir",
                &w.repo.to_string_lossy(),
                "log",
                "-1",
                "--format=%B",
            ])
            .unwrap();
        assert!(msg.contains("Change-Id:"));
        assert!(msg.contains("Amispec-Schema-Hash:"));
        assert!(msg.contains("Amiterra-Intent:"));
        assert!(msg.contains("Intent-Sha:"));

        // no secret material in the repo: only sops:// references
        let topo = writer
            .read_file("clusters/c0/topology.yaml")
            .unwrap()
            .unwrap();
        assert!(!topo.contains("private"), "no key material in repo");
    }

    #[test]
    fn apply_preserves_seed_flux_system() {
        let w = test_world();
        let (intent, pem) = w.signed_intent("app.example.io", "auto");
        apply_intent(&intent, &pem, &cfg(&w)).unwrap();
        // the seed-owned sync layer must survive delivery (gotk-sync contract)
        assert!(
            w.writer()
                .exists("clusters/c0/flux-system/gotk-sync.yaml")
                .unwrap(),
            "flux-system/ is seed-owned and must never be replaced by apply"
        );
    }

    #[test]
    fn same_change_id_is_idempotent_noop() {
        let w = test_world();
        let (intent, pem) = w.signed_intent("app.example.io", "auto");
        let cfg = cfg(&w);
        match apply_intent(&intent, &pem, &cfg).unwrap() {
            ApplyOutcome::Applied { commit_sha, .. } => {
                match apply_intent(&intent, &pem, &cfg).unwrap() {
                    ApplyOutcome::Noop { change_id } => {
                        assert_eq!(change_id, intent.metadata.change_id);
                    }
                    other => panic!("expected Noop, got {other:?}"),
                }
                let head = w.writer().head().unwrap().unwrap();
                assert_eq!(head, commit_sha, "no second commit");
            }
            other => panic!("expected Applied, got {other:?}"),
        }
    }

    #[test]
    fn tree_hash_mismatch_refuses_commit() {
        let w = test_world();
        let (intent, pem) = w.signed_intent("app.example.io", "sha256:deadbeef");
        let before = w.writer().head().unwrap().unwrap();
        let err = apply_intent(&intent, &pem, &cfg(&w)).unwrap_err();
        assert!(matches!(err, ApplyError::TreeHashMismatch { .. }), "{err}");
        let after = w.writer().head().unwrap().unwrap();
        assert_eq!(before, after, "nothing committed on mismatch");
    }

    #[test]
    fn flux_path_mismatch_refuses_commit() {
        // Silent misdelivery killer: bootstrap synced clusters/cluster-0 while
        // the intent delivers clusters/c0 — the bundle would never be applied.
        let w = test_world();
        let mut cfg = cfg(&w);
        cfg.flux_path_in_repo = Some("clusters/cluster-0".into());
        let (intent, pem) = w.signed_intent("app.example.io", "auto");
        let before = w.writer().head().unwrap().unwrap();
        let err = apply_intent(&intent, &pem, &cfg).unwrap_err();
        assert!(matches!(err, ApplyError::FluxPathMismatch { .. }), "{err}");
        let after = w.writer().head().unwrap().unwrap();
        assert_eq!(before, after, "no commit on path mismatch");
    }

    #[test]
    fn foreign_files_under_cluster_dir_are_preserved_and_reported() {
        let w = test_world();
        // operator's own file lives in the cluster dir — replace must not eat it
        {
            let mut files = BTreeMap::new();
            files.insert(
                "clusters/c0/custom/handmade.yaml".to_string(),
                "# operator-owned\n".to_string(),
            );
            w.writer()
                .commit(&files, "clusters/c0", &[], "operator file")
                .unwrap();
        }
        let (intent, pem) = w.signed_intent("app.example.io", "auto");
        let out = apply_intent(&intent, &pem, &cfg(&w)).unwrap();
        match &out {
            ApplyOutcome::Applied { warnings, .. } => {
                assert!(
                    warnings.iter().any(|x| x.contains("clusters/c0/custom")),
                    "foreign path must be reported: {warnings:?}"
                );
            }
            other => panic!("expected Applied, got {other:?}"),
        }
        assert!(
            w.writer()
                .exists("clusters/c0/custom/handmade.yaml")
                .unwrap(),
            "operator-owned file must survive apply"
        );
    }

    #[test]
    fn compiled_base_values_stay_in_sync_with_product_cilium_config() {
        // Contract test (zero-step review): the compiler repeats base keys of
        // the Day-0 Cilium config (merge semantics of helm-controller are
        // ambiguous) — if os/configs drifts, this test must fail, not a
        // production cluster.
        // The effective Day-0 base is what `ami init` renders — the
        // in-code manifest (os/configs is a reference copy).
        let rendered = crate::providers::server::render_cilium_manifest(false, "127.0.0.1");
        fn ypath<'a>(v: &'a serde_yaml::Value, path: &str) -> Option<&'a serde_yaml::Value> {
            let mut cur = v;
            for seg in path.trim_start_matches('/').split('/') {
                cur = cur.get(seg)?;
            }
            Some(cur)
        }
        let doc: serde_yaml::Value = serde_yaml::from_str(&rendered).unwrap();
        let base_values_text = ypath(&doc, "/spec/valuesContent")
            .and_then(|v| v.as_str())
            .expect("spec.valuesContent present");
        let base: serde_yaml::Value = serde_yaml::from_str(base_values_text).unwrap();
        let compiled: serde_yaml::Value =
            serde_yaml::from_str(&amispec_compile::exposure::activation_values_content(
                &amispec_compile::exposure::HelmActivationFlags {
                    envoy: true,
                    gateway_api: true,
                    ingress_controller: true,
                    l2_announcements: true,
                },
            ))
            .unwrap();

        // Only REPEATED keys are compared — keys the compiler never emits
        // (e.g. top-level `image`) cannot drift by clobbering. Every base key
        // inside a REPEATED map must survive the merge (concat-merge replaces
        // whole maps: `bpf:` in the activation would drop `hostRouting`).
        for path in [
            "/operator/replicas",
            "/operator/image/useDigest",
            "/operator/image/digest",
            "/bpf/masquerade",
            "/bpf/hostRouting",
        ] {
            let b = ypath(&base, path).unwrap_or_else(|| {
                panic!("base config missing {path} — update the contract test with it")
            });
            let c =
                ypath(&compiled, path).unwrap_or_else(|| panic!("compiled values missing {path}"));
            assert_eq!(
                b, c,
                "compiled {path} drifted from os/configs/cilium-helmchart.yaml — \
                 repeat the new base in activation_values_content"
            );
        }
        // Base-only keys the platform must provide (the compiler never emits
        // them, so they cannot drift by clobbering — but they must exist):
        // L2-announcement lease renewals exhaust the chart default qps=10.
        for path in ["/k8sClientRateLimit/qps", "/k8sClientRateLimit/burst"] {
            assert!(
                ypath(&base, path).is_some(),
                "base config missing {path} — L2 announcements throttle at ~50 VIPs without it"
            );
        }
        // Airgap digest bypass must actually bypass: `useDigest: false` alone
        // is ineffective while `digest` is non-empty (charts render
        // `tag@sha256:…` refs that imported airgap images never match).
        for (path, what) in [
            ("/image/useDigest", "false"),
            ("/image/digest", ""),
            ("/operator/image/useDigest", "false"),
            ("/operator/image/digest", ""),
        ] {
            let v = ypath(&base, path).unwrap_or_else(|| panic!("Day-0 base must define {path}"));
            assert_eq!(
                v,
                &if what.is_empty() {
                    serde_yaml::Value::String(String::new())
                } else {
                    serde_yaml::Value::Bool(false)
                },
                "{path} must be {what:?} — otherwise digest-qualified refs \
                 break airgap image imports (image pulls on slow egress)"
            );
        }
    }

    #[test]
    fn live_clock_is_read_at_verification_not_startup() {
        // Regression: the agent used to freeze now_epoch at process start, so
        // every intent arriving minutes later looked "from the future".
        let w = test_world();
        let mut cfg = cfg(&w);
        cfg.now_epoch = None; // live clock
        let (intent, pem) = w.signed_intent("app.example.io", "auto");
        let applied = apply_intent(&intent, &pem, &cfg).unwrap();
        assert!(
            matches!(
                applied,
                ApplyOutcome::Applied { .. } | ApplyOutcome::Noop { .. }
            ),
            "live-clock intent must apply, got {applied:?}"
        );
    }

    #[test]
    fn expired_intent_is_rejected() {
        let w = test_world();
        let (intent, pem) = w.signed_intent("app.example.io", "auto");
        let mut cfg = cfg(&w);
        cfg.now_epoch = Some(now() + 10_000);
        let err = apply_intent(&intent, &pem, &cfg).unwrap_err();
        assert!(matches!(err, ApplyError::Freshness(_)), "{err}");
    }

    #[test]
    fn version_skew_is_rejected() {
        let w = test_world();
        let mut intent = w.intent("app.example.io", "auto");
        intent.spec.amispec_version = "amispec-compile/9.9.9+1.0.0".into();
        let pem = w.sign(&intent);
        let err = apply_intent(&intent, &pem, &cfg(&w)).unwrap_err();
        assert!(matches!(err, ApplyError::VersionSkew { .. }), "{err}");
    }

    #[test]
    fn foreign_cluster_intent_is_rejected() {
        let w = test_world();
        let mut intent = w.intent("app.example.io", "auto");
        intent.spec.cluster_id = "other".into();
        let pem = w.sign(&intent);
        let err = apply_intent(&intent, &pem, &cfg(&w)).unwrap_err();
        assert!(matches!(err, ApplyError::ClusterMismatch { .. }), "{err}");
    }

    #[test]
    fn non_allowlisted_signer_is_rejected_before_any_git_write() {
        let w = test_world();
        let (intent, pem) = w.signed_intent("app.example.io", "auto");
        // allowlist now trusts a DIFFERENT key than the one that signed
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("k");
        let dk = crate::gitops::keys::generate(&p).unwrap();
        std::fs::remove_file(w.allow.join("operator.pub")).unwrap();
        std::fs::write(w.allow.join("other.pub"), format!("{}\n", dk.public_line)).unwrap();
        let before = w.writer().head().unwrap().unwrap();
        let err = apply_intent(&intent, &pem, &cfg(&w)).unwrap_err();
        assert!(matches!(err, ApplyError::Signature(_)), "{err}");
        let after = w.writer().head().unwrap().unwrap();
        assert_eq!(before, after, "no git write on bad signature");
    }

    #[test]
    fn rollback_reapplies_previous_bundle() {
        let w = test_world();
        let cfg = cfg(&w);
        let (a, pem_a) = w.signed_intent("a.example.io", "auto");
        let (b, pem_b) = w.signed_intent("b.example.io", "auto");
        apply_intent(&a, &pem_a, &cfg).unwrap();
        apply_intent(&b, &pem_b, &cfg).unwrap();
        let topo_b = w
            .writer()
            .read_file("clusters/c0/topology.yaml")
            .unwrap()
            .unwrap();
        assert!(topo_b.contains("b.example.io"));

        // V5: resubmit the previous bundle content (new change_id — new delivery)
        let (rollback, pem_r) = w.signed_intent("a.example.io", "auto");
        match apply_intent(&rollback, &pem_r, &cfg).unwrap() {
            ApplyOutcome::Applied { .. } => {}
            other => panic!("expected Applied, got {other:?}"),
        }
        let topo_back = w
            .writer()
            .read_file("clusters/c0/topology.yaml")
            .unwrap()
            .unwrap();
        assert!(topo_back.contains("a.example.io"), "state restored");

        // journal records every application
        for c in [&a, &b, &rollback] {
            assert!(
                w.writer()
                    .read_file(&format!("_intent/{}.yaml", c.metadata.change_id))
                    .unwrap()
                    .is_some(),
                "journal entry for {}",
                c.metadata.change_id
            );
        }
    }

    #[test]
    fn journal_entries_surface_the_audit_log() {
        use crate::delivery::intent::journal_entries;
        let w = test_world();
        let cfg = cfg(&w);
        let (a, pem_a) = w.signed_intent("a.example.io", "auto");
        let (b, pem_b) = w.signed_intent("b.example.io", "auto");
        apply_intent(&a, &pem_a, &cfg).unwrap();
        apply_intent(&b, &pem_b, &cfg).unwrap();

        let entries = journal_entries(&w.writer()).unwrap();
        assert_eq!(entries.len(), 2);
        for e in &entries {
            assert_eq!(e.spec.status, "applied");
            assert_eq!(e.spec.cluster_id, "c0");
            assert!(e.spec.tree_hash.starts_with("sha256:"));
            assert!(e.spec.signature_fingerprint.starts_with("SHA256:"));
            assert!(!e.spec.prev_head.is_empty(), "rollback base recorded");
        }
        let ids: Vec<&str> = entries
            .iter()
            .map(|e| e.metadata.change_id.as_str())
            .collect();
        assert!(ids.contains(&a.metadata.change_id.as_str()));
        assert!(ids.contains(&b.metadata.change_id.as_str()));
    }

    #[test]
    fn replace_semantics_drop_stale_stage_files() {
        let w = test_world();
        let cfg = cfg(&w);
        // with exposure → gateways.yaml exists
        let (with_exposure, pem) = w.signed_intent("a.example.io", "auto");
        apply_intent(&with_exposure, &pem, &cfg).unwrap();
        assert!(
            w.writer()
                .exists("clusters/c0/02-operators-and-networking/gateways.yaml")
                .unwrap()
        );

        // without exposure → the stale artifact file is gone from the repo
        let no_exposure_yaml = topology_yaml("a.example.io").replace(
            "        expose:\n          - { endpoint: web, viaBalancer: main-l7, scope: public, hostname: a.example.io }\n",
            "",
        );
        let mut idx = PassportIndex::new();
        idx.insert_document(WEB_PASSPORT).unwrap();
        let topo = amispec_schema::parse_topology(&no_exposure_yaml).unwrap();
        let bundle = build_bundle(&topo, "c0", &idx, true).unwrap();
        let spec = IntentSpec {
            cluster_id: "c0".into(),
            origin: Origin::Local,
            actor: "op".into(),
            amispec_version: amispec_compile::bundle_version(),
            expected_tree_hash: bundle.tree_hash.clone(),
            schema_hash: bundle.schema_hash.clone(),
            catalog_pins: bundle.catalog.clone(),
            topology_delta: no_exposure_yaml,
        };
        let intent = build_intent(spec, generate_nonce().unwrap(), now_rfc3339(), 900).unwrap();
        let pem = w.sign(&intent);
        apply_intent(&intent, &pem, &cfg).unwrap();
        assert!(
            !w.writer()
                .exists("clusters/c0/02-operators-and-networking/gateways.yaml")
                .unwrap(),
            "headless baseline: stale balancer artifacts removed"
        );
    }
}
