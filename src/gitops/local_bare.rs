//! LocalBare git provider.
//!
//! Bare repository on the node itself + `git-shell` account + read-only deploy
//! key forced to `git-upload-pack` on exactly one repo. Remote URL is the same
//! `ssh://git@host/path` shape used by GitHub/GitLab/self-hosted,
//! so the Flux binding never learns provider-specific code paths.
//!
//! Split for testability: pure helpers (URL, forced command, seed marker) are
//! unit-tested; host mutations (`useradd`, `chown`) stay in thin methods.

use anyhow::{Context, Result, bail};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::keys::{DeployKey, authorized_keys_line, known_hosts_entry};
use super::provider::{
    GitProvider, GitProviderKind, KeyAccess, ProvisionedRepo, RepoSpec, SeedCommit,
};
use super::seed::{self, SeedTree};

/// System account owning the bare repository (login shell: git-shell).
pub const GIT_USER: &str = "amiterra-git";
/// Home of [`GIT_USER`]; holds `.ssh/authorized_keys` and the bare repo.
pub const GIT_HOME: &str = "/var/lib/amiterra/git";
/// Bare repository path (cluster infrastructure repo).
pub const REPO_PATH: &str = "/var/lib/amiterra/git/infra.git";

/// Commit-message marker making seed commits self-describing and idempotent:
/// `seed_commit` skips work when HEAD already carries the desired tree hash.
const SEED_MARKER_PREFIX: &str = "amiterra: seed infrastructure layer (tree-sha256:";

/// `--receive-pack` override for local pushes: the spawned `git receive-pack`
/// child must get `safe.directory` on ITS OWN command line (protected scope) —
/// `-c` options of the parent reach it only via environment, where git ignores
/// `safe.directory`.
pub fn receive_pack_override(repo_path: &Path) -> String {
    format!(
        "git -c safe.directory={} receive-pack",
        repo_path.to_string_lossy()
    )
}

/// Everything host-specific the provider needs; overridable for tests.
#[derive(Debug, Clone)]
pub struct LocalBareConfig {
    /// Bare repository path.
    pub repo_path: PathBuf,
    /// System account that owns the repository.
    pub git_user: String,
    /// Home directory of [`Self::git_user`].
    pub git_home: PathBuf,
    /// Node IP used in the SSH remote URL.
    pub node_ip: String,
    /// Host public key line for known_hosts (None → read from /etc/ssh).
    pub host_key_line: Option<String>,
    /// Absolute path of `git` binary (test seam).
    pub git_bin: String,
}

impl LocalBareConfig {
    /// Production defaults (paths from constants, node IP from init config).
    pub fn production(node_ip: impl Into<String>) -> Self {
        Self {
            repo_path: PathBuf::from(REPO_PATH),
            git_user: GIT_USER.to_string(),
            git_home: PathBuf::from(GIT_HOME),
            node_ip: node_ip.into(),
            host_key_line: None,
            git_bin: "git".to_string(),
        }
    }
}

/// Local bare-repo provider. Construct with [`LocalBare::new`].
pub struct LocalBare {
    cfg: LocalBareConfig,
}

impl LocalBare {
    pub fn new(cfg: LocalBareConfig) -> Self {
        Self { cfg }
    }

    /// Unified SSH remote URL.
    pub fn remote_url_for(node_ip: &str, git_user: &str, repo_path: &Path) -> String {
        let p = repo_path.to_string_lossy();
        format!("ssh://{git_user}@{node_ip}{p}")
    }

    /// Forced command pinning the deploy key to read-only fetch on one repo.
    pub fn forced_command(repo_path: &Path) -> String {
        format!("git-upload-pack '{}'", repo_path.to_string_lossy())
    }

    /// Seed commit message embedding the tree hash (idempotency marker).
    pub fn seed_message(tree_hash: &str) -> String {
        format!("{SEED_MARKER_PREFIX}{tree_hash})")
    }

    /// Parse a tree hash out of a seed commit message; None when not a seed.
    pub fn parse_seed_marker(message: &str) -> Option<String> {
        let rest = message.trim().strip_prefix(SEED_MARKER_PREFIX)?;
        rest.strip_suffix(')').map(|h| h.to_string())
    }

    /// Locate ALL SSH host public key lines (one per key type).
    ///
    /// Recording a single key is not enough: the SSH client (Flux/go-git)
    /// negotiates its own host-key algorithm, and an unrecorded type fails
    /// with `knownhosts: key mismatch` even though the host identity is
    /// legitimate. Every published host key must land in known_hosts.
    fn read_host_key_lines(&self) -> Result<Vec<String>> {
        if let Some(line) = &self.cfg.host_key_line {
            return Ok(vec![line.clone()]);
        }
        let mut lines = Vec::new();
        for name in [
            "ssh_host_ed25519_key.pub",
            "ssh_host_ecdsa_key.pub",
            "ssh_host_rsa_key.pub",
        ] {
            let path = Path::new("/etc/ssh").join(name);
            if let Ok(raw) = fs::read_to_string(&path) {
                let trimmed = raw.trim().to_string();
                if !trimmed.is_empty() {
                    lines.push(trimmed);
                }
            }
        }
        if !lines.is_empty() {
            return Ok(lines);
        }
        bail!(
            "No SSH host public key found in /etc/ssh; cannot build known_hosts (zero-TOFU source). \
             Is sshd installed on this node?"
        )
    }

    fn run_git(&self, args: &[&str]) -> Result<String> {
        // The bare repo is chowned to GIT_USER so git-shell can serve it, while
        // these operator commands run as root. Git's ownership check
        // (CVE-2022-24765) then refuses with "detected dubious ownership".
        // `-c safe.directory` covers THIS process (command-line scope is
        // protected config). It does NOT cover child processes: `git push` to a
        // local path spawns `git receive-pack`, where `-c` options arrive via
        // GIT_CONFIG_PARAMETERS — and `safe.directory` is deliberately ignored
        // from environment sources. Children are handled separately:
        // protected system/global registration + `--receive-pack` override.
        let safe = format!("safe.directory={}", self.cfg.repo_path.to_string_lossy());
        let mut full: Vec<&str> = Vec::with_capacity(args.len() + 2);
        full.push("-c");
        full.push(&safe);
        full.extend_from_slice(args);
        let out = Command::new(&self.cfg.git_bin)
            .args(&full)
            .output()
            .with_context(|| format!("failed to run {} {}", self.cfg.git_bin, args.join(" ")))?;
        if !out.status.success() {
            bail!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn ensure_git_available(&self) -> Result<()> {
        let ok = Command::new(&self.cfg.git_bin)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            bail!(
                "'git' is required for the GitOps bootstrap but was not found. \
                 Install git (e.g. apt-get install -y git) and re-run."
            );
        }
        Ok(())
    }

    /// Create the git-shell system account (idempotent).
    fn ensure_git_user(&self) -> Result<()> {
        let exists = Command::new("id")
            .arg("-u")
            .arg(&self.cfg.git_user)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if exists {
            return Ok(());
        }
        fs::create_dir_all(&self.cfg.git_home)
            .with_context(|| format!("failed to create {}", self.cfg.git_home.display()))?;
        let status = Command::new("useradd")
            .args([
                "--system",
                "--create-home",
                "--home-dir",
                &self.cfg.git_home.to_string_lossy(),
                "--shell",
                "/usr/bin/git-shell",
                &self.cfg.git_user,
            ])
            .status()
            .context("failed to run useradd (root required)")?;
        if !status.success() {
            bail!("useradd for '{}' failed", self.cfg.git_user);
        }
        Ok(())
    }

    /// Register the bare repo as `safe.directory` in **protected** git config
    /// (system scope, falling back to global). Command-line `-c` is not enough:
    /// child processes (`git receive-pack`) ignore `safe.directory` from
    /// environment propagation, so the exception must live in a scope git
    /// trusts for every process touching the repo (operators, future agent).
    fn ensure_safe_directory(&self) -> Result<()> {
        let repo = self.cfg.repo_path.to_string_lossy().to_string();
        for scope in ["--system", "--global"] {
            let listed = Command::new(&self.cfg.git_bin)
                .args(["config", scope, "--get-all", "safe.directory"])
                .output();
            if let Ok(out) = listed
                && out.status.success()
                && String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .any(|l| l.trim() == repo)
            {
                return Ok(());
            }
            let status = Command::new(&self.cfg.git_bin)
                .args(["config", scope, "--add", "safe.directory", &repo])
                .status();
            if let Ok(st) = status
                && st.success()
            {
                return Ok(());
            }
        }
        bail!(
            "cannot register safe.directory for {repo} in system/global git config \
             (pushes to this repo will fail the ownership check)"
        )
    }

    /// Initialize the bare repository with `main` as HEAD (idempotent).
    fn ensure_bare_repo(&self) -> Result<bool> {
        let head_marker = self.cfg.repo_path.join("HEAD");
        if head_marker.exists() {
            return Ok(false);
        }
        if let Some(parent) = self.cfg.repo_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        self.run_git(&[
            "init",
            "--bare",
            "--initial-branch=main",
            &self.cfg.repo_path.to_string_lossy(),
        ])?;
        // Ownership: repo must be readable by the git-shell user for serving.
        let chown = Command::new("chown")
            .args([
                "-R",
                &format!("{}:{}", self.cfg.git_user, self.cfg.git_user),
                &self.cfg.repo_path.to_string_lossy(),
            ])
            .status()
            .context("failed to run chown (root required)")?;
        if !chown.success() {
            bail!(
                "chown {}:{} {} failed — git-shell cannot serve the repository",
                self.cfg.git_user,
                self.cfg.git_user,
                self.cfg.repo_path.display()
            );
        }
        Ok(true)
    }
}

impl GitProvider for LocalBare {
    fn kind(&self) -> GitProviderKind {
        GitProviderKind::LocalBare
    }

    fn provision(&mut self) -> Result<ProvisionedRepo> {
        self.ensure_git_available()?;
        self.ensure_git_user()?;
        let created = self.ensure_bare_repo()?;
        // Runs on every provision (not only on create): the repo may predate
        // this CLI version and still lack a protected safe.directory entry.
        // Non-fatal: the seed push passes safe.directory via --receive-pack and
        // works even without gitconfig registration.
        if let Err(e) = self.ensure_safe_directory() {
            eprintln!("  ! safe.directory registration failed (push still protected): {e:#}");
        }
        Ok(ProvisionedRepo {
            remote_url: self.remote_url(),
            created,
        })
    }

    fn register_key(&mut self, key: &DeployKey, access: KeyAccess) -> Result<()> {
        if access != KeyAccess::ReadOnly {
            bail!(
                "LocalBare only issues read-only deploy keys (read-only write contract); \
                 write access is reserved for the future gitops-agent"
            );
        }
        let ssh_dir = self.cfg.git_home.join(".ssh");
        fs::create_dir_all(&ssh_dir)
            .with_context(|| format!("failed to create {}", ssh_dir.display()))?;
        let forced = Self::forced_command(&self.cfg.repo_path);
        let line = authorized_keys_line(&key.public_line, &forced);
        let auth_keys = ssh_dir.join("authorized_keys");
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&auth_keys)
                .with_context(|| format!("failed to write {}", auth_keys.display()))?;
            f.write_all(format!("{line}\n").as_bytes())
                .with_context(|| format!("failed to write {}", auth_keys.display()))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&auth_keys, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to chmod {}", auth_keys.display()))?;
            fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("failed to chmod {}", ssh_dir.display()))?;
        }
        let chown = Command::new("chown")
            .args([
                "-R",
                &format!("{}:{}", self.cfg.git_user, self.cfg.git_user),
                &self.cfg.git_home.to_string_lossy(),
            ])
            .status()
            .context("failed to run chown (root required)")?;
        if !chown.success() {
            bail!(
                "chown {}:{} {} failed — deploy key unusable over SSH",
                self.cfg.git_user,
                self.cfg.git_user,
                self.cfg.git_home.display()
            );
        }
        Ok(())
    }

    fn remote_url(&self) -> String {
        Self::remote_url_for(&self.cfg.node_ip, &self.cfg.git_user, &self.cfg.repo_path)
    }

    fn known_hosts(&self) -> Result<String> {
        let entries: Result<Vec<String>> = self
            .read_host_key_lines()?
            .iter()
            .map(|raw| known_hosts_entry(&self.cfg.node_ip, raw))
            .collect();
        Ok(entries?.join("\n"))
    }

    fn seed_commit(&mut self, tree: &SeedTree, spec: &RepoSpec) -> Result<SeedCommit> {
        self.ensure_git_available()?;
        let desired_hash = seed::tree_hash(tree);
        let desired_msg = Self::seed_message(&desired_hash);
        // Seed must land on the branch Flux tracks, or the bind converges into a
        // permanently broken sync.
        let branch = spec.branch.as_str();

        // Idempotent converge: if HEAD already carries the desired tree, do nothing.
        let head_msg = self
            .run_git(&[
                "--git-dir",
                &self.cfg.repo_path.to_string_lossy(),
                "log",
                "-1",
                "--format=%s",
                branch,
            ])
            .unwrap_or_default();
        if head_msg == desired_msg {
            let sha = self.run_git(&[
                "--git-dir",
                &self.cfg.repo_path.to_string_lossy(),
                "rev-parse",
                branch,
            ])?;
            return Ok(SeedCommit { sha, skipped: true });
        }
        if !head_msg.is_empty() && Self::parse_seed_marker(&head_msg).is_some() {
            // History exists and is a seed commit, but for a different tree →
            // continue and append a new seed commit on top (converge to desired).
        } else if !head_msg.is_empty() {
            bail!(
                "Repository {} already has a history that was not created by amiterra \
                 (HEAD: '{}'). Refusing to overwrite; use a fresh repository path or \
                 `ami gitops retarget` for a deliberate migration.",
                self.cfg.repo_path.display(),
                head_msg
            );
        }

        // Seed via a temporary worktree, then push to the bare repo (no SSH
        // key involved — filesystem path only).
        let tmp = tempfile::tempdir().context("failed to create temp worktree")?;
        self.run_git(&[
            "init",
            "--initial-branch=main",
            &tmp.path().to_string_lossy(),
        ])?;
        seed::write_tree_to(tree, tmp.path())?;
        let tmp_s = tmp.path().to_string_lossy().to_string();
        self.run_git(&["-C", &tmp_s, "add", "-A"])?;
        self.run_git(&[
            "-C",
            &tmp_s,
            "-c",
            "user.name=amiterra",
            "-c",
            "user.email=gitops@amiterra.local",
            "commit",
            "-m",
            &desired_msg,
        ])?;
        let push_ref = format!("HEAD:{branch}");
        // The receive-pack child gets safe.directory on its own command line —
        // see receive_pack_override().
        let receive_arg = format!(
            "--receive-pack={}",
            receive_pack_override(&self.cfg.repo_path)
        );
        self.run_git(&[
            "-C",
            &tmp_s,
            "push",
            &receive_arg,
            &self.cfg.repo_path.to_string_lossy(),
            &push_ref,
        ])?;
        let sha = self.run_git(&[
            "--git-dir",
            &self.cfg.repo_path.to_string_lossy(),
            "rev-parse",
            branch,
        ])?;
        Ok(SeedCommit {
            sha,
            skipped: false,
        })
    }

    fn describe(&self) -> super::provider::ProviderStatus {
        super::provider::ProviderStatus {
            kind: GitProviderKind::LocalBare,
            remote_url: self.remote_url(),
            repo_path: Some(self.cfg.repo_path.to_string_lossy().into_owned()),
            key_fingerprint: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gitops::keys;

    fn test_cfg(repo_path: &Path) -> LocalBareConfig {
        LocalBareConfig {
            repo_path: repo_path.to_path_buf(),
            git_user: GIT_USER.to_string(),
            git_home: repo_path.parent().unwrap().to_path_buf(),
            node_ip: "10.0.0.5".into(),
            host_key_line: Some("ssh-ed25519 AAAAHOSTKEY root@node".into()),
            git_bin: "git".into(),
        }
    }

    #[test]
    fn remote_url_uses_unified_ssh_shape() {
        let url =
            LocalBare::remote_url_for("10.0.0.5", "amiterra-git", Path::new("/srv/git/infra.git"));
        assert_eq!(url, "ssh://amiterra-git@10.0.0.5/srv/git/infra.git");
    }

    #[test]
    fn forced_command_pins_upload_pack_only() {
        let cmd = LocalBare::forced_command(Path::new("/srv/git/infra.git"));
        assert_eq!(cmd, "git-upload-pack '/srv/git/infra.git'");
    }

    #[test]
    fn seed_marker_roundtrip() {
        let msg = LocalBare::seed_message("abc123");
        assert_eq!(
            LocalBare::parse_seed_marker(&msg).as_deref(),
            Some("abc123")
        );
        assert_eq!(LocalBare::parse_seed_marker("unrelated commit"), None);
    }

    #[test]
    fn known_hosts_from_injected_host_key() {
        let cfg = test_cfg(Path::new("/tmp/x.git"));
        let p = LocalBare::new(cfg);
        assert_eq!(p.known_hosts().unwrap(), "10.0.0.5 ssh-ed25519 AAAAHOSTKEY");
    }

    #[test]
    fn seed_commit_is_idempotent_and_write_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("infra.git");
        let cfg = test_cfg(&repo);
        let mut p = LocalBare::new(cfg);

        // provision without useradd: bare repo only (skip ensure_git_user by
        // initializing directly — provision() calls it; use ensure_bare_repo via
        // a repo that already "exists" is unnecessary: run provision only when
        // the git user check passes, else init here).
        p.run_git(&[
            "init",
            "--bare",
            "--initial-branch=main",
            &repo.to_string_lossy(),
        ])
        .unwrap();

        let spec = RepoSpec {
            branch: "main".into(),
            path_in_repo: "clusters/c0".into(),
            cluster_id: "c0".into(),
        };
        let tree = seed::render_seed_tree(&spec, "ssh://git@10.0.0.5/srv/git/infra.git");

        let first = p.seed_commit(&tree, &spec).unwrap();
        assert!(!first.skipped);

        let second = p.seed_commit(&tree, &spec).unwrap();
        assert!(second.skipped, "re-run must be a no-op");
        assert_eq!(first.sha, second.sha);

        // Read-only enforcement: write access is refused outright.
        let key = keys::generate(&dir.path().join("k")).unwrap();
        let err = p
            .register_key(&key, KeyAccess::ReadWrite)
            .unwrap_err()
            .to_string();
        assert!(err.contains("read-only"), "unexpected error: {err}");
    }

    #[test]
    fn receive_pack_override_carries_safe_directory() {
        let s = receive_pack_override(Path::new("/var/lib/amiterra/git/infra.git"));
        assert!(s.starts_with("git -c safe.directory="));
        assert!(s.contains("/var/lib/amiterra/git/infra.git"));
        assert!(s.ends_with(" receive-pack"));
    }

    #[test]
    fn seed_commit_lands_on_requested_branch() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("infra.git");
        let cfg = test_cfg(&repo);
        let mut p = LocalBare::new(cfg);
        p.run_git(&[
            "init",
            "--bare",
            "--initial-branch=main",
            &repo.to_string_lossy(),
        ])
        .unwrap();

        let spec = RepoSpec {
            branch: "release".into(),
            path_in_repo: "clusters/c0".into(),
            cluster_id: "c0".into(),
        };
        let tree = seed::render_seed_tree(&spec, "ssh://git@10.0.0.5/srv/git/infra.git");
        let first = p.seed_commit(&tree, &spec).unwrap();
        assert!(!first.skipped);
        // The seed must land on the branch Flux tracks, not a hardcoded `main`.
        let head = p
            .run_git(&["--git-dir", &repo.to_string_lossy(), "rev-parse", "release"])
            .unwrap();
        assert_eq!(head, first.sha);
    }
}
