//! ed25519 deploy keys for GitOps bootstrap.
//!
//! Keys are generated **locally** on the node: the private key
//! never leaves `/var/lib/amiterra/gitops/`, is written `0600`, and never appears
//! in state files, logs or reports. The public half is registered with the Git
//! provider as a **read-only** deploy key.

use anyhow::{Context, Result};
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::ui::Palette;

/// Directory for persistent GitOps state and key material.
pub const GITOPS_DIR: &str = "/var/lib/amiterra/gitops";
/// Private deploy key path (0600, never leaves the node).
pub const PRIVATE_KEY_PATH: &str = "/var/lib/amiterra/gitops/flux-deploy-key";
/// Public deploy key path (0644).
pub const PUBLIC_KEY_PATH: &str = "/var/lib/amiterra/gitops/flux-deploy-key.pub";
/// Comment recorded in the public key for provider UIs.
pub const KEY_COMMENT: &str = "amiterra-flux-readonly";

/// A locally generated OpenSSH deploy key pair.
pub struct DeployKey {
    /// Path of the private key file.
    pub private_path: PathBuf,
    /// OpenSSH public key line (`ssh-ed25519 AAAA…`), without comment.
    pub public_line: String,
    /// SHA256 fingerprint for operator verification (never the key material itself).
    pub fingerprint: String,
}

/// Generate a fresh ed25519 key pair at `private_path` (plus `.pub`).
pub fn generate(private_path: &Path) -> Result<DeployKey> {
    let key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519)
        .context("ed25519 key generation failed")?;
    write_key_pair(private_path, &key)
}

/// Persist an existing [`PrivateKey`] at `private_path` (0600) + `.pub` (0644).
pub fn write_key_pair(private_path: &Path, key: &PrivateKey) -> Result<DeployKey> {
    let private_openssh = key
        .to_openssh(LineEnding::LF)
        .context("failed to serialize private key")?;
    let public_line = key
        .public_key()
        .to_openssh()
        .context("failed to serialize public key")?;
    let fingerprint = key
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();

    if let Some(parent) = private_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    // Private key: 0600, owner-only (`.mode` applies only at creation, so an
    // existing file is re-chmod'ed explicitly).
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut f = opts
        .open(private_path)
        .with_context(|| format!("failed to write {}", private_path.display()))?;
    f.write_all(private_openssh.as_bytes())
        .context("failed to write private key material")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(private_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to chmod {}", private_path.display()))?;
    }

    // Public key: plain OpenSSH line + comment.
    let public_path = public_path_of(private_path);
    let public_body = format!("{public_line} {KEY_COMMENT}\n");
    fs::write(&public_path, public_body)
        .with_context(|| format!("failed to write {}", public_path.display()))?;

    Ok(DeployKey {
        private_path: private_path.to_path_buf(),
        public_line,
        fingerprint,
    })
}

/// Load the key pair from disk when it already exists (idempotent converge).
///
/// Repairs loose permissions on the private key (0600 is part of the key's
/// security contract — a pre-existing 0644 file must not be reused as-is).
pub fn load_existing(private_path: &Path) -> Result<DeployKey> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(private_path)
            .with_context(|| format!("failed to stat {}", private_path.display()))?;
        if meta.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(private_path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to chmod {}", private_path.display()))?;
        }
    }
    let raw = fs::read_to_string(private_path)
        .with_context(|| format!("failed to read {}", private_path.display()))?;
    let key: PrivateKey = raw
        .parse()
        .context("existing deploy key is not a valid OpenSSH private key")?;
    let public_line = key
        .public_key()
        .to_openssh()
        .context("failed to serialize public key")?;
    let fingerprint = key
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    Ok(DeployKey {
        private_path: private_path.to_path_buf(),
        public_line,
        fingerprint,
    })
}

/// Ensure a deploy key exists at `private_path`; generate only when missing (G5).
pub fn ensure(private_path: &Path) -> Result<DeployKey> {
    if private_path.exists() {
        println!(
            "  {}",
            Palette::dim(&format!("Reusing deploy key {}", private_path.display()))
        );
        return load_existing(private_path);
    }
    generate(private_path)
}

fn public_path_of(private_path: &Path) -> PathBuf {
    let mut s = private_path.as_os_str().to_owned();
    s.push(".pub");
    PathBuf::from(s)
}

/// Canonical OpenSSH line for `authorized_keys` with forced read-only command.
///
/// The `command=` restriction pins the session to `git upload-pack` on exactly
/// one repository: push (`git receive-pack`) can never run with this key (G2),
/// even if the account is otherwise reachable.
pub fn authorized_keys_line(public_line: &str, forced_command: &str) -> String {
    let opts = [
        format!("command=\"{forced_command}\""),
        "no-pty".to_string(),
        "no-agent-forwarding".to_string(),
        "no-port-forwarding".to_string(),
        "no-X11-forwarding".to_string(),
        "no-user-rc".to_string(),
    ];
    format!("{} {} {KEY_COMMENT}", opts.join(","), public_line.trim())
}

/// Build a `known_hosts` entry for `host` from a host public key line (G8).
///
/// Accepts the raw content of `/etc/ssh/ssh_host_*_key.pub`
/// (`ssh-ed25519 AAAA… comment`) and prefixes the host name.
pub fn known_hosts_entry(host: &str, host_pub_line: &str) -> Result<String> {
    let mut parts = host_pub_line.split_whitespace();
    let key_type = parts
        .next()
        .context("host public key line is empty: missing key type")?;
    let key_data = parts
        .next()
        .context("host public key line is empty: missing key data")?;
    Ok(format!("{host} {key_type} {key_data}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generate_writes_private_0600_and_public_line() {
        let dir = tempdir().unwrap();
        let priv_path = dir.path().join("id_ed25519");
        let key = generate(&priv_path).unwrap();

        assert!(priv_path.exists());
        let public_path = public_path_of(&priv_path);
        assert!(public_path.exists());

        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&priv_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "private key must be 0600");

        assert!(key.public_line.starts_with("ssh-ed25519 "));
        assert!(key.fingerprint.starts_with("SHA256:"));

        let pub_body = fs::read_to_string(&public_path).unwrap();
        assert!(pub_body.contains(&key.public_line));
        assert!(pub_body.contains(KEY_COMMENT));
    }

    #[test]
    fn ensure_reuses_existing_key() {
        let dir = tempdir().unwrap();
        let priv_path = dir.path().join("id_ed25519");
        let first = generate(&priv_path).unwrap();
        let second = ensure(&priv_path).unwrap();
        assert_eq!(first.fingerprint, second.fingerprint);
        assert_eq!(first.public_line, second.public_line);
    }

    #[test]
    fn authorized_keys_line_forces_upload_pack_only() {
        let line = authorized_keys_line("ssh-ed25519 AAAATEST", "git upload-pack /srv/repo.git");
        assert!(line.contains("command=\"git upload-pack /srv/repo.git\""));
        assert!(line.contains("no-port-forwarding"));
        assert!(line.contains("ssh-ed25519 AAAATEST"));
        assert!(!line.contains("receive-pack"));
    }

    #[test]
    fn known_hosts_entry_strips_comment_and_prefixes_host() {
        let entry = known_hosts_entry("10.0.0.5", "ssh-ed25519 AAAAHOSTKEY root@node").unwrap();
        assert_eq!(entry, "10.0.0.5 ssh-ed25519 AAAAHOSTKEY");
    }

    #[test]
    fn known_hosts_entry_rejects_empty_line() {
        assert!(known_hosts_entry("10.0.0.5", "   ").is_err());
    }
}
