//! Flux installation and Git binding.
//!
//! Controllers come from the vendored, checksum-pinned `assets/flux/install.yaml`
//! and are delivered through k3s auto-deploy manifests — the same
//! mechanism as Cilium and the storage class (`providers/server.rs`). Binding
//! objects (Secret + GitRepository + root Kustomization) are rendered as YAML and
//! applied with `kubectl apply`; re-application is content-idempotent (G5).

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

/// Vendored Flux install manifest (official v2.10.0 release artifact).
pub const INSTALL_YAML: &str = include_str!("../../assets/flux/install.yaml");
/// Expected sha256 of [`INSTALL_YAML`]; verified before first apply (G6).
pub const INSTALL_YAML_SHA256: &str =
    "a8c838ccd9be5d30eba9df87cd229b7c4eb80c0049fba1bc3b9840829f267f28";
/// Pinned Flux version documented in state and `ami gitops status`.
pub const FLUX_VERSION: &str = "2.10.0";

/// k3s auto-deploy manifest for the Flux controllers.
pub const K3S_MANIFEST_PATH: &str = "/var/lib/rancher/k3s/server/manifests/flux-components.yaml";
/// Namespace of Flux controllers and binding objects.
pub const FLUX_NAMESPACE: &str = "flux-system";
/// Name of the Git credentials Secret referenced by the GitRepository.
pub const FLUX_SECRET_NAME: &str = "flux-system";

/// Verify the embedded manifest against the pinned checksum (G6).
pub fn verify_install_yaml() -> Result<()> {
    let actual: String = Sha256::digest(INSTALL_YAML.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if actual != INSTALL_YAML_SHA256 {
        bail!(
            "vendored Flux install.yaml checksum mismatch: expected {INSTALL_YAML_SHA256}, \
             got {actual}. The build asset is corrupted or was tampered with."
        );
    }
    Ok(())
}

/// Install Flux controllers via the k3s auto-deploy directory. Idempotent:
/// content-identical file is left untouched (G5).
pub fn install_controllers(manifest_path: &Path) -> Result<bool> {
    verify_install_yaml()?;
    if let Ok(existing) = std::fs::read_to_string(manifest_path)
        && existing == INSTALL_YAML
    {
        return Ok(false);
    }
    if let Some(parent) = manifest_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(manifest_path, INSTALL_YAML)
        .with_context(|| format!("failed to write {}", manifest_path.display()))?;
    Ok(true)
}

fn kubectl_ok(args: &[&str]) -> bool {
    Command::new("kubectl")
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Wait until the staged Flux manifests are actually live in the cluster.
///
/// k3s's manifest deployer applies `/var/lib/rancher/k3s/server/manifests`
/// asynchronously — writing the file returns long before the `flux-system`
/// namespace and CRDs exist. Binding objects (Secret, GitRepository,
/// Kustomization) fail with `NotFound` if applied too early.
pub fn wait_for_binding_prereqs(timeout_secs: u64) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let crds = [
        "gitrepositories.source.toolkit.fluxcd.io",
        "kustomizations.kustomize.toolkit.fluxcd.io",
    ];
    loop {
        let ns_live = kubectl_ok(&["get", "namespace", FLUX_NAMESPACE]);
        // CRDs must be Established, not merely created: applying CRs against a
        // just-registered CRD fails while its API is not served yet.
        let crds_live = crds.iter().all(|crd| {
            Command::new("kubectl")
                .args([
                    "get",
                    "crd",
                    crd,
                    "-o",
                    r#"jsonpath={.status.conditions[?(@.type=="Established")].status}"#,
                ])
                .output()
                .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "True")
                .unwrap_or(false)
        });
        if ns_live && crds_live {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "Flux APIs not live within {timeout_secs}s (namespace '{FLUX_NAMESPACE}' + \
                 source/kustomize CRDs). The k3s manifest deployer may have failed — check \
                 `kubectl get pods -n kube-system` and {K3S_MANIFEST_PATH}"
            );
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

/// Binding inputs for the Flux ↔ Git secret and sync objects.
pub struct GitBinding {
    pub remote_url: String,
    pub branch: String,
    pub path_in_repo: String,
    /// OpenSSH private key material (stays in the rendered Secret only).
    pub private_key: String,
    pub known_hosts: String,
}

/// Render the Git credentials Secret (opaque, OpenSSH key formats for source-controller).
///
/// Values live under `data:` as single-line base64 (Kubernetes stores them
/// verbatim). Putting base64 into `stringData:` would be double-encoded —
/// `stringData` is plaintext-only and gets base64'd once by the API server.
pub fn render_git_secret(b: &GitBinding) -> String {
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s.as_bytes());
    format!(
        "apiVersion: v1\n\
         kind: Secret\n\
         metadata:\n\
         \x20 name: {FLUX_SECRET_NAME}\n\
         \x20 namespace: {FLUX_NAMESPACE}\n\
         type: Opaque\n\
         data:\n\
         \x20 identity: {identity}\n\
         \x20 known_hosts: {known}\n\
         \x20 username: {user}\n",
        identity = b64(&b.private_key),
        known = b64(&b.known_hosts),
        user = b64("git"),
    )
}

/// Render the GitRepository + root Kustomization pair (cluster-side counterpart
/// of the in-repo `gotk-sync.yaml`: the repo copy is the long-term
/// owner; this object bootstraps the first sync).
pub fn render_sync_objects(b: &GitBinding) -> String {
    format!(
        "apiVersion: source.toolkit.fluxcd.io/v1\n\
         kind: GitRepository\n\
         metadata:\n\
         \x20 name: flux-system\n\
         \x20 namespace: {FLUX_NAMESPACE}\n\
         spec:\n\
         \x20 interval: 1m0s\n\
         \x20 ref:\n\
         \x20   branch: {branch}\n\
         \x20 url: {url}\n\
         \x20 secretRef:\n\
         \x20   name: {FLUX_SECRET_NAME}\n\
         ---\n\
         apiVersion: kustomize.toolkit.fluxcd.io/v1\n\
         kind: Kustomization\n\
         metadata:\n\
         \x20 name: flux-system\n\
         \x20 namespace: {FLUX_NAMESPACE}\n\
         spec:\n\
         \x20 interval: 10m0s\n\
         \x20 path: ./{path}\n\
         \x20 prune: true\n\
         \x20 sourceRef:\n\
         \x20   kind: GitRepository\n\
         \x20   name: flux-system\n\
         \x20 timeout: 5m0s\n",
        branch = b.branch,
        url = b.remote_url,
        path = b.path_in_repo,
    )
}

/// Apply binding YAML with `kubectl apply -f -`. Returns true when applied.
pub fn kubectl_apply(yaml: &str) -> Result<()> {
    let mut child = Command::new("kubectl")
        .args(["--request-timeout=60s", "apply", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to run kubectl (is k3s installed and running?)")?;
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .context("kubectl stdin unavailable")?
            .write_all(yaml.as_bytes())
            .context("failed to pass manifests to kubectl")?;
    }
    let out = child.wait_with_output().context("kubectl did not finish")?;
    if !out.status.success() {
        bail!(
            "kubectl apply failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Return the remote URL of an already-installed `GitRepository/flux-system`, if any.
pub fn existing_gitrepository_url() -> Option<String> {
    let out = Command::new("kubectl")
        .args([
            "-n",
            FLUX_NAMESPACE,
            "get",
            "gitrepository",
            "flux-system",
            "-o",
            "jsonpath={.spec.url}",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let url = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if url.is_empty() { None } else { Some(url) }
}

/// Live sync state of the root Kustomization (M1: status must not trust state.yaml alone).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyncHealth {
    /// Root Kustomization reports Ready.
    Ready,
    /// Flux API reachable but the Kustomization is not Ready.
    Degraded,
    /// Flux objects absent (namespace empty or CRDs missing).
    NotInstalled,
    /// `kubectl` unavailable or cluster unreachable — cannot tell.
    Unknown,
}

impl std::fmt::Display for SyncHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SyncHealth::Ready => "Ready",
            SyncHealth::Degraded => "Degraded",
            SyncHealth::NotInstalled => "NotInstalled",
            SyncHealth::Unknown => "Unknown",
        })
    }
}

/// Probe live Flux state through kubectl (best-effort, never fails).
pub fn live_sync_health() -> SyncHealth {
    let ready = Command::new("kubectl")
        .args([
            "-n",
            FLUX_NAMESPACE,
            "get",
            "kustomization",
            "flux-system",
            "-o",
            r#"jsonpath={.status.conditions[?(@.type=="Ready")].status}"#,
        ])
        .output();
    let out = match ready {
        Ok(o) => o,
        Err(_) => return SyncHealth::Unknown,
    };
    if out.status.success() {
        return match String::from_utf8_lossy(&out.stdout).trim() {
            "True" => SyncHealth::Ready,
            _ => SyncHealth::Degraded,
        };
    }
    // kubectl ran but the object/CRD is missing.
    SyncHealth::NotInstalled
}

/// End-to-end smoke test of the SSH contract (design review finding): fetch the
/// remote with the deploy key **before** binding Flux, so sshd/key/repo problems
/// fail early with a clear error instead of a silent stale Kustomization.
pub fn smoke_fetch(remote_url: &str, private_key: &Path, known_hosts: &str) -> Result<()> {
    let tmp = tempfile::tempdir().context("failed to create temp dir for smoke fetch")?;
    let kh_path = tmp.path().join("known_hosts");
    std::fs::write(&kh_path, format!("{known_hosts}\n"))
        .context("failed to write temp known_hosts")?;
    let ssh_cmd = format!(
        "ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={}",
        private_key.display(),
        kh_path.display()
    );
    let out = Command::new("git")
        .args(["ls-remote", "--exit-code", remote_url])
        .env("GIT_SSH_COMMAND", &ssh_cmd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .context("failed to run `git ls-remote` (is git installed?)")?;
    // --exit-code: 2 = no matching refs (empty repo is fine), anything else with
    // non-success status is an auth/connectivity failure.
    if !out.status.success() {
        let code = out.status.code().unwrap_or(1);
        if code != 2 {
            bail!(
                "smoke fetch failed for {remote_url}: {} \
                 (check sshd reachability from the cluster and the deploy key registration)",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    }
    Ok(())
}

/// Wait until the root Kustomization reports Ready (bounded).
///
/// `kubectl wait` output is captured: leaking it to the terminal breaks the
/// spinner line rendering.
pub fn wait_for_kustomization_ready(timeout_secs: u64) -> Result<bool> {
    let out = Command::new("kubectl")
        .args([
            "-n",
            FLUX_NAMESPACE,
            "wait",
            "kustomization/flux-system",
            "--for=condition=Ready",
            &format!("--timeout={timeout_secs}s"),
        ])
        .output()
        .context("failed to run kubectl wait")?;
    Ok(out.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> GitBinding {
        GitBinding {
            remote_url: "ssh://git@10.0.0.5/srv/git/infra.git".into(),
            branch: "main".into(),
            path_in_repo: "clusters/c0".into(),
            private_key: "PRIVKEY".into(),
            known_hosts: "10.0.0.5 ssh-ed25519 AAAAHOST".into(),
        }
    }

    #[test]
    fn vendored_install_yaml_matches_pinned_checksum() {
        verify_install_yaml().unwrap();
    }

    #[test]
    fn install_controllers_is_content_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flux-components.yaml");
        assert!(install_controllers(&path).unwrap(), "first run writes");
        assert!(
            !install_controllers(&path).unwrap(),
            "second run is a no-op"
        );
    }

    #[test]
    fn git_secret_hides_key_material_behind_base64() {
        let yaml = render_git_secret(&binding());
        assert!(yaml.contains("kind: Secret"));
        assert!(yaml.contains("name: flux-system"));
        // Key material must not appear in clear text, and must live under
        // `data:` (base64) — never `stringData:` (which would double-encode).
        assert!(!yaml.contains("PRIVKEY"));
        assert!(yaml.contains("data:"));
        assert!(!yaml.contains("stringData"));
        let b64 = base64::engine::general_purpose::STANDARD.encode("PRIVKEY");
        assert!(yaml.contains(&b64));
    }

    #[test]
    fn sync_objects_point_at_remote_branch_and_path() {
        let yaml = render_sync_objects(&binding());
        assert!(yaml.contains("url: ssh://git@10.0.0.5/srv/git/infra.git"));
        assert!(yaml.contains("branch: main"));
        assert!(yaml.contains("path: ./clusters/c0"));
        assert!(yaml.contains("kind: GitRepository"));
        assert!(yaml.contains("kind: Kustomization"));
    }
}
