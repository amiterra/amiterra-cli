//! GitOps bootstrap: provision Git, deploy keys, seed the infrastructure layer,
//! install Flux controllers (vendored) and bind Flux to the repository.
//!
//! Turns a running k3s node into a GitOps-managed cluster. Converge semantics:
//! every step compares desired vs actual and changes nothing that already
//! matches. Re-running `ami gitops bootstrap` on a converged node is a no-op.
//!
//! This module never runs implicitly — only from `ami gitops bootstrap`,
//! `ami init --gitops-bootstrap` or an interactive wizard decision.

pub mod cli;
pub mod flux;
pub mod keys;
pub mod local_bare;
pub mod provider;
pub mod seed;
pub mod state;

use anyhow::{Context, Result, bail};
use std::path::PathBuf;

use crate::ui::{Palette, Ui};
use keys::{PRIVATE_KEY_PATH, PUBLIC_KEY_PATH};
use local_bare::{LocalBare, LocalBareConfig};
use provider::{GitProvider, GitProviderKind, RepoSpec};
use state::GitopsState;

/// Default cluster id used in the `clusters/<id>/` layout.
pub const DEFAULT_CLUSTER_ID: &str = "cluster-0";
/// Default branch tracked by Flux.
pub const DEFAULT_BRANCH: &str = "main";

/// Options for [`bootstrap`]; mirrors `ami gitops bootstrap` flags.
#[derive(Debug, Clone)]
pub struct BootstrapOptions {
    /// Remote URL override. `None` → LocalBare on this node (default).
    pub git: Option<String>,
    /// Tracked branch.
    pub branch: String,
    /// Cluster id for `clusters/<id>/`.
    pub cluster_id: String,
    /// Node IP used in the LocalBare SSH URL.
    pub node_ip: String,
    /// Skip interactive confirmation.
    pub yes: bool,
    /// Report planned steps without changing anything.
    pub dry_run: bool,
    /// Wait for the root Kustomization to become Ready after apply.
    pub wait_ready: bool,
}

impl Default for BootstrapOptions {
    fn default() -> Self {
        Self {
            git: None,
            branch: DEFAULT_BRANCH.to_string(),
            cluster_id: DEFAULT_CLUSTER_ID.to_string(),
            node_ip: String::new(),
            yes: false,
            dry_run: false,
            wait_ready: true,
        }
    }
}

/// Result summary for CLI / JSON reporting.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BootstrapReport {
    pub provider: String,
    pub remote_url: String,
    pub repo_created: bool,
    pub key_fingerprint: String,
    pub seed_sha: Option<String>,
    pub seed_skipped: bool,
    pub controllers_installed: bool,
    pub converged_at: String,
}

/// One applied intent from the `_intent/` journal (audit surface).
#[derive(Debug, Clone, serde::Serialize)]
pub struct IntentSummary {
    pub change_id: String,
    pub applied_at: String,
    pub status: String,
    pub origin: String,
    pub actor: String,
    /// Short tree hash (12 hex chars) — the review↔result binding.
    pub tree_hash: String,
}

/// Human-readable converge report for `ami gitops status`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GitopsStatus {
    pub installed: bool,
    pub state: Option<GitopsState>,
    pub private_key_present: bool,
    pub public_key_path: String,
    /// SHA256 fingerprint of the deploy key, when one exists on disk.
    pub key_fingerprint: Option<String>,
    /// Live Flux sync health (M1: probed from the cluster, not from state.yaml).
    pub sync: flux::SyncHealth,
    /// `_intent/` journal (newest last) — what was applied and when.
    #[serde(default)]
    pub intent_log: Vec<IntentSummary>,
    /// Drift of the fleet repo (`decompile(tree)` vs `topology.yaml`).
    #[serde(default)]
    pub drift: Option<String>,
}

/// Conservative grammar for values that end up in rendered YAML and filesystem
/// paths: ASCII identifier chars only (blocks whitespace, quotes, newlines,
/// `../` path traversal and YAML/manifest injection).
fn validate_token(value: &str, what: &str, allow_slash: bool) -> Result<()> {
    let ok = !value.is_empty()
        && value.len() <= 63
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') || (allow_slash && c == '/')
        })
        && !value.starts_with('-')
        && !value.contains("..");
    if !ok {
        bail!(
            "invalid {what} '{value}': use ASCII letters, digits, '.', '_', '-'{} \
             (max 63 chars, no leading '-', no '..')",
            if allow_slash { ", '/'" } else { "" }
        );
    }
    Ok(())
}

/// Host/IP grammar for the SSH remote: conservative allowlist (no userinfo,
/// whitespace, quotes or slashes — those would rewrite the remote URL).
fn validate_host(value: &str, what: &str) -> Result<()> {
    let ok = !value.is_empty()
        && value.len() <= 255
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '[' | ']'));
    if !ok {
        bail!("invalid {what} '{value}': expected an IP literal or hostname");
    }
    Ok(())
}

/// Run the full bootstrap converge. Idempotent.
pub fn bootstrap(opts: &BootstrapOptions) -> Result<BootstrapReport> {
    // dry_run_report prints its own header — avoid the double header.
    if !opts.dry_run {
        Ui::header(
            "Amiterra GitOps Bootstrap",
            "Flux controllers + Git binding (GitOps-first)",
        );
    }

    if opts.git.is_some() {
        bail!(
            "custom --git remotes are not supported yet: LocalBare is the only \
             implemented provider today. GitHub / GitLab / self-hosted land in \
             `amiterra git connect` (planned)."
        );
    }
    if opts.node_ip.is_empty() {
        bail!("node IP is required for the LocalBare SSH remote (pass --node-ip)");
    }

    // C1 (multi-node safety): never rebind a cluster that already has a different
    // Git source. Without this, a join node running bootstrap would overwrite the
    // cluster's Secret/GitRepository and orphan the bootstrap node's repository.
    if let Some(existing) = flux::existing_gitrepository_url() {
        let desired = match &opts.git {
            Some(url) => url.clone(),
            None => LocalBare::remote_url_for(
                &opts.node_ip,
                local_bare::GIT_USER,
                std::path::Path::new(local_bare::REPO_PATH),
            ),
        };
        if existing != desired {
            bail!(
                "cluster is already bound to a different Git repository:\n\
                 \x20 existing : {existing}\n\
                 \x20 requested: {desired}\n\
                 Refusing to rebind (this would orphan the current source of truth). \
                 Bootstrap must run on the node that owns the existing binding, or use \
                 `ami gitops retarget` for a deliberate migration."
            );
        }
    }
    // Rendered into YAML (Flux objects) and repo paths — validate before any
    // host mutation so hostile input cannot inject manifests or escape paths.
    validate_token(&opts.cluster_id, "cluster id", false)?;
    validate_token(&opts.branch, "branch", true)?;
    validate_host(&opts.node_ip, "node IP")?;

    let spec = RepoSpec {
        branch: opts.branch.clone(),
        path_in_repo: format!("clusters/{}", opts.cluster_id),
        cluster_id: opts.cluster_id.clone(),
    };

    let mut provider: Box<dyn GitProvider> =
        Box::new(LocalBare::new(LocalBareConfig::production(&opts.node_ip)));

    if opts.dry_run {
        return dry_run_report(&spec, provider.as_ref(), opts);
    }

    if !opts.yes {
        // Honest wording: a converge re-run is not a first install.
        let question = if is_bootstrapped() {
            "Re-run GitOps bootstrap (idempotent converge)?"
        } else {
            "Bootstrap GitOps on this node?"
        };
        match crate::tune::confirm(question, false) {
            Ok(true) => {}
            Ok(false) => {
                println!("  Aborted. Nothing changed.");
                return Ok(BootstrapReport {
                    provider: provider.kind().to_string(),
                    remote_url: provider.remote_url(),
                    repo_created: false,
                    key_fingerprint: String::new(),
                    seed_sha: None,
                    seed_skipped: false,
                    controllers_installed: false,
                    converged_at: state::now_rfc3339(),
                });
            }
            // Non-interactive without --yes is a refusal, not a silent no-op:
            // scripts must see a non-zero exit.
            Err(e) => {
                return Err(
                    e.context("GitOps bootstrap requires interactive confirmation or --yes")
                );
            }
        }
    }

    // 1. Provision repository (bare repo + git-shell account).
    let s = Ui::spinner("Provisioning Git repository...");
    let provisioned = provider.provision().context("Git provisioning failed")?;
    s.success(&format!(
        "Repository ready ({})",
        if provisioned.created {
            "created"
        } else {
            "existing"
        }
    ));

    // 2. Deploy key: reuse if present, generate otherwise (key stays node-local).
    let s = Ui::spinner("Ensuring deploy key...");
    let key = keys::ensure(PathBuf::from(PRIVATE_KEY_PATH).as_path())
        .context("deploy key setup failed")?;
    s.success(&format!("Deploy key ready ({})", key.fingerprint));

    // 3. Register read-only key with the provider.
    let s = Ui::spinner("Registering read-only deploy key...");
    provider
        .register_key(&key, provider::KeyAccess::ReadOnly)
        .context("deploy key registration failed")?;
    s.success("Deploy key registered (read-only, git-upload-pack only)");

    // 4. Seed commit of the infrastructure layer.
    let tree = seed::render_seed_tree(&spec, &provisioned.remote_url);
    let s = Ui::spinner("Seeding infrastructure layer...");
    let seed_commit = provider
        .seed_commit(&tree, &spec)
        .context("seed commit failed")?;
    if seed_commit.skipped {
        s.success(&format!(
            "Seed up to date ({})",
            &seed_commit.sha[..12.min(seed_commit.sha.len())]
        ));
    } else {
        s.success(&format!(
            "Seed committed ({}...)",
            &seed_commit.sha[..12.min(seed_commit.sha.len())]
        ));
    }

    // 5. Known hosts (zero-TOFU).
    let known_hosts = provider.known_hosts().context("known_hosts build failed")?;

    // 5b. Smoke-fetch over the exact SSH path Flux will use (early, clear failure).
    let s = Ui::spinner("Smoke-testing SSH fetch path...");
    flux::smoke_fetch(&provisioned.remote_url, &key.private_path, &known_hosts)
        .context("SSH fetch smoke test failed")?;
    s.success("SSH fetch path verified (deploy key + known_hosts + repo reachable)");

    // 6. Stage vendored Flux controllers for k3s auto-deploy.
    let s = Ui::spinner("Staging Flux controllers...");
    let installed = flux::install_controllers(PathBuf::from(flux::K3S_MANIFEST_PATH).as_path())
        .context("Flux controller install failed")?;
    s.success(if installed {
        "Flux manifests staged for k3s auto-deploy"
    } else {
        "Flux manifests already staged"
    });

    // 6b. k3s applies staged manifests asynchronously — wait until the
    // flux-system namespace and CRDs are live, or the binding apply fails
    // with NotFound.
    let s = Ui::spinner("Waiting for Flux APIs to become live...");
    flux::wait_for_binding_prereqs(180).context("Flux API readiness gate failed")?;
    s.success("Flux namespace and CRDs are live");

    // 7. Bind Flux to the repository.
    let binding = flux::GitBinding {
        remote_url: provisioned.remote_url.clone(),
        branch: spec.branch.clone(),
        path_in_repo: spec.path_in_repo.clone(),
        private_key: std::fs::read_to_string(&key.private_path)
            .context("failed to read deploy key material")?,
        known_hosts,
    };
    let s = Ui::spinner("Binding Flux to Git repository...");
    flux::kubectl_apply(&flux::render_git_secret(&binding))
        .and_then(|_| flux::kubectl_apply(&flux::render_sync_objects(&binding)))
        .context("Flux Git binding failed")?;
    s.success("Flux bound to Git repository");

    // 8. Readiness gate: a failed gate must not claim convergence — otherwise
    // `ami gitops status` reports "bootstrapped" over a broken sync.
    if opts.wait_ready {
        let s = Ui::spinner("Waiting for root Kustomization Ready...");
        match flux::wait_for_kustomization_ready(300) {
            Ok(true) => s.success("Root Kustomization is Ready"),
            Ok(false) => {
                s.fail("Kustomization not Ready within timeout (check `flux get ks`)");
                bail!(
                    "root Kustomization not Ready — state NOT saved; \
                     fix the sync and re-run `ami gitops bootstrap`"
                );
            }
            Err(e) => {
                s.fail(&format!("readiness check failed: {e}"));
                return Err(e.context("readiness check failed"));
            }
        }
    }

    // 9. Persist state for status / future converge diffs.
    let st = GitopsState {
        provider: provider.kind().to_string(),
        remote_url: provisioned.remote_url.clone(),
        branch: spec.branch.clone(),
        path_in_repo: spec.path_in_repo.clone(),
        cluster_id: spec.cluster_id.clone(),
        flux_version: flux::FLUX_VERSION.to_string(),
        key_fingerprint: key.fingerprint.clone(),
        seed_sha: Some(seed_commit.sha.clone()),
        seed_tree_hash: seed::tree_hash(&tree),
        converged_at: state::now_rfc3339(),
    };
    st.save(&GitopsState::default_path())?;

    Ui::card(
        "GitOps Bootstrap Complete",
        &[
            ("Provider", &provider.kind().to_string()),
            ("Remote", &provisioned.remote_url),
            ("Branch", &spec.branch),
            ("Path", &spec.path_in_repo),
            ("Flux", flux::FLUX_VERSION),
            ("Key fingerprint", &key.fingerprint),
        ],
    );

    Ok(BootstrapReport {
        provider: provider.kind().to_string(),
        remote_url: provisioned.remote_url,
        repo_created: provisioned.created,
        key_fingerprint: key.fingerprint,
        seed_sha: Some(seed_commit.sha),
        seed_skipped: seed_commit.skipped,
        controllers_installed: installed,
        converged_at: st.converged_at,
    })
}

/// Read-only status for `ami gitops status`.
pub fn status() -> Result<GitopsStatus> {
    let state = GitopsState::load(&GitopsState::default_path())?;
    let private_key_present = PathBuf::from(PRIVATE_KEY_PATH).exists();
    // The deploy key survives a failed bootstrap, so report its fingerprint
    // even when no converge has been recorded yet.
    let key_fingerprint = keys::load_existing(PathBuf::from(PRIVATE_KEY_PATH).as_path())
        .ok()
        .map(|k| k.fingerprint);
    let (intent_log, drift) = delivery_status();
    Ok(GitopsStatus {
        installed: state.is_some(),
        private_key_present,
        public_key_path: PUBLIC_KEY_PATH.to_string(),
        state,
        key_fingerprint,
        sync: flux::live_sync_health(),
        intent_log,
        drift,
    })
}

/// Best-effort delivery journal + drift from the local fleet repository.
/// Never fails the status command — an unreachable repo just yields empty data.
fn delivery_status() -> (Vec<IntentSummary>, Option<String>) {
    use crate::delivery::agent::RepoWriter;
    use crate::delivery::intent::journal_entries;

    let repo_path = PathBuf::from(local_bare::REPO_PATH);
    if !repo_path.exists() {
        return (Vec::new(), None);
    }
    let writer = RepoWriter::new(repo_path, DEFAULT_BRANCH.to_string());
    if writer.head().ok().flatten().is_none() {
        return (Vec::new(), None);
    }
    let log = journal_entries(&writer)
        .map(|entries| {
            entries
                .iter()
                .map(|r| IntentSummary {
                    change_id: r.metadata.change_id.clone(),
                    applied_at: r.metadata.applied_at.clone(),
                    status: r.spec.status.clone(),
                    origin: r.spec.origin.to_string(),
                    actor: r.spec.actor.clone(),
                    tree_hash: r
                        .spec
                        .tree_hash
                        .trim_start_matches("sha256:")
                        .chars()
                        .take(12)
                        .collect(),
                })
                .collect()
        })
        .unwrap_or_default();
    let drift = std::fs::read_to_string(GitopsState::default_path())
        .ok()
        .and_then(|raw| serde_yaml::from_str::<GitopsState>(&raw).ok())
        .and_then(|st| {
            let topo_path = format!("clusters/{}/topology.yaml", st.cluster_id);
            let topology = writer.read_file(&topo_path).ok().flatten()?;
            crate::delivery::drift::detect(&writer, &topology)
                .ok()
                .map(|r| r.summary())
        });
    (log, drift)
}

/// Print the status as a human-readable card or JSON.
pub fn print_status(json: bool) -> Result<()> {
    let st = status()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&st)?);
        return Ok(());
    }
    Ui::header("Amiterra GitOps Status", "Bootstrap state and deploy key");
    match &st.state {
        None => {
            println!(
                "  State           : {}",
                Palette::dim("not bootstrapped (run `ami gitops bootstrap`)")
            );
            println!(
                "  Remote          : {}",
                Palette::dim("— (binds on first successful bootstrap)")
            );
            println!(
                "  Key fingerprint : {}",
                st.key_fingerprint
                    .as_deref()
                    .map(|f| f.to_string())
                    .unwrap_or_else(|| Palette::dim("— (no deploy key yet)"))
            );
        }
        Some(s) => {
            Ui::card(
                "Bootstrapped",
                &[
                    ("Provider", &s.provider),
                    ("Remote", &s.remote_url),
                    ("Branch", &s.branch),
                    ("Path", &s.path_in_repo),
                    ("Flux", &s.flux_version),
                    ("Key fingerprint", &s.key_fingerprint),
                    ("Seed", s.seed_sha.as_deref().unwrap_or("—")),
                    ("Converged at", &s.converged_at),
                ],
            );
        }
    }
    match &st.drift {
        Some(d) => println!("  Drift           : {d}"),
        None => println!(
            "  Drift           : {}",
            Palette::dim("— (no compiled tree yet)")
        ),
    }
    if !st.intent_log.is_empty() {
        println!("  Recent changes  :");
        for e in st.intent_log.iter().rev().take(5) {
            println!(
                "    {}  {}  {}  tree {}  ({}/{})",
                e.applied_at, e.change_id, e.status, e.tree_hash, e.origin, e.actor
            );
        }
    }
    println!(
        "  Private key     : {}",
        if st.private_key_present {
            Palette::green("● present (0600, node-local)")
        } else {
            Palette::yellow("○ missing")
        }
    );
    println!("  Public key      : {}", st.public_key_path);

    // M1: live sync health — never let "bootstrapped" mask a broken sync.
    let sync_label = match st.sync {
        flux::SyncHealth::Ready => Palette::green("● Ready (root Kustomization)"),
        flux::SyncHealth::Degraded => Palette::yellow("○ Degraded (check `flux get ks`)"),
        flux::SyncHealth::NotInstalled => Palette::yellow("○ Not installed (Flux objects missing)"),
        flux::SyncHealth::Unknown => Palette::dim("? Unknown (kubectl unreachable)"),
    };
    println!("  Sync (live)     : {sync_label}");

    // M2: local-bare has no off-node replica — say so instead of implying durability.
    if let Some(s) = &st.state
        && s.provider == provider::GitProviderKind::LocalBare.to_string()
    {
        println!(
            "  {} local-bare: repository lives only on this node — no off-node backup.",
            Palette::yellow("!")
        );
        println!(
            "  {} Connect an external Git remote (`ami git connect`, planned) for durability.",
            Palette::dim("→")
        );
    }
    Ok(())
}

/// `--dry-run`: describe the converge plan without touching anything.
fn dry_run_report(
    spec: &RepoSpec,
    provider: &dyn GitProvider,
    opts: &BootstrapOptions,
) -> Result<BootstrapReport> {
    Ui::header(
        "GitOps Bootstrap (dry-run)",
        "Planned steps — zero modifications",
    );
    let remote = match &opts.git {
        Some(url) => url.clone(),
        None => provider.remote_url(),
    };
    let steps = [
        format!("Provision repository ({})", provider.kind()),
        format!("Ensure deploy key at {PRIVATE_KEY_PATH} (0600)"),
        "Register read-only deploy key (git-upload-pack only)".to_string(),
        format!("Seed commit → {}", spec.path_in_repo),
        format!(
            "Install Flux {} → {}",
            flux::FLUX_VERSION,
            flux::K3S_MANIFEST_PATH
        ),
        format!("Bind Flux → {remote} ({})", spec.branch),
    ];
    for (i, step) in steps.iter().enumerate() {
        println!(
            "    {} {}. {}",
            Palette::cyan("›"),
            i + 1,
            Palette::dim(step)
        );
    }
    println!();
    Ui::step_done(
        "Dry-run preview complete · Zero system modifications applied.",
        None,
    );
    Ok(BootstrapReport {
        provider: provider.kind().to_string(),
        remote_url: remote,
        repo_created: false,
        key_fingerprint: String::from("(dry-run)"),
        seed_sha: None,
        seed_skipped: false,
        controllers_installed: false,
        converged_at: state::now_rfc3339(),
    })
}

/// Convenience: is GitOps already bootstrapped on this node? (used by `ami init`)
pub fn is_bootstrapped() -> bool {
    GitopsState::load(&GitopsState::default_path())
        .ok()
        .flatten()
        .is_some()
}

/// Kind helper for reports.
pub fn default_provider_kind() -> GitProviderKind {
    GitProviderKind::LocalBare
}
