//! Delivery door CLI: `ami topology validate|diff` and `ami apply`
//! (Design Doc 0026 §1.7 — the local door, full air-gap parity with the
//! console path: same `amispec-core` rules, same compiler, same bundle).

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};

use super::agent::AgentConfig;
use super::channel::{default_socket, expect_applied, send_apply};
use super::intent::{
    IntentSpec, Origin, build_intent, ensure_operator_key, generate_nonce, load_allowlist,
    sign_intent,
};
use amispec_compile::{PassportIndex, build_bundle};
use amispec_schema::PassportSlots;
use amispec_validate::validate_str_with_catalog;

/// `ami topology …`
#[derive(Args, Debug, Clone, Default)]
pub struct TopologyArgs {
    #[command(subcommand)]
    pub command: Option<TopologyCommand>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TopologyCommand {
    /// Validate topology.yaml against the passport catalog (same rules as the API preview)
    Validate {
        /// Topology document
        #[arg(short = 'f', long)]
        file: PathBuf,
        /// Catalog directory of passport YAML files
        #[arg(long)]
        catalog: PathBuf,
        /// Machine-readable JSON report
        #[arg(long)]
        json: bool,
    },
    /// Review the delivery bundle: catalog pins, topology and compiled tree + tree_hash
    Diff {
        /// Topology document
        #[arg(short = 'f', long)]
        file: PathBuf,
        /// Catalog directory of passport YAML files
        #[arg(long)]
        catalog: PathBuf,
        /// Also print every compiled file
        #[arg(long)]
        full: bool,
        /// Compare against this fleet repo (default: the local-bare repo)
        #[arg(long)]
        repo: Option<PathBuf>,
        /// Machine-readable JSON report
        #[arg(long)]
        json: bool,
    },
}

/// `ami apply …`
#[derive(Args, Debug, Clone, Default)]
pub struct ApplyArgs {
    /// Topology document to deliver
    #[arg(short = 'f', long)]
    pub file: PathBuf,
    /// Catalog directory of passport YAML files
    #[arg(long)]
    pub catalog: PathBuf,
    /// Skip the interactive confirmation (tree_hash is still verified)
    #[arg(short = 'y', long)]
    pub yes: bool,
    /// Agent channel socket (default: /var/lib/amiterra/gitops/intent.sock)
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Actor id recorded in the intent journal
    #[arg(long)]
    pub actor: Option<String>,
}

/// Loaded catalog: passports for the compiler + slot contracts for validation.
pub struct Catalog {
    pub index: PassportIndex,
    pub slots: std::collections::BTreeMap<String, PassportSlots>,
}

/// Load every passport YAML in `dir` (recursive). Each document must parse as
/// a ComponentPassport — a broken catalog entry is a hard error, never a
/// silent skip (fail-fast, same as the API door).
pub fn load_catalog(dir: &Path) -> Result<Catalog> {
    if !dir.is_dir() {
        bail!("catalog directory not found: {}", dir.display());
    }
    let mut index = PassportIndex::new();
    let mut slots = std::collections::BTreeMap::new();
    let mut files: Vec<PathBuf> = walkdir_files(dir);
    files.sort();
    for path in files {
        let raw =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        index
            .insert_document(&raw)
            .map_err(|e| anyhow!("{}: {e}", path.display()))?;
        let slot = amispec_schema::parse_passport_slots(&raw)
            .map_err(|e| anyhow!("{}: {e}", path.display()))?;
        slots.insert(slot.id.clone(), slot);
    }
    if index.is_empty() {
        bail!("catalog {} contains no passports", dir.display());
    }
    Ok(Catalog { index, slots })
}

fn walkdir_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walkdir_files(&path));
            } else if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                out.push(path);
            }
        }
    }
    out
}

/// Parse + validate with the loaded catalog. Shared with the API preview —
/// identical findings is a contract (DoD: door parity).
fn validate_document(
    source: &str,
    yaml: &str,
    catalog: &Catalog,
) -> Result<amispec_validate::Report> {
    Ok(validate_str_with_catalog(
        source,
        yaml,
        &amispec_validate::Options::default(),
        &catalog.slots,
    ))
}

fn print_report(report: &amispec_validate::Report) {
    let status = if report.is_ok() { "PASS" } else { "FAIL" };
    println!("{status} {} (topology)", report.source);
    for f in &report.findings {
        let sev = match f.severity {
            amispec_validate::Severity::Error => "error",
            amispec_validate::Severity::Warning => "warn ",
        };
        println!("  {sev} [{}] {}: {}", f.rule, f.path, f.message);
    }
}

/// `ami topology validate`
pub fn handle_topology(args: TopologyArgs) -> Result<()> {
    match args.command.unwrap_or(TopologyCommand::Validate {
        file: PathBuf::new(),
        catalog: PathBuf::new(),
        json: false,
    }) {
        TopologyCommand::Validate {
            file,
            catalog,
            json,
        } => {
            let raw = read_topology(&file)?;
            let cat = load_catalog(&catalog)?;
            let report = validate_document(&file.display().to_string(), &raw, &cat)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report_json(&report))?);
            } else {
                print_report(&report);
            }
            if !report.is_ok() {
                bail!("topology validation failed");
            }
            Ok(())
        }
        TopologyCommand::Diff {
            file,
            catalog,
            full,
            repo,
            json,
        } => {
            let raw = read_topology(&file)?;
            let cat = load_catalog(&catalog)?;
            let report = validate_document(&file.display().to_string(), &raw, &cat)?;
            if !report.is_ok() {
                print_report(&report);
                bail!("topology validation failed — fix the errors before reviewing a diff");
            }
            let topology =
                amispec_schema::parse_topology(&raw).map_err(|e| anyhow!("parse topology: {e}"))?;
            let cluster_id = single_cluster_id(&topology)?;
            let bundle = build_bundle(&topology, &cluster_id, &cat.index, true)
                .map_err(|e| anyhow!("bundle: {e}"))?;
            if json {
                return print_diff_json(&bundle);
            }
            println!("tree_hash:   {}", bundle.tree_hash);
            println!("schema_hash: {}", bundle.schema_hash);
            println!("compiler:    {}", bundle.amispec_version);
            println!();
            println!("catalog pins:");
            for pin in &bundle.catalog {
                println!(
                    "  {}  {}/rev{}  {}",
                    pin.sha256["sha256:".len()..]
                        .chars()
                        .take(12)
                        .collect::<String>(),
                    pin.id,
                    pin.rev,
                    pin.path
                );
            }
            println!();
            println!("topology ({}):", bundle.topology_path);
            for line in bundle.topology_yaml.lines() {
                println!("  | {line}");
            }
            println!();
            // Honesty check: if Flux syncs another path, this bundle would
            // compile, deliver and never be applied — say so at review time.
            if let Ok(Some(state)) = crate::gitops::state::GitopsState::load(
                &crate::gitops::state::GitopsState::default_path(),
            ) {
                let want = format!("clusters/{cluster_id}");
                if state.path_in_repo != want {
                    println!(
                        "warn: Flux syncs `{}` but this bundle delivers `{want}` — \
                         apply will refuse until `ami gitops bootstrap --cluster-id \
                         {cluster_id}` matches",
                        state.path_in_repo
                    );
                }
            }
            let baseline = repo_baseline(repo, &cluster_id)?;
            println!("compiled tree ({} files):", bundle.tree.len());
            for f in &bundle.tree {
                let status = match baseline
                    .as_ref()
                    .and_then(|w| w.read_file(&f.relative_path).ok().flatten())
                {
                    Some(old) if old == f.contents => "unchanged",
                    Some(_) => "changed",
                    None => "new",
                };
                println!("  {status:9} {}", f.relative_path);
            }
            if full {
                for f in &bundle.tree {
                    println!();
                    println!("--- {} ---", f.relative_path);
                    print!("{}", f.contents);
                }
            }
            if let Some(w) = &baseline {
                println!();
                println!(
                    "drift vs repo HEAD: {}",
                    super::drift::detect(w, &bundle.topology_yaml)?.summary()
                );
            }
            Ok(())
        }
    }
}

/// `ami apply`
pub fn handle_apply(args: ApplyArgs) -> Result<()> {
    let raw = read_topology(&args.file)?;
    let cat = load_catalog(&args.catalog)?;

    // same validation as `ami topology validate` / API preview
    let report = validate_document(&args.file.display().to_string(), &raw, &cat)?;
    if !report.is_ok() {
        print_report(&report);
        bail!("topology validation failed — nothing was sent to the agent");
    }

    let topology =
        amispec_schema::parse_topology(&raw).map_err(|e| anyhow!("parse topology: {e}"))?;
    let cluster_id = single_cluster_id(&topology)?;
    let bundle = build_bundle(&topology, &cluster_id, &cat.index, true)
        .map_err(|e| anyhow!("bundle: {e}"))?;

    // intent: reviewed tree_hash + catalog pins + topology (replace semantics)
    let actor = args.actor.clone().unwrap_or_else(|| {
        format!(
            "{}@local",
            std::env::var("USER").unwrap_or("operator".into())
        )
    });
    let spec = IntentSpec {
        cluster_id: cluster_id.clone(),
        origin: Origin::Local,
        actor,
        amispec_version: bundle.amispec_version.clone(),
        expected_tree_hash: bundle.tree_hash.clone(),
        schema_hash: bundle.schema_hash.clone(),
        catalog_pins: bundle.catalog.clone(),
        topology_delta: raw.clone(),
    };
    let nonce = generate_nonce()?;
    let intent = build_intent(
        spec,
        nonce,
        crate::gitops::state::now_rfc3339(),
        super::intent::DEFAULT_TTL_SECONDS,
    )?;

    println!("change_id:   {}", intent.metadata.change_id);
    println!("tree_hash:   {}", bundle.tree_hash);
    println!("schema_hash: {}", bundle.schema_hash);
    println!("cluster:     {cluster_id}");
    println!("catalog:     {} pin(s)", bundle.catalog.len());

    if !args.yes && !crate::tune::confirm("Apply this bundle through the agent?", false)? {
        bail!("aborted");
    }

    // sign with the operator key (public part must be in the agent allowlist)
    let key_dir = PathBuf::from(crate::gitops::keys::GITOPS_DIR);
    let key = ensure_operator_key(&key_dir).context("operator intent key")?;
    println!("signer:      {}", key.fingerprint);
    if load_allowlist(&key_dir.join("allowlist.d"))?
        .iter()
        .all(|k| k.fingerprint(ssh_key::HashAlg::Sha256).to_string() != key.fingerprint)
    {
        eprintln!(
            "note: operator key {} is not in the agent allowlist yet — add {} to \
             {}/allowlist.d/ (the agent refuses unknown signers)",
            key.fingerprint,
            key.public_line.chars().take(24).collect::<String>(),
            key_dir.display()
        );
    }
    let private = ssh_key::PrivateKey::read_openssh_file(&key_dir.join("operator-intent-key"))
        .context("read operator intent key")?;
    let pem = sign_intent(&intent, &private)?;

    let socket = args.socket.clone().unwrap_or_else(default_socket);
    let response = send_apply(&socket, &intent, &pem)?;
    for w in &response.warnings {
        eprintln!("warn: {w}");
    }
    expect_applied(&response)?;
    match response.status.as_str() {
        "applied" => {
            println!(
                "applied:     commit {} (tree_hash verified by the agent)",
                response.commit_sha.unwrap_or_default()
            );
        }
        "noop" => {
            println!(
                "noop:        change {} already applied",
                intent.metadata.change_id
            );
        }
        other => bail!("unexpected agent status `{other}`"),
    }
    Ok(())
}

fn read_topology(file: &Path) -> Result<String> {
    std::fs::read_to_string(file).with_context(|| format!("read {}", file.display()))
}

fn single_cluster_id(topology: &amispec_schema::TopologyBlueprint) -> Result<String> {
    if topology.clusters.len() != 1 {
        bail!(
            "delivery bundles carry exactly one cluster (this topology has {}) — \
             split the blueprint per cluster",
            topology.clusters.len()
        );
    }
    Ok(topology.clusters[0].id.clone())
}

fn repo_baseline(
    repo: Option<PathBuf>,
    cluster_id: &str,
) -> Result<Option<super::agent::RepoWriter>> {
    let path = repo.unwrap_or_else(|| PathBuf::from(crate::gitops::local_bare::REPO_PATH));
    if !path.exists() {
        return Ok(None);
    }
    let _ = cluster_id;
    let writer = super::agent::RepoWriter::new(path, crate::gitops::DEFAULT_BRANCH.to_string());
    match writer.head() {
        Ok(Some(_)) => Ok(Some(writer)),
        _ => Ok(None),
    }
}

fn report_json(report: &amispec_validate::Report) -> serde_json::Value {
    serde_json::json!({
        "source": report.source,
        "ok": report.is_ok(),
        "findings": report.findings.iter().map(|f| serde_json::json!({
            "severity": match f.severity {
                amispec_validate::Severity::Error => "error",
                amispec_validate::Severity::Warning => "warning",
            },
            "rule": f.rule,
            "path": f.path,
            "message": f.message,
        })).collect::<Vec<_>>(),
    })
}

fn print_diff_json(bundle: &amispec_compile::Bundle) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "treeHash": bundle.tree_hash,
            "schemaHash": bundle.schema_hash,
            "amispecVersion": bundle.amispec_version,
            "catalog": bundle.catalog.iter().map(|p| serde_json::json!({
                "id": p.id, "rev": p.rev, "version": p.version, "sha256": p.sha256, "path": p.path,
            })).collect::<Vec<_>>(),
            "topologyPath": bundle.topology_path,
            "tree": bundle.tree.iter().map(|f| serde_json::json!({
                "path": f.relative_path, "bytes": f.contents.len(),
            })).collect::<Vec<_>>(),
        }))?
    );
    Ok(())
}

/// `ami gitops intent-serve` — run the agent-side channel (normally hosted by
/// `amiterra.service`; foreground here for single-node and test setups).
#[derive(Args, Debug, Clone, Default)]
pub struct IntentServeArgs {
    /// Cluster id this agent serves
    #[arg(long)]
    pub cluster_id: Option<String>,
    /// Fleet repository path (default: local-bare repo)
    #[arg(long)]
    pub repo: Option<PathBuf>,
    /// Tracked branch
    #[arg(long)]
    pub branch: Option<String>,
    /// Allowlist directory of intent public keys
    #[arg(long)]
    pub allowlist_dir: Option<PathBuf>,
    /// Channel socket path
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

pub fn handle_intent_serve(args: IntentServeArgs) -> Result<()> {
    let cluster_id = args
        .cluster_id
        .unwrap_or_else(|| crate::gitops::DEFAULT_CLUSTER_ID.to_string());
    let mut cfg = AgentConfig::production(cluster_id);
    if let Some(repo) = args.repo {
        cfg.repo_path = repo;
    }
    if let Some(branch) = args.branch {
        cfg.branch = branch;
    }
    if let Some(dir) = args.allowlist_dir {
        cfg.allowlist_dir = dir;
    }
    let socket = args.socket.unwrap_or_else(default_socket);
    if load_allowlist(&cfg.allowlist_dir)?.is_empty() {
        eprintln!(
            "warning: intent allowlist {} is empty — every intent will be refused",
            cfg.allowlist_dir.display()
        );
    }
    super::channel::serve(&socket, &cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::agent::tests_support::{WEB_PASSPORT, test_world, topology_yaml};

    fn write_catalog(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("stateless-app.yaml"), WEB_PASSPORT).unwrap();
    }

    #[test]
    fn validate_door_matches_library_findings() {
        let w = test_world();
        let cat_dir = w.dir.path().join("catalog");
        write_catalog(&cat_dir);
        // topology with an unknown viaBalancer → exposure rule error
        let bad =
            topology_yaml("app.example.io").replace("viaBalancer: main-l7", "viaBalancer: ghost");
        let topo_path = w.dir.path().join("topology.yaml");
        std::fs::write(&topo_path, &bad).unwrap();

        let cat = load_catalog(&cat_dir).unwrap();
        let report = validate_document("t", &bad, &cat).unwrap();
        assert!(!report.is_ok());
        assert!(
            report.errors().any(|e| e.rule == "expose-via-balancer"),
            "{:?}",
            report.findings
        );

        // the CLI handler fails on the same document (exit-code parity)
        let err = handle_topology(TopologyArgs {
            command: Some(TopologyCommand::Validate {
                file: topo_path.clone(),
                catalog: cat_dir.clone(),
                json: false,
            }),
        })
        .unwrap_err();
        assert!(err.to_string().contains("validation failed"), "{err:#}");
    }

    #[test]
    fn diff_shows_pins_topology_and_tree_hash() {
        let w = test_world();
        let cat_dir = w.dir.path().join("catalog");
        write_catalog(&cat_dir);
        let topo_path = w.dir.path().join("topology.yaml");
        std::fs::write(&topo_path, topology_yaml("app.example.io")).unwrap();

        let cat = load_catalog(&cat_dir).unwrap();
        let raw = read_topology(&topo_path).unwrap();
        let topology = amispec_schema::parse_topology(&raw).unwrap();
        let bundle = build_bundle(&topology, "c0", &cat.index, true).unwrap();
        assert!(bundle.tree_hash.starts_with("sha256:"));
        assert_eq!(bundle.catalog.len(), 1);
        assert_eq!(bundle.catalog[0].id, "stateless-app");

        // V1: two preview builds are byte-stable
        let bundle2 = build_bundle(&topology, "c0", &cat.index, true).unwrap();
        assert_eq!(bundle.tree_hash, bundle2.tree_hash);
    }

    #[test]
    fn load_catalog_rejects_broken_entries() {
        let w = test_world();
        let cat_dir = w.dir.path().join("broken");
        std::fs::create_dir_all(&cat_dir).unwrap();
        std::fs::write(cat_dir.join("bad.yaml"), "kind: Nope\n").unwrap();
        assert!(load_catalog(&cat_dir).is_err());
    }
}
