//! CLI surface: `ami network status | refresh` (Task 0008).

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use std::io::{IsTerminal, Write, stdin, stdout};

use super::refresh::{Outcome, RefreshContext, RefreshFlags, execute, plan, refuse_on_ha};
use super::{NetworkState, collect_applied, diff_facts, expected_sans};
use crate::ui::Ui;

#[derive(Args, Debug, Clone, Default)]
pub struct NetworkArgs {
    #[command(subcommand)]
    pub command: Option<NetworkCommand>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum NetworkCommand {
    /// Diff live network facts against applied configs (read-only)
    Status {
        /// Machine-readable JSON report
        #[arg(long)]
        json: bool,
    },
    /// Reconcile drifted addresses: explicit steps, fail-closed gates
    Refresh {
        /// Skip interactive confirmations (safe steps only)
        #[arg(short = 'y', long)]
        yes: bool,
        /// Explicitly consent to API certificate rotation (SANs)
        #[arg(long)]
        renew_certs: bool,
        /// Record explicit re-consent of the edge trust boundary
        #[arg(long)]
        re_consent_trust: bool,
        /// Address being re-consented (with --re-consent-trust)
        #[arg(long)]
        trust_edge: Option<String>,
        /// Update persistent WireGuard peer pins
        #[arg(long)]
        wg_pins: bool,
        /// Rewrite the Flux remote host to a stable name
        #[arg(long)]
        adopt_stable_names: bool,
        /// Stable host for the Flux remote (DNS or WG address)
        #[arg(long)]
        git_host: Option<String>,
        /// New control-plane endpoint for worker `server:` rewrites
        #[arg(long)]
        server_url: Option<String>,
        /// Print the plan without touching the host
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Serialize)]
struct StatusReport {
    drift: Vec<super::Change>,
    snapshot_mismatch: Vec<String>,
    egress_ip: Option<String>,
    cloud_provider: String,
}

pub async fn handle_network(args: NetworkArgs) -> Result<()> {
    match args
        .command
        .unwrap_or(NetworkCommand::Status { json: false })
    {
        NetworkCommand::Status { json } => status(json).await,
        NetworkCommand::Refresh {
            yes,
            renew_certs,
            re_consent_trust,
            trust_edge,
            wg_pins,
            adopt_stable_names,
            git_host,
            server_url,
            dry_run,
        } => {
            refresh(
                RefreshFlags {
                    yes,
                    renew_certs,
                    re_consent_trust,
                    wg_pins,
                    adopt_stable_names,
                    git_host,
                    server_url,
                },
                trust_edge,
                dry_run,
            )
            .await
        }
    }
}

/// Live facts: discovery without touching any config.
async fn live_facts() -> Result<super::NetworkFacts> {
    let report = crate::discovery::NetworkDiscovery::run_async().await;
    let node_ip = report.topology.primary_node_ip().to_string();
    let node_external_ip = report.topology.node_owned_external_ip().map(String::from);
    let egress_ip = report
        .public_probed_ip
        .clone()
        .or_else(|| report.topology.primary_external_ip().map(String::from));
    let hostname = report.hostname.clone();
    let sans = expected_sans(&super::NetworkFacts {
        node_ip: node_ip.clone(),
        node_external_ip: node_external_ip.clone(),
        hostname: hostname.clone(),
        ..Default::default()
    });
    Ok(super::NetworkFacts {
        node_ip,
        node_external_ip,
        egress_ip,
        hostname,
        sans,
        api_host: None,
        flux_remote: None,
    })
}

async fn status(json: bool) -> Result<()> {
    let live = live_facts().await?;
    let mut applied = collect_applied()?;
    // Egress is not stored in any config — the last recorded snapshot is its
    // baseline (otherwise every run would report false drift).
    let snapshot = NetworkState::load(&NetworkState::default_path())?;
    if let Some(state) = &snapshot
        && state.facts.egress_ip.is_some()
    {
        applied.egress_ip = state.facts.egress_ip.clone();
    }
    // Fresh host: nothing was applied yet — this is not drift.
    if applied.node_ip.is_empty() {
        let report = StatusReport {
            drift: vec![],
            snapshot_mismatch: vec![],
            egress_ip: live.egress_ip.clone(),
            cloud_provider: crate::discovery::probe::probe_cloud_provider()
                .await
                .to_string(),
        };
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            Ui::step_info(
                "Host",
                "not provisioned yet (no applied network facts) — run `ami init`",
            );
        }
        return Ok(());
    }
    let drift = diff_facts(&live, &applied);

    // Snapshot is an audit trail: mismatches against applied configs mean the
    // host was edited outside the platform.
    let mut snapshot_mismatch = Vec::new();
    if let Some(state) = NetworkState::load(&NetworkState::default_path())? {
        if state.facts.node_ip != applied.node_ip {
            snapshot_mismatch.push(format!(
                "node_ip: snapshot {} vs applied {} (manual edit?)",
                state.facts.node_ip, applied.node_ip
            ));
        }
        if state.facts.node_external_ip != applied.node_external_ip {
            snapshot_mismatch.push(format!(
                "node_external_ip: snapshot {:?} vs applied {:?} (manual edit?)",
                state.facts.node_external_ip, applied.node_external_ip
            ));
        }
    }

    let provider = crate::discovery::probe::probe_cloud_provider().await;
    let report = StatusReport {
        drift,
        snapshot_mismatch,
        egress_ip: live.egress_ip.clone(),
        cloud_provider: provider.to_string(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    if report.drift.is_empty() && report.snapshot_mismatch.is_empty() {
        Ui::step_done("Network is stable — live facts match applied configs", None);
        Ui::step_info("Cloud provider", &report.cloud_provider);
        if let Some(egress) = &report.egress_ip {
            Ui::step_info("Egress IP (allowlists)", egress);
        }
        return Ok(());
    }

    Ui::header(
        "Network drift detected",
        "ami network refresh reconciles explicitly",
    );
    for c in &report.drift {
        Ui::step_warn(&format!(
            "{}: applied `{}` -> live `{}`",
            c.field, c.applied, c.live
        ));
        for i in &c.impacts {
            Ui::step_info("impact", i.label());
        }
    }
    for m in &report.snapshot_mismatch {
        Ui::step_warn(&format!("snapshot: {m}"));
    }
    Ui::step_info(
        "Next",
        "`ami network refresh` (gated steps need explicit flags)",
    );
    Ok(())
}

fn confirm(prompt: &str) -> Result<bool> {
    print!("{prompt} [y/N] ");
    stdout().flush().ok();
    let mut input = String::new();
    stdin().read_line(&mut input)?;
    Ok(matches!(input.trim(), "y" | "Y" | "yes"))
}

async fn refresh(flags: RefreshFlags, trust_edge: Option<String>, dry_run: bool) -> Result<()> {
    let live = live_facts().await?;
    let mut applied = collect_applied()?;
    // Egress baseline: last recorded snapshot (see `status`).
    let snapshot = NetworkState::load(&NetworkState::default_path())?;
    if let Some(state) = &snapshot
        && state.facts.egress_ip.is_some()
    {
        applied.egress_ip = state.facts.egress_ip.clone();
    }
    let drift = diff_facts(&live, &applied);
    let steps = plan(&drift, &flags);

    if dry_run {
        Ui::header("ami network refresh — plan", "dry run, nothing changes");
        for s in &steps {
            let gate = if s.gated_by_certs {
                " [gated: --renew-certs]"
            } else if s.gated_by_trust {
                " [gated: --re-consent-trust]"
            } else {
                ""
            };
            Ui::step_info(&format!("{}{}", s.title, gate), &s.detail);
        }
        return Ok(());
    }

    // HA/etcd address changes are out of scope — refuse before touching
    // anything (fail-closed).
    refuse_on_ha()?;

    if !flags.yes {
        if !stdin().is_terminal() {
            anyhow::bail!(
                "non-interactive session: pass -y to apply safe steps (gated steps still need their explicit flags)"
            );
        }
        Ui::header("ami network refresh", "planned steps");
        for s in &steps {
            Ui::step_info("step", &s.title);
        }
        if !confirm("Apply these steps?")? {
            Ui::step_warn("Aborted; nothing changed.");
            return Ok(());
        }
    }

    let ctx = RefreshContext {
        node_ip: live.node_ip.clone(),
        node_external_ip: live.node_external_ip.clone(),
        expected_sans: expected_sans(&live),
        server_url: flags.server_url.clone(),
        git_host: flags.git_host.clone(),
        trust_consent_addr: trust_edge.clone(),
        ..Default::default()
    };
    let reports = execute(&steps, &flags, &ctx);
    let mut failed = false;
    for r in &reports {
        match &r.outcome {
            Outcome::Done(note) => Ui::step_done(&format!("{}: {note}", r.title), None),
            Outcome::Skipped(reason) => {
                Ui::step_info(&format!("~ {}", r.title), &format!("skipped ({reason})"))
            }
            Outcome::Failed(err) => {
                failed = true;
                Ui::step_err(&format!("x {}: {err}", r.title));
            }
        }
    }

    // declared = enforced: persist the refreshed facts as the new snapshot.
    let mut facts = collect_applied().unwrap_or(live.clone());
    facts.egress_ip = live.egress_ip.clone();
    facts.hostname = live.hostname.clone();
    super::refresh::save_state_after_refresh(
        facts,
        flags
            .re_consent_trust
            .then_some(trust_edge.as_deref())
            .flatten(),
    )
    .context("failed to save network-state snapshot")?;

    if failed {
        Ui::step_warn("Refresh finished with failed steps — re-run `ami network status`");
    } else {
        Ui::step_done("Refresh complete; run `ami network status` to verify", None);
    }
    Ok(())
}
