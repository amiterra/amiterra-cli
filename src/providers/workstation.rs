use anyhow::{Result, bail};
use std::fs;
use std::path::Path;

use crate::context::{AmiterraConfig, EnvironmentMode, ExecutionContext};
use crate::providers::runtime::{detect_active_runtime, detect_runtime_state};
use crate::providers::sandbox::{
    DEFAULT_CLUSTER_NAME, SandboxEngine, detect_sandbox_engine_preferred,
    print_missing_engine_recommendations,
};
use crate::providers::{EnvironmentBackend, EnvironmentStatus, StatusMetric};
use crate::ui::{Glyphs, Palette, Ui};

/// Resolve the sandbox engine honoring the family chosen in `ami init`
/// (stored in config / ExecutionContext). Falls back to auto-detect.
fn resolve_engine(ctx: &ExecutionContext) -> Option<Box<dyn SandboxEngine>> {
    let preferred = ctx.sandbox_engine.clone().or_else(|| {
        let raw = fs::read_to_string(&ctx.config_path).ok()?;
        let cfg: AmiterraConfig = serde_yaml::from_str(&raw).ok()?;
        cfg.cluster.sandbox_engine.clone()
    });
    detect_sandbox_engine_preferred(preferred.as_deref())
}

#[derive(Default)]
pub struct WorkstationBackend;

impl EnvironmentBackend for WorkstationBackend {
    fn name(&self) -> &'static str {
        "Local Development Workstation (Zero Host Pollution)"
    }

    fn init(&self, ctx: &ExecutionContext, dry_run: bool) -> Result<()> {
        // Step 1: Fail-Fast Prerequisite Verification
        let runtime_state = detect_runtime_state();
        let sandbox_engine = resolve_engine(ctx);
        let skip_check = std::env::var("AMITERRA_SKIP_RUNTIME_CHECK")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let engine_binary = match &sandbox_engine {
            Some(engine) => {
                if let Some(rt) = &runtime_state {
                    if rt.daemon_running {
                        Ui::step_done(
                            &format!("Container runtime: {} (running)", rt.display_name),
                            None,
                        );
                    } else {
                        Ui::step_warn(&format!(
                            "Container runtime: {} (installed · daemon stopped)",
                            rt.display_name
                        ));
                    }
                }
                Ui::step_done(&format!("Sandbox engine: {}", engine.name()), None);
                engine.binary().to_string()
            }
            None if skip_check => {
                Ui::step_warn("Sandbox engine check skipped (AMITERRA_SKIP_RUNTIME_CHECK=1)");
                "docker".to_string()
            }
            None => {
                print_missing_engine_recommendations("ami init");
                bail!(
                    "Initialization halted: no compatible container runtime or Kubernetes tool detected on this machine."
                );
            }
        };

        if dry_run {
            Ui::step_info(
                "Dry-run",
                "Prerequisite check passed. No configuration files were written.",
            );
            return Ok(());
        }

        fs::create_dir_all(&ctx.bin_dir)?;

        let cfg = AmiterraConfig {
            mode: EnvironmentMode::Workstation,
            cluster: crate::context::ClusterConfig {
                runtime: engine_binary.clone(),
                networking: "k3s-headless (no-traefik, no-servicelb)".to_string(),
                sandbox_engine: ctx.sandbox_engine.clone(),
                ..Default::default()
            },
        };
        ctx.save_config(&cfg)?;

        Ui::step_done(
            &format!("Configuration saved to {}", ctx.config_path.display()),
            None,
        );

        if let Some(rt) = &runtime_state
            && !rt.daemon_running
        {
            Ui::step_warn(&format!(
                "{} is installed, but daemon is stopped. 'ami up' will launch it, or run: {}",
                rt.display_name, rt.start_hint
            ));
        }

        let config_str = ctx.config_path.display().to_string();
        let card_items = [
            ("Host Policy", "Zero Host Pollution (user-space only)"),
            (
                "Cluster Profile",
                "Headless K3s (no Traefik · no ServiceLB)",
            ),
            ("Kubernetes API", "https://127.0.0.1:6443 (mTLS secured)"),
            ("Configuration", config_str.as_str()),
        ];
        Ui::card("Environment Initialized", &card_items);

        // Shared fidelity contract with production init (same story, different executor).
        println!();
        println!("  {}", Palette::bold("Host capability matrix (sandbox):"));
        println!(
            "    {} K3s sandbox cluster          {}",
            Glyphs::BULLET,
            Palette::green("applied")
        );
        println!(
            "    {} Zero host pollution          {}",
            Glyphs::BULLET,
            Palette::green("enforced (no host sysctl)")
        );
        println!(
            "    {} Platform prep / Cilium host  {}",
            Glyphs::BULLET,
            Palette::yellow("skipped in sandbox")
        );
        println!(
            "    {} Performance profile (tune)   {}",
            Glyphs::BULLET,
            Palette::yellow("skipped — run on a server")
        );
        println!(
            "    {} NVMe LVM / TopoLVM           {}",
            Glyphs::BULLET,
            Palette::yellow("skipped in sandbox")
        );
        println!(
            "     {}",
            Palette::dim(
                "Production fidelity: run `ami init` on Ubuntu 22.04/24.04 or Debian 12, or use QEMU sandbox."
            )
        );
        println!();

        Ui::next_steps(
            "Next actions:",
            &[
                "ami up        Start the local developer cluster",
                "ami status    Inspect environment health",
                "ami storage   Storage tier and plan",
            ],
        );

        Ok(())
    }

    fn up(&self, ctx: &ExecutionContext, dry_run: bool) -> Result<()> {
        if !ctx.config_path.exists() {
            self.init(ctx, dry_run)?;
        }

        if dry_run {
            Ui::step_info(
                "Dry-run",
                &format!(
                    "Would start local Headless K3s sandbox cluster '{}'.",
                    DEFAULT_CLUSTER_NAME
                ),
            );
            return Ok(());
        }

        Ui::header("Developer Sandbox", "Starting Local Cluster");

        let engine = match resolve_engine(ctx) {
            Some(e) => e,
            None => {
                print_missing_engine_recommendations("ami up");
                bail!(
                    "Cannot start sandbox: no compatible container runtime or Kubernetes tool found."
                );
            }
        };

        Ui::step_done(&format!("Using sandbox engine: {}", engine.name()), None);

        let kubeconfig_path = ctx.home_dir.join("kubeconfig.yaml");
        let spinner = Ui::spinner(format!(
            "Starting Headless K3s sandbox '{}'...",
            DEFAULT_CLUSTER_NAME
        ));
        engine.start(DEFAULT_CLUSTER_NAME, 6443, Some(&kubeconfig_path))?;
        spinner.success(&format!(
            "Sandbox cluster '{}' online",
            DEFAULT_CLUSTER_NAME
        ));

        let kc_str = kubeconfig_path.display().to_string();
        let card_items = [
            ("Sandbox Cluster", "● healthy (amiterra-dev)"),
            (
                "Cluster Profile",
                "Headless K3s (no Traefik · no ServiceLB)",
            ),
            ("Kubernetes API", "https://127.0.0.1:6443 (mTLS secured)"),
            ("Kubeconfig", kc_str.as_str()),
        ];
        Ui::card("Cluster Ready", &card_items);

        let export_cmd = format!("$ export KUBECONFIG=\"{}\"", kc_str);
        Ui::next_steps(
            "Quick start:",
            &[&export_cmd, "$ kubectl get pods -A", "$ ami status"],
        );

        Ok(())
    }

    fn down(&self, ctx: &ExecutionContext) -> Result<()> {
        Ui::header("Developer Sandbox", "Stopping Local Cluster");
        if let Some(engine) = resolve_engine(ctx) {
            let spinner = Ui::spinner(format!(
                "Stopping sandbox cluster '{}'...",
                DEFAULT_CLUSTER_NAME
            ));
            engine.stop(DEFAULT_CLUSTER_NAME)?;
            spinner.success(&format!(
                "Sandbox cluster '{}' stopped. Host resources released.",
                DEFAULT_CLUSTER_NAME
            ));
        } else {
            Ui::step_done("No active sandbox engine detected. Nothing to stop.", None);
        }
        Ok(())
    }

    fn status(&self, ctx: &ExecutionContext) -> Result<EnvironmentStatus> {
        let runtime = detect_active_runtime();
        let engine = resolve_engine(ctx);
        let cluster_running = engine
            .as_ref()
            .map(|e| e.is_running(DEFAULT_CLUSTER_NAME))
            .unwrap_or(false);
        let config_present = ctx.config_path.exists();

        let mut metrics = vec![
            StatusMetric {
                label: "Environment Mode".to_string(),
                value: "Workstation (Zero Host Pollution)".to_string(),
            },
            StatusMetric {
                label: "Configuration".to_string(),
                value: if config_present {
                    ctx.config_path.display().to_string()
                } else {
                    "○ not initialized (run 'ami init')".to_string()
                },
            },
            StatusMetric {
                label: "Container Runtime".to_string(),
                value: runtime
                    .clone()
                    .unwrap_or_else(|| "○ not detected".to_string()),
            },
            StatusMetric {
                label: "Sandbox Engine".to_string(),
                value: engine
                    .as_ref()
                    .map(|e| e.name().to_string())
                    .unwrap_or_else(|| "○ not installed".to_string()),
            },
            StatusMetric {
                label: "Sandbox Cluster".to_string(),
                value: if cluster_running {
                    format!("● healthy ({})", DEFAULT_CLUSTER_NAME)
                } else {
                    "○ inactive (stopped)".to_string()
                },
            },
            StatusMetric {
                label: "Cluster Profile".to_string(),
                value: "Headless K3s (no Traefik · no ServiceLB)".to_string(),
            },
            StatusMetric {
                label: "Kubernetes API".to_string(),
                value: "https://127.0.0.1:6443 (mTLS secured)".to_string(),
            },
        ];

        if cluster_running {
            let kc_path = ctx.home_dir.join("kubeconfig.yaml");
            if kc_path.exists() {
                metrics.push(StatusMetric {
                    label: "Kubeconfig".to_string(),
                    value: kc_path.display().to_string(),
                });
            }
        }

        let next_hint = if !config_present {
            Some("ami init        Initialize workstation configuration".to_string())
        } else if !cluster_running {
            Some("ami up          Start the local developer cluster".to_string())
        } else {
            Some("ami down        Stop sandbox cluster and release resources".to_string())
        };

        Ok(EnvironmentStatus {
            mode: "workstation".to_string(),
            // A config file alone is not health: the sandbox must be running.
            healthy: cluster_running,
            summary: if cluster_running {
                "Workstation Sandbox Running".to_string()
            } else {
                "Workstation Ready (Cluster Stopped)".to_string()
            },
            metrics,
            next_hint,
        })
    }

    fn uninstall(&self, ctx: &ExecutionContext, _purge: bool) -> Result<()> {
        if let Some(engine) = resolve_engine(ctx)
            && engine.is_running(DEFAULT_CLUSTER_NAME)
        {
            println!("  • Deleting sandbox cluster '{}'...", DEFAULT_CLUSTER_NAME);
            let _ = engine.delete(DEFAULT_CLUSTER_NAME);
        }

        let kubeconfig_path = ctx.home_dir.join("kubeconfig.yaml");
        if kubeconfig_path.exists() {
            let _ = fs::remove_file(&kubeconfig_path);
        }

        if ctx.config_path.exists() {
            let _ = fs::remove_file(&ctx.config_path);
            println!("  • Removed configuration {}", ctx.config_path.display());
        }

        for bin_name in ["ami", "amiterra"] {
            let bin_path = ctx.bin_dir.join(bin_name);
            if bin_path.exists() || fs::symlink_metadata(&bin_path).is_ok() {
                let _ = fs::remove_file(&bin_path);
                println!("  • Removed binary/alias {}", bin_path.display());
            }
        }

        if std::env::var("AMITERRA_INSTALL_DIR").is_err() {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            let path_candidates = [
                format!("{}/.amiterra/bin", home),
                format!("{}/.local/bin", home),
                "/opt/homebrew/bin".to_string(),
                "/usr/local/bin".to_string(),
                format!("{}/bin", home),
                format!("{}/.cargo/bin", home),
            ];
            for dir in path_candidates {
                for bin_name in ["ami", "amiterra"] {
                    let link_path = Path::new(&dir).join(bin_name);
                    if (link_path.exists() || fs::symlink_metadata(&link_path).is_ok())
                        && fs::remove_file(&link_path).is_ok()
                    {
                        println!("  • Removed PATH binary/link {}", link_path.display());
                    }
                }
            }
        }

        let _ = fs::remove_dir(&ctx.bin_dir);
        let _ = fs::remove_dir(&ctx.home_dir);
        Ok(())
    }
}
