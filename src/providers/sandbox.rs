use anyhow::{bail, Result};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use crate::ui::Ui;

pub const DEFAULT_CLUSTER_NAME: &str = "amiterra-dev";
const K3S_SANDBOX_IMAGE: &str = "rancher/k3s:v1.31.2-k3s1";

/// Trait for local Kubernetes sandbox orchestrators.
/// MVP scope: container-based headless K3s (Docker, Podman, nerdctl) and a native
/// host K3s fallback — no dedicated cluster wrappers (k3d/kind/minikube).
pub trait SandboxEngine: Send + Sync {
    fn name(&self) -> &'static str;
    fn binary(&self) -> &'static str;

    fn is_installed(&self) -> bool {
        Command::new(self.binary())
            .arg("--version")
            .output()
            .or_else(|_| Command::new(self.binary()).arg("version").output())
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn is_daemon_ready(&self) -> bool {
        true
    }

    fn start_daemon_if_possible(&self) -> Result<()> {
        Ok(())
    }

    fn is_running(&self, cluster_name: &str) -> bool;
    fn start(
        &self,
        cluster_name: &str,
        api_port: u16,
        kubeconfig_path: Option<&Path>,
    ) -> Result<()>;
    fn stop(&self, cluster_name: &str) -> Result<()>;
    fn delete(&self, cluster_name: &str) -> Result<()>;
}

/// Runs a lightweight Headless K3s node directly inside Docker (Docker Desktop, OrbStack, Colima, Rancher Desktop, Linux Docker)
/// or Podman/nerdctl without extra cluster-wrapper tools.
/// Disables Traefik and ServiceLB to maintain Dev/Prod parity and minimal pod footprint.
pub struct ContainerK3sEngine {
    pub display_name: &'static str,
    pub runtime_bin: &'static str,
}

impl ContainerK3sEngine {
    pub const fn docker() -> Self {
        Self {
            display_name: "Docker (Headless K3s Sandbox)",
            runtime_bin: "docker",
        }
    }

    pub const fn podman() -> Self {
        Self {
            display_name: "Podman (Headless K3s Sandbox)",
            runtime_bin: "podman",
        }
    }

    pub const fn nerdctl() -> Self {
        Self {
            display_name: "containerd / nerdctl (Headless K3s Sandbox)",
            runtime_bin: "nerdctl",
        }
    }

    fn container_exists(&self, cluster_name: &str) -> bool {
        Command::new(self.runtime_bin)
            .args(["inspect", cluster_name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Checks whether an existing sandbox container was provisioned with headless K3s flags
    /// (`--disable=traefik` and `--disable=servicelb`).
    fn is_headless_configured(&self, cluster_name: &str) -> bool {
        Command::new(self.runtime_bin)
            .args(["inspect", "-f", "{{json .Args}}", cluster_name])
            .output()
            .map(|o| {
                let args_json = String::from_utf8_lossy(&o.stdout);
                args_json.contains("--disable=traefik")
                    && args_json.contains("--disable=servicelb")
            })
            .unwrap_or(false)
    }

    fn export_kubeconfig(&self, cluster_name: &str, kubeconfig_path: &Path) -> Result<()> {
        for _ in 0..30 {
            if let Ok(out) = Command::new(self.runtime_bin)
                .args(["exec", cluster_name, "cat", "/etc/rancher/k3s/k3s.yaml"])
                .output()
                && out.status.success() && !out.stdout.is_empty()
            {
                fs::write(kubeconfig_path, &out.stdout)?;
                return Ok(());
            }
            sleep(Duration::from_secs(1));
        }
        bail!("Timed out waiting for K3s kubeconfig from container '{}'", cluster_name);
    }
}

impl SandboxEngine for ContainerK3sEngine {
    fn name(&self) -> &'static str {
        self.display_name
    }

    fn binary(&self) -> &'static str {
        self.runtime_bin
    }

    fn is_installed(&self) -> bool {
        let cli_ok = Command::new(self.runtime_bin)
            .arg("--version")
            .output()
            .or_else(|_| Command::new(self.runtime_bin).arg("version").output())
            .map(|o| o.status.success())
            .unwrap_or(false);
        if cli_ok {
            return true;
        }
        if self.runtime_bin == "docker" && cfg!(target_os = "macos") {
            return Path::new("/Applications/Docker.app").exists()
                || Path::new("/Applications/OrbStack.app").exists()
                || Path::new("/Applications/Rancher Desktop.app").exists();
        }
        false
    }

    fn is_daemon_ready(&self) -> bool {
        Command::new(self.runtime_bin)
            .arg("info")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn start_daemon_if_possible(&self) -> Result<()> {
        if self.is_daemon_ready() {
            return Ok(());
        }

        if self.runtime_bin == "docker" && cfg!(target_os = "macos") {
            let app_candidate = if Path::new("/Applications/OrbStack.app").exists() {
                Some("OrbStack")
            } else if Path::new("/Applications/Docker.app").exists() {
                Some("Docker")
            } else if Path::new("/Applications/Rancher Desktop.app").exists() {
                Some("Rancher Desktop")
            } else {
                None
            };

            if let Some(app_name) = app_candidate {
                println!(
                    "  • {} is installed but its daemon is stopped. Launching {}...",
                    app_name, app_name
                );
                let _ = Command::new("open").args(["-a", app_name]).status();
                for _ in 0..30 {
                    sleep(Duration::from_secs(2));
                    if self.is_daemon_ready() {
                        println!("  • {} daemon is now ready!", app_name);
                        return Ok(());
                    }
                }
                bail!(
                    "{} is starting up. Please wait a few seconds for the daemon to finish initializing and re-run 'ami up' (or 'amiterra up').",
                    app_name
                );
            }
        }

        bail!(
            "{} is installed, but its background daemon is not running (or inaccessible). Please start the daemon and re-run 'ami up' (or 'amiterra up').",
            self.display_name
        )
    }

    fn is_running(&self, cluster_name: &str) -> bool {
        Command::new(self.runtime_bin)
            .args(["inspect", "-f", "{{.State.Running}}", cluster_name])
            .output()
            .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "true")
            .unwrap_or(false)
    }

    fn start(
        &self,
        cluster_name: &str,
        api_port: u16,
        kubeconfig_path: Option<&Path>,
    ) -> Result<()> {
        self.start_daemon_if_possible()?;

        if self.container_exists(cluster_name) && !self.is_headless_configured(cluster_name) {
            let _ = Command::new(self.runtime_bin)
                .args(["rm", "-f", cluster_name])
                .output();
            if let Some(kc) = kubeconfig_path {
                let _ = fs::remove_file(kc);
            }
        }

        if !self.is_running(cluster_name) {
            if self.container_exists(cluster_name) {
                let out = Command::new(self.runtime_bin)
                    .args(["start", cluster_name])
                    .output()?;
                if !out.status.success() {
                    let err = String::from_utf8_lossy(&out.stderr);
                    bail!("Failed to start existing container '{}': {}", cluster_name, err.trim());
                }
            } else {
                let api_map = format!("{}:6443", api_port);
                let out = Command::new(self.runtime_bin)
                    .args([
                        "run",
                        "-d",
                        "--name",
                        cluster_name,
                        "--hostname",
                        cluster_name,
                        "--privileged",
                        "--restart",
                        "unless-stopped",
                        "-p",
                        &api_map,
                        K3S_SANDBOX_IMAGE,
                        "server",
                        "--disable=traefik",
                        "--disable=servicelb",
                        "--tls-san",
                        "127.0.0.1",
                        "--tls-san",
                        "localhost",
                    ])
                    .output()?;

                if !out.status.success() {
                    let err = String::from_utf8_lossy(&out.stderr);
                    bail!(
                        "{} failed to start sandbox container '{}': {}",
                        self.runtime_bin,
                        cluster_name,
                        err.trim()
                    );
                }
            }
        }

        if let Some(kc) = kubeconfig_path {
            self.export_kubeconfig(cluster_name, kc)?;
        }
        Ok(())
    }

    fn stop(&self, cluster_name: &str) -> Result<()> {
        if self.is_running(cluster_name) {
            let _ = Command::new(self.runtime_bin)
                .args(["stop", cluster_name])
                .status();
        }
        Ok(())
    }

    fn delete(&self, cluster_name: &str) -> Result<()> {
        if self.container_exists(cluster_name) {
            let _ = Command::new(self.runtime_bin)
                .args(["rm", "-f", cluster_name])
                .status();
        }
        Ok(())
    }
}

/// Native Headless K3s installed directly on the Linux host system.
#[derive(Default)]
pub struct HostK3sEngine;

/// QEMU micro-VM fidelity sandbox (production-like Ubuntu guest).
/// Delegates lifecycle to `scripts/sandbox-vm.sh` (CoW + cloud-init).
pub struct QemuSandboxEngine {
    pub script_path: std::path::PathBuf,
}

impl QemuSandboxEngine {
    /// Resolve sandbox-vm.sh from env, next to the binary, or the repo layout.
    pub fn discover() -> Option<Self> {
        if let Ok(p) = std::env::var("AMITERRA_SANDBOX_SCRIPT") {
            let pb = std::path::PathBuf::from(p);
            if pb.exists() {
                return Some(Self { script_path: pb });
            }
        }
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            let candidates = [
                dir.join("sandbox-vm.sh"),
                dir.join("../scripts/sandbox-vm.sh"),
                dir.join("../../scripts/sandbox-vm.sh"),
                dir.join("scripts/sandbox-vm.sh"),
            ];
            for c in candidates {
                if c.exists() {
                    return Some(Self {
                        script_path: c.canonicalize().unwrap_or(c),
                    });
                }
            }
        }
        let cwd = std::path::PathBuf::from("scripts/sandbox-vm.sh");
        if cwd.exists() {
            return Some(Self { script_path: cwd });
        }
        let abs = std::path::PathBuf::from("/usr/lib/amiterra/sandbox-vm.sh");
        if abs.exists() {
            return Some(Self { script_path: abs });
        }
        None
    }

    fn run(&self, verb: &str) -> std::io::Result<std::process::Output> {
        Command::new(&self.script_path).arg(verb).output()
    }
}

impl SandboxEngine for QemuSandboxEngine {
    fn name(&self) -> &'static str {
        "QEMU micro-VM (production-like Ubuntu)"
    }

    fn binary(&self) -> &'static str {
        "qemu-system"
    }

    fn is_installed(&self) -> bool {
        self.script_path.exists()
            && (Command::new("qemu-system-aarch64")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
                || Command::new("qemu-system-x86_64")
                    .arg("--version")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false))
    }

    fn is_daemon_ready(&self) -> bool {
        self.is_installed()
    }

    fn is_running(&self, _cluster_name: &str) -> bool {
        self.run("status")
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn start(
        &self,
        _cluster_name: &str,
        _api_port: u16,
        _kubeconfig_path: Option<&Path>,
    ) -> Result<()> {
        let out = self.run("up").map_err(|e| {
            anyhow::anyhow!("Failed to launch sandbox-vm.sh: {e}")
        })?;
        if !out.status.success() {
            bail!(
                "QEMU sandbox failed to start: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    fn stop(&self, _cluster_name: &str) -> Result<()> {
        let _ = self.run("down");
        Ok(())
    }

    fn delete(&self, _cluster_name: &str) -> Result<()> {
        let _ = self.run("down");
        Ok(())
    }
}

impl SandboxEngine for HostK3sEngine {
    fn name(&self) -> &'static str {
        "Native Headless K3s (systemd)"
    }

    fn binary(&self) -> &'static str {
        "k3s"
    }

    fn is_installed(&self) -> bool {
        Path::new("/usr/local/bin/k3s").exists()
            || Path::new("/etc/rancher/k3s/config.yaml").exists()
    }

    fn is_daemon_ready(&self) -> bool {
        Command::new("systemctl")
            .args(["is-active", "k3s"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false)
            || Command::new("systemctl")
                .args(["is-active", "k3s-agent"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
                .unwrap_or(false)
    }

    fn start_daemon_if_possible(&self) -> Result<()> {
        let service = if Path::new("/etc/systemd/system/k3s-agent.service").exists() {
            "k3s-agent"
        } else {
            "k3s"
        };
        let _ = Command::new("systemctl").args(["start", service]).status();
        Ok(())
    }

    fn is_running(&self, _cluster_name: &str) -> bool {
        self.is_daemon_ready()
    }

    fn start(
        &self,
        _cluster_name: &str,
        _api_port: u16,
        _kubeconfig_path: Option<&Path>,
    ) -> Result<()> {
        self.start_daemon_if_possible()
    }

    fn stop(&self, _cluster_name: &str) -> Result<()> {
        let service = if Path::new("/etc/systemd/system/k3s-agent.service").exists() {
            "k3s-agent"
        } else {
            "k3s"
        };
        let _ = Command::new("systemctl").args(["stop", service]).status();
        Ok(())
    }

    fn delete(&self, _cluster_name: &str) -> Result<()> {
        if Path::new("/usr/local/bin/k3s-uninstall.sh").exists() {
            let _ = Command::new("/usr/local/bin/k3s-uninstall.sh").status();
        }
        Ok(())
    }
}

/// Returns all supported sandbox engines in preference order for workstation mode.
/// Fidelity first (QEMU micro-VM), then fast container sandbox, then native host K3s.
pub fn available_engines() -> Vec<Box<dyn SandboxEngine>> {
    let mut engines: Vec<Box<dyn SandboxEngine>> = Vec::new();
    if let Some(q) = QemuSandboxEngine::discover() {
        engines.push(Box::new(q));
    }
    engines.push(Box::new(ContainerK3sEngine::docker()));
    engines.push(Box::new(ContainerK3sEngine::podman()));
    engines.push(Box::new(ContainerK3sEngine::nerdctl()));
    engines.push(Box::new(HostK3sEngine));
    engines
}

/// Resolve engines, optionally preferring a named family: "qemu" | "container" | "host".
pub fn detect_sandbox_engine_preferred(preferred: Option<&str>) -> Option<Box<dyn SandboxEngine>> {
    if std::env::var("AMITERRA_SIMULATE_NO_RUNTIME")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return None;
    }

    let engines = available_engines();

    let matches_pref = |e: &dyn SandboxEngine| -> bool {
        match preferred {
            Some("qemu") => e.name().contains("QEMU"),
            Some("container") => {
                e.name().contains("Docker")
                    || e.name().contains("Podman")
                    || e.name().contains("nerdctl")
            }
            Some("host") => e.name().contains("Native"),
            _ => true,
        }
    };

    let mut fallback_name: Option<&'static str> = None;

    // 1) Preferred family, installed + ready.
    for engine in &engines {
        if matches_pref(engine.as_ref()) && engine.is_installed() && engine.is_daemon_ready() {
            let name = engine.name();
            return engines.into_iter().find(|e| e.name() == name);
        }
    }
    // 2) Preferred family, installed (daemon may need start).
    for engine in &engines {
        if matches_pref(engine.as_ref()) && engine.is_installed() {
            let name = engine.name();
            return engines.into_iter().find(|e| e.name() == name);
        }
    }
    // 3) Any ready engine.
    for engine in &engines {
        if engine.is_installed() && engine.is_daemon_ready() {
            let name = engine.name();
            return engines.into_iter().find(|e| e.name() == name);
        }
    }
    // 4) Any installed engine.
    for engine in &engines {
        if engine.is_installed() {
            fallback_name = Some(engine.name());
            break;
        }
    }
    if let Some(name) = fallback_name {
        return engines.into_iter().find(|e| e.name() == name);
    }
    None
}

/// Resolves the best available sandbox engine on the host (no preference).
pub fn detect_sandbox_engine() -> Option<Box<dyn SandboxEngine>> {
    detect_sandbox_engine_preferred(None)
}

/// Prints comprehensive, platform-aware installation recommendations when no container runtime or sandbox engine is present.
pub fn print_missing_engine_recommendations(next_command: &str) {
    let steps: Vec<String> = if cfg!(target_os = "macos") {
        vec![
            "› Fidelity sandbox (production-like kernel):".to_string(),
            "  • QEMU micro-VM                : brew install qemu".to_string(),
            "› Fast container sandbox (60s demo):".to_string(),
            "  • OrbStack (fast & lightweight) : brew install --cask orbstack".to_string(),
            "  • Docker Desktop                : brew install --cask docker".to_string(),
            "  • Rancher Desktop               : brew install --cask rancher".to_string(),
            "  • Podman Desktop                : brew install --cask podman-desktop".to_string(),
            "› CLI-Only Runtime:".to_string(),
            "  • Colima + Docker CLI           : brew install colima docker && colima start".to_string(),
        ]
    } else {
        vec![
            "› Container Runtimes (Recommended for Linux):".to_string(),
            "  • Docker Engine                 : curl -fsSL https://get.docker.com | sh".to_string(),
            "  • Podman (rootless, daemonless) : sudo apt-get update && sudo apt-get install -y podman".to_string(),
            "› Fidelity sandbox:".to_string(),
            "  • QEMU                          : sudo apt-get install -y qemu-system-arm qemu-utils".to_string(),
        ]
    };

    let step_refs: Vec<&str> = steps.iter().map(|s| s.as_str()).collect();
    let why = "Amiterra preserves Zero Host Pollution and does not silently install\nheavy background hypervisors or container daemons without your consent.";

    Ui::error_box(
        "No compatible container runtime or Kubernetes tool detected",
        why,
        &step_refs,
        Some("https://docs.amiterra.io/workstation/prerequisites"),
    );

    let next_hint = format!("Run '{}' once a container runtime is ready.", next_command);
    Ui::next_steps("Next step:", &[&next_hint]);
}
