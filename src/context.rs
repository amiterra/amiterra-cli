use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Operating mode of the current Amiterra installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvironmentMode {
    Workstation,
    Server,
}

/// Persistent configuration stored in `~/.amiterra/config.yaml` or `/etc/amiterra/config.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmiterraConfig {
    pub mode: EnvironmentMode,
    #[serde(default)]
    pub cluster: ClusterConfig,
    // Note: legacy `mcp` section in old config.yaml is ignored (unknown fields).
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub runtime: String,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    #[serde(default = "default_networking_profile")]
    pub networking: String,
    /// Preferred sandbox engine family: "qemu" | "container" | "host".
    #[serde(default)]
    pub sandbox_engine: Option<String>,
}

fn default_api_port() -> u16 {
    6443
}

fn default_networking_profile() -> String {
    "k3s-headless".to_string()
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            runtime: "docker".to_string(),
            api_port: default_api_port(),
            networking: default_networking_profile(),
            sandbox_engine: None,
        }
    }
}

impl Default for AmiterraConfig {
    fn default() -> Self {
        Self {
            mode: EnvironmentMode::Workstation,
            cluster: ClusterConfig::default(),
        }
    }
}

/// Resolves filesystem paths and active environment mode without hardcoding OS assumptions.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub mode: EnvironmentMode,
    pub home_dir: PathBuf,
    pub bin_dir: PathBuf,
    pub config_path: PathBuf,
    pub init_args: Option<crate::cli::InitArgs>,
    /// Preferred sandbox engine family chosen in the unified init wizard.
    pub sandbox_engine: Option<String>,
}

impl ExecutionContext {
    /// Automatically detects or resolves the execution context based on CLI flags,
    /// persisted configuration, or host environment capabilities.
    /// Resolve the execution context for lifecycle commands (`up`/`down`/`status`).
    ///
    /// Mode resolution (no mode flags — one unified flow):
    /// saved config → host heuristics (k3s service, amiterra unit) → Workstation default.
    pub fn resolve() -> Self {
        Self::resolve_with_mode(None)
    }

    /// Resolve with an explicit mode (init: picked target; join: always server).
    /// `None` falls back to the [`Self::resolve`] chain.
    pub fn resolve_with_mode(mode: Option<EnvironmentMode>) -> Self {
        let home_dir = Self::resolve_amiterra_home();
        let bin_dir = std::env::var("AMITERRA_INSTALL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home_dir.join("bin"));
        let config_path = home_dir.join("config.yaml");

        let mode = mode
            .or_else(|| Self::load_saved_mode(&config_path))
            .or_else(|| {
                if Path::new("/etc/amiterra.conf").exists()
                    || Path::new("/etc/systemd/system/amiterra.service").exists()
                {
                    Some(EnvironmentMode::Server)
                } else {
                    None
                }
            })
            .unwrap_or(EnvironmentMode::Workstation);

        Self {
            mode,
            home_dir,
            bin_dir,
            config_path,
            init_args: None,
            sandbox_engine: None,
        }
    }

    fn load_saved_mode(config_path: &Path) -> Option<EnvironmentMode> {
        let content = fs::read_to_string(config_path).ok()?;
        let cfg: AmiterraConfig = serde_yaml::from_str(&content).ok()?;
        Some(cfg.mode)
    }

    pub fn resolve_amiterra_home() -> PathBuf {
        if let Ok(custom_home) = std::env::var("AMITERRA_HOME") {
            return PathBuf::from(custom_home);
        }
        if let Ok(install_dir) = std::env::var("AMITERRA_INSTALL_DIR") {
            let p = Path::new(&install_dir);
            if p.file_name().and_then(|n| n.to_str()) == Some("bin") {
                return p
                    .parent()
                    .map(|parent| parent.to_path_buf())
                    .unwrap_or_else(|| p.to_path_buf());
            }
            return p.to_path_buf();
        }

        // HOME may be absent in minimal/systemd contexts. Never fall back to
        // /tmp for root — a world-writable directory enables symlink attacks
        // against config writes.
        let home = std::env::var("HOME")
            .ok()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| {
                if crate::preflight::is_root() {
                    "/root".to_string()
                } else {
                    "/tmp".to_string()
                }
            });
        let default_dir = Path::new(&home).join(".amiterra");
        if fs::create_dir_all(&default_dir).is_ok() {
            let probe = default_dir.join(".write_probe");
            if fs::write(&probe, b"").is_ok() {
                let _ = fs::remove_file(&probe);
                return default_dir;
            }
        }
        Path::new(&home).join(".cargo").join("amiterra")
    }

    pub fn save_config(&self, config: &AmiterraConfig) -> Result<()> {
        fs::create_dir_all(&self.home_dir)?;
        let yaml = serde_yaml::to_string(config)?;
        fs::write(&self.config_path, yaml)?;
        Ok(())
    }
}
