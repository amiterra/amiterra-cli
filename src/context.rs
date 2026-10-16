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
    #[serde(default)]
    pub mcp: McpConfigSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub runtime: String,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    #[serde(default = "default_networking_profile")]
    pub networking: String,
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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfigSection {
    pub enabled: bool,
    pub endpoint: String,
}

impl Default for McpConfigSection {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: "http://127.0.0.1:8080".to_string(),
        }
    }
}

impl Default for AmiterraConfig {
    fn default() -> Self {
        Self {
            mode: EnvironmentMode::Workstation,
            cluster: ClusterConfig::default(),
            mcp: McpConfigSection::default(),
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
    pub mcp_config_path: PathBuf,
    pub init_args: Option<crate::cli::InitArgs>,
}

impl ExecutionContext {
    /// Automatically detects or resolves the execution context based on CLI flags,
    /// persisted configuration, or host environment capabilities.
    pub fn resolve(force_dev: bool, force_server: bool) -> Self {
        let home_dir = Self::resolve_amiterra_home();
        let bin_dir = std::env::var("AMITERRA_INSTALL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home_dir.join("bin"));
        let config_path = home_dir.join("config.yaml");
        let mcp_config_path = home_dir.join("mcp.json");

        let mode = if force_server {
            EnvironmentMode::Server
        } else if force_dev {
            EnvironmentMode::Workstation
        } else if let Some(saved_mode) = Self::load_saved_mode(&config_path) {
            saved_mode
        } else if Path::new("/etc/amiterra.conf").exists()
            || Path::new("/etc/systemd/system/amiterra.service").exists()
        {
            EnvironmentMode::Server
        } else {
            EnvironmentMode::Workstation
        };

        Self {
            mode,
            home_dir,
            bin_dir,
            config_path,
            mcp_config_path,
            init_args: None,
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

        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
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
