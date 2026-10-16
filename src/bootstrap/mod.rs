pub mod api;
pub mod cascade;
pub mod network;

use anyhow::Result;
use tracing::info;
use std::path::Path;

pub async fn run() -> Result<()> {
    info!("Initializing Bootstrap Cascading State Machine...");

    // 1. Attempt to read Cloud-Init configuration
    if let Some(config) = cascade::check_cloud_init() {
        info!("Found configuration in Cloud-Init!");
        apply_config(config).await?;
        return Ok(());
    }

    // 2. Attempt to read /proc/cmdline configuration
    if let Some(config) = cascade::check_cmdline() {
        info!("Found configuration in Kernel Cmdline!");
        apply_config(config).await?;
        return Ok(());
    }

    // 3. Fallback to API (Axum)
    info!("No local configuration found. Starting API fallback on 0.0.0.0:8080...");
    api::start_server().await?;
    
    Ok(())
}

pub async fn apply_config(config: api::BootstrapPayload) -> Result<()> {
    info!("Applying configuration: {:?}", config);
    
    // Create K3s config directory
    tokio::fs::create_dir_all("/etc/rancher/k3s").await?;

    let mut k3s_config = String::new();

    // === OS Configuration (Hostname & SSH) ===
    if !config.hostname.is_empty() {
        info!("Setting hostname to: {}", config.hostname);
        let _ = tokio::fs::write("/etc/hostname", &config.hostname).await;
        // Apply immediately
        let _ = std::process::Command::new("hostnamectl")
            .args(["set-hostname", &config.hostname])
            .status();
        let _ = std::process::Command::new("hostname")
            .arg(&config.hostname)
            .status();
    }

    if let Some(ssh_keys) = &config.ssh_keys {
        let keys = ssh_keys.trim();
        if !keys.is_empty() {
            use tokio::io::AsyncWriteExt;
            for (user, home) in [("amiterra", "/home/amiterra"), ("debian", "/home/debian"), ("root", "/root")] {
                if tokio::fs::metadata(home).await.is_ok() {
                    info!("Adding SSH keys for user '{}'...", user);
                    let ssh_dir = format!("{}/.ssh", home);
                    let _ = tokio::fs::create_dir_all(&ssh_dir).await;
                    
                    let auth_keys_path = format!("{}/authorized_keys", ssh_dir);
                    if let Ok(mut file) = tokio::fs::OpenOptions::new().create(true).append(true).open(&auth_keys_path).await {
                        let _ = file.write_all(format!("\n{}\n", keys).as_bytes()).await;
                    }
                    
                    // Fix permissions and ownership
                    let _ = std::process::Command::new("chown")
                        .args(["-R", &format!("{}:{}", user, user), &ssh_dir])
                        .status();
                    let _ = std::process::Command::new("chmod")
                        .args(["700", &ssh_dir])
                        .status();
                    let _ = std::process::Command::new("chmod")
                        .args(["600", &auth_keys_path])
                        .status();
                }
            }
        }
    }
    // ==========================================

    // Generate K3s configuration based on node role
    match config.role.as_str() {
        "first-master" => {
            info!("Configuring as first-master (Cluster Init)");
            k3s_config.push_str("cluster-init: true\n");
            
            if let Some(token) = config.cluster_token.as_deref().filter(|t| !t.is_empty()) {
                k3s_config.push_str(&format!("token: {}\n", token));
            }
            if let Some(node_ip) = &config.node_ip {
                k3s_config.push_str(&format!("node-ip: {}\n", node_ip));
            }
            if let Some(pod_cidr) = &config.pod_cidr {
                k3s_config.push_str(&format!("cluster-cidr: {}\n", pod_cidr));
            }
            if let Some(service_cidr) = &config.service_cidr {
                k3s_config.push_str(&format!("service-cidr: {}\n", service_cidr));
            }
            if config.isolate_control_plane.is_some() {
                k3s_config.push_str("node-taint:\n  - \"node-role.kubernetes.io/control-plane:NoSchedule\"\n");
            }
            
            info!("Enabling and starting k3s.service...");
            let _ = std::process::Command::new("systemctl")
                .args(["enable", "--now", "--no-block", "k3s"])
                .status();
        },
        "master" => {
            info!("Configuring as secondary master");
            if let Some(url) = config.server_url {
                k3s_config.push_str(&format!("server: {}\n", url));
            }
            if let Some(token) = config.cluster_token.as_deref().filter(|t| !t.is_empty()) {
                k3s_config.push_str(&format!("token: {}\n", token));
            }
            if let Some(node_ip) = &config.node_ip {
                k3s_config.push_str(&format!("node-ip: {}\n", node_ip));
            }
            if config.isolate_control_plane.is_some() {
                k3s_config.push_str("node-taint:\n  - \"node-role.kubernetes.io/control-plane:NoSchedule\"\n");
            }
            
            info!("Enabling and starting k3s.service...");
            let _ = std::process::Command::new("systemctl")
                .args(["enable", "--now", "--no-block", "k3s"])
                .status();
        },
        "worker" => {
            info!("Configuring as worker");
            if let Some(url) = config.server_url {
                k3s_config.push_str(&format!("server: {}\n", url));
            }
            if let Some(token) = config.cluster_token.as_deref().filter(|t| !t.is_empty()) {
                k3s_config.push_str(&format!("token: {}\n", token));
            }
            if let Some(node_ip) = &config.node_ip {
                k3s_config.push_str(&format!("node-ip: {}\n", node_ip));
            }
            
            info!("Disabling k3s.service and starting k3s-agent.service for worker role...");
            let _ = std::process::Command::new("systemctl")
                .args(["disable", "--now", "k3s"])
                .status();
            let _ = std::process::Command::new("systemctl")
                .args(["enable", "--now", "--no-block", "k3s-agent"])
                .status();
        },
        _ => {
            tracing::warn!("Unknown role: {}", config.role);
        }
    }

    // Append configuration since /etc/rancher/k3s/config.yaml may already contain base settings
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/etc/rancher/k3s/config.yaml")
        .await?;
    
    file.write_all(k3s_config.as_bytes()).await?;

    // Write marker file for systemd so the oneshot bootstrap service does not run again
    let marker_path = Path::new("/etc/amiterra.conf");
    tokio::fs::write(marker_path, format!("NODE_ROLE={}\n", config.role)).await?;
    info!("Wrote marker file to /etc/amiterra.conf");
    
    // Update MOTD with node configuration status
    let motd_status = format!("\n[Amiterra Node: Configured | Role: {} | Hostname: {}]\n\n", config.role, config.hostname);
    if let Ok(mut file) = tokio::fs::OpenOptions::new().append(true).open("/etc/motd").await {
        let _ = file.write_all(motd_status.as_bytes()).await;
    }
    
    // Start Day-2 daemon now that the marker file exists
    info!("Enabling and starting amiterra.service (Day 2 daemon)...");
    let _ = std::process::Command::new("systemctl")
        .args(["enable", "--now", "--no-block", "amiterra"])
        .status();

    info!("Bootstrap completed successfully. The node will now start K3s and Amiterra Daemon.");
    Ok(())
}
