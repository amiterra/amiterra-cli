//! Join-command surface.
//!
//! The cluster join token is a **secret**: with it anyone can join a node to the
//! cluster (and with `--control-plane`, reach etcd). Install output therefore
//! never prints the token — it prints these lookup commands instead, so the
//! full join string only appears when an operator explicitly asks for it on the
//! cluster node.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::fs;
use std::path::Path;

use crate::ui::{Palette, Ui};

/// k3s node token (root-only, 0600) — read on demand, never cached elsewhere.
pub const NODE_TOKEN_PATH: &str = "/var/lib/rancher/k3s/server/node-token";
/// k3s config rendered by `ami init` (contains `node-ip`).
pub const K3S_CONFIG_PATH: &str = "/etc/rancher/k3s/config.yaml";
/// API server port of the k3s control plane.
pub const API_PORT: u16 = 6443;

/// Which node type the join string is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinRole {
    Worker,
    ControlPlane,
}

impl JoinRole {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "worker" | "w" => Ok(JoinRole::Worker),
            "control-plane" | "cp" | "controlplane" | "control_plane" => Ok(JoinRole::ControlPlane),
            other => bail!("unknown role '{other}' — use `worker` or `control-plane`"),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            JoinRole::Worker => "worker",
            JoinRole::ControlPlane => "control-plane",
        }
    }
}

/// Machine-readable join string payload.
#[derive(Debug, Clone, Serialize)]
pub struct JoinCommandReport {
    pub role: String,
    pub endpoint: String,
    pub command: String,
}

/// Extract `node-ip` from a rendered k3s config YAML (pure, unit-tested).
///
/// Handles both `node-ip: 10.0.0.5` and `node-ip: "10.0.0.5"`.
pub fn parse_node_ip(config_yaml: &str) -> Option<String> {
    for line in config_yaml.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("node-ip:") {
            let value = rest.trim().trim_matches('"').trim_matches('\'');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Build the full `ami join …` string for `role` (pure, unit-tested).
pub fn render_join_command(role: JoinRole, endpoint: &str, token: &str) -> String {
    let cp_flag = match role {
        JoinRole::Worker => String::new(),
        JoinRole::ControlPlane => " --control-plane".to_string(),
    };
    format!("sudo ami join {endpoint} --token {token}{cp_flag}")
}

/// Read the node token (root-only file).
pub fn read_node_token(path: &Path) -> Result<String> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read node token at {}", path.display()))?;
    let token = raw.trim();
    if token.is_empty() {
        bail!(
            "node token at {} is empty — is this a control-plane-init node?",
            path.display()
        );
    }
    Ok(token.to_string())
}

/// Resolve the cluster API endpoint from the k3s config.
pub fn resolve_endpoint(config_path: &Path) -> Result<String> {
    let raw = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let ip = parse_node_ip(&raw).context("no `node-ip` in k3s config")?;
    Ok(format!("https://{ip}:{API_PORT}"))
}

/// CLI handler for `ami join-command`.
pub fn handle(role_raw: Option<&str>, json: bool) -> Result<()> {
    let roles: Vec<JoinRole> = match role_raw {
        None | Some("all") => vec![JoinRole::Worker, JoinRole::ControlPlane],
        Some(raw) => vec![JoinRole::parse(raw)?],
    };

    let endpoint = resolve_endpoint(Path::new(K3S_CONFIG_PATH))?;
    let token = read_node_token(Path::new(NODE_TOKEN_PATH))?;

    if json {
        let reports: Vec<JoinCommandReport> = roles
            .iter()
            .map(|r| JoinCommandReport {
                role: r.label().to_string(),
                endpoint: endpoint.clone(),
                command: render_join_command(*r, &endpoint, &token),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&reports)?);
        return Ok(());
    }

    Ui::header(
        "Amiterra Join Commands",
        "Full join string (embeds the cluster token)",
    );
    for role in &roles {
        println!(
            "  {} {}:",
            Palette::cyan("›"),
            match role {
                JoinRole::Worker => "Worker node",
                JoinRole::ControlPlane => "Control Plane node (HA)",
            }
        );
        println!(
            "    {} {}",
            Palette::dim("$"),
            Palette::bold_blue(&render_join_command(*role, &endpoint, &token))
        );
        println!();
    }
    println!(
        "  {} The join string embeds the cluster token — treat it as a secret.",
        Palette::yellow("!")
    );
    println!(
        "  {} Copy the line above and run it on the node you want to join.",
        Palette::dim("→")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_node_ip_plain_and_quoted() {
        assert_eq!(
            parse_node_ip("node-ip: 10.0.0.5\ncluster-init: true\n").as_deref(),
            Some("10.0.0.5")
        );
        assert_eq!(
            parse_node_ip("node-ip: \"10.0.0.5\"\n").as_deref(),
            Some("10.0.0.5")
        );
        assert_eq!(parse_node_ip("cluster-init: true\n"), None);
    }

    #[test]
    fn render_join_command_worker_and_cp() {
        let w = render_join_command(JoinRole::Worker, "https://1.2.3.4:6443", "TOK");
        assert_eq!(w, "sudo ami join https://1.2.3.4:6443 --token TOK");
        let cp = render_join_command(JoinRole::ControlPlane, "https://1.2.3.4:6443", "TOK");
        assert_eq!(
            cp,
            "sudo ami join https://1.2.3.4:6443 --token TOK --control-plane"
        );
    }

    #[test]
    fn role_parse_aliases_and_rejects_garbage() {
        assert_eq!(JoinRole::parse("worker").unwrap(), JoinRole::Worker);
        assert_eq!(JoinRole::parse("w").unwrap(), JoinRole::Worker);
        assert_eq!(
            JoinRole::parse("control-plane").unwrap(),
            JoinRole::ControlPlane
        );
        assert_eq!(JoinRole::parse("cp").unwrap(), JoinRole::ControlPlane);
        assert!(JoinRole::parse("banana").is_err());
    }

    #[test]
    fn read_node_token_roundtrip_and_guards() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("node-token");
        fs::write(&path, "abc123::server:xyz\n").unwrap();
        assert_eq!(read_node_token(&path).unwrap(), "abc123::server:xyz");

        fs::write(&path, "   \n").unwrap();
        assert!(read_node_token(&path).is_err(), "empty token must fail");
        assert!(
            read_node_token(&dir.path().join("missing")).is_err(),
            "missing file must fail"
        );
    }

    #[test]
    fn resolve_endpoint_from_k3s_config() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        fs::write(&path, "node-ip: \"65.108.237.169\"\ncluster-init: true\n").unwrap();
        assert_eq!(
            resolve_endpoint(&path).unwrap(),
            "https://65.108.237.169:6443"
        );
    }
}
