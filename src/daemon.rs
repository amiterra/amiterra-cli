use anyhow::{Context, Result};
use notify::{RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{error, info, warn};

// --- Data Models ---

#[derive(Debug, Deserialize, Serialize, Clone)]
struct KubeletConfig {
    #[serde(default = "default_api_endpoint")]
    api_endpoint: String,
    #[serde(default = "default_client_cert_path")]
    client_cert_path: String,
    #[serde(default = "default_client_key_path")]
    client_key_path: String,
    #[serde(default = "default_pods_dir")]
    pods_dir: String,
    #[serde(default = "default_annotation_key")]
    annotation_key: String,
}

impl Default for KubeletConfig {
    fn default() -> Self {
        Self {
            api_endpoint: default_api_endpoint(),
            client_cert_path: default_client_cert_path(),
            client_key_path: default_client_key_path(),
            pods_dir: default_pods_dir(),
            annotation_key: default_annotation_key(),
        }
    }
}

fn default_api_endpoint() -> String { "https://127.0.0.1:10250/pods".to_string() }
fn default_client_cert_path() -> String { "/var/lib/rancher/k3s/agent/client-kubelet.crt".to_string() }
fn default_client_key_path() -> String { "/var/lib/rancher/k3s/agent/client-kubelet.key".to_string() }
fn default_pods_dir() -> String { "/var/lib/kubelet/pods".to_string() }
fn default_annotation_key() -> String { "amiterra.io/tuning-role".to_string() }

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct RoleConfig {
    weight: i32,
    #[serde(default)]
    sysctl: HashMap<String, String>,
    #[serde(default)]
    sysfs: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct TuningRules {
    #[serde(default)]
    kubelet: KubeletConfig,
    #[serde(default)]
    roles: HashMap<String, RoleConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct BaselineState {
    #[serde(default)]
    paths: HashMap<String, String>,
}

enum ParamType {
    Sysctl,
    Sysfs,
}

fn expand_pattern(param_type: &ParamType, pattern: &str) -> Vec<String> {
    let mut paths = Vec::new();

    let glob_pattern = match param_type {
        ParamType::Sysctl => format!("/proc/sys/{}", pattern.replace('.', "/")),
        ParamType::Sysfs => format!("/sys/{}", pattern),
    };

    if !glob_pattern.contains('*') {
        paths.push(glob_pattern);
        return paths;
    }

    match glob::glob(&glob_pattern) {
        Ok(entries) => {
            for entry in entries.filter_map(Result::ok) {
                if entry.is_file() {
                    paths.push(entry.to_string_lossy().to_string());
                }
            }
        }
        Err(e) => error!("Failed to parse glob pattern '{}': {}", glob_pattern, e),
    }

    paths
}

fn read_absolute(path: &str) -> Result<String> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read path: {}", path))?;
    Ok(content.trim().to_string())
}

fn write_absolute(path: &str, value: &str) -> Result<()> {
    fs::write(path, value)
        .with_context(|| format!("Failed to write '{}' to {}", value, path))?;
    Ok(())
}

fn save_baseline(baseline: &BaselineState, baseline_path: &Path) {
    if let Some(parent) = baseline_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    match serde_yaml::to_string(baseline) {
        Ok(yaml) => {
            if let Err(e) = fs::write(baseline_path, yaml) {
                error!("Failed to persist baseline to disk: {}", e);
            }
        }
        Err(e) => error!("Failed to serialize baseline state: {}", e),
    }
}

// --- Engine Logic ---

fn capture_initial_baseline(rules: &TuningRules, baseline_path: &Path) -> Result<BaselineState> {
    if baseline_path.exists() {
        let content = fs::read_to_string(baseline_path)?;
        let state: BaselineState = serde_yaml::from_str(&content)?;
        info!("Baseline state loaded successfully.");
        return Ok(state);
    }

    info!("Baseline state not found. Capturing initial host baseline...");
    let mut baseline = BaselineState::default();

    for role in rules.roles.values() {
        for pattern in role.sysctl.keys() {
            for path in expand_pattern(&ParamType::Sysctl, pattern) {
                if !baseline.paths.contains_key(&path)
                    && let Ok(val) = read_absolute(&path) {
                        baseline.paths.insert(path, val);
                }
            }
        }
        for pattern in role.sysfs.keys() {
            for path in expand_pattern(&ParamType::Sysfs, pattern) {
                if !baseline.paths.contains_key(&path)
                    && let Ok(val) = read_absolute(&path) {
                        baseline.paths.insert(path, val);
                }
            }
        }
    }

    save_baseline(&baseline, baseline_path);
    info!("Initial baseline saved ({} paths).", baseline.paths.len());

    Ok(baseline)
}

fn calculate_target_state(
    active_roles: &[String],
    rules: &TuningRules,
    baseline: &BaselineState,
) -> HashMap<String, String> {
    let mut target_state = baseline.paths.clone();

    let mut matched_roles: Vec<(&String, &RoleConfig)> = active_roles
        .iter()
        .filter_map(|r| rules.roles.get(r).map(|cfg| (r, cfg)))
        .collect();

    matched_roles.sort_by_key(|&(_, cfg)| cfg.weight);

    for (_role_name, cfg) in matched_roles {
        for (pattern, target_val) in &cfg.sysctl {
            for path in expand_pattern(&ParamType::Sysctl, pattern) {
                target_state.insert(path, target_val.clone());
            }
        }
        for (pattern, target_val) in &cfg.sysfs {
            for path in expand_pattern(&ParamType::Sysfs, pattern) {
                target_state.insert(path, target_val.clone());
            }
        }
    }

    target_state
}

fn apply_state(
    target_state: &HashMap<String, String>,
    baseline: &mut BaselineState,
    baseline_path: &Path,
) {
    let mut baseline_updated = false;

    for (path, target_val) in target_state {
        // Enforce host security guardrails for sysctl parameters
        if let Some(sysctl_subpath) = path.strip_prefix("/proc/sys/") {
            let sysctl_key = sysctl_subpath.replace('/', ".");
            if let crate::guardrails::GuardrailDecision::Rejected(reason) =
                crate::guardrails::SecurityGuardrails::validate_parameter(&sysctl_key, target_val)
            {
                error!(
                    "Security Guardrail violation: rejected tuning for '{}' = '{}': {}",
                    sysctl_key, target_val, reason
                );
                continue;
            }
        }

        match read_absolute(path) {
            Ok(current_val) => {
                if !baseline.paths.contains_key(path) {
                    info!("Discovered new dynamic path '{}', recording initial value '{}' in baseline", path, current_val);
                    baseline.paths.insert(path.clone(), current_val.clone());
                    baseline_updated = true;
                }

                if current_val != *target_val {
                    info!("Updating '{}': '{}' -> '{}'", path, current_val, target_val);
                    if let Err(e) = write_absolute(path, target_val) {
                        error!("Failed to apply '{}': {}", path, e);
                    } else {
                        info!("Applied: {} = {}", path, target_val);
                    }
                }
            }
            Err(e) => {
                error!("Failed to read current state of '{}': {}", path, e);
            }
        }
    }

    if baseline_updated {
        save_baseline(baseline, baseline_path);
    }
}

// --- Kubernetes Integration (Local Kubelet API & Inotify) ---

#[derive(Debug, Clone)]
struct ResolvedTlsIdentity {
    cert_path: String,
    key_path: String,
    identity_source: &'static str,
}

fn resolve_client_credentials(config: &KubeletConfig) -> Option<ResolvedTlsIdentity> {
    // 1. Control-plane admin certificate (highest privilege, instantaneous 200 OK without RBAC delay)
    let admin_cert = Path::new("/var/lib/rancher/k3s/server/tls/client-admin.crt");
    let admin_key = Path::new("/var/lib/rancher/k3s/server/tls/client-admin.key");
    if admin_cert.exists() && admin_key.exists() {
        return Some(ResolvedTlsIdentity {
            cert_path: admin_cert.to_string_lossy().to_string(),
            key_path: admin_key.to_string_lossy().to_string(),
            identity_source: "K3s Cluster Admin (client-admin.crt)",
        });
    }

    // 2. Control-plane kubelet client certificate (designated for API server kubelet proxy)
    let srv_kubelet_cert = Path::new("/var/lib/rancher/k3s/server/tls/client-kubelet.crt");
    let srv_kubelet_key = Path::new("/var/lib/rancher/k3s/server/tls/client-kubelet.key");
    if srv_kubelet_cert.exists() && srv_kubelet_key.exists() {
        return Some(ResolvedTlsIdentity {
            cert_path: srv_kubelet_cert.to_string_lossy().to_string(),
            key_path: srv_kubelet_key.to_string_lossy().to_string(),
            identity_source: "K3s Server Kubelet Client (client-kubelet.crt)",
        });
    }

    // 3. Node agent client certificate (standard for worker and control-plane nodes, works with amiterra RBAC)
    let agent_cert = Path::new("/var/lib/rancher/k3s/agent/client-kubelet.crt");
    let agent_key = Path::new("/var/lib/rancher/k3s/agent/client-kubelet.key");
    if agent_cert.exists() && agent_key.exists() {
        return Some(ResolvedTlsIdentity {
            cert_path: agent_cert.to_string_lossy().to_string(),
            key_path: agent_key.to_string_lossy().to_string(),
            identity_source: "K3s Node Agent (client-kubelet.crt)",
        });
    }

    // 4. Custom configured paths
    let cfg_cert = Path::new(&config.client_cert_path);
    let cfg_key = Path::new(&config.client_key_path);
    if cfg_cert.exists() && cfg_key.exists() {
        return Some(ResolvedTlsIdentity {
            cert_path: config.client_cert_path.clone(),
            key_path: config.client_key_path.clone(),
            identity_source: "Custom Configured Paths",
        });
    }

    None
}

pub fn resolve_pods_dir(configured_path: &str) -> String {
    // 1. Check existing pod directories on disk
    let candidates = [
        configured_path,
        "/var/lib/kubelet/pods",
        "/var/lib/rancher/k3s/agent/kubelet/pods",
    ];

    for candidate in candidates {
        if Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }

    // Do not force mkdir -p; preserve system permissions and let watcher wait for Kubelet lifecycle
    configured_path.to_string()
}

async fn wait_for_kubelet_readiness(config: &KubeletConfig, timeout_secs: u64) {
    let start = std::time::Instant::now();
    info!("Waiting for Kubelet API and mTLS certificates readiness...");
    let mut last_warn = std::time::Instant::now();

    loop {
        if let Some(identity) = resolve_client_credentials(config) {
            match fetch_active_roles(config, &identity).await {
                Ok(roles) => {
                    info!(
                        "Kubelet API is ready (authenticated via {}). Active roles: {}",
                        identity.identity_source,
                        roles.len()
                    );
                    return;
                }
                Err(e) => {
                    if last_warn.elapsed().as_secs() >= 10 {
                        warn!("Kubelet API not ready yet ({:#}). Retrying...", e);
                        last_warn = std::time::Instant::now();
                    }
                }
            }
        } else if last_warn.elapsed().as_secs() >= 10 {
            warn!("Waiting for K3s TLS certificates to be generated on host...");
            last_warn = std::time::Instant::now();
        }

        if start.elapsed().as_secs() > timeout_secs {
            warn!(
                "Readiness probe reached {}s limit. Proceeding with daemon execution...",
                timeout_secs
            );
            return;
        }
        sleep(Duration::from_secs(2)).await;
    }
}

async fn fetch_active_roles(
    config: &KubeletConfig,
    identity_info: &ResolvedTlsIdentity,
) -> Result<Vec<String>> {
    let cert_pem = fs::read_to_string(&identity_info.cert_path)
        .with_context(|| format!("Failed to read certificate: {}", identity_info.cert_path))?;
    let key_pem = fs::read_to_string(&identity_info.key_path)
        .with_context(|| format!("Failed to read private key: {}", identity_info.key_path))?;

    let identity_pem = format!("{}\n{}", cert_pem, key_pem);
    let identity = reqwest::Identity::from_pem(identity_pem.as_bytes())
        .context("Failed to create Identity from PEM (verify certificate format)")?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .identity(identity)
        .timeout(Duration::from_secs(10))
        .build()?;

    let response = client
        .get(&config.api_endpoint)
        .send()
        .await
        .with_context(|| format!("HTTP request failed for {}", config.api_endpoint))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        anyhow::bail!("Kubelet API returned error {}: {}", status, text);
    }

    let json: serde_json::Value = response.json().await?;
    let mut active_roles = HashSet::new();

    if let Some(items) = json.get("items").and_then(|i| i.as_array()) {
        for pod in items {
            if let Some(annotations) = pod
                .get("metadata")
                .and_then(|m| m.get("annotations"))
                .and_then(|a| a.as_object())
                && let Some(role) = annotations.get(&config.annotation_key).and_then(|v| v.as_str())
            {
                for r in role.split(',') {
                    let r = r.trim();
                    if !r.is_empty() {
                        active_roles.insert(r.to_string());
                    }
                }
            }
        }
    }

    Ok(active_roles.into_iter().collect())
}

// --- Inotify Watcher with Debounce ---

fn start_pod_watcher(pods_dir: String, tx: mpsc::Sender<()>) {
    std::thread::spawn(move || {
        let mut warned_missing = false;
        // Outer resilient loop to recover if directory is recreated or inotify drops
        loop {
            let (notify_tx, notify_rx) = std::sync::mpsc::channel();

            let mut watcher = match notify::recommended_watcher(notify_tx) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to initialize inotify watcher: {}", e);
                    std::thread::sleep(Duration::from_secs(30));
                    continue;
                }
            };

            let path = Path::new(&pods_dir);
            loop {
                if path.exists() {
                    if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                        error!("Failed to watch {}: {}", pods_dir, e);
                        std::thread::sleep(Duration::from_secs(30));
                        continue;
                    }
                    info!("Successfully subscribed to inotify events on {}", pods_dir);
                    break;
                } else {
                    if !warned_missing {
                        info!(
                            "Kubelet pods directory ({}) not present yet. Daemon will poll Kubelet API every 30s until directory is initialized by Kubelet...",
                            pods_dir
                        );
                        warned_missing = true;
                    }
                    std::thread::sleep(Duration::from_secs(5));
                }
            }

            for res in notify_rx {
                match res {
                    Ok(event) => {
                        if event.kind.is_create() || event.kind.is_remove() {
                            // Channel capacity is 1; if full, debounce is already scheduled
                            let _ = tx.try_send(());
                        }
                    }
                    Err(e) => {
                        error!("Inotify channel error: {:?}", e);
                        break; // Break inner loop to recreate watcher
                    }
                }
            }

            warn!("Restarting inotify watcher module...");
            std::thread::sleep(Duration::from_secs(5));
        }
    });
}

// --- Main Reconciliation Loop ---

pub async fn run() -> Result<()> {
    info!("Starting Amiterra Host & Workload Tuner Daemon (Day 2)...");

    let rules_path = Path::new("/etc/amiterra/tuning_rules.yaml");
    let baseline_path = Path::new("/var/lib/amiterra/baseline.yaml");

    if !rules_path.exists() {
        warn!("Tuning rules file not found. Creating default configuration...");
        if let Some(parent) = rules_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let demo_rules = r#"
kubelet:
  api_endpoint: "https://127.0.0.1:10250/pods"
  client_cert_path: "/var/lib/rancher/k3s/agent/client-kubelet.crt"
  client_key_path: "/var/lib/rancher/k3s/agent/client-kubelet.key"
  pods_dir: "/var/lib/kubelet/pods"
  annotation_key: "amiterra.io/tuning-role"
roles:
  clickhouse:
    weight: 100
    sysctl:
      vm.swappiness: "1"
      vm.max_map_count: "1600000"
    sysfs:
      kernel/mm/transparent_hugepage/enabled: "never"
  kafka:
    weight: 50
    sysfs:
      block/*/queue/scheduler: "none"
"#;
        fs::write(rules_path, demo_rules)?;
    }

    let rules_content = fs::read_to_string(rules_path)?;
    let rules: TuningRules = serde_yaml::from_str(&rules_content)
        .context("Failed to parse tuning_rules.yaml")?;
    info!("Loaded tuning rules for roles: {:?}", rules.roles.keys().collect::<Vec<_>>());

    // Wait for Kubelet mTLS certificates (Readiness Probe)
    wait_for_kubelet_readiness(&rules.kubelet, 60).await;

    let mut baseline = capture_initial_baseline(&rules, baseline_path)?;

    let (tx, mut rx) = mpsc::channel(1);

    let resolved_pods_dir = resolve_pods_dir(&rules.kubelet.pods_dir);
    start_pod_watcher(resolved_pods_dir, tx.clone());

    // Trigger initial reconciliation on startup
    let _ = tx.send(()).await;

    loop {
        // Wait for inotify trigger with a 30-second periodic re-sync timeout
        match tokio::time::timeout(Duration::from_secs(30), rx.recv()).await {
            Ok(Some(())) => {
                // Debounce 500ms to coalesce burst events
                sleep(Duration::from_millis(500)).await;
                while rx.try_recv().is_ok() {}
                info!("Received pod topology update trigger.");
            }
            Ok(None) => break,
            Err(_) => {
                // Periodic reconciliation (every 30s) against manual drift or pods without local volumes
            }
        }

        if let Some(identity) = resolve_client_credentials(&rules.kubelet) {
            match fetch_active_roles(&rules.kubelet, &identity).await {
                Ok(active_roles) => {
                    info!("Active workload roles on node: {:?}", active_roles);
                    let target_state = calculate_target_state(&active_roles, &rules, &baseline);
                    apply_state(&target_state, &mut baseline, baseline_path);
                }
                Err(e) => {
                    error!("Failed to fetch active roles from Kubelet API: {:#}", e);
                }
            }
        } else {
            error!("Failed to locate valid K3s TLS identity for Kubelet API");
        }
    }

    Ok(())
}
