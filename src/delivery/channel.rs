//! Local intent channel: unix socket between the delivery door
//! (`ami apply`) and the agent (Design Doc 0026 §1.7).
//!
//! One request per connection, newline-free JSON payloads (the intent YAML is
//! embedded as a JSON string). The socket lives on the node
//! (`/var/lib/amiterra/gitops/intent.sock`) — air-gap delivery never leaves
//! localhost. Transport trust is OS-level (socket permissions); the payload
//! trust is the SSHSIG signature the agent verifies independently.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use super::agent::{AgentConfig, ApplyError, ApplyOutcome, apply_intent};
use super::intent::TopologyChange;

/// Default socket path of the local intent channel.
pub fn default_socket() -> PathBuf {
    PathBuf::from(crate::gitops::keys::GITOPS_DIR).join("intent.sock")
}

/// Request sent by the door (`ami apply`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyRequest {
    /// Canonical `TopologyChange` YAML (exactly what was signed).
    pub intent_yaml: String,
    /// SSHSIG signature (PEM) over the canonical intent bytes.
    pub signature_pem: String,
}

/// Response returned by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyResponse {
    /// `applied` | `noop` | `rejected` | `stopping`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Honesty notes (preserved foreign files, enforcement gaps…).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl ApplyResponse {
    pub fn from_outcome(outcome: &ApplyOutcome) -> Self {
        match outcome {
            ApplyOutcome::Applied {
                change_id,
                commit_sha,
                tree_hash,
                warnings,
                ..
            } => Self {
                status: "applied".into(),
                change_id: Some(change_id.clone()),
                commit_sha: Some(commit_sha.clone()),
                tree_hash: Some(tree_hash.clone()),
                error: None,
                warnings: warnings.clone(),
            },
            ApplyOutcome::Noop { change_id } => Self {
                status: "noop".into(),
                change_id: Some(change_id.clone()),
                commit_sha: None,
                tree_hash: None,
                error: None,
                warnings: Vec::new(),
            },
        }
    }

    pub fn rejected(err: &ApplyError) -> Self {
        Self {
            status: "rejected".into(),
            change_id: None,
            commit_sha: None,
            tree_hash: None,
            error: Some(err.to_string()),
            warnings: Vec::new(),
        }
    }
}

/// Internal control request (tests / graceful shutdown).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlRequest {
    #[serde(default)]
    pub shutdown: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum Request {
    Apply(ApplyRequest),
    Control(ControlRequest),
}

/// Handle one connection: parse the request, run the agent apply path,
/// write the JSON response.
fn handle_connection(mut stream: UnixStream, cfg: &AgentConfig) -> Result<bool> {
    let mut buf = String::new();
    stream
        .read_to_string(&mut buf)
        .context("read intent request")?;
    let response = match serde_json::from_str::<Request>(&buf) {
        Ok(Request::Control(ControlRequest { shutdown })) => {
            let r = ApplyResponse {
                status: "stopping".into(),
                change_id: None,
                commit_sha: None,
                tree_hash: None,
                error: None,
                warnings: Vec::new(),
            };
            let payload = serde_json::to_string(&r)?;
            stream.write_all(payload.as_bytes())?;
            return Ok(!shutdown);
        }
        Ok(Request::Apply(req)) => {
            let outcome = {
                let parsed: TopologyChange = match serde_yaml::from_str(&req.intent_yaml) {
                    Ok(t) => t,
                    Err(e) => {
                        let r = ApplyResponse::rejected(&ApplyError::Intent(format!(
                            "parse intent: {e}"
                        )));
                        let payload = serde_json::to_string(&r)?;
                        stream.write_all(payload.as_bytes())?;
                        return Ok(true);
                    }
                };
                apply_intent(&parsed, &req.signature_pem, cfg)
            };
            match outcome {
                Ok(o) => ApplyResponse::from_outcome(&o),
                Err(e) => ApplyResponse::rejected(&e),
            }
        }
        Err(e) => ApplyResponse::rejected(&ApplyError::Intent(format!("bad request: {e}"))),
    };
    let payload = serde_json::to_string(&response)?;
    stream.write_all(payload.as_bytes())?;
    Ok(true)
}

/// Serve the intent channel until a shutdown control request arrives.
pub fn serve(socket_path: &Path, cfg: &AgentConfig) -> Result<()> {
    if socket_path.exists() {
        std::fs::remove_file(socket_path)
            .with_context(|| format!("remove stale socket {}", socket_path.display()))?;
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind intent socket {}", socket_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // The channel is node-local; still, restrict to the service user.
        let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600));
    }
    eprintln!(
        "intent channel listening on {} (cluster {}, repo {})",
        socket_path.display(),
        cfg.cluster_id,
        cfg.repo_path.display()
    );
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("intent channel: accept failed: {e}");
                continue;
            }
        };
        match handle_connection(stream, cfg) {
            Ok(true) => continue,
            Ok(false) => {
                eprintln!("intent channel: shutdown requested");
                break;
            }
            Err(e) => {
                eprintln!("intent channel: connection failed: {e:#}");
                continue;
            }
        }
    }
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

/// Run the channel in a background thread (CLI `intent-serve`, tests).
pub fn serve_in_thread(
    socket_path: PathBuf,
    cfg: AgentConfig,
) -> std::thread::JoinHandle<Result<()>> {
    std::thread::spawn(move || serve(&socket_path, &cfg))
}

/// Send a signed intent to the agent and wait for its verdict.
pub fn send_apply(
    socket_path: &Path,
    intent: &TopologyChange,
    signature_pem: &str,
) -> Result<ApplyResponse> {
    let intent_yaml = String::from_utf8(intent.canonical_bytes()?)
        .context("intent canonical bytes are not UTF-8")?;
    let request = ApplyRequest {
        intent_yaml,
        signature_pem: signature_pem.to_string(),
    };
    let payload = serde_json::to_string(&request)?;
    let mut stream = UnixStream::connect(socket_path).with_context(|| {
        format!(
            "connect to agent channel {} (is the agent running? `ami gitops intent-serve`)",
            socket_path.display()
        )
    })?;
    stream.write_all(payload.as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut buf = String::new();
    stream
        .read_to_string(&mut buf)
        .context("read agent response")?;
    let response: ApplyResponse = serde_json::from_str(&buf).context("parse agent response")?;
    Ok(response)
}

/// Ask the agent to stop (graceful shutdown hook for tests/unit hosts).
pub fn send_shutdown(socket_path: &Path) -> Result<()> {
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("connect {}", socket_path.display()))?;
    stream.write_all(serde_json::to_string(&ControlRequest { shutdown: true })?.as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(())
}

/// Convenience for callers that treat a non-applied response as an error.
pub fn expect_applied(response: &ApplyResponse) -> Result<&ApplyResponse> {
    match response.status.as_str() {
        "applied" | "noop" => Ok(response),
        other => Err(anyhow!(
            "apply {other}: {}",
            response
                .error
                .clone()
                .unwrap_or_else(|| "unknown error".into())
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::agent::tests_support::test_world;

    /// Wait (bounded) for the server socket to appear.
    pub(crate) fn wait_for_socket(path: &Path) {
        for _ in 0..200 {
            if path.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("socket {} never appeared", path.display());
    }

    #[test]
    fn roundtrip_apply_over_socket() {
        let w = test_world();
        let socket = w.dir.path().join("intent.sock");
        let cfg = w.agent_config();
        let handle = serve_in_thread(socket.clone(), cfg);
        wait_for_socket(&socket);

        let (intent, pem) = w.signed_intent("app.example.io", "auto");
        let resp = send_apply(&socket, &intent, &pem).unwrap();
        assert_eq!(resp.status, "applied");
        assert_eq!(
            resp.change_id.as_deref(),
            Some(intent.metadata.change_id.as_str())
        );
        assert!(resp.commit_sha.is_some());
        assert!(resp.tree_hash.unwrap().starts_with("sha256:"));

        // idempotent redelivery through the channel
        let resp2 = send_apply(&socket, &intent, &pem).unwrap();
        assert_eq!(resp2.status, "noop");

        // rejected: verify-don't-trust gate stays structured over the wire
        let (evil, evil_pem) = w.signed_intent("evil.example.io", "sha256:nope");
        let resp3 = send_apply(&socket, &evil, &evil_pem).unwrap();
        assert_eq!(resp3.status, "rejected");
        assert!(resp3.error.unwrap().contains("compile mismatch"));

        send_shutdown(&socket).unwrap();
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn missing_socket_is_a_clear_error() {
        let w = test_world();
        let (intent, pem) = w.signed_intent("app.example.io", "auto");
        let err = send_apply(
            std::path::Path::new("/nonexistent-amiterra/intent.sock"),
            &intent,
            &pem,
        )
        .unwrap_err();
        assert!(err.to_string().contains("agent running"), "{err:#}");
    }

    #[test]
    fn response_maps_outcomes() {
        let applied = ApplyResponse::from_outcome(&ApplyOutcome::Applied {
            change_id: "chg-1".into(),
            commit_sha: "abc".into(),
            tree_hash: "sha256:t".into(),
            journal_path: "_intent/chg-1.yaml".into(),
            warnings: vec!["note".into()],
        });
        assert_eq!(applied.status, "applied");
        let noop = ApplyResponse::from_outcome(&ApplyOutcome::Noop {
            change_id: "chg-1".into(),
        });
        assert_eq!(noop.status, "noop");
        assert!(expect_applied(&applied).is_ok());
        assert!(expect_applied(&noop).is_ok());
    }
}
