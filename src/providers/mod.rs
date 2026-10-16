pub mod runtime;
pub mod sandbox;
pub mod server;
pub mod workstation;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::context::{EnvironmentMode, ExecutionContext};
use server::LinuxServerBackend;
use workstation::WorkstationBackend;

/// Structured status item for unified CLI and JSON reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusMetric {
    pub label: String,
    pub value: String,
}

/// Context-aware environment status report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentStatus {
    pub mode: String,
    pub healthy: bool,
    pub summary: String,
    pub metrics: Vec<StatusMetric>,
    pub next_hint: Option<String>,
}

/// Core lifecycle abstraction for any target OS or deployment mode.
/// Adding support for a new OS (e.g., FreeBSD, Talos, WSL2) only requires implementing this trait.
pub trait EnvironmentBackend: Send + Sync {
    /// Human-readable name of the environment backend.
    fn name(&self) -> &'static str;

    /// Initialize configuration and provision required components (`ami init`).
    fn init(&self, ctx: &ExecutionContext, dry_run: bool) -> Result<()>;

    /// Start the environment (`ami up`).
    fn up(&self, ctx: &ExecutionContext, dry_run: bool) -> Result<()>;

    /// Stop the environment and release resources (`ami down`).
    fn down(&self, ctx: &ExecutionContext) -> Result<()>;

    /// Inspect current status (`ami status`).
    fn status(&self, ctx: &ExecutionContext) -> Result<EnvironmentStatus>;

    /// Uninstall components and revert host state (`ami uninstall`).
    fn uninstall(&self, ctx: &ExecutionContext, purge: bool) -> Result<()>;
}

/// Factory function that returns the appropriate backend for the resolved context.
pub fn resolve_backend(mode: EnvironmentMode) -> Box<dyn EnvironmentBackend> {
    match mode {
        EnvironmentMode::Workstation => Box::new(WorkstationBackend),
        EnvironmentMode::Server => Box::new(LinuxServerBackend),
    }
}
