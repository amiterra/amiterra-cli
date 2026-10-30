//! Host tuning profiles, split from install-time bootstrap.
//!
//! Parameter sources live in [`tuning/`](../../../tuning/) (repo root) and are
//! embedded at build time — see [`profile`]. CLI apply/init paths print a
//! subsystem warning and the public docs link before any change.
//!
//! Two layers:
//! - **Platform prep** — minimal sysctls required for Kubernetes pod networking.
//!   Applied by `ami init`, always shown in preview, never aggressive.
//! - **Performance profile** — BBR, backlog, limits, swappiness, etc.
//!   Explicit `ami tune apply` / `ami tune rollback` / `ami tune status`.
//!
//! Safety rules:
//! - Absolute security blacklist is never applied by any tune path.
//! - Performance keys are validated through [`crate::guardrails::SecurityGuardrails`].
//! - Baseline is captured before first change and restored on rollback.
//! - Firewall policy (`ufw`) and panic policy are intentionally out of scope.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::guardrails::{GuardrailDecision, SecurityGuardrails};
use crate::ui::{Glyphs, Palette, Ui};

pub mod cli;
pub mod profile;

pub use profile::{
    LIMITS_TEXT, PERFORMANCE_SYSCTL_TEXT, PLATFORM_SYSCTL_TEXT, PerformanceProfile, PlatformPrep,
    SysctlEntry, TUNING_DOCS_URL, parse_sysctl_entries,
};

/// Directory for persistent Amiterra state.
pub const STATE_DIR: &str = "/var/lib/amiterra";
/// Baseline of host values captured before the first `tune apply`.
pub const BASELINE_PATH: &str = "/var/lib/amiterra/tune-baseline.yaml";
/// Platform prep sysctl drop-in (installed by `ami init`).
pub const PLATFORM_SYSCTL_PATH: &str = "/etc/sysctl.d/98-amiterra-platform.conf";
/// Performance profile sysctl drop-in (installed by `ami tune apply`).
pub const TUNE_SYSCTL_PATH: &str = "/etc/sysctl.d/99-amiterra-tune.conf";
/// Performance limits drop-in (installed by `ami tune apply`).
pub const TUNE_LIMITS_PATH: &str = "/etc/security/limits.d/99-amiterra.conf";
/// Legacy file from pre-split installers; cleaned up on migrate/rollback/uninstall.
pub const LEGACY_SYSCTL_PATH: &str = "/etc/sysctl.d/99-amiterra-bootstrap.conf";

/// Snapshot of host values prior to Amiterra modifications.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TuneBaseline {
    /// sysctl dotted key → original value.
    #[serde(default)]
    pub sysctl: BTreeMap<String, String>,
    /// Absolute limits file content before we wrote ours (if it existed).
    #[serde(default)]
    pub limits_existed: bool,
    #[serde(default)]
    pub limits_content: Option<String>,
}

impl TuneBaseline {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read baseline {}", path.display()))?;
        serde_yaml::from_str(&raw).context("Failed to parse tune baseline YAML")
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        let yaml = serde_yaml::to_string(self).context("Failed to serialize tune baseline")?;
        fs::write(path, yaml)
            .with_context(|| format!("Failed to write baseline {}", path.display()))?;
        Ok(())
    }
}

/// Convert dotted sysctl key to `/proc/sys/...` path.
pub fn sysctl_proc_path(key: &str) -> PathBuf {
    let mut p = PathBuf::from("/proc/sys");
    for part in key.split('.') {
        p.push(part);
    }
    p
}

/// Read current live value of a sysctl key.
pub fn read_sysctl(key: &str) -> Result<String> {
    let path = sysctl_proc_path(key);
    let raw =
        fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(raw.trim().to_string())
}

/// Write a sysctl key via `/proc/sys` (immediate) — used for rollback restore.
fn write_sysctl_live(key: &str, value: &str) -> Result<()> {
    let path = sysctl_proc_path(key);
    fs::write(&path, value)
        .with_context(|| format!("Failed to write {}={}", path.display(), value))?;
    Ok(())
}

/// True when this OS can apply sysctl drop-ins via `sysctl --system` (Linux only).
pub fn sysctl_reload_supported() -> bool {
    cfg!(target_os = "linux")
}

/// Reload sysctl drop-ins into the live kernel.
///
/// Linux uses `sysctl --system` (procps). macOS/BSD `sysctl` has no `--system`
/// flag — invoking it there prints `illegal option` and is meaningless.
pub fn reload_sysctl() -> Result<()> {
    if !sysctl_reload_supported() {
        return Ok(());
    }
    // Capture stderr: never leak host tool noise into the user's terminal.
    let out = Command::new("sysctl")
        .arg("--system")
        .output()
        .context("failed to run `sysctl --system`")?;
    if !out.status.success() {
        bail!(
            "`sysctl --system` failed to reload drop-ins: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Print which OS subsystems the performance profile will touch, plus the
/// public docs link (source-of-truth files under `tuning/`).
pub fn print_tuning_scope_warning() {
    use crate::tune::profile::TUNING_DOCS_URL;

    println!();
    println!(
        "  {}",
        Palette::bold("Host OS subsystems modified by the performance profile:")
    );
    println!(
        "    {} kernel networking — TCP congestion (BBR), BPF JIT, listen queues, ARP/rp_filter/neigh",
        Palette::yellow(Glyphs::WARN)
    );
    println!(
        "    {} virtual memory    — vm.swappiness (prefer RAM over swap-out)",
        Palette::yellow(Glyphs::WARN)
    );
    println!(
        "    {} file capacity     — fs.file-max, fs.nr_open, inotify instances/watches",
        Palette::yellow(Glyphs::WARN)
    );
    println!(
        "    {} process limits    — nofile soft/hard (limits.d)",
        Palette::yellow(Glyphs::WARN)
    );
    println!(
        "     {}",
        Palette::dim("Not modified: firewall (ufw), panic policy, BPF lockdown, disk schedulers.")
    );
    println!(
        "     {}",
        Palette::dim(&format!("Parameter sources & docs: {TUNING_DOCS_URL}"))
    );
    println!(
        "     {}",
        Palette::dim("Reversible: `ami tune rollback` restores the captured baseline.")
    );
    println!();
}

/// A single planned change: key, current value (if known), target value.
#[derive(Debug, Clone, Serialize)]
pub struct PlannedChange {
    pub key: String,
    pub current: Option<String>,
    pub target: String,
    pub layer: String,
}

/// Compute the plan without applying anything.
pub fn plan() -> Result<Vec<PlannedChange>> {
    let mut changes = Vec::new();
    let platform = PlatformPrep;
    let perf = PerformanceProfile;

    for e in platform.sysctl() {
        let current = read_sysctl(&e.key).ok();
        if current.as_deref() != Some(e.value.as_str()) {
            changes.push(PlannedChange {
                key: e.key.clone(),
                current,
                target: e.value.clone(),
                layer: "platform".into(),
            });
        }
    }

    for e in perf.sysctl() {
        // Never plan blacklisted keys — they must not enter the tune path.
        if let GuardrailDecision::Rejected(reason) =
            SecurityGuardrails::validate_parameter(&e.key, &e.value)
        {
            bail!(
                "Tune profile rejected by security guardrail: {} = {} ({})",
                e.key,
                e.value,
                reason
            );
        }
        let current = read_sysctl(&e.key).ok();
        if current.as_deref() != Some(e.value.as_str()) {
            changes.push(PlannedChange {
                key: e.key.clone(),
                current,
                target: e.value.clone(),
                layer: "performance".into(),
            });
        }
    }

    Ok(changes)
}

/// Apply **platform prep** only (called from `ami init`).
/// Minimal: pod networking routing. No performance, no firewall, no panic policy.
pub fn apply_platform_prep() -> Result<Vec<PlannedChange>> {
    let platform = PlatformPrep;
    validate_platform_profile(&platform)?;

    let changes: Vec<PlannedChange> = platform
        .sysctl()
        .iter()
        .filter_map(|e| {
            let current = read_sysctl(&e.key).ok();
            if current.as_deref() == Some(e.value.as_str()) {
                None
            } else {
                Some(PlannedChange {
                    key: e.key.clone(),
                    current,
                    target: e.value.clone(),
                    layer: "platform".into(),
                })
            }
        })
        .collect();

    if let Some(parent) = Path::new(PLATFORM_SYSCTL_PATH).parent() {
        fs::create_dir_all(parent)?;
    }
    // Write the embedded source verbatim (includes pipeline warning header).
    fs::write(PLATFORM_SYSCTL_PATH, platform.raw())
        .with_context(|| format!("Failed to write {}", PLATFORM_SYSCTL_PATH))?;
    reload_sysctl().context("platform prep written but `sysctl --system` reload failed")?;

    // Migrate away from the legacy combined file if present.
    if Path::new(LEGACY_SYSCTL_PATH).exists() {
        let _ = fs::remove_file(LEGACY_SYSCTL_PATH);
    }

    Ok(changes)
}

/// Install-time keys allowed in `tuning/platform.sysctl`.
/// These sit on the *dynamic* security blacklist (so workload annotations cannot
/// flip them) but are legitimate, reviewed constants for Kubernetes networking.
const PLATFORM_INSTALL_KEYS: &[&str] = &["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"];

/// Guard the platform profile: only the explicit install allowlist, nothing else.
/// Prevents a bad edit of `tuning/platform.sysctl` from landing privileged knobs.
fn validate_platform_profile(platform: &PlatformPrep) -> Result<()> {
    validate_platform_entries(&platform.sysctl())
}

/// Validate platform entries against [`PLATFORM_INSTALL_KEYS`] (testable core).
pub fn validate_platform_entries(entries: &[SysctlEntry]) -> Result<()> {
    for e in entries {
        if !PLATFORM_INSTALL_KEYS.contains(&e.key.as_str()) {
            bail!(
                "platform profile key '{}' is not in the install allowlist {:?}. \
                 Refusing to apply — see {TUNING_DOCS_URL}.",
                e.key,
                PLATFORM_INSTALL_KEYS
            );
        }
    }
    // Sanity: the documented keys must still be present (no accidental emptying).
    let keys: Vec<String> = entries.iter().map(|e| e.key.clone()).collect();
    for expected in PLATFORM_INSTALL_KEYS {
        if !keys.iter().any(|k| k == expected) {
            bail!(
                "platform profile is missing required key '{expected}' — see {TUNING_DOCS_URL}/platform.sysctl"
            );
        }
    }
    Ok(())
}

/// Validate every performance entry against security guardrails.
fn validate_performance(perf: &PerformanceProfile) -> Result<()> {
    for e in perf.sysctl() {
        match SecurityGuardrails::validate_parameter(&e.key, &e.value) {
            GuardrailDecision::Allowed => {}
            GuardrailDecision::Rejected(reason) => {
                bail!(
                    "Security guardrail rejected performance profile entry {} = {}: {}",
                    e.key,
                    e.value,
                    reason
                );
            }
        }
    }
    Ok(())
}

fn capture_baseline(perf: &PerformanceProfile) -> Result<TuneBaseline> {
    let mut baseline = TuneBaseline::load(Path::new(BASELINE_PATH)).unwrap_or_default();

    for e in perf.sysctl() {
        if !baseline.sysctl.contains_key(&e.key)
            && let Ok(val) = read_sysctl(&e.key)
        {
            baseline.sysctl.insert(e.key.clone(), val);
        }
    }

    let limits_path = Path::new(TUNE_LIMITS_PATH);
    if !baseline.limits_content.is_some() {
        if limits_path.exists() {
            baseline.limits_existed = true;
            baseline.limits_content = Some(fs::read_to_string(limits_path)?);
        } else {
            baseline.limits_existed = false;
            baseline.limits_content = None;
        }
    }

    baseline.save(Path::new(BASELINE_PATH))?;
    Ok(baseline)
}

/// Status report for `ami tune status`.
#[derive(Debug, Serialize)]
pub struct TuneStatus {
    pub platform_applied: bool,
    pub performance_applied: bool,
    pub baseline_present: bool,
    pub performance_changes_vs_baseline: usize,
    pub notes: Vec<String>,
}

pub fn status() -> Result<TuneStatus> {
    let platform_applied = Path::new(PLATFORM_SYSCTL_PATH).exists();
    let performance_applied =
        Path::new(TUNE_SYSCTL_PATH).exists() && Path::new(TUNE_LIMITS_PATH).exists();
    let baseline_present = Path::new(BASELINE_PATH).exists();

    let mut drift = 0usize;
    let mut notes = Vec::new();

    if baseline_present {
        let baseline = TuneBaseline::load(Path::new(BASELINE_PATH))?;
        let perf = PerformanceProfile;
        for e in perf.sysctl() {
            if let Some(orig) = baseline.sysctl.get(&e.key)
                && let Ok(cur) = read_sysctl(&e.key)
                && &cur != orig
                && cur != e.value
            {
                drift += 1;
            }
        }
        if drift > 0 {
            notes.push(format!(
                "{drift} performance parameter(s) differ from both baseline and profile (manual drift?)"
            ));
        }
    }

    if !performance_applied {
        notes.push(
            "Performance profile is NOT applied. Run `ami tune apply` for BBR / limits / swappiness."
                .into(),
        );
    }
    if Path::new(LEGACY_SYSCTL_PATH).exists() {
        notes.push(format!(
            "Legacy file {} is still present (pre-split installer)",
            LEGACY_SYSCTL_PATH
        ));
    }

    Ok(TuneStatus {
        platform_applied,
        performance_applied,
        baseline_present,
        performance_changes_vs_baseline: drift,
        notes,
    })
}

/// Policy gate before host mutation: interactive prompt, or explicit `--yes`.
/// Non-interactive without `--yes` is **always refused** (safety).
pub fn ensure_apply_consent(yes: bool, interactive: bool) -> Result<()> {
    if yes || interactive {
        return Ok(());
    }
    bail!(
        "Refusing to modify host tuning in a non-interactive session without --yes. \
         Re-run with --yes after reviewing `ami tune plan` and {TUNING_DOCS_URL}."
    )
}

/// Interactive confirm. Non-interactive sessions **require** an explicit `--yes`:
/// silent host modification in scripts is a safety bug, not a convenience.
pub fn confirm(prompt: &str, yes: bool) -> Result<bool> {
    use std::io::{IsTerminal, Write, stdin, stdout};
    if yes {
        return Ok(true);
    }
    let interactive = stdin().is_terminal();
    ensure_apply_consent(false, interactive)?;
    print!("{} {} [y/N]: ", Palette::cyan(Glyphs::WARN), prompt);
    stdout().flush()?;
    let mut input = String::new();
    stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}

/// Apply the **performance profile**. Captures baseline first (idempotent).
pub fn apply(yes: bool, dry_run: bool) -> Result<()> {
    let perf = PerformanceProfile;
    validate_performance(&perf)?;

    let changes = plan()?;
    let perf_changes: Vec<_> = changes
        .iter()
        .filter(|c| c.layer == "performance")
        .cloned()
        .collect();

    Ui::header(
        "Amiterra Performance Profile",
        "Kernel & limits optimization (opt-in, reversible)",
    );

    if perf_changes.is_empty() && Path::new(TUNE_SYSCTL_PATH).exists() {
        Ui::step_done("Performance profile already applied and consistent", None);
        return Ok(());
    }

    print_plan(&perf_changes, "performance");
    print_tuning_scope_warning();

    if dry_run {
        Ui::step_info("Dry-run", "No host modifications applied.");
        return Ok(());
    }

    if !confirm("Apply performance profile to this host?", yes)? {
        println!("  Aborted. Host left unchanged.");
        return Ok(());
    }

    // Root required to write drop-ins and /proc/sys.
    if !crate::preflight::is_root() {
        bail!("Superuser privileges are required for `ami tune apply`. Re-run with sudo.");
    }

    let spinner = Ui::spinner("Capturing host baseline...");
    let baseline = capture_baseline(&perf)?;
    spinner.success(&format!(
        "Baseline captured ({} sysctl keys)",
        baseline.sysctl.len()
    ));

    let spinner = Ui::spinner("Writing performance profile...");
    if let Some(parent) = Path::new(TUNE_SYSCTL_PATH).parent() {
        fs::create_dir_all(parent)?;
    }
    // Write the embedded source verbatim (includes pipeline warning header).
    fs::write(TUNE_SYSCTL_PATH, perf.raw_sysctl())
        .with_context(|| format!("Failed to write {}", TUNE_SYSCTL_PATH))?;

    if let Some(parent) = Path::new(TUNE_LIMITS_PATH).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(TUNE_LIMITS_PATH, perf.limits())
        .with_context(|| format!("Failed to write {}", TUNE_LIMITS_PATH))?;

    if Path::new(LEGACY_SYSCTL_PATH).exists() {
        let _ = fs::remove_file(LEGACY_SYSCTL_PATH);
    }

    if let Err(e) = reload_sysctl() {
        spinner.fail(&format!(
            "profile files written but reload failed: {e:#} — values may not be live"
        ));
        return Err(e.context(
            "performance profile written but not reloaded; fix sysctl and re-run `ami tune apply`",
        ));
    }
    spinner.success("Performance profile applied (sysctl + limits)");
    Ok(())
}

/// Restore baseline values and remove performance drop-ins.
pub fn rollback(yes: bool) -> Result<()> {
    Ui::header(
        "Amiterra Tune Rollback",
        "Restoring host values captured before tuning",
    );

    if !Path::new(BASELINE_PATH).exists()
        && !Path::new(TUNE_SYSCTL_PATH).exists()
        && !Path::new(TUNE_LIMITS_PATH).exists()
    {
        Ui::step_done(
            "Nothing to roll back (performance profile never applied)",
            None,
        );
        return Ok(());
    }

    if !confirm("Restore previous host tuning values?", yes)? {
        println!("  Aborted.");
        return Ok(());
    }

    if !crate::preflight::is_root() {
        bail!("Superuser privileges are required for `ami tune rollback`. Re-run with sudo.");
    }

    let baseline = TuneBaseline::load(Path::new(BASELINE_PATH))?;
    let spinner = Ui::spinner("Restoring baseline sysctl values...");
    let mut restored = 0usize;
    let mut failed: Vec<String> = Vec::new();
    for (key, val) in &baseline.sysctl {
        match write_sysctl_live(key, val) {
            Ok(()) => restored += 1,
            Err(e) => failed.push(format!("{key}: {e:#}")),
        }
    }
    // Partial restore must not claim success and must keep the drop-in files
    // so the operator can retry.
    if !failed.is_empty() {
        spinner.fail(&format!(
            "restored {restored} key(s), {} failed",
            failed.len()
        ));
        bail!(
            "rollback incomplete — drop-ins kept for retry:\n  {}",
            failed.join("\n  ")
        );
    }
    spinner.success(&format!("Restored {} sysctl key(s)", restored));

    if Path::new(TUNE_SYSCTL_PATH).exists() {
        let _ = fs::remove_file(TUNE_SYSCTL_PATH);
        Ui::step_done(&format!("Removed {}", TUNE_SYSCTL_PATH), None);
    }

    if Path::new(TUNE_LIMITS_PATH).exists() {
        let _ = fs::remove_file(TUNE_LIMITS_PATH);
        Ui::step_done(&format!("Removed {}", TUNE_LIMITS_PATH), None);
    }

    reload_sysctl().context("baseline restored but `sysctl --system` reload failed")?;
    Ui::step_done("Performance profile rolled back", None);
    Ok(())
}

/// Print a compact plan table.
pub fn print_plan(changes: &[PlannedChange], layer: &str) {
    if changes.is_empty() {
        Ui::step_info("Plan", "No pending changes.");
        return;
    }
    println!(
        "  {}",
        Palette::bold(format!("Planned changes ({layer}):").as_str())
    );
    for c in changes {
        let cur = c
            .current
            .clone()
            .unwrap_or_else(|| Palette::dim("(unset)").to_string());
        println!(
            "    {} {}  {} → {}",
            Palette::cyan(Glyphs::CHEVRON),
            c.key,
            cur,
            Palette::green(&c.target)
        );
    }
    // rp_filter relaxes reverse-path (anti-spoofing) checks — deliberate for
    // multi-homing/WireGuard, but security-relevant on a public-IP node.
    if changes.iter().any(|c| c.key.contains("rp_filter")) {
        println!(
            "  {} rp_filter is relaxed (anti-spoofing off) — intentional for WireGuard/multi-homing.",
            Palette::yellow("!")
        );
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysctl_proc_path() {
        assert_eq!(
            sysctl_proc_path("net.ipv4.ip_forward"),
            PathBuf::from("/proc/sys/net/ipv4/ip_forward")
        );
    }

    #[test]
    fn test_performance_profile_passes_guardrails() {
        let perf = PerformanceProfile;
        validate_performance(&perf).expect("profile must pass security guardrails");
    }

    #[test]
    fn test_platform_prep_is_minimal() {
        let p = PlatformPrep;
        let keys: Vec<String> = p.sysctl().into_iter().map(|e| e.key).collect();
        assert!(
            keys.iter().any(|k| k == "net.ipv4.ip_forward"),
            "platform prep must enable IPv4 forwarding for pod networking"
        );
        // Aggressive / policy keys must NOT live in platform prep.
        for forbidden in [
            "vm.swappiness",
            "net.ipv4.tcp_congestion_control",
            "kernel.panic",
            "kernel.unprivileged_bpf_disabled",
        ] {
            assert!(
                !keys.iter().any(|k| k == forbidden),
                "{forbidden} must not be in platform prep"
            );
        }
    }

    #[test]
    fn test_performance_excludes_policy_and_blacklist() {
        let perf = PerformanceProfile;
        let keys: Vec<String> = perf.sysctl().into_iter().map(|e| e.key).collect();
        for forbidden in [
            "net.ipv4.ip_forward",
            "kernel.core_pattern",
            "kernel.modprobe",
            "kernel.panic",
            "kernel.unprivileged_bpf_disabled",
        ] {
            assert!(
                !keys.iter().any(|k| k == forbidden),
                "{forbidden} must not be in performance profile"
            );
        }
    }

    #[test]
    fn test_baseline_roundtrip() {
        let mut b = TuneBaseline::default();
        b.sysctl.insert("vm.swappiness".into(), "60".into());
        let dir = std::env::temp_dir().join("amiterra-tune-test");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("baseline.yaml");
        b.save(&path).unwrap();
        let loaded = TuneBaseline::load(&path).unwrap();
        assert_eq!(
            loaded.sysctl.get("vm.swappiness").map(String::as_str),
            Some("60")
        );
    }

    #[test]
    fn test_raw_embedded_files_are_written_verbatim() {
        // Host drop-ins must be byte-identical to published sources (docs include).
        assert_eq!(PlatformPrep.raw(), profile::PLATFORM_SYSCTL_TEXT);
        assert_eq!(
            PerformanceProfile.raw_sysctl(),
            profile::PERFORMANCE_SYSCTL_TEXT
        );
        assert_eq!(PerformanceProfile.limits(), profile::LIMITS_TEXT);
        assert!(PlatformPrep.raw().contains("WARNING"));
        assert!(
            PerformanceProfile
                .raw_sysctl()
                .contains("tuning/performance.sysctl")
        );
    }

    #[test]
    fn test_platform_profile_matches_install_allowlist() {
        validate_platform_profile(&PlatformPrep).expect("current platform profile must be valid");
        let keys: Vec<String> = PlatformPrep.sysctl().into_iter().map(|e| e.key).collect();
        assert_eq!(
            keys.len(),
            PLATFORM_INSTALL_KEYS.len(),
            "no extra platform keys"
        );
    }

    #[test]
    fn test_platform_profile_rejects_privileged_key() {
        // Bad edit of tuning/platform.sysctl must not apply.
        let evil = parse_sysctl_entries(
            "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\nkernel.core_pattern = |/tmp/evil\n",
        );
        let err = validate_platform_entries(&evil).unwrap_err();
        assert!(err.to_string().contains("core_pattern"), "got: {err}");

        // Missing required key is also rejected.
        let incomplete = parse_sysctl_entries("net.ipv4.ip_forward = 1\n");
        assert!(validate_platform_entries(&incomplete).is_err());
    }

    #[test]
    fn test_confirm_requires_yes_when_non_interactive() {
        // Safety regression: non-TTY without --yes must refuse.
        assert!(
            ensure_apply_consent(true, false).is_ok(),
            "--yes overrides non-TTY"
        );
        assert!(
            ensure_apply_consent(false, true).is_ok(),
            "interactive prompts"
        );
        let err = ensure_apply_consent(false, false).unwrap_err();
        assert!(err.to_string().contains("--yes"), "got: {err}");
        assert!(err.to_string().contains("tuning"), "should point at docs");
    }

    #[test]
    fn test_performance_profile_key_count_is_stable() {
        // Drift guard: 19 performance keys published in tuning/performance.sysctl.
        let keys = PerformanceProfile.sysctl();
        assert_eq!(
            keys.len(),
            19,
            "performance profile key count changed — update docs + this test"
        );
    }

    #[test]
    fn test_platform_prep_applies_only_allowlisted_keys() {
        // End-to-end parse of the embedded file against the allowlist.
        let entries = parse_sysctl_entries(PLATFORM_SYSCTL_TEXT);
        assert!(!entries.is_empty());
        for e in &entries {
            assert!(
                PLATFORM_INSTALL_KEYS.contains(&e.key.as_str()),
                "unexpected platform key {}",
                e.key
            );
        }
    }

    #[test]
    fn test_status_serializes() {
        let st = TuneStatus {
            platform_applied: false,
            performance_applied: false,
            baseline_present: false,
            performance_changes_vs_baseline: 0,
            notes: vec!["n".into()],
        };
        let json = serde_json::to_string(&st).unwrap();
        assert!(json.contains("platform_applied"));
        assert!(json.contains("performance_applied"));
    }

    #[test]
    fn test_sysctl_reload_is_linux_only() {
        // macOS/BSD `sysctl` rejects `--system`; reload must be a no-op there.
        if cfg!(target_os = "linux") {
            assert!(sysctl_reload_supported());
        } else {
            assert!(!sysctl_reload_supported());
            // Must not spawn `sysctl --system` (would print "illegal option -- -").
            reload_sysctl().unwrap();
        }
    }
}
