//! Static tuning profile definitions — **source of truth lives outside `src/`**.
//!
//! Profiles are plain-text drop-ins under [`tuning/`](../../../tuning/) and are
//! embedded at **build time** with `include_str!` so:
//! - public docs can include the exact same files,
//! - audits can diff host drop-ins against the repo,
//! - the binary cannot drift from the published parameters.
//!
//! Layers:
//! - [`PlatformPrep`] — required for Kubernetes pod networking (`ami init`).
//! - [`PerformanceProfile`] — reversible optimization (`ami tune apply`).

/// Repository path of the tuning sources (documentation / CLI references).
pub const TUNING_DOCS_URL: &str = "https://github.com/amiterra/amiterra-cli/tree/main/tuning";

/// Raw platform prep drop-in (with pipeline warning header).
pub const PLATFORM_SYSCTL_TEXT: &str = include_str!("../../tuning/platform.sysctl");
/// Raw performance sysctl drop-in (with pipeline warning header).
pub const PERFORMANCE_SYSCTL_TEXT: &str = include_str!("../../tuning/performance.sysctl");
/// Raw process-limits drop-in (with pipeline warning header).
pub const LIMITS_TEXT: &str = include_str!("../../tuning/limits.conf");

/// A single sysctl key/value pair in a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysctlEntry {
    pub key: String,
    pub value: String,
}

impl SysctlEntry {
    pub fn new(key: &str, value: &str) -> Self {
        Self {
            key: key.to_string(),
            value: value.to_string(),
        }
    }
}

/// Parse a native sysctl drop-in body into key/value pairs.
/// Comment lines (`#`) and blanks are ignored. Accepts `key = value` and `key=value`.
pub fn parse_sysctl_entries(body: &str) -> Vec<SysctlEntry> {
    body.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() || value.is_empty() {
                return None;
            }
            Some(SysctlEntry::new(key, value))
        })
        .collect()
}

/// Minimal host prep so Kubernetes pod networking functions.
///
/// Embedded body: [`PLATFORM_SYSCTL_TEXT`] (`tuning/platform.sysctl`).
#[derive(Debug, Clone, Copy, Default)]
pub struct PlatformPrep;

impl PlatformPrep {
    pub fn raw(&self) -> &'static str {
        PLATFORM_SYSCTL_TEXT
    }

    pub fn sysctl(&self) -> Vec<SysctlEntry> {
        parse_sysctl_entries(PLATFORM_SYSCTL_TEXT)
    }
}

/// Performance & capacity profile for high-throughput data services.
///
/// Embedded body: [`PERFORMANCE_SYSCTL_TEXT`] (`tuning/performance.sysctl`).
/// Deliberately excludes policy/availability knobs (panic*, firewall, BPF lockdown).
#[derive(Debug, Clone, Copy, Default)]
pub struct PerformanceProfile;

impl PerformanceProfile {
    pub fn raw_sysctl(&self) -> &'static str {
        PERFORMANCE_SYSCTL_TEXT
    }

    pub fn sysctl(&self) -> Vec<SysctlEntry> {
        parse_sysctl_entries(PERFORMANCE_SYSCTL_TEXT)
    }

    /// ulimits drop-in body (`tuning/limits.conf`), including warning header.
    pub fn limits(&self) -> &'static str {
        LIMITS_TEXT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_and_performance_do_not_overlap() {
        let platform: Vec<String> = PlatformPrep.sysctl().into_iter().map(|e| e.key).collect();
        let perf: Vec<String> = PerformanceProfile
            .sysctl()
            .into_iter()
            .map(|e| e.key)
            .collect();
        for k in &platform {
            assert!(!perf.contains(k), "key {k} in both layers");
        }
    }

    #[test]
    fn performance_profile_has_bbr_and_somaxconn() {
        let keys: Vec<String> = PerformanceProfile
            .sysctl()
            .into_iter()
            .map(|e| e.key)
            .collect();
        assert!(keys.iter().any(|k| k == "net.ipv4.tcp_congestion_control"));
        assert!(keys.iter().any(|k| k == "net.core.somaxconn"));
        assert!(keys.iter().any(|k| k == "vm.swappiness"));
    }

    #[test]
    fn embedded_files_carry_pipeline_warning() {
        for body in [PLATFORM_SYSCTL_TEXT, PERFORMANCE_SYSCTL_TEXT, LIMITS_TEXT] {
            assert!(
                body.contains("Amiterra Tuning Pipeline"),
                "missing pipeline header"
            );
            assert!(body.contains("WARNING"), "missing WARNING banner");
            assert!(body.contains("tuning/"), "missing source path reference");
            assert!(body.contains("github.com/amiterra"), "missing docs link");
        }
    }

    #[test]
    fn parse_skips_comments_and_blanks() {
        let entries = parse_sysctl_entries(
            "# comment\n\n  net.core.somaxconn = 32768  \n# more\nvm.swappiness=0\n",
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "net.core.somaxconn");
        assert_eq!(entries[0].value, "32768");
        assert_eq!(entries[1].key, "vm.swappiness");
        assert_eq!(entries[1].value, "0");
    }

    #[test]
    fn platform_raw_written_matches_parsed_keys() {
        let keys: Vec<String> = PlatformPrep.sysctl().into_iter().map(|e| e.key).collect();
        assert!(keys.iter().any(|k| k == "net.ipv4.ip_forward"));
        let raw = PlatformPrep.raw();
        assert!(raw.contains("net.ipv4.ip_forward = 1"));
    }
}
