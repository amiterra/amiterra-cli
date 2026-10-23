use anyhow::{bail, Result};
use tracing::error;

/// Result of validating a system parameter against the host security policy.
#[derive(Debug, PartialEq, Eq)]
pub enum GuardrailDecision {
    Allowed,
    Rejected(String),
}

pub struct SecurityGuardrails;

impl SecurityGuardrails {
    /// Categorical blacklist of dangerous kernel/host parameters that must NEVER be modified
    /// dynamically via workload annotations or tuning profiles (prevents RCE and Privilege Escalation).
    pub const ABSOLUTE_BLACKLIST: &'static [&'static str] = &[
        "kernel.core_pattern",
        "kernel.modprobe",
        "kernel.hotplug",
        "fs.suid_dumpable",
        "kernel.unprivileged_bpf_disabled",
        "net.ipv4.ip_forward",
        "net.ipv6.conf.all.forwarding",
        "kernel.panic_on_oops",
    ];

    /// Validates a single parameter (sysctl or sysfs) against the security allowlist and bounds.
    pub fn validate_parameter(key: &str, value: &str) -> GuardrailDecision {
        let norm_key = key.trim().replace('/', ".");

        // 1. Check Absolute Blacklist
        for prohibited in Self::ABSOLUTE_BLACKLIST {
            if norm_key == *prohibited || norm_key.ends_with(prohibited) {
                return GuardrailDecision::Rejected(format!(
                    "Parameter '{}' is on the Absolute Security Blacklist (prohibited)",
                    key
                ));
            }
        }

        // 2. Validate known tuning parameters against strict numerical/enum bounds
        match norm_key.as_str() {
            k if k.ends_with("vm.max_map_count") => {
                match value.trim().parse::<u64>() {
                    Ok(val) if (65_536..=16_777_216).contains(&val) => GuardrailDecision::Allowed,
                    _ => GuardrailDecision::Rejected(format!(
                        "vm.max_map_count must be between 65,536 and 16,777,216, got '{}'",
                        value
                    )),
                }
            }
            k if k.ends_with("vm.swappiness") => {
                match value.trim().parse::<u32>() {
                    Ok(val) if val <= 100 => GuardrailDecision::Allowed,
                    _ => GuardrailDecision::Rejected(format!(
                        "vm.swappiness must be between 0 and 100, got '{}'",
                        value
                    )),
                }
            }
            k if k.ends_with("vm.dirty_background_ratio") => {
                match value.trim().parse::<u32>() {
                    Ok(val) if (1..=50).contains(&val) => GuardrailDecision::Allowed,
                    _ => GuardrailDecision::Rejected(format!(
                        "vm.dirty_background_ratio must be between 1 and 50, got '{}'",
                        value
                    )),
                }
            }
            k if k.ends_with("vm.dirty_ratio") => {
                match value.trim().parse::<u32>() {
                    Ok(val) if (5..=80).contains(&val) => GuardrailDecision::Allowed,
                    _ => GuardrailDecision::Rejected(format!(
                        "vm.dirty_ratio must be between 5 and 80, got '{}'",
                        value
                    )),
                }
            }
            k if k.ends_with("net.core.somaxconn") => {
                match value.trim().parse::<u32>() {
                    Ok(val) if (1024..=65_535).contains(&val) => GuardrailDecision::Allowed,
                    _ => GuardrailDecision::Rejected(format!(
                        "net.core.somaxconn must be between 1024 and 65,535, got '{}'",
                        value
                    )),
                }
            }
            k if k.ends_with("net.ipv4.tcp_max_syn_backlog") => {
                match value.trim().parse::<u32>() {
                    Ok(val) if (1024..=65_535).contains(&val) => GuardrailDecision::Allowed,
                    _ => GuardrailDecision::Rejected(format!(
                        "net.ipv4.tcp_max_syn_backlog must be between 1024 and 65,535, got '{}'",
                        value
                    )),
                }
            }
            k if k.contains("transparent_hugepage.enabled") => {
                let v = value.trim();
                if v == "always" || v == "madvise" || v == "never" {
                    GuardrailDecision::Allowed
                } else {
                    GuardrailDecision::Rejected(format!(
                        "transparent_hugepage.enabled must be 'always', 'madvise', or 'never', got '{}'",
                        value
                    ))
                }
            }
            k if k.contains("queue.scheduler") => {
                let v = value.trim();
                if v == "none" || v == "mq-deadline" || v == "kyber" || v == "bfq" {
                    GuardrailDecision::Allowed
                } else {
                    GuardrailDecision::Rejected(format!(
                        "Disk scheduler must be 'none', 'mq-deadline', 'kyber', or 'bfq', got '{}'",
                        value
                    ))
                }
            }
            // --- Performance profile allowlist (static `ami tune` + dynamic roles) ---
            "net.core.bpf_jit_enable" => match value.trim() {
                "0" | "1" => GuardrailDecision::Allowed,
                _ => GuardrailDecision::Rejected(format!(
                    "net.core.bpf_jit_enable must be 0 or 1, got '{}'",
                    value
                )),
            },
            "net.core.bpf_jit_harden" => match value.trim() {
                "0" | "1" | "2" => GuardrailDecision::Allowed,
                _ => GuardrailDecision::Rejected(format!(
                    "net.core.bpf_jit_harden must be 0, 1, or 2, got '{}'",
                    value
                )),
            },
            k if k.ends_with("net.core.netdev_max_backlog") => match value.trim().parse::<u32>() {
                Ok(v) if (1024..=1_048_576).contains(&v) => GuardrailDecision::Allowed,
                _ => GuardrailDecision::Rejected(format!(
                    "net.core.netdev_max_backlog must be between 1024 and 1048576, got '{}'",
                    value
                )),
            },
            k if k.ends_with("net.core.default_qdisc") => {
                let v = value.trim();
                if matches!(v, "fq" | "fq_codel" | "pfifo_fast" | "codel" | "cake" | "noqueue") {
                    GuardrailDecision::Allowed
                } else {
                    GuardrailDecision::Rejected(format!(
                        "net.core.default_qdisc must be fq, fq_codel, pfifo_fast, codel, cake, or noqueue, got '{}'",
                        value
                    ))
                }
            }
            k if k.ends_with("tcp_congestion_control") => {
                let v = value.trim();
                if matches!(v, "bbr" | "cubic" | "reno" | "htcp" | "westwood" | "vegas") {
                    GuardrailDecision::Allowed
                } else {
                    GuardrailDecision::Rejected(format!(
                        "tcp_congestion_control must be an approved algorithm, got '{}'",
                        value
                    ))
                }
            }
            k if k.ends_with("gc_thresh1") => match value.trim().parse::<u32>() {
                Ok(v) if (128..=65_536).contains(&v) => GuardrailDecision::Allowed,
                _ => GuardrailDecision::Rejected(format!(
                    "neigh gc_thresh1 must be between 128 and 65536, got '{}'",
                    value
                )),
            },
            k if k.ends_with("gc_thresh2") => match value.trim().parse::<u32>() {
                Ok(v) if (256..=131_072).contains(&v) => GuardrailDecision::Allowed,
                _ => GuardrailDecision::Rejected(format!(
                    "neigh gc_thresh2 must be between 256 and 131072, got '{}'",
                    value
                )),
            },
            k if k.ends_with("gc_thresh3") => match value.trim().parse::<u32>() {
                Ok(v) if (512..=262_144).contains(&v) => GuardrailDecision::Allowed,
                _ => GuardrailDecision::Rejected(format!(
                    "neigh gc_thresh3 must be between 512 and 262144, got '{}'",
                    value
                )),
            },
            k if k.ends_with("rp_filter") => match value.trim() {
                "0" | "1" | "2" => GuardrailDecision::Allowed,
                _ => GuardrailDecision::Rejected(format!(
                    "rp_filter must be 0, 1, or 2, got '{}'",
                    value
                )),
            },
            k if k.ends_with("arp_announce") => match value.trim() {
                "0" | "1" | "2" => GuardrailDecision::Allowed,
                _ => GuardrailDecision::Rejected(format!(
                    "arp_announce must be 0, 1, or 2, got '{}'",
                    value
                )),
            },
            k if k.ends_with("arp_ignore") => match value.trim().parse::<u32>() {
                Ok(v) if v <= 8 => GuardrailDecision::Allowed,
                _ => GuardrailDecision::Rejected(format!(
                    "arp_ignore must be 0-8, got '{}'",
                    value
                )),
            },
            k if k.ends_with("fs.file-max") => match value.trim().parse::<u64>() {
                Ok(v) if (10_000..=10_000_000).contains(&v) => GuardrailDecision::Allowed,
                _ => GuardrailDecision::Rejected(format!(
                    "fs.file-max must be between 10000 and 10000000, got '{}'",
                    value
                )),
            },
            k if k.ends_with("fs.nr_open") => match value.trim().parse::<u64>() {
                Ok(v) if (1024..=10_000_000).contains(&v) => GuardrailDecision::Allowed,
                _ => GuardrailDecision::Rejected(format!(
                    "fs.nr_open must be between 1024 and 10000000, got '{}'",
                    value
                )),
            },
            k if k.ends_with("inotify.max_user_instances") => match value.trim().parse::<u32>() {
                Ok(v) if (128..=1_048_576).contains(&v) => GuardrailDecision::Allowed,
                _ => GuardrailDecision::Rejected(format!(
                    "inotify.max_user_instances must be between 128 and 1048576, got '{}'",
                    value
                )),
            },
            k if k.ends_with("inotify.max_user_watches") => match value.trim().parse::<u64>() {
                Ok(v) if (1024..=10_485_760).contains(&v) => GuardrailDecision::Allowed,
                _ => GuardrailDecision::Rejected(format!(
                    "inotify.max_user_watches must be between 1024 and 10485760, got '{}'",
                    value
                )),
            },
            _ => {
                // If it's not in the known performance domain allowlist, reject by default (Zero-Trust)
                GuardrailDecision::Rejected(format!(
                    "Parameter '{}' is not in the approved Performance Tuning Allowlist",
                    key
                ))
            }
        }
    }

    /// Enforces guardrails over a set of parameters, aborting on the first violation.
    pub fn enforce(key: &str, value: &str) -> Result<()> {
        match Self::validate_parameter(key, value) {
            GuardrailDecision::Allowed => Ok(()),
            GuardrailDecision::Rejected(err) => {
                error!("SECURITY_ALERT: {}", err);
                bail!("Host Security Guardrail Violation: {}", err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blacklist_blocks_core_pattern() {
        let res = SecurityGuardrails::validate_parameter("kernel.core_pattern", "|/tmp/evil.sh");
        assert!(matches!(res, GuardrailDecision::Rejected(_)));

        let res2 = SecurityGuardrails::validate_parameter("kernel/modprobe", "/tmp/evil");
        assert!(matches!(res2, GuardrailDecision::Rejected(_)));

        let res3 = SecurityGuardrails::validate_parameter("fs.suid_dumpable", "2");
        assert!(matches!(res3, GuardrailDecision::Rejected(_)));
    }

    #[test]
    fn test_blacklist_blocks_ip_forward_dynamic_tuning() {
        // Platform prep may set this at install time; dynamic path must never.
        let res = SecurityGuardrails::validate_parameter("net.ipv4.ip_forward", "1");
        assert!(matches!(res, GuardrailDecision::Rejected(_)));
        let res2 =
            SecurityGuardrails::validate_parameter("net.ipv6.conf.all.forwarding", "1");
        assert!(matches!(res2, GuardrailDecision::Rejected(_)));
    }

    #[test]
    fn test_allowlist_permits_valid_bounds() {
        let res = SecurityGuardrails::validate_parameter("vm.max_map_count", "1600000");
        assert_eq!(res, GuardrailDecision::Allowed);

        let res2 = SecurityGuardrails::validate_parameter("vm.swappiness", "0");
        assert_eq!(res2, GuardrailDecision::Allowed);

        let res3 = SecurityGuardrails::validate_parameter("net.core.somaxconn", "32768");
        assert_eq!(res3, GuardrailDecision::Allowed);

        let res4 = SecurityGuardrails::validate_parameter(
            "kernel/mm/transparent_hugepage/enabled",
            "never",
        );
        assert_eq!(res4, GuardrailDecision::Allowed);
    }

    #[test]
    fn test_allowlist_rejects_out_of_bounds() {
        let res = SecurityGuardrails::validate_parameter("vm.swappiness", "150");
        assert!(matches!(res, GuardrailDecision::Rejected(_)));

        let res2 = SecurityGuardrails::validate_parameter("vm.max_map_count", "10");
        assert!(matches!(res2, GuardrailDecision::Rejected(_)));
    }
}
