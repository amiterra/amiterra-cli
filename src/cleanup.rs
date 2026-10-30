//! Post-uninstall host cleanup and restoration audit.
//!
//! The k3s uninstaller only knows its own stack (flannel, cni0, kube-*).
//! Cilium — the CNI we deploy — leaves datapath artifacts behind: interfaces
//! (`cilium_host`, `cilium_wg0`, …) with addresses and routes, and `CILIUM_*`
//! netfilter chains. Those leftovers both pollute the host and confuse the
//! next install's network auto-discovery (occupied CIDRs force fallback
//! subnets). This module removes them and verifies restoration honestly.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::{Command, Stdio};

use crate::ui::Ui;

/// Parse interface names from `ip -o link show` output
/// (one `ifindex: name: <flags>` record per line). Pure — unit-tested.
pub fn parse_link_names(ip_o_link: &str) -> Vec<String> {
    ip_o_link
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _idx = fields.next()?;
            // `ip -o link` renders peer-linked interfaces as `name@peer`
            // (e.g. `cilium_net@cilium_host`) — the kernel name is the part
            // before `@`; the peer suffix is display-only.
            let name = fields.next()?.trim_end_matches(':');
            let name = name.split('@').next()?;
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            }
        })
        .collect()
}

/// Drop every line mentioning cilium from `iptables-save` output, keeping the
/// table skeleton intact. Pure — unit-tested.
pub fn strip_cilium_rules(save_output: &str) -> String {
    save_output
        .lines()
        .filter(|l| !l.to_lowercase().contains("cilium"))
        .map(|l| format!("{l}\n"))
        .collect()
}

/// Datapath interfaces owned by the Cilium CNI.
fn is_cilium_link(name: &str) -> bool {
    name.starts_with("cilium")
}

fn run_capture(cmd: &str, args: &[&str]) -> Option<std::process::Output> {
    Command::new(cmd).args(args).output().ok()
}

fn user_exists(user: &str) -> bool {
    Command::new("id")
        .args(["-u", user])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Result of a datapath sweep: what went away, what refused to go.
#[derive(Debug, Default)]
pub struct CleanupReport {
    pub removed: Vec<String>,
    pub failed: Vec<String>,
}

/// Remove Cilium datapath artifacts left after the k3s uninstaller: the
/// interfaces (routes travel with them) and the netfilter chains. Best-effort;
/// silent — the caller renders the report after its spinner completes.
pub fn cleanup_cilium_datapath() -> CleanupReport {
    let mut report = CleanupReport::default();

    // 1. Interfaces — deleting the link drops its addresses and routes.
    if let Some(out) = run_capture("ip", &["-o", "link", "show"]) {
        let names = parse_link_names(&String::from_utf8_lossy(&out.stdout));
        let mut done = std::collections::BTreeSet::new();
        for name in names.iter().filter(|n| is_cilium_link(n)) {
            if !done.insert(name.clone()) {
                continue;
            }
            let ok = run_capture("ip", &["link", "delete", name])
                .map(|o| o.status.success())
                .unwrap_or(false);
            // Peer-linked interfaces (veth-style) vanish when their counterpart
            // is deleted — a failed delete on an already-gone device is success.
            let gone = ok
                || !run_capture("ip", &["link", "show", "dev", name])
                    .map(|o| o.status.success())
                    .unwrap_or(true);
            if gone {
                report.removed.push(format!("interface {name}"));
            } else {
                report.failed.push(format!("interface {name}"));
            }
        }
    }

    // 2. Netfilter chains and rules (iptables + ip6tables).
    for (save_bin, restore_bin) in [
        ("iptables-save", "iptables-restore"),
        ("ip6tables-save", "ip6tables-restore"),
    ] {
        let Some(out) = run_capture(save_bin, &[]) else {
            continue; // tool absent — nothing to clean
        };
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.status.success() || !text.to_lowercase().contains("cilium") {
            continue;
        }
        let filtered = strip_cilium_rules(&text);
        let restored = Command::new(restore_bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                {
                    use std::io::Write;
                    let mut stdin = child.stdin.take().expect("stdin piped");
                    stdin.write_all(filtered.as_bytes())?;
                }
                child.wait_with_output()
            })
            .map(|o| o.status.success())
            .unwrap_or(false);
        if restored {
            report
                .removed
                .push(format!("Cilium netfilter rules ({save_bin})"));
        } else {
            report.failed.push(format!("netfilter rules ({save_bin})"));
        }
    }

    report
}

/// Remove the gitops system account. The repository under its home is *data*
/// (removed by `--purge`), the account itself is host state.
pub fn remove_git_user(user: &str) -> Vec<String> {
    let mut removed = Vec::new();
    if !user_exists(user) {
        return removed;
    }
    // No `-r`: the home directory lives under /var/lib/amiterra and is owned
    // by the purge step.
    let ok = run_capture("userdel", &[user])
        .map(|o| o.status.success())
        .unwrap_or(false);
    if ok {
        removed.push(format!("system user {user}"));
    } else {
        Ui::step_warn(&format!("could not remove system user {user}"));
    }
    // The matching login group is best-effort (may already be gone).
    let _ = run_capture("groupdel", &[user]);
    removed
}

/// What the uninstall left behind — classified so the final message can be
/// honest: `leftovers` must not exist after uninstall; `kept` is data that
/// survives on purpose when `--purge` was not requested.
#[derive(Debug, Default)]
pub struct UninstallAudit {
    pub leftovers: Vec<String>,
    pub kept: Vec<String>,
}

fn exists(path: &str) -> bool {
    Path::new(path).exists()
}

/// Inspect the host after both backends ran. Best-effort: checks whose probe
/// tool is missing are skipped (never a false "clean").
pub fn audit(purge_requested: bool) -> UninstallAudit {
    let mut out = UninstallAudit::default();

    // Datapath artifacts.
    if let Some(o) = run_capture("ip", &["-o", "link", "show"]) {
        for name in parse_link_names(&String::from_utf8_lossy(&o.stdout))
            .iter()
            .filter(|n| is_cilium_link(n))
        {
            out.leftovers
                .push(format!("Cilium interface still present: {name}"));
        }
    }
    for save_bin in ["iptables-save", "ip6tables-save"] {
        if let Some(o) = run_capture(save_bin, &[])
            && String::from_utf8_lossy(&o.stdout)
                .to_lowercase()
                .contains("cilium")
        {
            out.leftovers
                .push(format!("Cilium netfilter rules remain ({save_bin})"));
        }
    }

    // Host state owned by components.
    if user_exists(crate::gitops::local_bare::GIT_USER) {
        out.leftovers.push(format!(
            "system user still present: {}",
            crate::gitops::local_bare::GIT_USER
        ));
    }
    if exists("/etc/systemd/system/amiterra.service") {
        out.leftovers
            .push("systemd unit still present: amiterra.service".into());
    }
    for dropin in [
        crate::tune::PLATFORM_SYSCTL_PATH,
        crate::tune::TUNE_SYSCTL_PATH,
        crate::tune::TUNE_LIMITS_PATH,
    ] {
        if exists(dropin) {
            out.leftovers
                .push(format!("drop-in still present: {dropin}"));
        }
    }

    // Binary and data directories.
    for bin in ["/usr/local/bin/ami", "/usr/local/bin/amiterra"] {
        if exists(bin) {
            out.leftovers.push(format!("binary still present: {bin}"));
        }
    }
    for dir in ["/var/lib/amiterra", "/etc/amiterra"] {
        if exists(dir) {
            if purge_requested {
                out.leftovers
                    .push(format!("data directory not removed by --purge: {dir}"));
            } else {
                out.kept.push(dir.to_string());
            }
        }
    }

    out
}

/// Run the k3s uninstaller with its output captured: the script is verbose by
/// design (xtrace, umount listings) and must not interleave with our UI.
/// Captured output is surfaced only when the script fails.
pub fn run_k3s_uninstaller(script: &str) -> Result<()> {
    let out = Command::new(script)
        .output()
        .with_context(|| format!("failed to start {script}"))?;
    if !out.status.success() {
        let log = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        for line in log.lines().take(40) {
            println!("     {}", crate::ui::Palette::dim(line));
        }
        anyhow::bail!("{script} exited with {}", out.status);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_link_names_extracts_interface_names() {
        let out = "\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n\
2: cilium_host: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500\n\
3: cilium_wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420\n\
4: enp6s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n";
        assert_eq!(
            parse_link_names(out),
            vec!["lo", "cilium_host", "cilium_wg0", "enp6s0"]
        );
    }

    #[test]
    fn parse_link_names_strips_peer_suffix() {
        // `ip -o link` shows peer-linked interfaces as name@peer — the kernel
        // name (what `ip link delete` needs) is the part before `@`.
        let out = "\
3: cilium_net@cilium_host: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500\n\
4: cilium_host@cilium_net: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500\n";
        assert_eq!(parse_link_names(out), vec!["cilium_net", "cilium_host"]);
    }

    #[test]
    fn strip_cilium_rules_removes_chains_and_referencing_rules() {
        let save = "\
*filter\n\
:CILIUM_INPUT - [0:0]\n\
:FORWARD ACCEPT [0:0]\n\
-A FORWARD -m comment --comment \"cilium: accept\" -j ACCEPT\n\
-A FORWARD -j CILIUM_FORWARD\n\
-A FORWARD -p tcp --dport 22 -j ACCEPT\n\
COMMIT\n";
        let filtered = strip_cilium_rules(save);
        assert!(filtered.contains(":FORWARD ACCEPT [0:0]"));
        assert!(filtered.contains("--dport 22"));
        assert!(!filtered.to_lowercase().contains("cilium"));
        // Table skeleton survives so restore stays valid.
        assert!(filtered.starts_with("*filter"));
        assert!(filtered.trim_end().ends_with("COMMIT"));
    }

    #[test]
    fn parse_link_names_ignores_malformed_lines() {
        assert!(parse_link_names("").is_empty());
        assert!(parse_link_names("\n\n").is_empty());
    }
}
