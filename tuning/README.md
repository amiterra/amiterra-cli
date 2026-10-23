# Amiterra Tuning Profiles (source of truth)

**These files are part of the Amiterra tuning pipeline.** The `ami` binary
embeds them at **build time** via `include_str!` — what you read here is
exactly what `ami init` / `ami tune apply` writes on the host.

Public documentation and security audits **must** reference these sources.
Do not change values without updating the docs and the tune unit tests.

| File | Layer | Written to | Applied by |
|------|-------|------------|------------|
| [`platform.sysctl`](platform.sysctl) | Platform Prep | `/etc/sysctl.d/98-amiterra-platform.conf` | `ami init`, `ami tune platform` |
| [`performance.sysctl`](performance.sysctl) | Performance | `/etc/sysctl.d/99-amiterra-tune.conf` | `ami tune apply` (opt-in) |
| [`limits.conf`](limits.conf) | Performance | `/etc/security/limits.d/99-amiterra.conf` | `ami tune apply` (opt-in) |

## Safety rules

1. **Platform Prep** stays minimal: only host sysctls required for Kubernetes
   pod networking. Never put performance or policy knobs here.
2. **Performance Profile** is opt-in and reversible (`ami tune rollback`).
3. Every performance key must pass `SecurityGuardrails` (`src/guardrails.rs`).
   Absolute blacklist (e.g. `kernel.core_pattern`, `kernel.modprobe`,
   `net.ipv4.ip_forward`, panic policy) must not appear in performance files.
4. Firewall posture (`ufw`) and panic policy are **out of scope** by design.

## OS subsystems touched

| Subsystem | Keys (examples) | Profile |
|-----------|-----------------|---------|
| Kernel networking (TCP/BPF/ARP/neigh) | `bpf_jit_*`, `somaxconn`, `tcp_congestion_control`, `arp_*`, `rp_filter` | platform (forwarding) + performance |
| Virtual memory | `vm.swappiness` | performance |
| File / inode capacity | `fs.file-max`, `fs.nr_open`, `inotify.*` | performance |
| Process limits | `nofile` (limits.d) | performance |

## CLI contract

```bash
ami tune plan          # preview (no changes)
ami tune apply         # shows subsystem warning + this docs link, then applies
ami tune rollback      # restore baseline
ami init --tune-apply  # same warning, then apply after install
```

Docs link used in CLI: <https://github.com/amiterra/amiterra-cli/tree/main/tuning>
