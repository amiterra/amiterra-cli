# Amiterra CLI & Autonomous Host Engine (`ami`)

[![License: FSL-1.1-ALv2](https://img.shields.io/badge/License-FSL--1.1--ALv2-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://www.rust-lang.org/)

**Amiterra** (`ami`) is a single-binary, high-performance engine for autonomous private clouds, bare-metal servers, and edge nodes. Written in Rust, it delivers zero-touch Kubernetes clustering, Cilium eBPF host-routing, and workload-driven host kernel tuning.

---

## ⚡ Quickstart

Install the single static binary and launch the guided setup:

```bash
curl -fsSL https://get.amiterra.io | bash
```

Or install non-interactively on a production server:

```bash
# Initialize Primary Control Plane
sudo ami init --server -y

# Join an existing cluster as an HA Control Plane
sudo ami join https://<primary-ip>:6443 --token <token> --control-plane -y

# Join an existing cluster as a Worker Node
sudo ami join https://<primary-ip>:6443 --token <token> -y
```

---

## 🚀 Key Features

* **Single Static Binary**: Zero external runtime dependencies. Self-contained Day-0 bootstrapper, Day-1 installer, and Day-2 host daemon.
* **Headless Kubernetes**: Deploys lightweight K3s stripped of legacy overhead (no Traefik, no ServiceLB, no flannel).
* **Cilium eBPF Host-Routing**: Native eBPF replacing `kube-proxy` for line-rate packet processing, direct host-routing, and optional WireGuard transparent encryption.
* **Autonomous Kernel Tuner (Day-2 Daemon)**:
  * Uses Linux `inotify` on Kubelet pod directories combined with local mTLS Kubelet API (`https://127.0.0.1:10250/pods`).
  * **0% CPU in idle mode** — wakes up purely on container scheduling events.
  * Dynamically computes and applies optimal `sysctl`/`sysfs` invariants (e.g. `vm.max_map_count`, `net.core.somaxconn`, `TCP BBR`) based on pod annotations (`amiterra.io/tuning-role`).
  * Automatic rollback to baseline factory settings when workloads terminate or migrate.
* **AI-Native Model Context Protocol (MCP)**: Built-in stdio MCP server (`ami mcp`) allowing AI assistants (Claude, Gemini, Cursor) to safely inspect and orchestrate infrastructure.

---

## 🛠 Command Reference

| Command | Description |
| :--- | :--- |
| `ami init` | Initialize environment (Production Server or Local Dev Workstation) |
| `ami join <url>` | Join an existing cluster as Control-Plane (`--control-plane`) or Worker |
| `ami status` | Context-aware health and status of active cluster and tuner daemon |
| `ami doctor` | System diagnostic inspection (Kernel, cgroups v2, eBPF BTF, BBR) |
| `ami mcp` | Start Model Context Protocol server for AI coding assistants |
| `ami uninstall` | Cleanly remove components, revert sysctl kernel profiles, restore host state |

---

## 🏗 Building from Source

### Prerequisites
* Rust 1.85+ (Edition 2024)
* Docker (for cross-compiling Linux release binaries on macOS)
* QEMU (for running the local multi-node test cluster)

### Build Targets

```bash
# Build native binary for current machine
make build

# Run unit and integration tests
make test

# Cross-compile distribution binaries (macOS + Linux x86_64 and arm64 via Docker)
make dist

# Run complete end-to-end multi-node lifecycle test in local QEMU VMs (Ubuntu 26.04)
make test-cluster
```

---

## 🧪 Local Multi-Node Test Suite

Amiterra CLI includes a self-contained local multi-node test environment running on Ubuntu 26.04 Resolute via QEMU:

```bash
# Spin up two minimal test instances using instant Copy-on-Write overlays (~10s)
make cluster-up

# Check running instances
make cluster-status

# SSH into node 1 or node 2
make cluster-ssh NODE=1

# Stop cluster and cleanly wipe temporary storage
make cluster-down
```

---

## 📄 License & Trademark

* **License:** Distributed under the **Functional Source License, Version 1.1, ALv2 Future License ([FSL-1.1-ALv2](LICENSE))**.
  * **Free to use, view, modify, and redistribute** for personal, academic, and internal production operations.
  * **Commercial Protection:** You may not make the software available to others as a competing commercial product or managed hosting service.
  * **Automatic Open Source Conversion:** On the second anniversary of each version release, that specific version automatically and irrevocably transforms into the **Apache License, Version 2.0 (ALv2)**.
* **Copyright:** Copyright © 2026 Evgenii Myzgin. All rights reserved.
* **Trademarks:** **Amiterra™**, **Amiterra Technologies™**, and **ami™** are trademarks of Evgenii Myzgin. Refer to [TRADEMARK.md](TRADEMARK.md) for brand usage and guidelines.
