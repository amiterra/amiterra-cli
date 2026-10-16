#!/usr/bin/env bash
# =============================================================================
# Amiterra Multi-Node Local Cluster VM Manager (QEMU + Cloud-Init + CoW)
# =============================================================================
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:${PATH}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CACHE_DIR="${ROOT_DIR}/.cache"
IMAGE_DIR="${CACHE_DIR}/images"
VM_DIR="${CACHE_DIR}/cluster-vms"

# Detect Host Architecture
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64)
        ARCH="amd64"
        QEMU_BIN="qemu-system-x86_64"
        QEMU_MACHINE=""
        QEMU_ACCEL="-accel tcg"
        if [ "$(uname -s)" = "Linux" ] && [ -e /dev/kvm ]; then
            QEMU_ACCEL="-accel kvm"
        fi
        UBUNTU_URL="https://cloud-images.ubuntu.com/minimal/daily/resolute/current/resolute-minimal-cloudimg-amd64.img"
        ;;
    arm64|aarch64)
        ARCH="arm64"
        QEMU_BIN="qemu-system-aarch64"
        QEMU_MACHINE="-machine virt -cpu host"
        QEMU_ACCEL="-accel hvf"
        UBUNTU_URL="https://cloud-images.ubuntu.com/minimal/daily/resolute/current/resolute-minimal-cloudimg-arm64.img"
        ;;
    *)
        echo "Error: Unsupported CPU architecture: ${ARCH}" >&2
        exit 1
        ;;
esac

BASE_IMAGE="${IMAGE_DIR}/ubuntu-26.04-minimal-${ARCH}.qcow2"
QEMU_SHARE="$(command -v brew >/dev/null 2>&1 && brew --prefix qemu || echo /usr)/share/qemu"
EFI_CODE="${QEMU_SHARE}/edk2-aarch64-code.fd"
EFI_VARS_TEMPLATE="${QEMU_SHARE}/edk2-arm-vars.fd"

ensure_dirs() {
    mkdir -p "${IMAGE_DIR}" "${VM_DIR}"
    if [ ! -f "${BASE_IMAGE}" ] && [ -f "${ROOT_DIR}/../.cache/images/$(basename "${BASE_IMAGE}")" ]; then
        ln -sf "${ROOT_DIR}/../.cache/images/$(basename "${BASE_IMAGE}")" "${BASE_IMAGE}"
    fi
}

download_base_image() {
    ensure_dirs
    if [ -f "${BASE_IMAGE}" ] && [ "$(wc -c < "${BASE_IMAGE}")" -gt 100000000 ]; then
        return 0
    fi

    echo "==> [Cache Miss] Downloading Ubuntu 26.04 Minimal Cloud Image (${ARCH})..."
    echo "    URL: ${UBUNTU_URL}"
    rm -f "${BASE_IMAGE}.tmp"
    curl -L --retry 5 --retry-delay 3 -C - "${UBUNTU_URL}" -o "${BASE_IMAGE}.tmp"
    mv "${BASE_IMAGE}.tmp" "${BASE_IMAGE}"
    echo "✔ Cached base image: ${BASE_IMAGE} ($(du -h "${BASE_IMAGE}" | awk '{print $1}'))"
}

ensure_ssh_key() {
    ensure_dirs
    if [ ! -f "${CACHE_DIR}/cluster_key" ]; then
        echo "==> Generating cluster SSH keypair..."
        ssh-keygen -t ed25519 -f "${CACHE_DIR}/cluster_key" -N "" -q -C "amiterra-cluster"
    fi
}

generate_cidata() {
    local node_id="$1"
    local staging="${VM_DIR}/cidata-node${node_id}"
    local pub_key
    pub_key="$(cat "${CACHE_DIR}/cluster_key.pub")"
    local private_ip="192.168.100.$((node_id * 10))"

    rm -rf "${staging}"
    mkdir -p "${staging}"

    cat <<EOF > "${staging}/meta-data"
instance-id: ami-node${node_id}
local-hostname: ami-node${node_id}
EOF

    cat <<EOF > "${staging}/network-config"
version: 2
ethernets:
  lan0:
    match:
      macaddress: "52:54:00:10:00:0${node_id}"
    set-name: eth0
    dhcp4: true
    dhcp4-overrides:
      route-metric: 100
    optional: true
  lan1:
    match:
      macaddress: "52:54:00:20:00:0${node_id}"
    set-name: eth1
    addresses:
      - ${private_ip}/24
    optional: true
EOF

    cat <<EOF > "${staging}/user-data"
#cloud-config
users:
  - name: ubuntu
    gecos: Ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - ${pub_key}
bootcmd:
  - systemctl mask systemd-networkd-wait-online.service
growpart:
  mode: auto
  devices: ['/']
package_update: false
EOF

    local iso_path="${VM_DIR}/node${node_id}-cidata.iso"
    rm -f "${iso_path}"
    if command -v hdiutil >/dev/null 2>&1; then
        hdiutil makehybrid -o "${iso_path}" -iso -default-volume-name cidata "${staging}" >/dev/null 2>&1
    elif command -v genisoimage >/dev/null 2>&1; then
        genisoimage -output "${iso_path}" -volid cidata -rock "${staging}" >/dev/null 2>&1
    else
        echo "Error: Neither hdiutil nor genisoimage found to build cloud-init ISO" >&2
        exit 1
    fi

    rm -rf "${staging}"
}

start_node() {
    local node_id="$1"
    local pid_file="${VM_DIR}/node${node_id}.pid"
    local private_ip="192.168.100.$((node_id * 10))"

    if [ -f "${pid_file}" ] && kill -0 "$(cat "${pid_file}")" 2>/dev/null; then
        echo "  • Node ${node_id} is already running (PID: $(cat "${pid_file}"))"
        return 0
    fi

    echo "==> Spawning Node ${node_id} (ami-node${node_id}, SSH port: $((2220 + node_id)), Private IP: ${private_ip})..."
    
    # 1. Create instant Copy-on-Write overlay
    local overlay_path="${VM_DIR}/node${node_id}.qcow2"
    rm -f "${overlay_path}"
    qemu-img create -f qcow2 -b "${BASE_IMAGE}" -F qcow2 "${overlay_path}" 20G >/dev/null

    # 2. Setup EFI NVRAM variables
    local vars_path="${VM_DIR}/node${node_id}-vars.fd"
    rm -f "${vars_path}"
    cp "${EFI_VARS_TEMPLATE}" "${vars_path}"

    # 3. Generate Cloud-Init NoCloud ISO
    generate_cidata "${node_id}"

    # 4. Launch QEMU daemon
    local ssh_port=$((2220 + node_id))
    local local_port=$((12344 + node_id))
    local remote_port=$((node_id == 1 ? 12346 : 12345))

    ${QEMU_BIN} \
        ${QEMU_MACHINE} \
        ${QEMU_ACCEL} \
        -m 2048 \
        -smp 2 \
        -drive file="${EFI_CODE}",if=pflash,unit=0,format=raw,readonly=on \
        -drive file="${vars_path}",if=pflash,unit=1,format=raw \
        -drive file="${overlay_path}",if=virtio,format=qcow2 \
        -drive file="${VM_DIR}/node${node_id}-cidata.iso",if=virtio,format=raw \
        -netdev user,id=net0,hostfwd=tcp::${ssh_port}-:22 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:10:00:0${node_id} \
        -netdev socket,id=net1,udp=127.0.0.1:${remote_port},localaddr=127.0.0.1:${local_port} \
        -device virtio-net-pci,netdev=net1,mac=52:54:00:20:00:0${node_id} \
        -display none \
        -daemonize \
        -pidfile "${pid_file}" \
        -serial file:"${VM_DIR}/node${node_id}-serial.log"

    echo "  ✔ Node ${node_id} started (PID: $(cat "${pid_file}"))"
}

stop_node() {
    local node_id="$1"
    local pid_file="${VM_DIR}/node${node_id}.pid"
    if [ -f "${pid_file}" ]; then
        local pid
        pid="$(cat "${pid_file}")"
        echo "==> Stopping Node ${node_id} (PID: ${pid})..."
        kill -TERM "${pid}" 2>/dev/null || true
        for _ in {1..6}; do
            if ! kill -0 "${pid}" 2>/dev/null; then break; fi
            sleep 0.5
        done
        if kill -0 "${pid}" 2>/dev/null; then
            kill -KILL "${pid}" 2>/dev/null || true
        fi
        rm -f "${pid_file}"
    fi

    rm -f "${VM_DIR}/node${node_id}.qcow2" \
          "${VM_DIR}/node${node_id}-vars.fd" \
          "${VM_DIR}/node${node_id}-cidata.iso"
    echo "  ✔ Node ${node_id} stopped and storage cleaned"
}

ssh_node() {
    local node_id="$1"
    shift
    local ssh_port=$((2220 + node_id))
    ssh -i "${CACHE_DIR}/cluster_key" \
        -p "${ssh_port}" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -o ConnectTimeout=3 \
        ubuntu@127.0.0.1 "$@"
}

wait_ssh() {
    local node_id="$1"
    local timeout="${2:-60}"
    local start_time
    start_time="$(date +%s)"
    printf "==> Waiting for SSH connectivity on Node %s (port %s)..." "${node_id}" "$((2220 + node_id))"

    while true; do
        if ssh_node "${node_id}" "echo pong" >/dev/null 2>&1; then
            printf " Connected!\n"
            return 0
        fi
        local now
        now="$(date +%s)"
        if [ "$((now - start_time))" -ge "${timeout}" ]; then
            printf " Timed out (%ss)!\n" "${timeout}"
            return 1
        fi
        sleep 2
        printf "."
    done
}

status_all() {
    echo "╭── Amiterra Local Test Cluster Instances ────────────────────╮"
    for id in 1 2; do
        local pid_file="${VM_DIR}/node${id}.pid"
        if [ -f "${pid_file}" ] && kill -0 "$(cat "${pid_file}")" 2>/dev/null; then
            local pid
            pid="$(cat "${pid_file}")"
            local private_ip="192.168.100.$((id * 10))"
            echo "│  Node ${id} (ami-node${id})    ● RUNNING (PID: ${pid}, SSH: 127.0.0.1:$((2220 + id)), IP: ${private_ip})"
        else
            echo "│  Node ${id} (ami-node${id})    ○ STOPPED"
        fi
    done
    echo "╰─────────────────────────────────────────────────────────────╯"
}

case "${1:-help}" in
    download)
        download_base_image
        ;;
    up)
        download_base_image
        ensure_ssh_key
        start_node 1
        start_node 2
        wait_ssh 1 60
        wait_ssh 2 60
        status_all
        ;;
    down)
        stop_node 1
        stop_node 2
        echo "✔ All local test cluster nodes stopped."
        ;;
    status)
        status_all
        ;;
    ssh)
        node_num="${2:-1}"
        ssh_port=$((2220 + node_num))
        echo "Connecting to Node ${node_num} via SSH (port ${ssh_port})..."
        exec ssh -i "${CACHE_DIR}/cluster_key" \
            -p "${ssh_port}" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            ubuntu@127.0.0.1
        ;;
    run)
        node_num="$2"
        shift 2
        ssh_node "${node_num}" "$@"
        ;;
    wait)
        node_num="${2:-1}"
        timeout="${3:-60}"
        wait_ssh "${node_num}" "${timeout}"
        ;;
    *)
        echo "Usage: $0 {up|down|status|ssh <1|2>|run <1|2> <cmd>|wait <1|2>}"
        exit 1
        ;;
esac
