#!/usr/bin/env bash
# =============================================================================
# Amiterra QEMU Sandbox (single-node fidelity VM)
# Production-like Ubuntu guest for `ami init` / `ami tune` testing.
# Reuses the CoW + cloud-init approach from cluster-vm.sh (multi-node e2e).
# =============================================================================
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:${PATH}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CACHE_DIR="${ROOT_DIR}/.cache"
IMAGE_DIR="${CACHE_DIR}/images"
VM_DIR="${CACHE_DIR}/sandbox-vm"
SSH_PORT="${AMITERRA_SANDBOX_SSH_PORT:-2221}"
VM_NAME="ami-sandbox"

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
PID_FILE="${VM_DIR}/sandbox.pid"
OVERLAY="${VM_DIR}/sandbox.qcow2"

ensure_dirs() {
    mkdir -p "${IMAGE_DIR}" "${VM_DIR}"
}

download_base_image() {
    ensure_dirs
    if [ -f "${BASE_IMAGE}" ] && [ "$(wc -c < "${BASE_IMAGE}")" -gt 100000000 ]; then
        return 0
    fi
    # Reuse multi-node cache if present.
    if [ -f "${ROOT_DIR}/../.cache/images/$(basename "${BASE_IMAGE}")" ]; then
        ln -sf "${ROOT_DIR}/../.cache/images/$(basename "${BASE_IMAGE}")" "${BASE_IMAGE}"
        return 0
    fi
    echo "==> Downloading Ubuntu minimal cloud image (${ARCH})..."
    curl -L --retry 5 --retry-delay 3 -C - "${UBUNTU_URL}" -o "${BASE_IMAGE}.tmp"
    mv "${BASE_IMAGE}.tmp" "${BASE_IMAGE}"
    echo "✔ Cached: ${BASE_IMAGE}"
}

ensure_ssh_key() {
    ensure_dirs
    if [ ! -f "${CACHE_DIR}/cluster_key" ]; then
        ssh-keygen -t ed25519 -f "${CACHE_DIR}/cluster_key" -N "" -q -C "amiterra-sandbox"
    fi
}

generate_cidata() {
    local staging="${VM_DIR}/cidata"
    local pub_key
    pub_key="$(cat "${CACHE_DIR}/cluster_key.pub")"
    rm -rf "${staging}"
    mkdir -p "${staging}"

    cat > "${staging}/meta-data" <<EOF
instance-id: ${VM_NAME}
local-hostname: ${VM_NAME}
EOF

    cat > "${staging}/user-data" <<EOF
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
  devices: ["/"]
packages:
  - qemu-guest-agent
runcmd:
  - [touch, /var/lib/cloud/instance/boot-finished]
EOF

    if command -v hdiutil >/dev/null 2>&1; then
        # macOS: build ISO via hdiutil (no genisoimage required).
        local iso_src="${VM_DIR}/cidata-src"
        rm -rf "${iso_src}"
        mkdir -p "${iso_src}"
        cp "${staging}/meta-data" "${staging}/user-data" "${iso_src}/"
        rm -f "${VM_DIR}/cidata.iso"
        hdiutil makehybrid -o "${VM_DIR}/cidata.iso" -hfs -joliet -iso -default-volume-name cidata "${iso_src}" >/dev/null
    else
        genisoimage -output "${VM_DIR}/cidata.iso" -volid cidata -joliet -rock \
            "${staging}/user-data" "${staging}/meta-data" >/dev/null 2>&1 \
            || cloud-localds "${VM_DIR}/cidata.iso" "${staging}/user-data" "${staging}/meta-data"
    fi
}

ssh_sandbox() {
    ssh -i "${CACHE_DIR}/cluster_key" \
        -p "${SSH_PORT}" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -o ConnectTimeout=3 \
        ubuntu@127.0.0.1 "$@"
}

wait_ssh() {
    local timeout="${1:-90}"
    local start_time
    start_time="$(date +%s)"
    printf "==> Waiting for SSH on 127.0.0.1:%s..." "${SSH_PORT}"
    while true; do
        if ssh_sandbox "echo pong" >/dev/null 2>&1; then
            printf " Connected!\n"
            return 0
        fi
        if [ "$(($(date +%s) - start_time))" -ge "${timeout}" ]; then
            printf " Timed out!\n"
            return 1
        fi
        sleep 2
        printf "."
    done
}

start_vm() {
    download_base_image
    ensure_ssh_key
    generate_cidata

    rm -f "${OVERLAY}"
    qemu-img create -f qcow2 -b "${BASE_IMAGE}" -F qcow2 "${OVERLAY}" 20G >/dev/null

    local vars_path="${VM_DIR}/sandbox-vars.fd"
    rm -f "${vars_path}"
    cp "${EFI_VARS_TEMPLATE}" "${vars_path}"

    local pid_file="${PID_FILE}"
    ${QEMU_BIN} \
        ${QEMU_MACHINE} \
        ${QEMU_ACCEL} \
        -m 2048 \
        -smp 2 \
        -drive file="${EFI_CODE}",if=pflash,unit=0,format=raw,readonly=on \
        -drive file="${vars_path}",if=pflash,unit=1,format=raw \
        -drive file="${OVERLAY}",if=virtio,format=qcow2 \
        -drive file="${VM_DIR}/cidata.iso",if=virtio,format=raw \
        -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:10:00:01 \
        -display none \
        -daemonize \
        -pidfile "${pid_file}" \
        -serial file:"${VM_DIR}/sandbox-serial.log"

    echo "✔ ${VM_NAME} started (PID: $(cat "${pid_file}"), SSH: 127.0.0.1:${SSH_PORT})"
    wait_ssh 90
}

stop_vm() {
    if [ -f "${PID_FILE}" ]; then
        local pid
        pid="$(cat "${PID_FILE}")"
        echo "==> Stopping ${VM_NAME} (PID: ${pid})..."
        kill -TERM "${pid}" 2>/dev/null || true
        for _ in {1..6}; do
            if ! kill -0 "${pid}" 2>/dev/null; then break; fi
            sleep 0.5
        done
        if kill -0 "${pid}" 2>/dev/null; then
            kill -KILL "${pid}" 2>/dev/null || true
        fi
        rm -f "${PID_FILE}"
    fi
    rm -f "${OVERLAY}" "${VM_DIR}/sandbox-vars.fd" "${VM_DIR}/cidata.iso"
    echo "✔ ${VM_NAME} stopped and ephemeral storage cleaned"
}

status_vm() {
    if [ -f "${PID_FILE}" ] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
        echo "${VM_NAME} running pid=$(cat "${PID_FILE}") ssh=127.0.0.1:${SSH_PORT}"
        exit 0
    fi
    echo "${VM_NAME} stopped"
    exit 3
}

case "${1:-help}" in
    download) download_base_image ;;
    up) start_vm ;;
    down) stop_vm ;;
    status) status_vm ;;
    ssh) exec ssh_sandbox ;;
    run) shift; ssh_sandbox "$@" ;;
    wait) wait_ssh "${2:-90}" ;;
    *)
        echo "Usage: $0 {download|up|down|status|ssh|run <cmd>|wait [timeout]}"
        exit 1
        ;;
esac
