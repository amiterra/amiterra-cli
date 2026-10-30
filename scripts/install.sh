#!/bin/sh
# Amiterra Day-0 Bootstrap Installer (Thin Courier)
# https://amiterra.io — Autonomous Private Cloud Infrastructure
set -eu

can_write_dir() {
    mkdir -p "$1" 2>/dev/null && touch "$1/.amiterra_probe" 2>/dev/null && rm -f "$1/.amiterra_probe" 2>/dev/null
}

can_write_existing_dir() {
    [ -d "$1" ] && touch "$1/.amiterra_probe" 2>/dev/null && rm -f "$1/.amiterra_probe" 2>/dev/null
}

link_into_active_path() {
    TARGET_BIN="$1"
    if [ -n "${AMITERRA_INSTALL_DIR:-}" ]; then
        return 0
    fi
    for CANDIDATE in "${HOME}/.local/bin" "/opt/homebrew/bin" "/usr/local/bin" "${HOME}/bin" "${HOME}/.cargo/bin"; do
        case ":${PATH}:" in
            *:"${CANDIDATE}":*)
                if [ "${CANDIDATE}" != "${INSTALL_DIR}" ] && can_write_existing_dir "${CANDIDATE}"; then
                    rm -f "${CANDIDATE}/amiterra" "${CANDIDATE}/ami"
                    ln -sf "${TARGET_BIN}" "${CANDIDATE}/amiterra"
                    ln -sf "${TARGET_BIN}" "${CANDIDATE}/ami"
                    printf "  ✔ Linked 'amiterra' and alias 'ami' into %s (active in PATH)\n" "${CANDIDATE}"
                    break
                fi
                ;;
        esac
    done
    return 0
}

run_ami() {
    # If stdin was consumed by a pipe (e.g. curl ... | bash), reconnect to /dev/tty
    # if available so that interactive terminal wizard prompts work as expected.
    if [ ! -t 0 ] && [ -e /dev/tty ]; then
        exec < /dev/tty 2>/dev/null || true
    fi

    if [ $# -eq 0 ]; then
        exec "${INSTALL_DIR}/amiterra" init
    elif [ "$1" = "--dry-run" ] || [ "$1" = "-y" ] || [ "$1" = "--yes" ] || [ "$1" = "--all-features" ]; then
        exec "${INSTALL_DIR}/amiterra" init "$@"
    else
        exec "${INSTALL_DIR}/amiterra" "$@"
    fi
}

main() {
    DOMAIN="${AMITERRA_DOMAIN:-get.amiterra.io}"
    VERSION="${AMITERRA_VERSION:-latest}"

    # 1. Determine privileges and target installation directory
    if [ -n "${AMITERRA_INSTALL_DIR:-}" ]; then
        INSTALL_DIR="${AMITERRA_INSTALL_DIR}"
        mkdir -p "${INSTALL_DIR}"
    elif [ "$(id -u)" -eq 0 ]; then
        INSTALL_DIR="/usr/local/bin"
        mkdir -p "${INSTALL_DIR}"
    else
        INSTALL_DIR="${HOME}/.amiterra/bin"
        if ! can_write_dir "${INSTALL_DIR}"; then
            # Fallback if home root is restricted by a sandbox
            INSTALL_DIR="${HOME}/.cargo/bin"
            mkdir -p "${INSTALL_DIR}"
            export AMITERRA_HOME="${HOME}/.cargo/amiterra"
        fi
    fi

    # 2. Local offline mode for development and testing
    if [ -n "${AMITERRA_LOCAL_BIN:-}" ] && [ -f "${AMITERRA_LOCAL_BIN}" ]; then
        printf "  • Using local binary: %s\n" "${AMITERRA_LOCAL_BIN}"
        rm -f "${INSTALL_DIR}/amiterra" "${INSTALL_DIR}/ami"
        cp "${AMITERRA_LOCAL_BIN}" "${INSTALL_DIR}/amiterra"
        chmod +x "${INSTALL_DIR}/amiterra"
        ln -sf "${INSTALL_DIR}/amiterra" "${INSTALL_DIR}/ami"
        printf "  ✔ Installed amiterra to %s\n" "${INSTALL_DIR}"
        link_into_active_path "${INSTALL_DIR}/amiterra"
        run_ami "$@"
    fi

    # 3. Detect OS and CPU architecture
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"
    case "${ARCH}" in
        x86_64|amd64) ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *) echo "Error: Unsupported CPU architecture: ${ARCH}" >&2; exit 1 ;;
    esac

    BIN_NAME="amiterra-${OS}-${ARCH}"
    BASE_URL="https://${DOMAIN}/dist/${VERSION}"
    TMP_DIR="$(mktemp -d -t amiterra-install.XXXXXX)"
    trap 'rm -rf "${TMP_DIR}"' EXIT INT TERM

    printf "  • Downloading Amiterra (%s/%s) via TLS...\n" "${OS}" "${ARCH}"
    CURL_OPTS="--proto =https --tlsv1.2 -fsSL"
    if [ -n "${AMITERRA_DEV_CA:-}" ] && [ -f "${AMITERRA_DEV_CA}" ]; then
        CURL_OPTS="${CURL_OPTS} --cacert ${AMITERRA_DEV_CA}"
    fi

    curl ${CURL_OPTS} "${BASE_URL}/${BIN_NAME}" -o "${TMP_DIR}/amiterra"
    curl ${CURL_OPTS} "${BASE_URL}/SHA256SUMS" -o "${TMP_DIR}/SHA256SUMS"

    (
        cd "${TMP_DIR}"
        grep "${BIN_NAME}" SHA256SUMS | sed "s/${BIN_NAME}/amiterra/" > check.sum
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum -c check.sum >/dev/null
        elif command -v shasum >/dev/null 2>&1; then
            shasum -a 256 -c check.sum >/dev/null
        else
            echo "Error: sha256sum or shasum tool not found." >&2; exit 1
        fi
    )
    printf "  ✔ Verified SHA-256 checksum\n"

    rm -f "${INSTALL_DIR}/amiterra" "${INSTALL_DIR}/ami"
    mv "${TMP_DIR}/amiterra" "${INSTALL_DIR}/amiterra"
    chmod +x "${INSTALL_DIR}/amiterra"
    ln -sf "${INSTALL_DIR}/amiterra" "${INSTALL_DIR}/ami"
    printf "  ✔ Installed amiterra to %s\n" "${INSTALL_DIR}"
    link_into_active_path "${INSTALL_DIR}/amiterra"
    run_ami "$@"
}

main "$@"
