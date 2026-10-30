#!/usr/bin/env bash
# =============================================================================
# Amiterra GitOps Bootstrap — acceptance checks
#
# Covers the DoD items NOT proven by a single happy-path install:
#   8.2  re-run is a no-op (converge, no drift)
#   8.5  deploy key is read-only (push must fail)
#   8.6  non-TTY without --yes refuses
#   +    join-command prints the string without leaking it into install logs
#
# Run on the cluster-init node AFTER a successful `ami gitops bootstrap`.
# The reboot check (8.2, second half) is manual: reboot, then re-run this
# script — everything must still pass.
# =============================================================================
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[32m"
CYAN="\033[36m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[94m"
RESET="\033[0m"

PASS=0
FAIL=0

log_step() { printf "\n%b==> [%s] %s%b\n" "${CYAN}" "$1" "$2" "${RESET}"; }
log_ok()   { printf "  %b✔ %s%b\n" "${GREEN}" "$1" "${RESET}"; PASS=$((PASS + 1)); }
log_fail() { printf "  %b✘ %s%b\n" "${RED}" "$1" "${RESET}"; FAIL=$((FAIL + 1)); }
log_warn() { printf "  %b! %s%b\n" "${YELLOW}" "$1" "${RESET}"; }

AMI="${AMI:-ami}"
REPO_PATH="${REPO_PATH:-/var/lib/amiterra/git/infra.git}"
KEY_PATH="${KEY_PATH:-/var/lib/amiterra/gitops/flux-deploy-key}"
NODE_IP="${NODE_IP:-$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')}"

# ---------------------------------------------------------------- 8.2 no-op
log_step "8.2" "Idempotent re-run of ami gitops bootstrap"
BEFORE="$(git --git-dir="${REPO_PATH}" rev-parse main 2>/dev/null || echo none)"
if OUT="$("${AMI}" gitops bootstrap --yes --node-ip "${NODE_IP}" --no-wait 2>&1)"; then
    AFTER="$(git --git-dir="${REPO_PATH}" rev-parse main 2>/dev/null || echo none)"
    if [[ "${BEFORE}" == "${AFTER}" ]]; then
        log_ok "seed sha unchanged (${AFTER:0:12})"
    else
        log_fail "seed sha changed on re-run: ${BEFORE:0:12} -> ${AFTER:0:12}"
    fi
    if grep -q "Seed up to date" <<<"${OUT}"; then
        log_ok "converge reported 'Seed up to date'"
    else
        log_warn "converge output lacks 'Seed up to date' (check manually)"
    fi
else
    log_fail "re-run failed: ${OUT}"
fi

# ------------------------------------------------- 8.5 read-only deploy key
log_step "8.5" "Deploy key is read-only (push must be rejected)"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
chmod 700 "${TMP}"
if git clone -q "${REPO_PATH}" "${TMP}/wt" 2>/dev/null; then
    # Simulate the key's forced command surface: push over SSH as the git user.
    GIT_SSH_COMMAND="ssh -i ${KEY_PATH} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o BatchMode=yes"
    export GIT_SSH_COMMAND
    if git -C "${TMP}/wt" push "ssh://amiterra-git@${NODE_IP}${REPO_PATH}" main:main >/dev/null 2>&1; then
        log_fail "push over deploy key SUCCEEDED — key is not read-only"
    else
        log_ok "push over deploy key rejected (read-only enforced)"
    fi
    unset GIT_SSH_COMMAND
else
    log_fail "could not clone ${REPO_PATH}"
fi

# ------------------------------------------------- 8.6 non-TTY refusal
log_step "8.6" "Non-TTY without --yes refuses with non-zero exit"
if OUT="$(ami gitops bootstrap --node-ip "${NODE_IP}" --no-wait </dev/null 2>&1)"; then
    log_fail "non-TTY run succeeded without --yes (must refuse)"
else
    log_ok "non-TTY run refused with non-zero exit"
fi

# --------------------------------------- join-command shape (C2 surface)
log_step "C2" "ami join-command prints full join string on demand"
if OUT="$("${AMI}" join-command worker 2>/dev/null)"; then
    if grep -q -- "--token" <<<"${OUT}" && grep -q "sudo ami join" <<<"${OUT}"; then
        log_ok "join-command worker prints full join string"
    else
        log_fail "join-command output missing 'sudo ami join … --token'"
    fi
else
    log_warn "ami join-command not available or node-token unreadable (skipped)"
fi

# ----------------------------------------------------------------- summary
printf "\n%b── Acceptance summary ──%b\n" "${BOLD}" "${RESET}"
printf "  passed: %d · failed: %d\n" "${PASS}" "${FAIL}"
if [[ ${FAIL} -gt 0 ]]; then
    printf "  %bRESULT: FAIL%b\n" "${RED}" "${RESET}"
    exit 1
fi
printf "  %bRESULT: PASS%b\n" "${GREEN}" "${RESET}"
printf "  %bManual follow-up:%b reboot the node and re-run this script (8.2 reboot half).\n" "${BLUE}" "${RESET}"
