# =============================================================================
# Amiterra CLI & Host Tuner (ami) — Open Core Standalone Engine
# https://amiterra.io — Autonomous Private Cloud Infrastructure
# =============================================================================

ARCH ?= $(shell uname -m)

# Normalization of architecture for Docker cross-compilation
ifeq ($(ARCH),x86_64)
	DOCKER_ARCH = amd64
	DIST_ARCH = x86_64
else ifeq ($(ARCH),amd64)
	DOCKER_ARCH = amd64
	DIST_ARCH = x86_64
else ifeq ($(ARCH),aarch64)
	DOCKER_ARCH = arm64
	DIST_ARCH = aarch64
else ifeq ($(ARCH),arm64)
	DOCKER_ARCH = arm64
	DIST_ARCH = aarch64
else
	DOCKER_ARCH ?= amd64
	DIST_ARCH ?= x86_64
endif

TARGET_PLATFORM = linux/$(DOCKER_ARCH)
BUILDER_IMAGE = amiterra-cli-builder-$(DOCKER_ARCH)

# Run container with current directory and Cargo cache mounted
DOCKER_RUN = docker run --rm \
	--platform $(TARGET_PLATFORM) \
	-v $(CURDIR):/app \
	-v cargo-cache:/usr/local/cargo/registry \
	-v cargo-target-$(DOCKER_ARCH):/app/target \
	-w /app

# Remote publication server credentials (get.amiterra.io)
AMITERRA_DEV_HOST ?= amiterra.dev
AMITERRA_DEV_USER ?= root
AMITERRA_DEV_PORT ?= 22
AMITERRA_DEV_DIR  ?= /var/www/get.amiterra.io

.PHONY: all help dev-env check test build build-linux clean shell \
	dist dist-darwin dist-linux-amd64 dist-linux-arm64 \
	publish publish-dist publish-linux \
	test-cluster cluster-up cluster-down cluster-status cluster-ssh

all: build

help:
	@echo "Amiterra CLI & Engine (ami) Build System:"
	@echo "  make build             - Build native binary for host OS"
	@echo "  make test              - Run Rust unit and integration tests"
	@echo "  make check             - Run cargo check syntax and types"
	@echo "  make dev-env           - Build isolated Docker builder container"
	@echo "  make shell             - Open interactive shell in builder container"
	@echo "  make dist              - Build complete distribution bundle (macOS + Linux)"
	@echo "  make dist-linux-amd64  - Build Linux x86_64 release binary via Docker"
	@echo "  make dist-linux-arm64  - Build Linux arm64 release binary via Docker"
	@echo "  make publish           - Deploy distribution bundle to https://get.amiterra.io"
	@echo "  make test-cluster      - Run multi-node cluster e2e test (QEMU CoW Ubuntu 26.04)"
	@echo "  make cluster-up        - Start local test cluster instances"
	@echo "  make cluster-down      - Stop local test cluster instances and wipe storage"
	@echo "  make cluster-status    - Display status of local cluster instances"
	@echo "  make cluster-ssh       - Connect to node via SSH (e.g. make cluster-ssh NODE=1)"
	@echo "  make clean             - Clean build artifacts and temporary files"

# -----------------------------------------------------------------------------
# Development & Testing
# -----------------------------------------------------------------------------
dev-env:
	docker build --platform $(TARGET_PLATFORM) -t $(BUILDER_IMAGE) -f ci/app/Dockerfile .

shell: dev-env
	$(DOCKER_RUN) -it $(BUILDER_IMAGE) bash

check:
	cargo check

test:
	cargo test

build:
	@cargo build --release
	@mkdir -p out/
	@cp target/release/amiterra out/amiterra
	@ln -sf amiterra out/ami
	@echo "✔ Native binary built: out/amiterra (alias: out/ami)"

# -----------------------------------------------------------------------------
# Distribution Packaging
# -----------------------------------------------------------------------------
dist-darwin:
	@echo "==> Building macOS release binary..."
	@cargo build --release
	@mkdir -p dist/dist/latest dist/latest
	@cp target/release/amiterra dist/dist/latest/amiterra-darwin-aarch64
	@cp target/release/amiterra dist/latest/amiterra-darwin-aarch64
	@echo "  ✔ Built dist/dist/latest/amiterra-darwin-aarch64"

dist-linux-amd64:
	@echo "==> Building Linux x86_64 release binary via Docker..."
	@$(MAKE) build-docker-binary DOCKER_ARCH=amd64 DIST_ARCH=x86_64

dist-linux-arm64:
	@echo "==> Building Linux arm64 release binary via Docker..."
	@$(MAKE) build-docker-binary DOCKER_ARCH=arm64 DIST_ARCH=aarch64

build-docker-binary:
	@docker build --platform linux/$(DOCKER_ARCH) -t $(BUILDER_IMAGE) -f ci/app/Dockerfile .
	@echo "=> Building release binary for linux/$(DOCKER_ARCH)..."
	# The parent workspace is mounted (not just amiterra-cli) so the path
	# dependencies on ../amispec-core/crates resolve inside the container.
	@docker run --rm --platform linux/$(DOCKER_ARCH) \
		-v $(CURDIR)/..:/workspace \
		-v cargo-cache:/usr/local/cargo/registry \
		-v cargo-target-$(DOCKER_ARCH):/workspace/amiterra-cli/target \
		-w /workspace/amiterra-cli $(BUILDER_IMAGE) cargo build --release
	@mkdir -p out/ dist/dist/latest dist/latest
	@docker run --rm --platform linux/$(DOCKER_ARCH) \
		-v cargo-target-$(DOCKER_ARCH):/workspace/amiterra-cli/target \
		-v $(CURDIR)/out:/out \
		$(BUILDER_IMAGE) cp /workspace/amiterra-cli/target/release/amiterra /out/amiterra-linux-$(DIST_ARCH)
	@cp out/amiterra-linux-$(DIST_ARCH) out/amiterra
	@ln -sf amiterra out/ami
	@cp out/amiterra-linux-$(DIST_ARCH) dist/dist/latest/amiterra-linux-$(DIST_ARCH)
	@cp out/amiterra-linux-$(DIST_ARCH) dist/latest/amiterra-linux-$(DIST_ARCH)
	@echo "  ✔ Built dist/dist/latest/amiterra-linux-$(DIST_ARCH)"

dist: dist-darwin dist-linux-amd64 dist-linux-arm64
	@echo "==> Packaging complete distribution bundle and calculating checksums..."
	@mkdir -p dist/dist/latest dist/latest
	@cp scripts/install.sh dist/install.sh
	@cd dist/dist/latest && ( shasum -a 256 amiterra-* 2>/dev/null || sha256sum amiterra-* ) > SHA256SUMS
	@cp dist/dist/latest/SHA256SUMS dist/latest/SHA256SUMS
	@printf "\033[32m✔ Distribution bundle prepared in dist/:\033[0m\n"
	@ls -lh dist/install.sh dist/dist/latest/

# -----------------------------------------------------------------------------
# Deployment to get.amiterra.io
# -----------------------------------------------------------------------------
publish: publish-dist

publish-dist: dist
	@printf "\033[36m==> Deploying distribution artifacts to $(AMITERRA_DEV_USER)@$(AMITERRA_DEV_HOST):$(AMITERRA_DEV_DIR)...\033[0m\n"
	@ssh -p $(AMITERRA_DEV_PORT) $(AMITERRA_DEV_USER)@$(AMITERRA_DEV_HOST) "mkdir -p $(AMITERRA_DEV_DIR)/dist/latest"
	@rsync -avz --progress -e "ssh -p $(AMITERRA_DEV_PORT)" \
		dist/install.sh \
		$(AMITERRA_DEV_USER)@$(AMITERRA_DEV_HOST):$(AMITERRA_DEV_DIR)/install.sh
	@rsync -avz --progress -e "ssh -p $(AMITERRA_DEV_PORT)" \
		dist/dist/latest/ \
		$(AMITERRA_DEV_USER)@$(AMITERRA_DEV_HOST):$(AMITERRA_DEV_DIR)/dist/latest/
	@ssh -p $(AMITERRA_DEV_PORT) $(AMITERRA_DEV_USER)@$(AMITERRA_DEV_HOST) \
		"chmod -R a+rX $(AMITERRA_DEV_DIR) && ls -lh $(AMITERRA_DEV_DIR)/dist/latest/"
	@printf "\033[32m✔ Successfully published to https://get.amiterra.io\033[0m\n"

publish-linux: dist-linux-amd64 dist-linux-arm64
	@printf "\033[36m==> Packaging Linux distribution bundle and calculating checksums...\033[0m\n"
	@mkdir -p dist/dist/latest dist/latest
	@cp scripts/install.sh dist/install.sh
	@cd dist/dist/latest && ( shasum -a 256 amiterra-* 2>/dev/null || sha256sum amiterra-* ) > SHA256SUMS
	@cp dist/dist/latest/SHA256SUMS dist/latest/SHA256SUMS
	@ssh -p $(AMITERRA_DEV_PORT) $(AMITERRA_DEV_USER)@$(AMITERRA_DEV_HOST) "mkdir -p $(AMITERRA_DEV_DIR)/dist/latest"
	@rsync -avz --progress -e "ssh -p $(AMITERRA_DEV_PORT)" \
		dist/install.sh \
		$(AMITERRA_DEV_USER)@$(AMITERRA_DEV_HOST):$(AMITERRA_DEV_DIR)/install.sh
	@rsync -avz --progress -e "ssh -p $(AMITERRA_DEV_PORT)" \
		dist/dist/latest/ \
		$(AMITERRA_DEV_USER)@$(AMITERRA_DEV_HOST):$(AMITERRA_DEV_DIR)/dist/latest/
	@ssh -p $(AMITERRA_DEV_PORT) $(AMITERRA_DEV_USER)@$(AMITERRA_DEV_HOST) \
		"chmod -R a+rX $(AMITERRA_DEV_DIR) && ls -lh $(AMITERRA_DEV_DIR)/dist/latest/"
	@printf "\033[32m✔ Successfully published Linux binaries to https://get.amiterra.io\033[0m\n"

# -----------------------------------------------------------------------------
# Local Multi-Node Test Cluster — delegated to the foundation e2e harness
# (scripts/e2e/ in the amiterra monorepo). The legacy cluster-vm.sh pair was
# removed (tech-debt 0005: duplicated harness scripts).
# -----------------------------------------------------------------------------
E2E_HARNESS ?= ../scripts/e2e

test-cluster:
	@test -x "$(E2E_HARNESS)/run.sh" || { echo "e2e harness not found at $(E2E_HARNESS) — run from the amiterra monorepo (see 'make e2e' there)"; exit 1; }
	@"$(E2E_HARNESS)/run.sh" run all

cluster-up:
	@test -x "$(E2E_HARNESS)/vm.sh" || { echo "e2e harness not found at $(E2E_HARNESS)"; exit 1; }
	@"$(E2E_HARNESS)/vm.sh" up $(or $(NODES),3)

cluster-down:
	@"$(E2E_HARNESS)/vm.sh" down

cluster-status:
	@"$(E2E_HARNESS)/vm.sh" status

cluster-ssh:
	@"$(E2E_HARNESS)/vm.sh" ssh $(or $(NODE),1)

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------
clean:
	docker volume rm cargo-cache cargo-target-amd64 cargo-target-arm64 cargo-target 2>/dev/null || true
	rm -rf target/ out/ dist/ .cache/cluster-vms/
