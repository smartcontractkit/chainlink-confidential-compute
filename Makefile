# Local end-to-end test setup.
#
# The E2E suites need a chainlink node image (built from a pinned chainlink
# commit with the CRE capability plugins baked in) plus a couple of supporting
# images. Building the chainlink image by hand is the main friction; this
# Makefile automates the whole flow so a local run is one command:
#
#   make e2e-local-conf-http        # TestConfidentialHTTPE2E
#   make e2e-local-conf-workflows   # TestConfidentialWorkflowsEngineE2E
#
# Runs default to fake (non-Nitro) enclaves. On a Nitro-capable host with
# nitro-cli installed, override the environment to run against real enclaves:
#
#   make e2e-local-conf-http ENCLAVE_TYPE=NITRO
#
# Real-enclave runs clear stale Nitro state automatically before starting;
# `make clean-e2e-nitro` runs the same cleanup on demand.
#
# All pins (chainlink commit, job-distributor version, chip-router CTF commit)
# are read from .github/workflows/go-tests.yaml so local runs match CI exactly.
#
# Prerequisites:
#   - Docker running, >= 24 GB memory allocated, root disk < 85% full.
#   - gh CLI authenticated (used for the image build secret and to clone the
#     private smartcontractkit repos).
#   - ~40 GB free disk for the chainlink build.
#
# External repos are shallow-cloned into $(WORK_DIR) (default /tmp/cc-e2e) at the
# pinned refs; your own chainlink checkout is never touched. Built images are
# cached by tag, so re-runs skip the heavy builds.
#
# Note: multi-step recipes run as a single `bash -c` over an exported script so
# they work on macOS's GNU Make 3.81 (which lacks .ONESHELL) as well as 4.x.

SHELL := bash
.SILENT:

REPO_ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
E2E_DIR := $(REPO_ROOT)/tests/e2e
WORKFLOW_YAML := $(REPO_ROOT)/.github/workflows/go-tests.yaml

# Pins sourced from CI (single source of truth).
CHAINLINK_COMMIT_SHA := $(shell awk '/^[[:space:]]*CHAINLINK_COMMIT_SHA:/{print $$2; exit}' $(WORKFLOW_YAML))
JD_VERSION := $(shell awk '/^[[:space:]]*JD_VERSION:/{print $$2; exit}' $(WORKFLOW_YAML))
CTF_SHA := $(shell awk '/^[[:space:]]*CTF_SHA:/{print $$2; exit}' $(WORKFLOW_YAML))

CHAINLINK_IMAGE := chainlink:$(CHAINLINK_COMMIT_SHA)
JD_IMAGE := job-distributor:$(JD_VERSION)
CHIP_ROUTER_IMAGE := local-cre-chip-router:v1.0.1

# Enclave environment for the e2e suites. Defaults to FAKE (no hardware);
# override with ENCLAVE_TYPE=NITRO on a Nitro-capable host to run real enclaves.
ENCLAVE_TYPE ?= FAKE

WORK_DIR ?= /tmp/cc-e2e
CHAINLINK_DIR := $(WORK_DIR)/chainlink
JD_DIR := $(WORK_DIR)/job-distributor
CTF_DIR := $(WORK_DIR)/chainlink-testing-framework

# The CRE chiprouter resolves the env state file four dirs above tests/e2e, i.e.
# one level above the repo root. Point `core` there at the pinned checkout.
CORE_LINK := $(abspath $(REPO_ROOT)/..)/core

.DEFAULT_GOAL := help

.PHONY: help
help:
	echo "Local E2E targets (default: fake enclaves; add ENCLAVE_TYPE=NITRO for real):"
	echo "  make e2e-local-conf-http        Run TestConfidentialHTTPE2E"
	echo "  make e2e-local-conf-workflows   Run TestConfidentialWorkflowsEngineE2E"
	echo "  make e2e-images                 Build/cache all required Docker images (no tests)"
	echo "  make clean-e2e                  Remove scratch clones, plugin binaries, and the core symlink"
	echo "  make clean-e2e-nitro            Clear stale Nitro state (enclaves, wg-vsock orphans, EIF/PCR)"
	echo ""
	echo "  Environment: ENCLAVE_TYPE=$(ENCLAVE_TYPE) (override with ENCLAVE_TYPE=NITRO on a Nitro host)"
	echo ""
	echo "Module maintenance:"
	echo "  make gomodtidy                  Run go mod tidy in every module"
	echo ""
	echo "Pins (from .github/workflows/go-tests.yaml):"
	echo "  chainlink        $(CHAINLINK_COMMIT_SHA)"
	echo "  job-distributor  v$(JD_VERSION)"
	echo "  chip-router CTF  $(CTF_SHA)"
	echo "  work dir         $(WORK_DIR)"

.PHONY: e2e-images
e2e-images: chainlink-image jd-image chip-router-image

# chainlink node image: shallow-fetch the pinned commit, strip the
# confidential-http and confidential-workflows plugins (the e2e supplies them as
# local binaries, and building them would pull an unrelated pinned CC version),
# then build with CRE plugins.
define CHAINLINK_IMAGE_SH
set -euo pipefail
if docker image inspect $(CHAINLINK_IMAGE) >/dev/null 2>&1; then
  echo "OK chainlink image present: $(CHAINLINK_IMAGE)"
  exit 0
fi
echo "Preparing chainlink checkout ($(CHAINLINK_COMMIT_SHA))..."
dir="$(CHAINLINK_DIR)"
# Re-init if the checkout is missing OR left corrupt by an interrupted run (a
# bare `.git` dir without HEAD/config would otherwise make git fail the fetch).
if ! git -C "$$dir" rev-parse --git-dir >/dev/null 2>&1; then
  rm -rf "$$dir"
  mkdir -p "$$dir"
  git -C "$$dir" init -q
  git -C "$$dir" remote add origin "https://github.com/smartcontractkit/chainlink.git"
fi
if ! git -C "$$dir" rev-parse -q --verify HEAD >/dev/null 2>&1 || [ "$$(git -C "$$dir" rev-parse HEAD)" != "$(CHAINLINK_COMMIT_SHA)" ]; then
  echo "  fetching chainlink@$(CHAINLINK_COMMIT_SHA)"
  git -c credential."https://github.com".helper='!gh auth git-credential' -C "$$dir" fetch -q --depth 1 origin "$(CHAINLINK_COMMIT_SHA)"
  # Force the checkout so a prior run's local edit to plugins.private.yaml
  # (stripped below on every run) doesn't block switching commits.
  git -C "$$dir" checkout -q -f FETCH_HEAD
fi
pp="$$dir/plugins/plugins.private.yaml"
if [ -f "$$pp" ]; then
  awk '/^  (confidential-http|confidential-workflows):/{skip=1;next} skip&&(/^  [^ ]/||/^[^ ]/){skip=0} !skip{print}' "$$pp" > "$$pp.tmp"
  mv "$$pp.tmp" "$$pp"
fi
tok="$$(mktemp)"
trap 'rm -f "$$tok"' EXIT
gh auth token > "$$tok"
echo "Building $(CHAINLINK_IMAGE) (first build takes a while)..."
docker build --secret id=GIT_AUTH_TOKEN,src="$$tok" --build-arg CL_INSTALL_PRIVATE_PLUGINS=true --build-arg CL_IS_PROD_BUILD=false -f "$$dir/core/chainlink.Dockerfile" -t $(CHAINLINK_IMAGE) "$$dir"
docker tag $(CHAINLINK_IMAGE) chainlink:latest
echo "OK built $(CHAINLINK_IMAGE)"
endef
export CHAINLINK_IMAGE_SH

.PHONY: chainlink-image
chainlink-image:
	bash -c "$$CHAINLINK_IMAGE_SH"

define JD_IMAGE_SH
set -euo pipefail
if docker image inspect $(JD_IMAGE) >/dev/null 2>&1; then
  echo "OK job-distributor image present: $(JD_IMAGE)"
  exit 0
fi
echo "Preparing job-distributor checkout (v$(JD_VERSION))..."
dir="$(JD_DIR)"
if ! git -C "$$dir" rev-parse --git-dir >/dev/null 2>&1; then
  rm -rf "$$dir"
  mkdir -p "$$dir"
  git -C "$$dir" init -q
  git -C "$$dir" remote add origin "https://github.com/smartcontractkit/job-distributor.git"
fi
if ! git -C "$$dir" rev-parse -q --verify HEAD >/dev/null 2>&1; then
  echo "  fetching job-distributor@v$(JD_VERSION)"
  git -c credential."https://github.com".helper='!gh auth git-credential' -C "$$dir" fetch -q --depth 1 origin "v$(JD_VERSION)"
  git -C "$$dir" checkout -q FETCH_HEAD
fi
echo "Building $(JD_IMAGE)..."
docker build -f "$$dir/e2e/Dockerfile.e2e" -t $(JD_IMAGE) "$$dir"
echo "OK built $(JD_IMAGE)"
endef
export JD_IMAGE_SH

.PHONY: jd-image
jd-image:
	bash -c "$$JD_IMAGE_SH"

define CHIP_ROUTER_IMAGE_SH
set -euo pipefail
if docker image inspect $(CHIP_ROUTER_IMAGE) >/dev/null 2>&1; then
  echo "OK chip-router image present: $(CHIP_ROUTER_IMAGE)"
  exit 0
fi
echo "Preparing chainlink-testing-framework checkout ($(CTF_SHA))..."
dir="$(CTF_DIR)"
if ! git -C "$$dir" rev-parse --git-dir >/dev/null 2>&1; then
  rm -rf "$$dir"
  mkdir -p "$$dir"
  git -C "$$dir" init -q
  git -C "$$dir" remote add origin "https://github.com/smartcontractkit/chainlink-testing-framework.git"
fi
if ! git -C "$$dir" rev-parse -q --verify HEAD >/dev/null 2>&1 || [ "$$(git -C "$$dir" rev-parse HEAD)" != "$(CTF_SHA)" ]; then
  echo "  fetching chainlink-testing-framework@$(CTF_SHA)"
  git -c credential."https://github.com".helper='!gh auth git-credential' -C "$$dir" fetch -q --depth 1 origin "$(CTF_SHA)"
  git -C "$$dir" checkout -q FETCH_HEAD
fi
echo "Building $(CHIP_ROUTER_IMAGE)..."
docker build -f "$$dir/framework/components/chiprouter/Dockerfile" -t $(CHIP_ROUTER_IMAGE) "$$dir/framework/components/chiprouter"
echo "OK built $(CHIP_ROUTER_IMAGE)"
endef
export CHIP_ROUTER_IMAGE_SH

.PHONY: chip-router-image
chip-router-image:
	bash -c "$$CHIP_ROUTER_IMAGE_SH"

define PLUGIN_BINARIES_SH
set -euo pipefail
arch="$$(docker info --format '{{.Architecture}}')"
case "$$arch" in
  x86_64|amd64) goarch=amd64 ;;
  aarch64|arm64) goarch=arm64 ;;
  *) echo "unknown docker arch: $$arch" >&2; exit 1 ;;
esac
mkdir -p "$(E2E_DIR)/binaries"
for plugin in confidential-http confidential-workflows; do
  echo "Building $$plugin (linux/$$goarch)..."
  ( cd "$(REPO_ROOT)/enclave/apps/$$plugin/capability" && CGO_ENABLED=0 GOOS=linux GOARCH="$$goarch" go build -o "$(E2E_DIR)/binaries/$$plugin" "./cmd/$$plugin/" )
done
echo "OK plugin binaries in $(E2E_DIR)/binaries"
endef
export PLUGIN_BINARIES_SH

.PHONY: plugin-binaries
plugin-binaries:
	bash -c "$$PLUGIN_BINARIES_SH"

.PHONY: core-symlink
core-symlink:
	ln -sfn "$(CHAINLINK_DIR)/core" "$(CORE_LINK)"
	echo "OK core symlink: $(CORE_LINK) -> $(CHAINLINK_DIR)/core"

.PHONY: e2e-local-conf-http
e2e-local-conf-http: chainlink-image jd-image plugin-binaries core-symlink
	if [ "$(ENCLAVE_TYPE)" = "NITRO" ]; then $(MAKE) --no-print-directory clean-e2e-nitro; fi
	cd "$(E2E_DIR)" && \
	CI=1 ENCLAVE_TYPE=$(ENCLAVE_TYPE) GOTOOLCHAIN=auto GOSUMDB=sum.golang.org \
	  CTF_CONFIGS=configs/workflow-don.toml \
	  CTF_CHAINLINK_IMAGE=$(CHAINLINK_IMAGE) \
	  CTF_JD_IMAGE=$(JD_IMAGE) \
	  go test -tags e2e -v -timeout 60m -run '^TestConfidentialHTTPE2E$$' .

.PHONY: e2e-local-conf-workflows
e2e-local-conf-workflows: chainlink-image jd-image chip-router-image plugin-binaries core-symlink
	if [ "$(ENCLAVE_TYPE)" = "NITRO" ]; then $(MAKE) --no-print-directory clean-e2e-nitro; fi
	cd "$(E2E_DIR)" && \
	CI=1 ENCLAVE_TYPE=$(ENCLAVE_TYPE) GOTOOLCHAIN=auto GOSUMDB=sum.golang.org \
	  CTF_CONFIGS=configs/workflow-don-engine.toml \
	  CTF_CHAINLINK_IMAGE=$(CHAINLINK_IMAGE) \
	  CTF_JD_IMAGE=$(JD_IMAGE) \
	  go test -tags e2e -v -timeout 60m -run '^TestConfidentialWorkflowsEngineE2E$$' .

.PHONY: clean-e2e
clean-e2e:
	rm -rf "$(WORK_DIR)"
	rm -f "$(CORE_LINK)"
	rm -rf "$(E2E_DIR)/binaries"
	echo "OK removed $(WORK_DIR), core symlink, and plugin binaries"

# Clear stale Nitro runtime state between real-enclave runs. Leftover enclaves
# block the allocator restart, orphaned wireguard-go-vsock helpers hold vsock
# ports, and cached EIF/PCR artifacts can mask code changes. The ENCLAVE_TYPE=NITRO
# e2e targets invoke this automatically before each run; it's also exposed as a
# standalone target.
.PHONY: clean-e2e-nitro
clean-e2e-nitro:
	echo "Cleaning stale Nitro state..."
	-pkill -9 -f host-server 2>/dev/null || true
	-{ sudo pkill -9 -f wireguard-go-vsock || pkill -9 -f wireguard-go-vsock; } 2>/dev/null || true
	-nitro-cli terminate-enclave --all 2>/dev/null || true
	-find "$(REPO_ROOT)/enclave/apps" \( -name 'go-enclave-outbound-cid*.eif' -o -name 'pcr_measurements*.json' \) -print -delete 2>/dev/null || true
	echo "OK cleaned Nitro enclaves, wireguard-go-vsock orphans, and stale EIF/PCR artifacts"

# Run `go mod tidy` in every module found under the repo root. GOTOOLCHAIN=auto
# lets modules pinning a newer Go toolchain fetch it automatically.
.PHONY: gomodtidy
gomodtidy:
	set -euo pipefail; \
	export GOTOOLCHAIN=auto; \
	while IFS= read -r -d '' mod; do \
	  dir="$$(dirname "$$mod")"; \
	  rel="$${dir#$(REPO_ROOT)/}"; \
	  [ "$$rel" = "$$dir" ] && rel="."; \
	  echo ">> go mod tidy: $$rel"; \
	  ( cd "$$dir" && go mod tidy ); \
	done < <(find "$(REPO_ROOT)" -name go.mod -not -path '*/.git/*' -print0)
