#!/bin/bash
set -euo pipefail

log() { echo "=== $(date +%H:%M:%S) $*"; }

# Step 0: Extract GitHub token from repo clone URL (baked in by 1-click deploy)
export GITHUB_TOKEN=$(grep -oP 'https://\K[^@]+(?=@github.com)' ~/confidential-compute/.git/config | head -1)
if [ -z "$GITHUB_TOKEN" ]; then
    echo "ERROR: Could not extract GITHUB_TOKEN from repo .git/config"
    exit 1
fi
# Set up global git auth so clones of other repos work
git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
export GOPRIVATE="github.com/smartcontractkit/*"
export GONOSUMCHECK="github.com/smartcontractkit/*"
log "Token extracted: ${GITHUB_TOKEN:0:8}..."

# Step 1: Clone chainlink
log "Cloning chainlink..."
cd ~
if [ ! -d chainlink ]; then
    git clone https://github.com/smartcontractkit/chainlink.git
fi
cd chainlink && git checkout tejaswi/cw-e2e-combined
cd ~

# Step 2: Build chainlink Docker image (needs --secret for private deps)
log "Building chainlink Docker image..."
cd ~/chainlink
echo "$GITHUB_TOKEN" > /tmp/.git_auth_token
docker build --secret id=GIT_AUTH_TOKEN,src=/tmp/.git_auth_token \
    -t chainlink-tmp:latest \
    --build-arg CHAINLINK_USER=chainlink \
    --build-arg CL_INSTALL_PRIVATE_PLUGINS=false \
    --build-arg CL_IS_PROD_BUILD=false \
    -f core/chainlink.Dockerfile .
rm -f /tmp/.git_auth_token
log "Chainlink image built"

# Step 3: Build job-distributor
log "Building job-distributor..."
cd ~
if [ ! -d job-distributor ]; then
    git clone https://github.com/smartcontractkit/job-distributor.git
fi
cd job-distributor && git checkout v0.22.1
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o job-distributor ./cmd/server
docker build -t job-distributor:0.22.1 .
cd ~
log "JD image built"

# Step 4: Build chip-ingress
log "Building chip-ingress..."
if [ ! -d atlas ]; then
    git clone https://github.com/smartcontractkit/atlas.git
fi
cd ~/atlas && git checkout da84cb72d3a160e02896247d46ab4b9806ebee2f
cd chip-ingress && go mod vendor && cd ..
docker build -f chip-ingress/Dockerfile -t chip-ingress:local-cre chip-ingress
log "chip-ingress image built"

# Step 5: Build chip-config
log "Building chip-config..."
cd ~/atlas && git checkout 7b4e9ee68fd1c737dd3480b5a3ced0188f29b969
cd chip-config && go mod vendor && cd ..
docker build -f chip-config/Dockerfile -t chip-config:local-cre chip-config
cd ~
log "chip-config image built"

# Step 6: Terminate existing enclave (test starts its own)
log "Terminating existing enclave..."
sudo nitro-cli terminate-enclave --all || true
pkill -f host-server || true

# Step 7: Run E2E test
log "Starting E2E test..."
cd ~/confidential-compute/tests
export CTF_CONFIGS=e2e/configs/workflow-don.toml
export CTF_CHAINLINK_IMAGE=chainlink-tmp:latest
export CTF_JD_IMAGE=job-distributor:0.22.1
export CI=true

go test -v -tags e2e \
    -run "TestConfidentialCapabilities/Testing_confidential-http" \
    -timeout 1200s -count=1

log "Done!"
