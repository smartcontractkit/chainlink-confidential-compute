#!/bin/bash

set -euo pipefail

# Default values - can be overridden by environment variables
APP=${APP:-"confidential-http"}
ENCLAVE_NAME=${ENCLAVE_NAME:-"go-outbound-enclave"}
DOCKER_TAG=${DOCKER_TAG:-"go-enclave-outbound"}
OUTPUT_EIF=${OUTPUT_EIF:-"go-enclave-outbound.eif"}
MEASUREMENTS_FILE=${MEASUREMENTS_FILE:-"pcr_measurements.json"}
ENCLAVE_PATH="$(pwd)/enclave/apps/$APP" ## should be run from root of the repo
NITRO_PATH="$(pwd)/enclave/nitro" ## should be run from root of the repo

# Select Dockerfile: apps with CGO deps (wasmtime) use Dockerfile.cgo.
if [ -z "${DOCKERFILE:-}" ]; then
    if [ "$APP" = "confidential-workflows" ]; then
        DOCKERFILE="${NITRO_PATH}/Dockerfile.cgo"
    else
        DOCKERFILE="${NITRO_PATH}/Dockerfile"
    fi
fi

# Default values - can be overridden by environment variables
ENCLAVE_CID=${ENCLAVE_CID:-16}
HOST_CID=${HOST_CID:-3}
CPU_COUNT=${ENCLAVE_CPU_COUNT:-2}
MEMORY_MIB=${ENCLAVE_MEMORY_MIB:-1024}
# Total allocator pool - should be sum of all enclaves if running multiple
TOTAL_CPU_COUNT=${TOTAL_CPU_COUNT:-4}
TOTAL_MEMORY_MIB=${TOTAL_MEMORY_MIB:-2048}
HTTP_PORT=${HTTP_PORT:-8080}
CONFIG_HTTP_PORT=${CONFIG_HTTP_PORT:-8081}
KEYPAIR_ROTATION=${KEYPAIR_ROTATION:-}
KEYPAIR_EXPIRATION=${KEYPAIR_EXPIRATION:-}
ALLOW_RECONFIG=${ALLOW_RECONFIG:-}
DEBUG_MODE=${DEBUG_MODE:-false}
SKIP_ALLOCATOR_RESTART=${SKIP_ALLOCATOR_RESTART:-false}
SKIP_IMAGE_BUILD=${SKIP_IMAGE_BUILD:-false}

# Display build parameters
echo "=== Building and running Go-based enclave with outbound HTTPS traffic ==="
echo "Image name: ${DOCKER_TAG}"
echo "Output EIF: ${OUTPUT_EIF}"
echo "Enclave name: ${ENCLAVE_NAME}"
echo "Enclave CID: ${ENCLAVE_CID}"
echo "Host CID: ${HOST_CID}"
echo "CPU count: ${CPU_COUNT}"
echo "Memory: ${MEMORY_MIB} MiB"
echo "Host HTTP Port: ${HTTP_PORT}"
echo "Config HTTP Port: ${CONFIG_HTTP_PORT}"
echo "Keypair rotation: ${KEYPAIR_ROTATION:-default}"
echo "Keypair expiration: ${KEYPAIR_EXPIRATION:-default}"
echo "Allow reconfig: ${ALLOW_RECONFIG:-false}"
echo "Skip allocator restart: ${SKIP_ALLOCATOR_RESTART}"
echo "Skip image build: ${SKIP_IMAGE_BUILD}"
echo "Total allocator pool: ${TOTAL_CPU_COUNT} CPUs, ${TOTAL_MEMORY_MIB} MiB"
echo

# Configure the Nitro Enclave allocator only if not skipping
if [ "$SKIP_ALLOCATOR_RESTART" = "false" ]; then
    echo "Configuring Nitro Enclave allocator..."
    echo "Allocator pool: ${TOTAL_CPU_COUNT} CPUs, ${TOTAL_MEMORY_MIB} MiB total"
    echo "This enclave: ${CPU_COUNT} CPUs, ${MEMORY_MIB} MiB"
    sudo sed -i \
      -e "s/^cpu_count: .*/cpu_count: $TOTAL_CPU_COUNT/" \
      -e "s/^memory_mib: .*/memory_mib: $TOTAL_MEMORY_MIB/" \
      /etc/nitro_enclaves/allocator.yaml

    # Clear all caches and compact memory
    sudo sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    echo 1 | sudo tee /proc/sys/vm/compact_memory > /dev/null

    sleep 5

    echo "Restarting nitro-enclaves-allocator service..."
    sudo systemctl restart nitro-enclaves-allocator.service
    echo "Waiting for allocator service to be ready..."
    sleep 5
    echo
else
    echo "Skipping allocator restart (subsequent enclave in same session)..."
    echo
fi

# Check if wireguard-tools is installed, install if not
if ! command -v wg &>/dev/null; then
    echo "wireguard-tools is not installed. Installing now..."
    sudo dnf install -y wireguard-tools
    echo "wireguard-tools installed successfully."
    echo
fi

# Prepare temporary directory for WireGuard keys
WG_DIR="${NITRO_PATH}/.wireguard"
mkdir -p "${WG_DIR}"

# Each enclave gets its own key pair so the host can configure separate
# WireGuard peers with distinct allowed-ips.  The host key is shared across
# all enclaves (generated once, reused for subsequent enclaves).
ENCLAVE_KEY_PREFIX="${WG_DIR}/enclave-${ENCLAVE_CID}"

# Host key: generate once, reuse for every enclave
if [[ -f "${WG_DIR}/host-private-key" ]]; then
    echo "Using existing host WireGuard key..."
    SK_HOST=$(cat "${WG_DIR}/host-private-key")
else
    echo "Generating new host WireGuard key..."
    SK_HOST=$(wg genkey)
    echo "$SK_HOST" > "${WG_DIR}/host-private-key"
fi
PK_HOST=$(echo $SK_HOST | wg pubkey)
echo "$PK_HOST" > "${WG_DIR}/host-public-key"

# Per-enclave key: unique per CID
if [[ -f "${ENCLAVE_KEY_PREFIX}-private-key" ]]; then
    echo "Using existing WireGuard key for enclave CID ${ENCLAVE_CID}..."
    SK_ENCLAVE=$(cat "${ENCLAVE_KEY_PREFIX}-private-key")
else
    echo "Generating new WireGuard key for enclave CID ${ENCLAVE_CID}..."
    SK_ENCLAVE=$(wg genkey)
    echo "$SK_ENCLAVE" > "${ENCLAVE_KEY_PREFIX}-private-key"
fi
PK_ENCLAVE=$(echo $SK_ENCLAVE | wg pubkey)
echo "$PK_ENCLAVE" > "${ENCLAVE_KEY_PREFIX}-public-key"

# Write the per-enclave key files where the Dockerfile expects them so each
# EIF gets the correct key pair baked in.
cp "${ENCLAVE_KEY_PREFIX}-private-key" "${WG_DIR}/enclave-private-key"
cp "${ENCLAVE_KEY_PREFIX}-public-key" "${WG_DIR}/enclave-public-key"

echo "Host:"
echo " - Private key: ${SK_HOST}"
echo " - Public key:  ${PK_HOST}"
echo
echo "Enclave:"
echo " - Private key: ${SK_ENCLAVE}"
echo " - Public key:  ${PK_ENCLAVE}"
echo

# Make wireguard-go-vsock executable if it isn't
chmod +x ${NITRO_PATH}/wireguard-go-vsock

# Build host application only if not skipping build
if [ "$SKIP_IMAGE_BUILD" = "false" ]; then
    echo "Building host application..."
    # The host proxy is its own Go module (enclave/nitro/host/go.mod); build from its
    # directory with -C so module resolution uses that module, not the repo root.
    go build -C "${NITRO_PATH}/host" -o ${ENCLAVE_PATH}/host-server .
    chmod +x ${ENCLAVE_PATH}/host-server
    echo "Host application built successfully."
    echo
else
    echo "Skipping host application build..."
    echo
fi

# Each enclave needs its own EIF because its unique WireGuard private key is
# baked into the image.  We tag images per-CID to avoid clobbering.
ENCLAVE_DOCKER_TAG="${DOCKER_TAG}-cid${ENCLAVE_CID}"
ENCLAVE_EIF="go-enclave-outbound-cid${ENCLAVE_CID}.eif"

# Step 1: Build Docker image (always needed per-enclave for unique keys)
if [ "$SKIP_IMAGE_BUILD" = "false" ]; then
    echo "Building Docker image ${ENCLAVE_DOCKER_TAG} from ${DOCKERFILE}..."
    docker build --no-cache -f "${DOCKERFILE}" . -t ${ENCLAVE_DOCKER_TAG} \
        --build-arg HOST_CID=${HOST_CID} \
        --build-arg ENCLAVE_CID=${ENCLAVE_CID} \
        --build-arg APP_NAME=${APP} \
        --build-arg KEYPAIR_ROTATION="${KEYPAIR_ROTATION}" \
        --build-arg KEYPAIR_EXPIRATION="${KEYPAIR_EXPIRATION}" \
        --build-arg GATEWAY_URL="${GATEWAY_URL:-}" \
        --build-arg STORAGE_SERVICE_URL="${STORAGE_SERVICE_URL:-}" \
        --build-arg STORAGE_SERVICE_TLS="${STORAGE_SERVICE_TLS:-}" \
        --build-arg ALLOW_RECONFIG="${ALLOW_RECONFIG}"
    echo "Docker image built successfully."
    echo
else
    # Even with SKIP_IMAGE_BUILD, we must rebuild if keys changed (new enclave)
    if [ ! -f "${ENCLAVE_PATH}/${ENCLAVE_EIF}" ]; then
        echo "No EIF found for CID ${ENCLAVE_CID}, building Docker image..."
        docker build --no-cache -f "${DOCKERFILE}" . -t ${ENCLAVE_DOCKER_TAG} \
            --build-arg HOST_CID=${HOST_CID} \
            --build-arg ENCLAVE_CID=${ENCLAVE_CID} \
            --build-arg APP_NAME=${APP} \
            --build-arg KEYPAIR_ROTATION="${KEYPAIR_ROTATION}" \
            --build-arg KEYPAIR_EXPIRATION="${KEYPAIR_EXPIRATION}" \
            --build-arg GATEWAY_URL="${GATEWAY_URL:-}" \
            --build-arg STORAGE_SERVICE_URL="${STORAGE_SERVICE_URL:-}" \
            --build-arg STORAGE_SERVICE_TLS="${STORAGE_SERVICE_TLS:-}" \
            --build-arg ALLOW_RECONFIG="${ALLOW_RECONFIG}"
        echo "Docker image built successfully."
    else
        echo "Skipping Docker image build (existing EIF found for CID ${ENCLAVE_CID})..."
    fi
    echo
fi

# Step 2: Convert Docker image to EIF (Enclave Image Format)
if [ "$SKIP_IMAGE_BUILD" = "false" ] || [ ! -f "${ENCLAVE_PATH}/${ENCLAVE_EIF}" ]; then
    echo "Building Enclave Image File (EIF) for CID ${ENCLAVE_CID}..."

    BUILD_OUTPUT=$(nitro-cli build-enclave --docker-uri ${ENCLAVE_DOCKER_TAG}:latest --output-file ${ENCLAVE_PATH}/${ENCLAVE_EIF})
    echo "EIF file built successfully: ${ENCLAVE_PATH}/${ENCLAVE_EIF}"

    echo "$BUILD_OUTPUT" | awk '/^{/,/^}$/' | sed 's/^}/}/' > ${ENCLAVE_PATH}/${MEASUREMENTS_FILE}
    echo "PCR measurements saved to: ${ENCLAVE_PATH}/${MEASUREMENTS_FILE}"
    echo
else
    echo "Skipping EIF build (using existing image for CID ${ENCLAVE_CID})..."
    echo
fi

# Step 3: Set up host networking for the enclave.
# Pass the per-enclave public key so the host can add it as a distinct peer.
if [ "$SKIP_ALLOCATOR_RESTART" = "false" ]; then
    echo "Setting up host networking for outbound connectivity..."
    ENCLAVE_CID=${ENCLAVE_CID} HOST_CID=${HOST_CID} \
        ENCLAVE_PUBLIC_KEY="${PK_ENCLAVE}" \
        ${NITRO_PATH}/host/setup-host-networking.sh
    echo
else
    echo "Setting up additional enclave networking (adding WireGuard peer)..."
    SKIP_WIREGUARD_SETUP=true ENCLAVE_CID=${ENCLAVE_CID} HOST_CID=${HOST_CID} \
        ENCLAVE_PUBLIC_KEY="${PK_ENCLAVE}" \
        ${NITRO_PATH}/host/setup-host-networking.sh
    echo
fi

# Step 4: Terminate any existing enclave with the same name
echo "Stopping any running enclave with name '${ENCLAVE_NAME}'..."
nitro-cli terminate-enclave --enclave-name ${ENCLAVE_NAME} 2>/dev/null || true
echo

# Step 5: Run the enclave
echo "Starting enclave..."
nitro-cli run-enclave \
    --cpu-count ${CPU_COUNT} \
    --memory ${MEMORY_MIB} \
    --enclave-cid ${ENCLAVE_CID} \
    --enclave-name ${ENCLAVE_NAME} \
    $(if [ "$DEBUG_MODE" = "true" ]; then echo '    --debug-mode'; fi) --eif-path ${ENCLAVE_PATH}/${ENCLAVE_EIF} &

echo "Enclave started successfully."
echo

# Wait for enclave to be responsive on vsock before starting host
echo "Waiting for enclave to be responsive on vsock (CID: ${ENCLAVE_CID}, port: 5000)..."
# Ensure socat is installed (Amazon Linux 2023: dnf install -y socat)
if ! command -v socat >/dev/null 2>&1; then
    echo "socat not found. Installing socat (requires sudo)..."
    sudo dnf install -y socat
fi
MAX_WAIT=60
WAITED=0
while true; do
    socat -T 2 - "VSOCK-CONNECT:${ENCLAVE_CID}:5000" < /dev/null >/dev/null 2>&1 && break
    sleep 2
    WAITED=$((WAITED+2))
    if [ $WAITED -ge $MAX_WAIT ]; then
        echo "Timeout waiting for enclave vsock to become responsive."
        exit 1
    fi
done
echo "Enclave is responsive on vsock."
echo

# Step 6: Kill any existing host server processes on the target ports
echo "Checking for existing host server processes on ports ${HTTP_PORT} and ${CONFIG_HTTP_PORT}..."
if lsof -i:${HTTP_PORT} -t >/dev/null 2>&1; then
    EXISTING_PIDS=$(lsof -i:${HTTP_PORT} -t)
    echo "Found existing processes on port ${HTTP_PORT} (PIDs: $EXISTING_PIDS). Terminating them..."
    for pid in $EXISTING_PIDS; do
        echo "Killing PID: $pid"
        kill -TERM $pid 2>/dev/null || true
        sleep 1
        # Force kill if still running
        if kill -0 $pid 2>/dev/null; then
            kill -9 $pid 2>/dev/null || true
        fi
    done
fi

if lsof -i:${CONFIG_HTTP_PORT} -t >/dev/null 2>&1; then
    EXISTING_CONFIG_PIDS=$(lsof -i:${CONFIG_HTTP_PORT} -t)
    echo "Found existing processes on port ${CONFIG_HTTP_PORT} (PIDs: $EXISTING_CONFIG_PIDS). Terminating them..."
    for pid in $EXISTING_CONFIG_PIDS; do
        echo "Killing PID: $pid"
        kill -TERM $pid 2>/dev/null || true
        sleep 1
        # Force kill if still running
        if kill -0 $pid 2>/dev/null; then
            kill -9 $pid 2>/dev/null || true
        fi
    done
fi

# Start the host server application in the background
LOGFILE="${ENCLAVE_PATH}/host-server.log"
echo "Starting host server on port ${HTTP_PORT}..."
${ENCLAVE_PATH}/host-server --port=${HTTP_PORT} --config-port=${CONFIG_HTTP_PORT} --enclave-cid=${ENCLAVE_CID} --enclave-port=5000 > "${LOGFILE}" 2>&1 &

HOST_SERVER_PID=$!
echo "Host server started with PID ${HOST_SERVER_PID}"
echo "API endpoints available at:"
echo "- GET  http://localhost:${HTTP_PORT}/publicKeys"
echo "- POST http://localhost:${HTTP_PORT}/config"
echo "- POST http://localhost:${HTTP_PORT}/requests"
echo
echo "To terminate the enclave, run:"
echo "nitro-cli terminate-enclave --enclave-name ${ENCLAVE_NAME}"
echo
echo "To stop the host server, run:"
echo "kill ${HOST_SERVER_PID}"
