#!/bin/bash

# Build and run a "fake" enclave for local development and E2E tests.
#
# Unlike the real Nitro flow (build-and-run-go-enclave.sh) this does NOT build
# an EIF or talk to nitro-cli. Instead it runs the exact same Go binaries —
# the enclave app and the untrusted host proxy — as ordinary local processes.
# The vsock package
# (enclave/vsock) transparently emulates vsock over loopback TCP when
# VSOCK_BACKEND=tcp, so all inter-service communication exercises the same
# code paths as production.
#
# This script accepts the same environment variables as the real one so the
# E2E harness (tests.MustSetupEnclave) can drive either implementation.

set -euo pipefail

APP=${APP:-"confidential-http"}
ENCLAVE_CID=${ENCLAVE_CID:-16}
HTTP_PORT=${HTTP_PORT:-8080}
CONFIG_HTTP_PORT=${CONFIG_HTTP_PORT:-8081}
ENCLAVE_VSOCK_PORT=${ENCLAVE_VSOCK_PORT:-5000}
KEYPAIR_ROTATION=${KEYPAIR_ROTATION:-}
KEYPAIR_EXPIRATION=${KEYPAIR_EXPIRATION:-}
ALLOW_RECONFIG=${ALLOW_RECONFIG:-}
ENCLAVE_PATH="$(pwd)/enclave/apps/$APP"

# Tell the vsock abstraction and starter to use the fake/TCP backend. Exported
# so every child process (app, host) inherits them.
export VSOCK_BACKEND=tcp
export ENCLAVE_TYPE=FAKE
export ENCLAVE_CID

# Mirror enclave/vsock.getTCPPort: (cid * 1000) + (port % 10000) + 10000.
# We compute the loopback port the app will bind so we can wait on / clean it
# up without depending on the Go process to report readiness.
tcp_port_for() {
    local port=$1
    echo $(( (ENCLAVE_CID * 1000) + (port % 10000) + 10000 ))
}
APP_TCP_PORT=$(tcp_port_for "${ENCLAVE_VSOCK_PORT}")

echo "=== Building and running fake enclave ==="
echo "App: ${APP}"
echo "Enclave CID: ${ENCLAVE_CID}"
echo "Host HTTP Port: ${HTTP_PORT}"
echo "Config HTTP Port: ${CONFIG_HTTP_PORT}"
echo "Enclave vsock port: ${ENCLAVE_VSOCK_PORT} (loopback tcp ${APP_TCP_PORT})"
echo "Keypair rotation: ${KEYPAIR_ROTATION:-default}"
echo "Keypair expiration: ${KEYPAIR_EXPIRATION:-default}"
echo "Allow reconfig: ${ALLOW_RECONFIG:-false}"
echo

# Kill any stale processes left on the loopback ports this enclave uses so
# reruns (and crashed previous runs) don't collide.
kill_port() {
    local port=$1
    if command -v lsof >/dev/null 2>&1 && lsof -i:"${port}" -t >/dev/null 2>&1; then
        echo "Killing stale process on port ${port}..."
        lsof -i:"${port}" -t | xargs kill -9 2>/dev/null || true
    fi
}
kill_port "${APP_TCP_PORT}"

# Build the app flag list the same way the real Dockerfile entrypoint does.
APP_ARGS="--vsock-port=${ENCLAVE_VSOCK_PORT}"
if [ -n "${KEYPAIR_ROTATION}" ]; then APP_ARGS="${APP_ARGS} --keypair-rotation=${KEYPAIR_ROTATION}"; fi
if [ -n "${KEYPAIR_EXPIRATION}" ]; then APP_ARGS="${APP_ARGS} --keypair-expiration=${KEYPAIR_EXPIRATION}"; fi
if [ "${ALLOW_RECONFIG}" = "true" ]; then APP_ARGS="${APP_ARGS} --allow-reconfig"; fi

PIDS=()

# Build the app to a binary rather than `go run`-ing it, so the supervisor
# supervises the app itself instead of the `go run` wrapper (which would mask the
# app's exit status and signals behind its own).
#
# Build from the app directory so imports resolve against the app's own module.
# Some apps (e.g. confidential-workflows) are separate Go modules, so building
# from the repo root would resolve against the root module and fail to find the
# app's packages. -C handles both layouts.
APP_BINARY="${ENCLAVE_PATH}/fake-enclave-app-cid${ENCLAVE_CID}"
echo "Building fake enclave app (${APP})..."
go build -C "${ENCLAVE_PATH}" -o "${APP_BINARY}" ./environments/fake/
chmod +x "${APP_BINARY}"

# Run the app under the supervisor, mirroring the real EIF's /start.sh. Without
# this the fake environment would not exercise the supervisor or the crash
# reporting path at all, so a test passing here would say nothing about the
# behaviour that only exists in the real enclave.
SUPERVISOR_BINARY="${ENCLAVE_PATH}/enclave-supervisor-cid${ENCLAVE_CID}"
echo "Building enclave supervisor..."
go build -o "${SUPERVISOR_BINARY}" ./enclave/nitro/supervisor/
chmod +x "${SUPERVISOR_BINARY}"

echo "Starting fake enclave app (${APP}) under supervisor with args: ${APP_ARGS}"
"${SUPERVISOR_BINARY}" "${APP_BINARY}" ${APP_ARGS} &
PIDS+=($!)

# Clean up every child process when this script exits.
# EXIT is not run for untrapped fatal signals; clear traps before terminating
# and waiting for children.
trap 'trap - EXIT INT TERM; kill -TERM "${PIDS[@]}" 2>/dev/null || true; wait "${PIDS[@]}" 2>/dev/null || true' EXIT INT TERM

# Wait for the enclave app to be listening on its loopback vsock port before
# starting the host proxy, mirroring the real script's socat readiness probe.
echo "Waiting for enclave app to be responsive on loopback tcp ${APP_TCP_PORT}..."
MAX_WAIT=120
WAITED=0
until bash -c "echo > /dev/tcp/127.0.0.1/${APP_TCP_PORT}" >/dev/null 2>&1; do
    sleep 2
    WAITED=$((WAITED + 2))
    if [ "${WAITED}" -ge "${MAX_WAIT}" ]; then
        echo "Timeout waiting for enclave app to become responsive."
        exit 1
    fi
done
echo "Enclave app is responsive."

# Build the host proxy. Each enclave gets its own binary path so concurrent
# enclaves don't clobber a shared file (and avoid "text file busy" on rerun).
HOST_BINARY="${ENCLAVE_PATH}/host-server-cid${ENCLAVE_CID}"
echo "Building host application..."
# The host proxy is its own Go module (enclave/nitro/host/go.mod); build from its
# directory with -C so module resolution uses that module, not the repo root.
go build -C ./enclave/nitro/host -o "${HOST_BINARY}" .
chmod +x "${HOST_BINARY}"

echo "Starting fake host-server on port ${HTTP_PORT}..."
# Mirror the real script and send the host's own output to a file, so tests can
# assert on what it logged (e.g. an enclave crash report). Per-CID so concurrent
# fake enclaves do not clobber each other.
# Redirect rather than pipe through tee: $! after a pipeline is the PID of the
# last element, so piping would record tee's PID here and the EXIT trap would
# leave the host server alive holding VSOCK 5001. Matches the real script.
HOST_LOGFILE="${ENCLAVE_PATH}/host-server-cid${ENCLAVE_CID}.log"
"${HOST_BINARY}" \
    --port="${HTTP_PORT}" \
    --config-port="${CONFIG_HTTP_PORT}" \
    --enclave-cid="${ENCLAVE_CID}" \
    --enclave-port="${ENCLAVE_VSOCK_PORT}" > "${HOST_LOGFILE}" 2>&1 &
HOST_PID=$!
PIDS+=("${HOST_PID}")

echo "API endpoints available at:"
echo "- GET  http://localhost:${HTTP_PORT}/publicKeys"
echo "- POST http://localhost:${HTTP_PORT}/config"
echo "- POST http://localhost:${HTTP_PORT}/requests"

wait "${HOST_PID}"
