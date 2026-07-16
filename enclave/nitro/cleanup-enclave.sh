#!/bin/bash

set -euo pipefail

cleanup() {
    echo
    echo "Cleaning up resources..."
    
    # Kill console streaming process if running
    if [[ -n "${CONSOLE_PID:-}" ]] && ps -p $CONSOLE_PID > /dev/null; then
        echo "Terminating console streaming (PID: $CONSOLE_PID)..."
        kill $CONSOLE_PID || kill -9 $CONSOLE_PID 2>/dev/null || true
    fi
    
    # Kill host process if running
    if [[ -n "${HOST_SERVER_PID:-}" ]] && ps -p $HOST_SERVER_PID > /dev/null; then
        echo "Terminating host server (PID: $HOST_SERVER_PID)..."
        kill $HOST_SERVER_PID || kill -9 $HOST_SERVER_PID 2>/dev/null || true
    fi

    # Kill all running enclaves
    RUNNING_ENCLAVES=$(nitro-cli describe-enclaves 2>/dev/null | grep EnclaveID | awk '{print $2}' | tr -d '",')
    if [[ -n "$RUNNING_ENCLAVES" ]]; then
        echo "Terminating all running enclaves..."
        for enclave_id in $RUNNING_ENCLAVES; do
            echo "Terminating enclave $enclave_id..."
            nitro-cli terminate-enclave --enclave-id $enclave_id || true
        done
    else
        echo "No running enclaves found."
    fi
    
    # Stop wireguard-go-vsock if running
    if pgrep wireguard-go-vsock >/dev/null 2>&1; then
        echo "Stopping wireguard-go-vsock..."
        sudo killall wireguard-go-vsock || true
    fi
    
    echo "Cleanup complete."
}

cleanup
