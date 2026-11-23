#!/bin/bash -e
set -o pipefail

# Modified from source: https://github.com/aws/aws-nitro-enclaves-with-k8s/tree/main
# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file has been modified from the original source.
# Changes made: Updated EIF path and container behavior for this project.

# Use the go-enclave-outbound EIF
readonly EIF_PATH="/home/go-enclave-outbound.eif"
readonly ENCLAVE_CPU_COUNT="${ENCLAVE_CPU_COUNT:-2}"
readonly ENCLAVE_MEMORY_SIZE="${ENCLAVE_MEMORY_SIZE:-1024}"
readonly ENCLAVE_CID=16

# DEBUG BUILD ONLY. "true" starts the enclave with --debug-mode, which makes it
# attest all-zero PCRs, and copies its console to this container's output.
readonly ENCLAVE_DEBUG_MODE="${ENCLAVE_DEBUG_MODE:-false}"

# Seconds between checks that the enclave is still running.
if [ "$ENCLAVE_DEBUG_MODE" = "true" ]; then
    readonly ENCLAVE_POLL_SECONDS="${ENCLAVE_POLL_SECONDS:-5}"
else
    readonly ENCLAVE_POLL_SECONDS="${ENCLAVE_POLL_SECONDS:-30}"
fi

timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

# Prints what is known about the parent instance, once, at startup.
print_parent_info() {
    echo "----- parent instance -----"
    echo "time: $(timestamp)"
    echo "kernel: $(uname -a)"
    echo "cpu: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null || echo unknown)"
    echo "microcode: $(grep -m1 'microcode' /proc/cpuinfo 2>/dev/null || echo unknown)"
    echo "cpus: $(grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo unknown)"
    echo "nitro-cli: $(nitro-cli --version 2>&1 || true)"
    echo "eif sha256: $(sha256sum "$EIF_PATH" 2>/dev/null | cut -d' ' -f1)"
    echo "---------------------------"
}

# Copies the enclave console to stdout, one prefixed line per console line. The
# reader is restarted if it drops while the enclave is still there.
stream_console() {
    local enclave_id="$1"
    while true; do
        nitro-cli console --enclave-id "$enclave_id" 2>&1 | sed -u 's/^/[enclave-console] /' || true
        echo "[enclave-console] reader exited at $(timestamp)"
        if ! nitro-cli describe-enclaves 2>/dev/null | jq -e --arg id "$enclave_id" 'any(.[]; .EnclaveID == $id)' > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done
}

# Prints everything this container can see about why the enclave went away.
print_exit_diagnostics() {
    local describe_output="$1"
    echo "----- enclave exit diagnostics at $(timestamp) -----"
    printf 'nitro-cli describe-enclaves output:\n%s\n' "$describe_output"
    echo "--- /var/log/nitro_enclaves/nitro_enclaves.log (tail) ---"
    tail -n 200 /var/log/nitro_enclaves/nitro_enclaves.log 2>/dev/null || echo "(not readable)"
    echo "--- parent kernel log (tail) ---"
    { dmesg 2>/dev/null || echo "(dmesg not permitted)"; } | tail -n 200 || true
    echo "--- parent memory ---"
    grep -E 'MemTotal|MemFree|MemAvailable|HugePages|Hugepagesize' /proc/meminfo 2>/dev/null || true
    echo "----- end enclave exit diagnostics -----"
}

main() {
    # Ensure log directory exists and is writable
    mkdir -p /var/log/nitro_enclaves
    chmod 777 /var/log/nitro_enclaves 2>/dev/null || true

    print_parent_info

    local run_args=(--cpu-count "$ENCLAVE_CPU_COUNT" --memory "$ENCLAVE_MEMORY_SIZE"
        --enclave-cid "$ENCLAVE_CID" --eif-path "$EIF_PATH")
    if [ "$ENCLAVE_DEBUG_MODE" = "true" ]; then
        echo "DEBUG MODE: starting the enclave with --debug-mode. Its attestation PCRs are all zero and its console is copied below."
        run_args+=(--debug-mode)
    fi

    local enclave_info
    local enclave_id
    if ! enclave_info=$(nitro-cli run-enclave "${run_args[@]}"); then
        echo "Failed to start enclave." >&2
        print_exit_diagnostics "$(nitro-cli describe-enclaves 2>&1 || true)"
        exit 1
    fi
    printf '%s\n' "$enclave_info"
    if ! enclave_id=$(jq -er '.EnclaveID // empty' <<< "$enclave_info"); then
        echo "Could not determine enclave ID from run-enclave output." >&2
        exit 1
    fi
    echo "-------------------------------"
    echo "Enclave ID is $enclave_id (started $(timestamp))"
    echo "-------------------------------"

    local console_pid=""
    if [ "$ENCLAVE_DEBUG_MODE" = "true" ]; then
        stream_console "$enclave_id" &
        console_pid=$!
    fi

    # Keep the container running instead of blocking on console
    echo "Enclave started successfully.. Container will keep running..."
    local describe_output
    while true; do
        sleep "$ENCLAVE_POLL_SECONDS"
        if ! describe_output=$(nitro-cli describe-enclaves) || \
            ! jq -e \
            --arg enclave_id "$enclave_id" \
            'any(.[]; .EnclaveID == $enclave_id and .State == "RUNNING")' \
            > /dev/null 2>&1 <<< "$describe_output"; then
            echo "Enclave $enclave_id is no longer running (noticed $(timestamp))."
            if [ -n "$console_pid" ]; then
                # Let the console reader print what it still holds.
                sleep 3
                kill "$console_pid" 2>/dev/null || true
            fi
            print_exit_diagnostics "$describe_output"
            echo "Enclave $enclave_id is no longer running. Exiting..."
            exit 1
        fi
    done
}

main
