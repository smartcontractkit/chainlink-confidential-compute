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

main() {
    # Ensure log directory exists and is writable
    mkdir -p /var/log/nitro_enclaves
    chmod 777 /var/log/nitro_enclaves 2>/dev/null || true
    
    local enclave_info
    local enclave_id
    if ! enclave_info=$(nitro-cli run-enclave --cpu-count "$ENCLAVE_CPU_COUNT" --memory "$ENCLAVE_MEMORY_SIZE" \
        --enclave-cid "$ENCLAVE_CID" --eif-path "$EIF_PATH"); then
        echo "Failed to start enclave." >&2
        exit 1
    fi
    printf '%s\n' "$enclave_info"
    if ! enclave_id=$(jq -er '.EnclaveID // empty' <<< "$enclave_info"); then
        echo "Could not determine enclave ID from run-enclave output." >&2
        exit 1
    fi
    echo "-------------------------------"
    echo "Enclave ID is $enclave_id"
    echo "-------------------------------"

    # Keep the container running instead of blocking on console
    echo "Enclave started successfully.. Container will keep running..."
    while true; do
        sleep 30
        if ! nitro-cli describe-enclaves | jq -e \
            --arg enclave_id "$enclave_id" \
            'any(.[]; .EnclaveID == $enclave_id and .State == "RUNNING")' \
            > /dev/null 2>&1; then
            echo "Enclave $enclave_id is no longer running. Exiting..."
            exit 1
        fi
    done
}

main
