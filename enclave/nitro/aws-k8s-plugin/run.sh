#!/bin/bash -e
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

main() {
    # Ensure log directory exists and is writable
    mkdir -p /var/log/nitro_enclaves
    chmod 777 /var/log/nitro_enclaves 2>/dev/null || true
    
    nitro-cli run-enclave --cpu-count $ENCLAVE_CPU_COUNT --memory $ENCLAVE_MEMORY_SIZE \
        --enclave-cid 16 --eif-path $EIF_PATH

    local enclave_id=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
    echo "-------------------------------"
    echo "Enclave ID is $enclave_id"
    echo "-------------------------------"

    # Keep the container running instead of blocking on console
    echo "Enclave started successfully.. Container will keep running..."
    while true; do
        sleep 30
        # Check if enclave is still running
        if ! nitro-cli describe-enclaves | jq -r ".[0].EnclaveID" > /dev/null 2>&1; then
            echo "Enclave appears to have stopped. Exiting..."
            exit 1
        fi
    done
}

main
