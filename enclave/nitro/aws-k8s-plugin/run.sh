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
# Consecutive failed health probes (30s apart) before we treat the enclave as
# wedged and exit, so Kubernetes restarts this container (which re-launches the
# VM). ~5 min of grace, long enough to cover initial config and transient blips.
readonly HEALTH_FAIL_THRESHOLD="${HEALTH_FAIL_THRESHOLD:-10}"

# enclave_responds returns 0 if the enclave answers over vsock. The host container
# serves /publicKeys on the shared-pod localhost, forwarding to the enclave; 200
# (ready) and 503 (not yet configured) both mean the vsock path works. Anything
# else (500 = host could not reach the VM, or connection refused/timeout) means
# the enclave is unreachable.
enclave_responds() {
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:8080/publicKeys || echo 000)
    [ "$code" = "200" ] || [ "$code" = "503" ]
}

main() {
    # Ensure log directory exists and is writable
    mkdir -p /var/log/nitro_enclaves
    chmod 777 /var/log/nitro_enclaves 2>/dev/null || true

    # A prior run (e.g. a container restart) can leave an enclave allocated on this
    # dedicated single-enclave node. Terminate that specific enclave by id (never
    # --all) so run-enclave can re-launch cleanly instead of failing on a CID clash.
    local stale
    stale=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID // empty')
    if [ -n "$stale" ]; then
        echo "Terminating stale enclave $stale before launch"
        nitro-cli terminate-enclave --enclave-id "$stale" || true
    fi

    nitro-cli run-enclave --cpu-count $ENCLAVE_CPU_COUNT --memory $ENCLAVE_MEMORY_SIZE \
        --enclave-cid 16 --eif-path $EIF_PATH

    local enclave_id=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
    echo "-------------------------------"
    echo "Enclave ID is $enclave_id"
    echo "-------------------------------"

    # Keep the container running, but supervise the enclave so a dead OR wedged VM
    # gets restarted. describe-enclaves only catches a fully-gone VM; a wedged VM
    # stays RUNNING per nitro-cli yet stops answering over vsock, so also probe it
    # functionally and exit (Kubernetes restarts us) when it is persistently unresponsive.
    echo "Enclave started successfully.. Container will keep running..."
    local fails=0
    while true; do
        sleep 30
        if ! nitro-cli describe-enclaves | jq -e '.[0].EnclaveID' > /dev/null 2>&1; then
            echo "Enclave is gone. Exiting to restart..."
            exit 1
        fi
        if enclave_responds; then
            fails=0
        else
            fails=$((fails + 1))
            echo "Enclave unresponsive on /publicKeys ($fails/$HEALTH_FAIL_THRESHOLD)"
            if [ "$fails" -ge "$HEALTH_FAIL_THRESHOLD" ]; then
                echo "Enclave wedged (unresponsive). Exiting to restart..."
                exit 1
            fi
        fi
    done
}

main
