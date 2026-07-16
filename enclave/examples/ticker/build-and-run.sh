#!/bin/bash
cleanup() {
    echo
    echo "Cleaning up resources..."
    
    nitro-cli terminate-enclave --all
    
    echo "Cleanup complete."
}

trap cleanup EXIT INT TERM

docker build -t ticker .

nitro-cli build-enclave --docker-uri ticker:latest --output-file ticker-enclave.eif

nitro-cli run-enclave --cpu-count 2 --memory 1024 --enclave-cid 16 --eif-path ticker-enclave.eif --debug-mode

nitro-cli console --enclave-name ticker-enclave