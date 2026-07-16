#!/bin/bash
set -euo pipefail

function print_usage() {
    echo "Usage: $0 --docker-uri <docker_uri> [--output-file <output_eif>] [--measurements-file <file>]"
    echo
    echo "Options:"
    echo "  --docker-uri <uri>          Docker URI to build the enclave image from"
    echo "  --output-file <file>        Output EIF file name (default: enclave.eif)"
    echo "  --measurements-file <file>  File containing expected measurements for verification"
    echo "                              If not provided, measurements will be saved to <output_file>.measurements.json"
    echo
    echo "Examples:"
    echo "  $0 --docker-uri ghcr.io/example/my-enclave:latest"
    echo "  $0 --docker-uri ghcr.io/example/my-enclave:latest --measurements-file measurements.json"
    exit 1
}

DOCKER_URI=""
OUTPUT_FILE="enclave.eif"
MEASUREMENTS_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --docker-uri)
            DOCKER_URI="$2"
            shift 2
            ;;
        --output-file)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --measurements-file)
            MEASUREMENTS_FILE="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            ;;
        *)
            echo "Unknown option: $1"
            print_usage
            ;;
    esac
done

if [[ -z "$DOCKER_URI" ]]; then
    echo "Error: Docker URI is required"
    print_usage
fi

if [[ -z "$MEASUREMENTS_FILE" ]]; then
    MEASUREMENTS_FILE="${OUTPUT_FILE}.measurements.json"
    echo "No measurements file provided, will save to: $MEASUREMENTS_FILE"
    VERIFY_MODE=false
else
    if [[ ! -f "$MEASUREMENTS_FILE" ]]; then
        echo "Error: Measurements file '$MEASUREMENTS_FILE' not found"
        exit 1
    fi
    echo "Verifying against measurements in: $MEASUREMENTS_FILE"
    VERIFY_MODE=true
fi

echo "=== Building enclave image ==="
echo "Docker URI: $DOCKER_URI"
echo "Output EIF: $OUTPUT_FILE"
echo

echo "Checking for Docker image availability..."
docker pull "$DOCKER_URI" || echo "Using locally available Docker image..."

echo "Building enclave image..."
BUILD_OUTPUT=$(nitro-cli build-enclave --docker-uri "$DOCKER_URI" --output-file "$OUTPUT_FILE")
echo "$BUILD_OUTPUT"

MEASUREMENTS_SECTION=$(echo "$BUILD_OUTPUT" | awk '/^{/,/^}$/' | sed 's/^}/}/')

echo "----------------"
echo $MEASUREMENTS_SECTION
echo "----------------"

if $VERIFY_MODE; then
    echo "Verifying measurements..."
    EXPECTED=$(cat "$MEASUREMENTS_FILE")
    
    PCR0_ACTUAL=$(echo "$MEASUREMENTS_SECTION" | grep -oP '"PCR0": "\K[^"]+')
    PCR1_ACTUAL=$(echo "$MEASUREMENTS_SECTION" | grep -oP '"PCR1": "\K[^"]+')
    PCR2_ACTUAL=$(echo "$MEASUREMENTS_SECTION" | grep -oP '"PCR2": "\K[^"]+')

    PCR0_EXPECTED=$(echo "$EXPECTED" | grep -oP '"PCR0": "\K[^"]+')
    PCR1_EXPECTED=$(echo "$EXPECTED" | grep -oP '"PCR1": "\K[^"]+')
    PCR2_EXPECTED=$(echo "$EXPECTED" | grep -oP '"PCR2": "\K[^"]+')
    
    if [ -z "$PCR0_ACTUAL" ] || [ -z "$PCR1_ACTUAL" ] || [ -z "$PCR2_ACTUAL" ] || \
       [ -z "$PCR0_EXPECTED" ] || [ -z "$PCR1_EXPECTED" ] || [ -z "$PCR2_EXPECTED" ]; then
        echo "Error: Failed to extract PCR values. Debug output:"
        echo "Actual measurements:"
        echo "$MEASUREMENTS_SECTION"
        echo "Expected measurements:"
        echo "$EXPECTED"
        exit 1
    fi
    
    echo "Comparing PCR values:"
    echo "PCR0 Expected: $PCR0_EXPECTED"
    echo "PCR0 Actual:   $PCR0_ACTUAL"
    echo "PCR1 Expected: $PCR1_EXPECTED"
    echo "PCR1 Actual:   $PCR1_ACTUAL"
    echo "PCR2 Expected: $PCR2_EXPECTED"
    echo "PCR2 Actual:   $PCR2_ACTUAL"
    
    if [[ "$PCR0_ACTUAL" == "$PCR0_EXPECTED" ]] && [[ "$PCR1_ACTUAL" == "$PCR1_EXPECTED" ]] && [[ "$PCR2_ACTUAL" == "$PCR2_EXPECTED" ]]; then
        echo "✅ Verification successful: Measurements match expected values"
    else
        echo "❌ Verification failed: Measurements do not match expected values"
        exit 1
    fi
else
    echo "Saving measurements to $MEASUREMENTS_FILE"
    echo "$MEASUREMENTS_SECTION" > "$MEASUREMENTS_FILE"
    echo "✅ Measurements saved successfully"
fi

echo
echo "=== Summary ==="
echo "Docker URI: $DOCKER_URI"
echo "Output EIF: $OUTPUT_FILE"

if $VERIFY_MODE; then
    echo "Measurements verified against: $MEASUREMENTS_FILE"
    echo "✅ Verification result: Success - All measurements match expected values"
else
    echo "Measurements saved to: $MEASUREMENTS_FILE"
fi

echo "Process completed successfully"