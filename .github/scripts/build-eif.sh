#!/usr/bin/env bash
#
# Builds an enclave image file (EIF) from a Docker image already loaded into the
# local daemon, using the containerised Nitro CLI (enclave/nitro/nitro-cli).
#
# The host Docker socket is mounted in so nitro-cli can read the source image.
# build-enclave does not need an enclave-enabled instance, so this works on any
# runner with Docker.
#
# nitro-cli's own output (including the measurements JSON the caller parses) is
# passed through on stdout untouched; this script's messages go to stderr.
#
# Usage: build-eif.sh <docker-uri> <output-file>

set -euo pipefail

DOCKER_URI="${1:?docker-uri is required}"
OUTPUT_FILE="${2:?output-file is required}"
NITRO_CLI_IMAGE="${NITRO_CLI_IMAGE:-nitro-cli:ci}"

out_dir=$(cd "$(dirname "$OUTPUT_FILE")" && pwd)
out_name=$(basename "$OUTPUT_FILE")

echo "Building ${out_name} from ${DOCKER_URI} using ${NITRO_CLI_IMAGE}" >&2

docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${out_dir}:/out" \
  "$NITRO_CLI_IMAGE" \
  build-enclave --docker-uri "$DOCKER_URI" --output-file "/out/${out_name}"

# nitro-cli runs as root inside the container, so the EIF lands root-owned.
sudo chown "$(id -u):$(id -g)" "${out_dir}/${out_name}"
