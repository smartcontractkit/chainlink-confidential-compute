# Containerised AWS Nitro CLI, used by CI to turn a Docker image into an EIF.
#
# `nitro-cli build-enclave` needs only a Docker daemon. Per AWS, enclave image
# files can be built "on any Linux environment, including outside of AWS"; only
# run-enclave requires an enclave-enabled parent instance. Mounting the host's
# Docker socket into this image therefore lets ordinary CI runners produce EIFs.
#
# nitro-cli speaks the Docker API over the socket directly (via shiplift), so no
# Docker client is installed here.
#
# The kernel and init blobs shipped with the CLI feed PCR0 and PCR1, so the
# nitro-cli version determines the measurements. Set NITRO_CLI_VERSION to pin it.
FROM amazonlinux:2023

ARG NITRO_CLI_VERSION=

RUN if [ -n "${NITRO_CLI_VERSION}" ]; then \
        packages="aws-nitro-enclaves-cli-${NITRO_CLI_VERSION} aws-nitro-enclaves-cli-devel-${NITRO_CLI_VERSION}"; \
    else \
        packages="aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel"; \
    fi && \
    dnf install -y ${packages} && \
    dnf clean all && \
    rm -rf /var/cache/dnf

RUN mkdir -p /run/nitro_enclaves /var/log/nitro_enclaves

ENV NITRO_CLI_BLOBS=/usr/share/nitro_enclaves/blobs

ENTRYPOINT ["/usr/bin/nitro-cli"]
