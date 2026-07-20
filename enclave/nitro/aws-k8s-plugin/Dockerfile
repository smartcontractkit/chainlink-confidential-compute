# Modified from source: https://github.com/aws/aws-nitro-enclaves-with-k8s/tree/main
# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file has been modified from the original source.
# Changes made: Updated COPY commands to include project-specific EIF files and build structure.

######## full image ########

FROM public.ecr.aws/amazonlinux/amazonlinux:2 as full_image

RUN amazon-linux-extras install aws-nitro-enclaves-cli && \
    yum install aws-nitro-enclaves-cli-devel jq -y

WORKDIR /ne-deps

# Copy only the required binaries to /ne-deps folder.
#
RUN BINS="\
    /usr/bin/nitro-cli \
    /usr/bin/nitro-enclaves-allocator \
    /usr/bin/jq \
    " && \
    for bin in $BINS; do \
        { echo "$bin"; ldd "$bin" | grep -Eo "/.*lib.*/[^ ]+"; } | \
            while read path; do \
                mkdir -p ".$(dirname $path)"; \
                cp -fL "$path" ".$path"; \
            done \
    done

# Prepare other required files and folders for the final image.
#
RUN \
    mkdir -p /ne-deps/etc/nitro_enclaves && \
    mkdir -p /ne-deps/run/nitro_enclaves && \
    mkdir -p /ne-deps/var/log/nitro_enclaves && \
    cp -rf /usr/share/nitro_enclaves/ /ne-deps/usr/share/ && \
    cp -f /etc/nitro_enclaves/allocator.yaml /ne-deps/etc/nitro_enclaves/allocator.yaml

######## hello image ########

FROM public.ecr.aws/amazonlinux/amazonlinux:2 as image

# Copying dependencies of the enclave apps from the 'full_image'
# to shrink the final image size.
#
COPY --from=full_image /ne-deps/etc /etc
COPY --from=full_image /ne-deps/lib64 /lib64
COPY --from=full_image /ne-deps/run /run
COPY --from=full_image /ne-deps/usr /usr
COPY --from=full_image /ne-deps/var /var

# shadow-utils for user/group management; curl for the enclave health probe in run.sh
RUN yum install -y shadow-utils curl && yum clean all

# Create 'ne' group (GID 1001) to match host for /dev/nitro_enclaves access
# Create primary group (GID 1000) and user with UID 1000, supplemental group 'ne'
RUN groupadd -g 1001 ne && \
    groupadd -g 1000 enclave && \
    useradd -u 1000 -g 1000 -G ne --no-create-home --shell /bin/sh enclave

# Fix permissions for non-root user
RUN chmod -R 777 /var/log/nitro_enclaves && \
    chmod -R 777 /run/nitro_enclaves

COPY go-enclave-outbound.eif /home
COPY enclave/nitro/aws-k8s-plugin/run.sh  /home

# Make the script executable and set ownership
RUN chmod +x /home/run.sh && \
    chown -R 1000:1000 /home

# Switch to non-root user (matches pod securityContext)
USER 1000

CMD ["/home/run.sh"]
