FROM golang:1.26-alpine AS builder

# Match root go.mod (currently go 1.26.x) and allow minor toolchain bumps
# without another Dockerfile edit when chainlink-common moves forward.
ENV GOTOOLCHAIN=auto

ARG HOST_CID=3
ARG ENCLAVE_CID=16
ENV HOST_CID=$HOST_CID
ENV ENCLAVE_CID=$ENCLAVE_CID

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

# Copy source files
COPY enclave/ ./enclave/
COPY types/ ./types/
COPY util/ ./util/

# Build the Go binary
ARG APP_NAME=confidential-http
RUN CGO_ENABLED=0 GOOS=linux go build -o /enclave-app enclave/apps/${APP_NAME}/environments/nitro/main.go

FROM amazonlinux:latest

ARG HOST_CID=3
ARG ENCLAVE_CID=16
ENV HOST_CID=$HOST_CID
ENV ENCLAVE_CID=$ENCLAVE_CID

# Install required packages for networking and time synchronization
RUN dnf upgrade -y && \
    dnf install -y \
    hostname \
    iputils \
    iproute \
    wireguard-tools \
    bind-utils \
    procps-ng \
    curl-minimal \
    ca-certificates \
    chrony && \
    dnf clean all

# Configure chrony for AWS PTP clock synchronization
# For more: https://aws.amazon.com/blogs/compute/its-about-time-microsecond-accurate-clocks-on-amazon-ec2-instances/
RUN echo "refclock PHC /dev/ptp0 poll 0 offset 0 prefer" > /etc/chrony.conf && \
    echo "makestep 1.0 3" >> /etc/chrony.conf

# Create directory structure for WireGuard keys
RUN mkdir -p /etc/wireguard

COPY enclave/nitro/wireguard-go-vsock /usr/bin/
COPY enclave/nitro/outbound-https/setup-enclave-networking.sh /usr/bin/

RUN chmod +x /usr/bin/wireguard-go-vsock /usr/bin/setup-enclave-networking.sh

COPY enclave/nitro/.wireguard/host-public-key /etc/wireguard/
COPY enclave/nitro/.wireguard/enclave-private-key /etc/wireguard/

COPY --from=builder /enclave-app /usr/bin/

ARG KEYPAIR_ROTATION=
ARG KEYPAIR_EXPIRATION=
ARG ALLOW_RECONFIG=
ENV KEYPAIR_ROTATION=$KEYPAIR_ROTATION
ENV KEYPAIR_EXPIRATION=$KEYPAIR_EXPIRATION
ENV ALLOW_RECONFIG=$ALLOW_RECONFIG

# Create startup script that initializes chrony and then runs the enclave app
# If KEYPAIR_ROTATION or KEYPAIR_EXPIRATION are set, pass corresponding flags.
RUN echo '#!/bin/sh' > /start.sh && \
    echo 'chronyd' >> /start.sh && \
    echo 'chronyc wait syncing' >> /start.sh && \
    echo 'ARGS=""' >> /start.sh && \
    echo 'if [ -n "$KEYPAIR_ROTATION" ]; then ARGS="$ARGS --keypair-rotation=$KEYPAIR_ROTATION"; fi' >> /start.sh && \
    echo 'if [ -n "$KEYPAIR_EXPIRATION" ]; then ARGS="$ARGS --keypair-expiration=$KEYPAIR_EXPIRATION"; fi' >> /start.sh && \
    echo 'if [ "$ALLOW_RECONFIG" = "true" ]; then ARGS="$ARGS --allow-reconfig"; fi' >> /start.sh && \
    echo 'exec /usr/bin/enclave-app $ARGS' >> /start.sh && \
    chmod +x /start.sh

ENTRYPOINT ["/start.sh"]