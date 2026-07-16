#!/bin/bash

# This script configures the host side to allow outbound network traffic from the
# enclave. It sets up the WireGuard interface, configures IP addresses, and
# sets up iptables rules for NAT.
ENCLAVE_PATH="$(pwd)/enclave/apps/confidential-http" ## should be run from root of the repo
NITRO_PATH="$(pwd)/enclave/nitro"

set -euo pipefail

# Default values
HOST_CID=${HOST_CID:-3}
ENCLAVE_CID=${ENCLAVE_CID:-16}
SKIP_WIREGUARD_SETUP=${SKIP_WIREGUARD_SETUP:-false}

# Display current settings
echo "Setting up host networking for enclave outbound traffic"
echo "HOST_CID: $HOST_CID"
echo "ENCLAVE_CID: $ENCLAVE_CID"
echo "SKIP_WIREGUARD_SETUP: $SKIP_WIREGUARD_SETUP"
echo

################################################################################
### WIREGUARD SETUP                                                          ###
################################################################################

# ENCLAVE_PUBLIC_KEY can be passed from build-and-run-go-enclave.sh for
# per-enclave key pairs.  Fall back to the legacy shared key file.
if [ -z "${ENCLAVE_PUBLIC_KEY:-}" ]; then
    if [ -f ${NITRO_PATH}/.wireguard/enclave-public-key ]; then
        ENCLAVE_PUBLIC_KEY=$(cat ${NITRO_PATH}/.wireguard/enclave-public-key)
    else
        echo "Error: No ENCLAVE_PUBLIC_KEY provided and no enclave-public-key file found."
        exit 1
    fi
fi

ENCLAVE_IP=100.64.0.$ENCLAVE_CID

if [ "$SKIP_WIREGUARD_SETUP" = "false" ]; then
    if [ ! -f ${NITRO_PATH}/.wireguard/host-private-key ]; then
        echo "Error: Required WireGuard key file is missing."
        echo "Make sure the following file exists:"
        echo " - ${NITRO_PATH}/.wireguard/host-private-key"
        exit 1
    fi

    echo "Using host WireGuard private key..."
    echo "Enclave Public Key (CID ${ENCLAVE_CID}): ${ENCLAVE_PUBLIC_KEY}"
    echo

    # Kill any previously running instance and remove stale interface
    sudo killall -q wireguard-go-vsock || true
    sudo ip link delete wg0 2>/dev/null || true

    # Configure the WireGuard interface using wireguard-go-vsock
    echo "Starting wireguard-go-vsock..."
    sudo ${NITRO_PATH}/wireguard-go-vsock wg0

    # Set the WireGuard interface IP addresses
    HOST_IP=100.64.0.$HOST_CID
    echo "Configuring IP addresses:"
    echo "Host IP: $HOST_IP"
    sudo ip addr add dev wg0 $HOST_IP/24

    # Initial WireGuard config with the first enclave as a peer.
    # Each enclave gets its own peer entry with a /32 allowed-ip so WireGuard
    # can route return traffic to the correct enclave.
    echo "Enclave IP: $ENCLAVE_IP"
    sudo wg set wg0 \
      private-key ${NITRO_PATH}/.wireguard/host-private-key \
      listen-port 51820 \
      peer ${ENCLAVE_PUBLIC_KEY} \
      allowed-ips ${ENCLAVE_IP}/32 \
      endpoint ${ENCLAVE_IP}:51820

    # Set large MTU to increase VSOCK throughput
    sudo ip link set mtu 50000 dev wg0

    # Bring up the WireGuard interface
    sudo ip link set up dev wg0

    echo "WireGuard configured with peer for enclave CID ${ENCLAVE_CID}."
else
    # Add a NEW peer for this enclave (subsequent enclaves).
    # Because each enclave has its own key pair, WireGuard can distinguish
    # them and route return traffic correctly via the /32 allowed-ip.
    echo "Adding WireGuard peer for enclave CID ${ENCLAVE_CID}..."
    echo "Enclave Public Key: ${ENCLAVE_PUBLIC_KEY}"
    echo "Enclave IP: ${ENCLAVE_IP}"
    sudo wg set wg0 \
      peer ${ENCLAVE_PUBLIC_KEY} \
      allowed-ips ${ENCLAVE_IP}/32 \
      endpoint ${ENCLAVE_IP}:51820
    echo "WireGuard peer added for enclave CID ${ENCLAVE_CID}."
fi

################################################################################
### FORWARDING & IPTABLES                                                    ###
################################################################################

echo "Configuring IP forwarding and iptables..."

# Enable IP Forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Persist sysctl setting
sudo mkdir -p /etc/sysctl.d
sudo tee /etc/sysctl.d/99-enclave.conf > /dev/null <<EOF
net.ipv4.ip_forward=1
EOF

# Auto-detect the default network interface
DEFAULT_INTERFACE=$(ip route | grep '^default' | head -n1 | awk '{print $5}')
echo "Detected default interface: $DEFAULT_INTERFACE"

# Setup iptables rules only on first run
if [ "$SKIP_WIREGUARD_SETUP" = "false" ]; then
    # Create custom chain for enclave rules (or flush if it exists)
    echo "Creating custom iptables chain for enclave rules..."
    sudo iptables -N ENCLAVE_FORWARD 2>/dev/null || sudo iptables -F ENCLAVE_FORWARD

    # Add rules to custom chain with comments for identification
    # Restrict to enclave subnet only
    ENCLAVE_SUBNET=100.64.0.0/24
    sudo iptables -A ENCLAVE_FORWARD -i wg0 -s $ENCLAVE_SUBNET -o $DEFAULT_INTERFACE -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT -m comment --comment "ENCLAVE: outbound traffic"

    # Allow RETURN traffic FROM Internet TO WireGuard (Internet back to Enclave)
    sudo iptables -A ENCLAVE_FORWARD -i $DEFAULT_INTERFACE -o wg0 -d $ENCLAVE_SUBNET -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment "ENCLAVE: return traffic"

    # Insert jump to custom chain at the top of FORWARD chain
    # This ensures our rules are evaluated before any Kubernetes-managed rules
    sudo iptables -I FORWARD 1 -j ENCLAVE_FORWARD -m comment --comment "ENCLAVE: main chain"

    # NAT masquerade for enclave subnet only (not the whole /24)
    sudo iptables -t nat -I POSTROUTING 1 -s $ENCLAVE_SUBNET -o $DEFAULT_INTERFACE -j MASQUERADE -m comment --comment "ENCLAVE: NAT masquerade"

    echo "Iptables configured for outbound traffic."
else
    echo "Skipping iptables setup (already configured)."
fi

# Add INPUT rule for this specific enclave (always add, scoped to specific IP)
echo "Adding INPUT rule for enclave IP: $ENCLAVE_IP"
sudo iptables -I INPUT 1 -i wg0 -s $ENCLAVE_IP/32 -p tcp --dport 8082 -j ACCEPT -m comment --comment "ENCLAVE: local echo server for CID $ENCLAVE_CID"

echo
echo "Host network setup complete. The enclave can now access the internet through the host."