#!/bin/bash

# This script configures the enclave side to establish outbound network traffic
# through the host using WireGuard over VSOCK.

set -euo pipefail

# Default values
HOST_CID=${HOST_CID:-3}
ENCLAVE_CID=${ENCLAVE_CID:-16}

echo "Setting up enclave networking for outbound traffic"
echo "HOST_CID: $HOST_CID"
echo "ENCLAVE_CID: $ENCLAVE_CID"
echo

mkdir -p /etc/wireguard

if [ ! -f /etc/wireguard/enclave-private-key ] || [ ! -f /etc/wireguard/host-public-key ]; then
    echo "Error: Required WireGuard key files are missing."
    echo "Make sure the following files exist:"
    echo " - /etc/wireguard/enclave-private-key"
    echo " - /etc/wireguard/host-public-key"
    exit 1
fi

echo "WireGuard keys:"
echo "Enclave Private Key:"
cat /etc/wireguard/enclave-private-key
echo
echo "Host Public Key:"
cat /etc/wireguard/host-public-key
echo

echo "Setting up WireGuard network interface 'wg0'..."
wireguard-go-vsock wg0

HOST_IP=100.64.0.$HOST_CID
ENCLAVE_IP=100.64.0.$ENCLAVE_CID

echo "Configuring IP addresses:"
echo "Enclave IP: $ENCLAVE_IP"
echo "Host IP: $HOST_IP"

ip addr add dev wg0 $ENCLAVE_IP/24

max_attempts=5
attempt=1
success=false

while [ $attempt -le $max_attempts ] && [ "$success" = false ]; do
    echo "Attempt $attempt to configure WireGuard (of $max_attempts)..."
    
    wg set wg0 \
        private-key /etc/wireguard/enclave-private-key \
        listen-port 51820 \
        peer $(cat /etc/wireguard/host-public-key) \
        allowed-ips 0.0.0.0/0 \
        persistent-keepalive 25 \
        endpoint $HOST_IP:51820
    
    # Set large MTU to increase VSOCK throughput
    ip link set mtu 50000 dev wg0
    ip link set up dev wg0
    
    if ip link show wg0 | grep -q "UP"; then
        echo "WireGuard interface successfully configured."
        success=true
    else
        echo "WireGuard interface configuration failed. Retrying..."
        sleep 2
        attempt=$((attempt+1))
    fi
done

if [ "$success" = false ]; then
    echo "Failed to configure WireGuard interface after $max_attempts attempts."
    echo "Debug info:"
    ip link show
    exit 1
fi

echo "WireGuard interface configured."

echo "Configuring default route via WireGuard..."
ip route add default dev wg0
echo "Default route configured."

echo "Configuring loopback interface..."
ip addr add 127.0.0.1/8 dev lo
ip link set dev lo up
echo "Loopback interface configured."

# Resolver used by the enclave. Defaults to the AWS VPC resolver
# (169.254.169.253), which resolves both the VPC private zone and public names.
# Override with DNS_RESOLVER=<vpc-cidr-base+2>.
# Public resolvers stay as a fallback for public names only.
# For more see: https://docs.aws.amazon.com/vpc/latest/userguide/AmazonDNS-concepts.html#AmazonDNS
DNS_RESOLVER=${DNS_RESOLVER:-169.254.169.253}

echo "Configuring DNS (resolver: $DNS_RESOLVER)..."
if [ -L /etc/resolv.conf ]; then
    rm -f /etc/resolv.conf
fi
echo "nameserver $DNS_RESOLVER" > /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf
echo "DNS configured."

echo "Waiting for WireGuard connection to establish..."
sleep 5
if ! command -v ping > /dev/null; then
    echo "Error: ping command not available"
    exit 1
fi

echo "Testing connectivity to the host..."
if ! ping -c 3 -w 5 $HOST_IP; then
    echo "Error: Ping to host failed"
    exit 1
fi

echo "Testing connectivity to the internet..."
if ! ping -c 3 -w 5 8.8.8.8; then
    echo "Error: Ping to internet failed"
    exit 1
fi

echo "Testing DNS resolution..."
if ! nslookup example.com; then
    echo "Error: DNS resolution failed"
    exit 1
fi

echo
echo "Network configuration details:"
echo "----------------------------"
echo "Interface information:"
ip addr show
echo
echo "Routing table:"
ip route
echo

echo "Enclave network setup complete."