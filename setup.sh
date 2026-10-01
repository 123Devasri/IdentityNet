#!/bin/bash
# =============================================================================
# IdentityNet Gateway Server Setup Script
# Target Platform: Linux Mint 22+ / Ubuntu 24.04 / Debian 12
# =============================================================================

set -e

echo "================================================================="
echo " Installing System & Network Dependencies for IdentityNet Gateway"
echo "================================================================="

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run setup.sh with root privileges (e.g., sudo ./setup.sh)"
  exit 1
fi

echo "[1/4] Updating package cache..."
apt-get update -y

echo "[2/4] Installing Python 3, nftables, iptables, dnsmasq, net-tools..."
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nftables \
    iptables \
    dnsmasq \
    net-tools \
    tcpdump \
    procps \
    curl \
    iputils-ping

echo "[3/4] Installing Python packages (FastAPI, Uvicorn, Jinja2, Scapy)..."
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt

echo "[4/4] Setting execution permissions..."
chmod +x src/main.py
chmod +x test/*.py
chmod +x setup.sh
chmod +x start.sh 2>/dev/null || true

echo "================================================================="
echo " IdentityNet Gateway Setup Complete Successfully!"
echo " "
echo " Start Gateway Server:"
echo "   sudo ./start.sh"
echo " "
echo " Run Test Suite:"
echo "   python3 test/test_gateway.py"
echo "================================================================="
