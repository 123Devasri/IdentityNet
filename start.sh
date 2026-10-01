#!/bin/bash
# =============================================================================
# IdentityNet Gateway Quick Start Script
# =============================================================================

if [ "$EUID" -ne 0 ]; then
  echo "Error: IdentityNet Gateway requires root privileges for port 53 DNS and firewall rules."
  echo "Usage: sudo ./start.sh"
  exit 1
fi

echo "Starting IdentityNet Gateway Server..."
python3 src/main.py --lan-iface eth1 --wan-iface eth0 --gateway-ip 192.168.50.1 --port 80
