#!/bin/sh
set -e

CONF_FILE="/app/ninja-server.conf"

# Auto-detect the container's own IP address unless SERVER_IP is explicitly set.
# This matters because docker's port-forwarding (-p 8053:53/udp) performs DNAT to the
# container's internal address, so the "ip dst" the scapy sniff filter must match is
# the container's own IP, not the host's public IP.
if [ -z "${SERVER_IP}" ]; then
    SERVER_IP=$(hostname -i | awk '{print $1}')
fi

SERVER_DOMAIN=${SERVER_DOMAIN:-ninja.example.com}

if [ ! -f "${CONF_FILE}" ]; then
    cat > "${CONF_FILE}" <<EOF
---
ServerIP: ${SERVER_IP}
ServerDomain: ${SERVER_DOMAIN}
EOF
fi

echo "Using config:"
cat "${CONF_FILE}"

exec python /app/dns-ninja-server.py

