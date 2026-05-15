#!/bin/bash
# Restore the dongle to NM-managed mode after a monitor capture.
# Usage: sudo bash probes/monitor_restore.sh

set -e
IFACE="${IFACE:-wlx00c0caac3206}"

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: must run as root"
    exit 1
fi

ip link set "$IFACE" down
iwconfig "$IFACE" mode managed
ip link set "$IFACE" up
nmcli device set "$IFACE" managed yes

echo "Dongle restored to managed mode."
iwconfig "$IFACE" 2>&1 | grep -iE 'mode|essid' | sed 's/^/    /'
echo ""
echo "To reconnect to the camera (if needed):"
echo "    nmcli connection up ActionCam_1A80DF ifname $IFACE"
