#!/bin/bash
# Drop a USB WiFi dongle into monitor mode on the camera's channel and
# capture all 802.11 frames until you CTRL-C.
#
# Usage:
#   sudo bash tools/monitor_capture.sh
#   sudo IFACE=wlx... CHANNEL=6 BSSID=AA:BB:CC:DD:EE:FF bash tools/monitor_capture.sh
#
# Output: /tmp/larkfly-capture-<timestamp>.pcap, with
#         /tmp/larkfly-capture-latest.pcap symlinked to it.
# Decrypt with: python3 tools/decrypt_pcap.py /tmp/larkfly-capture-latest.pcap \
#                 --ssid <camera-SSID> --psk 1234567890

set -e

IFACE="${IFACE:-wlx00c0caac3206}"
CHANNEL="${CHANNEL:-1}"
PCAP="${PCAP:-/tmp/larkfly-capture-$(date +%Y%m%d-%H%M%S).pcap}"
LATEST_SYMLINK="/tmp/larkfly-capture-latest.pcap"
# Optional: restrict the capture to one camera's BSSID. Defaults to no
# filter (captures every frame on the channel — fine, just larger pcaps).
BSSID="${BSSID:-}"

rm -f "$PCAP" 2>/dev/null
ln -sf "$PCAP" "$LATEST_SYMLINK"

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: must run as root (need it to set monitor mode + tcpdump)"
    exit 1
fi

echo "[1/4] Telling NetworkManager to stop managing $IFACE..."
nmcli device set "$IFACE" managed no

echo "[2/4] Bringing $IFACE down and into monitor mode on channel $CHANNEL..."
ip link set "$IFACE" down
iwconfig "$IFACE" mode monitor
ip link set "$IFACE" up
iwconfig "$IFACE" channel "$CHANNEL"

echo "[3/4] Verifying mode:"
iwconfig "$IFACE" 2>&1 | grep -iE 'mode|frequency|access point' | sed 's/^/    /'

echo ""
echo "[4/4] Starting tcpdump → $PCAP"
if [ -n "$BSSID" ]; then
    echo "    Filter: any frame to/from BSSID $BSSID"
    FILTER="wlan host $BSSID"
else
    echo "    Filter: every frame on channel $CHANNEL"
    FILTER=""
fi
echo ""
echo "    >>> NOW: trigger the WiFi traffic you want to capture <<<"
echo "    CTRL-C here when you're done."
echo ""

# -s 0 = no snap-length limit, -U = packet-buffered output, -w = pcap file
exec tcpdump -i "$IFACE" -s 0 -w "$PCAP" -U $FILTER
