#!/bin/bash
# Put the dongle into monitor mode on the camera's channel and capture all
# 802.11 frames between the camera and any client until you CTRL-C.
#
# Usage: sudo bash probes/monitor_capture.sh
#
# Output: /tmp/larkfly-capture.pcap (decrypt with WPA-PSK "1234567890")
#
# Order of operations:
#   1. Run this script (it sets monitor mode and starts tcpdump).
#   2. THEN on phone: toggle WiFi off → on (so we capture the EAPOL
#      handshake we need for WPA decryption).
#   3. Open iSmart DV2; let it do its full setup + a few actions
#      (preview, snapshot, list files).
#   4. CTRL-C here to stop the capture.
#   5. Run probes/monitor_restore.sh to put the dongle back in managed mode.

set -e

IFACE="${IFACE:-wlx00c0caac3206}"
CHANNEL="${CHANNEL:-1}"
# Use a timestamped path so a stale file from a previous run (owned by the
# tcpdump user) doesn't block the new one with "Permission denied".
PCAP="${PCAP:-/tmp/larkfly-capture-$(date +%Y%m%d-%H%M%S).pcap}"
LATEST_SYMLINK="/tmp/larkfly-capture-latest.pcap"
BSSID="00:E0:4C:1A:80:DF"

# If user explicitly set PCAP, remove stale file (best effort)
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
echo "    Filter: any frame to/from camera BSSID $BSSID"
echo ""
echo "    >>> NOW: on phone, toggle WiFi off+on, then open iSmart DV2 <<<"
echo "    CTRL-C here when iSmart DV2 has finished one full session."
echo ""

# -i monitor iface, -s 0 = no snap limit, -w = pcap output
# Filter: anything with the camera BSSID in it. wlan host matches addr1, 2, 3
exec tcpdump -i "$IFACE" -s 0 -w "$PCAP" -U "wlan host $BSSID"
