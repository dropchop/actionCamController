# Operational tools

Diagnostic and capture utilities used during ongoing work with a real
Larkfly A6+. All scripts use the `larkfly` package or stdlib only — no
extra `pip install`.

## Tools

| Script                  | What it does                                                       |
| ----------------------- | ------------------------------------------------------------------ |
| `ptpip_probe.py`        | One-shot PTP/IP smoke test — connects, opens a session, reads `DeviceInfo`, disconnects. Confirms protocol-level reachability. |
| `decrypt_pcap.py`       | Decrypts a WPA2-PSK 802.11 monitor-mode pcap, given the SSID + PSK. Pure stdlib + `cryptography`. Handles the chained-present radiotap header + the `0xC78F` AAD mask quirk we documented. |
| `monitor_capture.sh`    | Drops the USB WiFi dongle into monitor mode on the camera's channel, runs `tcpdump` to a timestamped pcap. Requires `sudo`. |
| `monitor_restore.sh`    | Puts the dongle back into NetworkManager-managed mode. |

## Quick start

```bash
# (Once) join the camera's WiFi AP from the dongle
nmcli device wifi connect <camera-SSID> password 1234567890 \
    ifname <dongle-iface>

# (Once) add the per-camera /32 host route into the NM profile so it
# survives DHCP renewal
sudo nmcli connection modify <camera-SSID> \
    +ipv4.routes "192.168.1.1/32 0.0.0.0"

# Confirm the camera is responding to PTP/IP
python3 tools/ptpip_probe.py 192.168.1.1 --bind 192.168.1.10
```

`ptpip_probe.py` prints the camera's `DeviceInfo` (model, firmware,
supported operations / events / properties) and exits 0 on success.
If it fails: see `docs/findings.md` "How the protocol works" — the
iCatch wire-format quirks (no-length-prefix initiator name; `"localhost"`
whitelist; packet type 12 = EndData) are documented there and handled
in `larkfly/protocol.py`.

## Capturing WiFi traffic for analysis

```bash
# 1. Free the dongle from any active connection
nmcli connection down <camera-SSID>

# 2. Start the capture (sudo)
sudo bash tools/monitor_capture.sh

# 3. Drive whatever phone/app traffic you want to capture

# 4. Ctrl-C in the terminal when done — pcap lands at /tmp/larkfly-capture-<timestamp>.pcap
#    and /tmp/larkfly-capture-latest.pcap is symlinked to it

# 5. Restore the dongle
sudo bash tools/monitor_restore.sh

# 6. Decrypt the capture (no sudo)
python3 tools/decrypt_pcap.py /tmp/larkfly-capture-latest.pcap \
    --ssid <camera-SSID> --psk 1234567890
# → produces a *-decrypted.pcap (Ethernet-encapsulated, ready for tshark/wireshark)
```

## What ptpip_probe verifies

- TCP 15740 is open
- iCatch's three wire-format quirks are correctly handled in `larkfly`:
  1. Initiator name is raw UTF-16LE (no PTP-string length prefix)
  2. Name must be `"localhost"` or empty
  3. PTP-IP packet type 12 = `EndData` (NOT `Cancel`)
- `OpenSession` + `GetDeviceInfo` round-trip cleanly
- The full operations / events / properties inventory is reported

A successful run is the prerequisite for trusting any other camera work.
