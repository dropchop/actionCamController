# Operational tools

Diagnostic and capture utilities used during ongoing work with a real
Larkfly A6+. All scripts use the `larkfly` package or stdlib only — no
extra `pip install`.

## Tools

| Script                  | What it does                                                       |
| ----------------------- | ------------------------------------------------------------------ |
| `ptpip_probe.py`        | One-shot PTP/IP smoke test — connects, opens a session, reads `DeviceInfo`, disconnects. Confirms protocol-level reachability. |
| `ftp_pull.py`           | Recover files off the SD card remotely over FTP — recursively mirrors the FTP-visible tree (`/VIDEO`, `/JPG`, root) to a local dir. **Download-only** (only ever sends `RETR`; never `DELE`/`STOR`/`RMD`). Resumable (SIZE-matched files skip on re-run), single sequential connection with pacing + retry/reconnect/backoff to respect the FTP-catatonia landmine. `--bind` pins both control + data sockets. Optional `--verify-ptp` cross-checks completeness against the PTP object index. For when a card is physically stuck in the camera. |
| `recover_camera.py`     | Interactive multi-camera recovery orchestrator (wraps `ftp_pull.py`). Scans for `ActionCam_*` APs on the dongle, shows a numbered menu (or takes `--ssid`/`--bssid`), then per camera: `sudo nmcli` connect (BSSID fallback on a stale scan cache) → idempotent `192.168.1.1/32` route into the NM profile → detect+validate the DHCP dongle IP → FTP reachability check → dry-run preview → confirm → drives `ftp_pull.py` as the **non-root user** (files stay user-owned) into `~/larkfly-recovered/<SSID>/`. Loops to the next camera. Runs as your normal user and `sudo`s only the individual nmcli commands (prompts on the TTY); refuses to run as root. Ctrl-C-safe (disconnects the dongle; resume on re-run). `-n` prints the exact commands without touching anything. |
| `rtsp_probe.py`         | Maps everything the camera's RTSP port (554) accepts — verbs, paths, query params, playback, concurrency. Crash-safe (per-request health check + `--resume`), because some DESCRIBE targets freeze the RTSP service and require a power-cycle. See `docs/rtsp.md`. |
| `ptp_vendor_probe.py`   | Exhaustive sweep of the 8 PTP/IP vendor opcodes (`0x9601`-`0x9812`) across a parameter-shape matrix. Same crash-safe pattern as `rtsp_probe.py` because three of the ops wedge the PTP service. See `docs/ptp-vendor.md`. |
| `prop_walk.py`          | Reads `properties_supported` and dumps each property's descriptor + live value. `--block d7` filters to the D7xx block. Used to enumerate the 56-property catalog and discover the 3 "fake-RW" locked booleans. |
| `prop_write_probe.py`   | Tries write-and-revert on candidate properties to classify them as truly writable / silently-ignored / rejected. Output proved `0xD75F`, `0xD7FC`, `0xD7FF` are firmware-locked despite RW descriptors. |
| `unlock_hunt.py`        | Attempts 13 different "primer" sequences (vendor-op calls, magic-string writes, sentinel-mode writes) trying to flip the firmware lock on the three fake-RW booleans. All negative as of 2026-05-17. |
| `sendobject_unlock.py`  | Tests PTP `SendObjectInfo`+`SendObject` file upload. Proved the camera accepts arbitrary file uploads via PTP (bypasses FTP chroot). **Always deletes uploaded handles after testing** — esp. `SPHOST.BRN` which triggers the FW-update menu on next boot. |
| `icatch_verify.py`      | Implements the iCatch `device_verify` handshake reversed from libcontrol.so (writes 16 zero bytes to property `0xD617` to unlock hidden surface). Doesn't apply to this firmware — `0xD617` isn't in the property list. Useful reference for other iCatch variants. |
| `msdc_scsi_runner.py`   | Named SCSI command runner for the (stripped) iCatch MSC vendor catalog. Sends `0xC0`-class CDBs with named operations (CAM_VER_GET, CAM_SD_CARD_STATUS, etc.). Useful for testing other iCatch cameras; this firmware's dispatcher is stubbed. |
| `msdc_scsi_diag.py`     | 7-axis SCSI dispatcher diagnostic — used to prove the iCatch vendor surface is stripped on this firmware. |
| `msdc_scsi_wide.py`     | ~2100-probe wider SCSI sweep (vendor opcode sweep, INQUIRY VPD pages, READ_BUFFER, MODE_SENSE, RECEIVE_DIAGNOSTIC, LOG_SENSE) — confirms no factory hooks on the SCSI surface beyond the iCatch stub. |
| `uvc_xu_probe.py`       | Probes the camera's UVC vendor extension unit (GUID `63610682-5070-49ab-b8cc-b3855e8d221d`, 32 control selectors) via kernel `UVCIOC_CTRL_QUERY` ioctls. Camera must be in USB UVC mode. |
| `ptp_factory_probe.py`  | Earlier exhaustive boolean RW write-sweep + magic OpenSession probe. Found `0xD727` to be the only writable boolean at the time (later superseded by `prop_write_probe.py`). |
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

## Recovering footage from a stuck SD card

When a card is physically stuck in a camera, pull the files over WiFi/FTP
instead. `recover_camera.py` automates the whole loop — pick the camera's
AP, connect, route, download:

```bash
# Interactive: scan for ActionCam_* APs, pick one, recover, repeat.
# Run as your NORMAL user (it sudoes the nmcli steps itself; you'll be
# prompted for your password). Files land in ~/larkfly-recovered/<SSID>/.
python3 tools/recover_camera.py

# Non-interactive single camera:
python3 tools/recover_camera.py --ssid ActionCam_C762D5 --yes

# Preview the exact nmcli + ftp_pull commands without touching anything:
python3 tools/recover_camera.py -n --ssid ActionCam_C762D5
```

Override the dongle interface with `--iface` (or `$IFACE`). The `/32`
route is required because the host's home WiFi can share `192.168.1.0/24`
with the camera AP. Re-running resumes (SIZE-matched files are skipped).

For a single, already-connected camera you can also call the downloader
directly: `python3 tools/ftp_pull.py 192.168.1.1 --bind <dongle-ip>`.

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
