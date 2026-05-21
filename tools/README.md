# Operational tools

Diagnostic and capture utilities used during ongoing work with a real
Larkfly A6+. All scripts use the `larkfly` package or stdlib only — the
one exception is `decrypt_pcap.py`, which needs `cryptography`.

## Tools

### PTP/IP — connection, enumeration, capture

| Script | What it does |
| --- | --- |
| `ptpip_probe.py` | One-shot PTP/IP smoke test — connects, opens a session, reads `DeviceInfo`, disconnects. Confirms protocol-level reachability. |
| `ptp_vendor_probe.py` | Exhaustive sweep of the 8 PTP/IP vendor opcodes (`0x9601`-`0x9812`) across a parameter-shape matrix. Crash-safe (health check + `--resume`) — three ops wedge the PTP service. See `docs/ptp-vendor.md`. |
| `prop_walk.py` | Reads `properties_supported` and dumps each property's descriptor + live value. `--block d7` filters to the D7xx block. |
| `prop_write_probe.py` | Write-and-revert classification of properties (truly-writable / silently-ignored / rejected). Proved `0xD75F`/`0xD7FC`/`0xD7FF` are firmware-locked despite RW descriptors. |
| `unlock_hunt.py` | Attempts 13 "primer" sequences (vendor-op calls, magic-string writes, sentinel modes) trying to unlock the three fake-RW booleans. All negative. |
| `sendobject_unlock.py` | Tests PTP `SendObjectInfo`+`SendObject` upload with magic filenames, then re-tests the locked booleans. Proved arbitrary PTP upload works. **Always deletes uploaded handles after** — esp. `SPHOST.BRN`. |
| `sendobject_magic_v2.py` | SendObject magic-filename battery, v2 — uses the 4-byte-padded encoder (quirk #4 fix) so filenames land intact. Re-ran the battery; negative. |
| `icatch_verify.py` | Implements the iCatch `device_verify` handshake reversed from libcontrol.so (writes 16 zero bytes to `0xD617`). Doesn't apply to this firmware — `0xD617` isn't advertised. Reference for other iCatch variants. |
| `photo_capture_test.py` | Live test of PTP `InitiateCapture` (`0x100E`): does it produce a JPG? (It doesn't — `rc=OK`, no file.) Optionally holds an RTSP preview; can sweep camera modes. |

### PTP/IP — wire-parser fuzzing & the pre-auth DoS

| Script | What it does |
| --- | --- |
| `ptp_container_fuzz.py` | PTP-IP container / packet-type fuzz — hits the wire parser before handler dispatch. Phase 3 is the pre-auth DoS trigger. |
| `ptp_p3_full_isolate.py` | Checkpoint-based isolator for the post-init ptype DoS — tests each candidate ptype in its own fresh-camera session, resuming across power-cycles. |
| `ptp_string_quirk.py` | Characterizes the iCatch PTP-string encoding quirk in `SendObjectInfo.Filename` (the 4-byte alignment header — quirk #4). |
| `datetime_parser_fuzz.py` | Fuzzes the DateTime parser on property `0x5011` (40 payloads). The parser is a robust `strptime`/`mktime` chain — no crashes. |
| `fmtstr_fuzz.py` | Format-string fuzz of writable PTP STRING properties. |

### RTSP

| Script | What it does |
| --- | --- |
| `rtsp_probe.py` | Maps everything RTSP port 554 accepts — verbs, paths, query params, playback, concurrency. Crash-safe (`--resume`) — some DESCRIBE targets freeze the service. See `docs/rtsp.md`. |

### FTP & SD-card

| Script | What it does |
| --- | --- |
| `ftp_traversal_fuzz.py` | FTP attack-surface fuzz — path traversal, command injection, overflow against the stripped FTP daemon (`wificam:wificam`). |
| `ftp_advanced_probe.py` | FTP follow-up probe — extra cases after the traversal fuzz. |
| `sd_autorun_probe.py` | SD-card autorun probe — drops candidate autorun/config filenames at the SD root and checks for boot-time pickup. |
| `sd_wifi_probe_ftp.py` | WiFi-config-file probe over FTP (no PTP-string truncation) — tests whether SD-root WiFi config files are honored. |
| `media_parser_fuzz.py` | Media parser fuzz — plants crafted JPEG/MP4 files in `/JPG` and `/VIDEO`, then probes the camera's reaction via PTP enumeration. |
| `media_parser_fuzz_v2.py` | Media parser fuzz, v2 — corrects v1's methodology errors (both kept; different methods). |

### USB — MSC (vendor SCSI) & UVC

| Script | What it does |
| --- | --- |
| `msdc_scsi_runner.py` | Named SCSI command runner for the iCatch MSC vendor catalog (`CAM_VER_GET`, etc.). Camera in MSC mode (`2aad:6371`) + `sudo`. |
| `msdc_scsi_diag.py` | 7-axis SCSI dispatcher diagnostic — proved the iCatch vendor-SCSI surface is stripped on this firmware. |
| `msdc_scsi_wide.py` | ~2100-probe wider SCSI sweep (vendor opcodes, INQUIRY VPD, READ_BUFFER, MODE_SENSE, …) — confirms no factory hooks beyond the iCatch stub. |
| `msdc_scsi_probe2.py` | Refined MSC vendor-SCSI probe, round 2 — candidate opcodes with varied `extendCmd`. Supersedes `archive/msdc_scsi_probe.py`. |
| `uvc_xu_probe.py` | Probes the UVC vendor extension unit (GUID `63610682-5070-49ab-b8cc-b3855e8d221d`, 32 selectors) via kernel `UVCIOC_CTRL_QUERY` ioctls. Camera in USB UVC mode. |
| `usb_ep0_vendor_probe.py` | USB endpoint-0 vendor control-transfer sweep (the S1 ISP-mode vector) — `bmRequestType` × `bRequest` matrix. |

### Capture / pcap

| Script | What it does |
| --- | --- |
| `decrypt_pcap.py` | Decrypts a WPA2-PSK 802.11 monitor-mode pcap, given SSID + PSK. Pure stdlib + `cryptography`. Handles the chained radiotap header + the `0xC78F` AAD-mask quirk. |
| `monitor_capture.sh` | Drops the USB WiFi dongle into monitor mode on the camera's channel, runs `tcpdump` to a timestamped pcap. Requires `sudo`. |
| `monitor_restore.sh` | Puts the dongle back into NetworkManager-managed mode. |

### `tools/archive/` — superseded one-shot scripts

Kept as reproducible references; each replaced by a newer script.

| Script | Superseded by | What it was |
| --- | --- | --- |
| `archive/msdc_scsi_probe.py` | `msdc_scsi_probe2.py` | Round-1 MSC vendor-SCSI probe. |
| `archive/ptp_p3_isolate.py` | `ptp_p3_full_isolate.py` | First post-init ptype DoS isolator (no checkpoint/resume). |
| `archive/ptp_factory_probe.py` | `prop_write_probe.py` | Early factory-mode / boolean-RW write sweep. |

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
- iCatch wire-format quirks #1–#3 are correctly handled in `larkfly`
  (quirk #4, the `SendObjectInfo.Filename` padding, isn't exercised by
  this probe — see `docs/findings.md`):
  1. Initiator name is raw UTF-16LE (no PTP-string length prefix)
  2. Name must be `"localhost"` or empty
  3. PTP-IP packet type 12 = `EndData` (NOT `Cancel`)
- `OpenSession` + `GetDeviceInfo` round-trip cleanly
- The full operations / events / properties inventory is reported

A successful run is the prerequisite for trusting any other camera work.
