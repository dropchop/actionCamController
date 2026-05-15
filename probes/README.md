# Camera probes

Standalone scripts to verify protocol hypotheses against a real Larkfly A6+
before building the multi-camera controller. Stdlib-only — no `pip install`.

## Probes

| Script              | What it tests                                                       | Status |
| ------------------- | ------------------------------------------------------------------- | ------ |
| `ptpip_probe.py`    | Camera speaks PTP/IP on TCP 15740, completes InitCommand handshake, returns a parseable DeviceInfo. **The protocol-confirmation test.** | Solid — implements PIMA 15740 + PTP-IP. |
| `wifi_provision.py` | Camera supports `simpleConfig` (AP → STATION mode switch). | Sandbox — vendor opcode + payload layout are unknown until a pcap of iSmart DV2 confirms them. |

## Order of operations on first hardware contact

```bash
# 0. Join the camera's own WiFi AP (default password 1234567890).
#    On this box:
nmcli device wifi connect <camera-SSID> password 1234567890

# 1. Confirm the camera is reachable at all.
ping -c 3 192.168.1.1

# 2. Confirm the protocol hypothesis from docs/findings.md.
python3 probes/ptpip_probe.py 192.168.1.1
#    Expected: prints camera Manufacturer/Model/Firmware + a list of
#    supported PTP operations and properties. Exits 0.
#    If this fails, the entire architecture plan in docs/findings.md
#    needs revisiting before going further.

# 3. See which vendor opcodes this camera exposes — one of these is simpleConfig.
python3 probes/wifi_provision.py 192.168.1.1 --list-vendor-ops

# 4. (Once a Wireshark capture of iSmart DV2 narrows down the opcode and
#     the payload format, sandbox-test it here.)
python3 probes/wifi_provision.py 192.168.1.1 \
    --send-vendor 0xE601 \
    --string "MyLaptopAP" \
    --string "supersecret" \
    --param 4 \
    --dry-run   # remove --dry-run once confident
```

## Verbose mode

Both probes accept `-v` / `--verbose` to hexdump every packet. Useful when:

- The handshake hangs and you need to see exactly what the camera replied
- You're cross-referencing wire bytes against a Wireshark capture
- The camera returns a non-standard packet type and the parser is confused

## What "success" of `ptpip_probe.py` proves

- Camera speaks **PTP** (not the Ambarella JSON/7878 protocol)
- Camera is reachable on TCP **15740** as expected
- Standard PTP operations OpenSession / GetDeviceInfo work
- We have the **full list of supported PTP operations and properties** for
  this camera model — including vendor extensions in the 0xD000-0xEFFF
  ranges. This is the inventory needed to build the controller.

## What `ptpip_probe.py` *does not* prove

- Vendor operations actually do what we think they do (e.g., that opcode
  0xE604 really starts recording). That requires either calling each one
  and observing the camera, or capturing iSmart DV2 in action.
- Two PTP/IP sessions to the same camera can coexist (we open one). The
  multi-camera plan in `docs/findings.md` opens one session per camera, not
  multiple to a single camera, so this isn't a blocker.

## Handling pcap data

If you can put a phone running iSmart DV2 on the same network as Wireshark:

```bash
# On Linux, filter for PTP/IP:
sudo tcpdump -i <iface> -w ismartdv2.pcap 'tcp port 15740'
# Then in Wireshark, use display filter:
#   tcp.port == 15740
# Right-click an Operation Request → Decode As → PTPIP
```

PTP/IP packets are plaintext; the 16-bit opcode is the first field after
the 8-byte container header (4-byte length, 4-byte type=6). Vendor
operations are the 0xE000-0xFFFF range.

## Stdlib-only

Both scripts use only Python 3.10 stdlib. No dependencies to install.
`wifi_provision.py` imports from `ptpip_probe.py` for the framing
primitives, so keep them in the same directory.
