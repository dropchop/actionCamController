# actionCamController

Linux controller for **Larkfly A6+** action cameras (iCatch chipset
internal product code `V11`, firmware `20251206`), replacing the
iSmart DV2 Android app.

## Status

**Functional single-camera control proven; multi-camera architecture
designed and built.** What works as of the latest commit:

- Full PTP-IP session against a real Larkfly A6+
- All 56 device properties enumerated (`probes/data/properties.json`)
- Live RTSP preview at ~30 fps in a Flask web UI
- Video recording start/stop via the `D604` mode property
  (`D604=17` → record, `D604=1` → stop; produces real `.MOV` files on
  the SD card)
- Synchronized "burst" recording across all configured cameras with
  auto-stop after N seconds
- File access via FTP (`wificam:wificam@<camera>/JPG`, `/VIDEO`)

What does **not** yet work:

- Photo capture via PTP (`InitiateCapture` returns OK but no JPG
  appears on the SD card — see `docs/findings.md` for the trail).
  Workaround: the camera's physical shutter button.
- Multi-camera scaling has been **designed** but only validated with
  one physical camera so far (we have only one Larkfly on hand).

## Quick start

```bash
# Assumes the workstation is on the camera's WiFi (the original setup
# documented in docs/findings.md uses a USB WiFi dongle for this; the
# laptop's built-in WiFi stays on its primary network).
python3 -m unittest tests/test_protocol.py   # 23 unit tests, no hardware

# Live tests against the camera:
python3 probes/ptpip_probe.py 192.168.1.1 --bind 192.168.1.10
python3 examples/quickstart.py 192.168.1.1 --bind 192.168.1.10

# Run the web UI:
python3 webui/app.py --bind 192.168.1.10
# → http://127.0.0.1:5000/
```

## Layout

```
larkfly/        Python client library — PTP-IP with iCatch quirks
webui/          Flask multi-camera controller (analog of ClaudesWorld/webcam)
probes/         Standalone diagnostic scripts (probes, capture tools)
docs/           Protocol notes + findings log
examples/       Usage demos
tests/          Unit tests (no hardware required)
apk-analysis/   APK decompile artifacts (gitignored)
```

The full reverse-engineering trail — APK static analysis, packet
captures, the three iCatch wire-format quirks, the D604 mode-toggle
discovery — is documented in `docs/findings.md`. Read that doc first
for context.

## Required setup (one-time)

A USB WiFi dongle (Realtek RTL8812AU works) lets the host stay on its
normal WiFi while a second interface holds the camera AP. The
[aircrack-ng rtl8812au fork](https://github.com/aircrack-ng/rtl8812au)
is needed on kernel ≥6.x; an install script is at
`/tmp/install_rtl8812au.sh` after running this project once.

Routing: both interfaces wind up on `192.168.1.0/24` when the camera
hands out IPs from its default subnet. Add a `/32` host route to the
camera via the dongle:

```bash
sudo nmcli connection modify ActionCam_<MAC> \
    +ipv4.routes "192.168.1.1/32 0.0.0.0"
```

Pass `--bind 192.168.1.10` (the dongle's IP) to all the Python tools so
they source-bind correctly.

## Acknowledgements / sources

- [`clerie/rollei-AC-420`](https://github.com/clerie/rollei-AC-420) —
  same iCatch hardware family, confirmed RTSP + FTP paths.
- [`Linouth/iCatch-V50-Playground`](https://github.com/Linouth/iCatch-V50-Playground)
  — firmware/debug notes for related chipset.
- libgphoto2's `camlibs/ptp2/ptpip.c` — reference PTP-IP implementation,
  resolved the packet-type-12-is-EndData ambiguity.
- The iSmart DV2 APK itself — provided the wire format and the SDK
  Java enums that pointed at `D604` as the mode property.
