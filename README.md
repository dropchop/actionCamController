# actionCamController

A Linux controller for **Larkfly A6+** action cameras (ODM model code
`V11`, iCatch V39A-family SoC, firmware build 20251206), reverse-engineered
from the iSmart DV2 Android app and a real device. Replaces the official
app for single-camera control and (eventually, see caveats below)
coordinates several cameras at once.

`V11` is the white-label model code the camera reports in its
`ProductName` property — the same hardware also sells as VIRAN V11 /
CERASTES V11. It is not an iCatch designation.

Born from the realization that the camera speaks an off-spec dialect of
PTP/IP with four undocumented quirks. The library encapsulates those
so a normal Python client can drive it.

## Status

**Functional for single-camera WiFi control.** Builds on `larkfly` (the
client library, 23 unit tests) plus a Flask web UI for live preview +
burst recording. Multi-camera works in principle but needs cameras to
be on a shared network — see `docs/architecture.md` for the tradeoffs.

What works:
- PTP/IP session against the camera; the protocol-level wire format is
  reverse-engineered and tested
- All 56 device properties enumerated + named where they matter
- Live RTSP preview (~30 fps) in a browser via the Flask UI
- Video recording start / stop / burst via property `0xD604`
- File access via FTP (`wificam` / `wificam`)
- USB UVC capture (1080p MJPEG) — but the camera doesn't dual-record
  to SD in UVC mode, so this is host-streaming only

What's stuck:
- Photo capture via PTP — unsolved. A library bug (wrong opcode:
  `0x100C` SendObjectInfo instead of `0x100E` InitiateCapture) is now
  fixed, but live testing shows the correct `InitiateCapture(0x100E)`
  returns OK yet still captures no photo. Workaround: the camera's
  physical shutter button.
- Putting multiple cameras on one shared WiFi (STATION mode) — the
  camera-side protocol is Realtek SmartConfig (UDP-broadcast, AES-
  encrypted). We have the default AES key + multicast target but the
  encoding algorithm needs more work. See `docs/findings.md`.

## Install

```bash
git clone https://github.com/dropchop/actionCamController.git
cd actionCamController

# Library only (pure stdlib at the core):
pip install -e .

# Library + web UI deps:
pip install -e '.[webui]'

# Library + capture-tool deps (cryptography for pcap decryption):
pip install -e '.[capture]'

# Everything:
pip install -e '.[all]'
```

Runs on Python 3.10+.

## Quick start

```python
# Talk to a camera that's at 192.168.1.1 (its factory default).
# `bind` is the local source IP — only needed when multiple interfaces
# share the 192.168.1.0/24 subnet.
from larkfly import Camera

with Camera('192.168.1.1', bind='192.168.1.10') as cam:
    info = cam.device_info()
    print(info['operations_supported'])

    # Read a property
    print(cam.get_prop_value(0x501E))   # 'V11'  — ProductName
    print(cam.get_prop_value(0x501F))   # '20251206' — FwVersion

    # Record video for 3 seconds (mode-toggle paradigm)
    cam.start_recording()        # sets D604=17 (VIDEO_ON)
    time.sleep(3)
    cam.stop_recording()         # sets D604=1  (VIDEO_OFF)
    # → .MOV file appears in the camera's /VIDEO/ via FTP

    # Browse / download
    for handle in cam.list_objects():
        print(cam.object_info(handle))
```

## Repo layout

```
actionCamController/
├── larkfly/         the Python client library (protocol + high-level Camera)
├── webui/           Flask multi-camera controller (preview + burst record)
├── tools/           operational utilities (probe, pcap decryption, monitor capture)
├── analyses/        one-shot RE scripts + their outputs (data/*.json)
├── tests/           unit tests for the protocol codec
├── examples/        library usage demos
├── docs/            findings.md, architecture.md, archived chronology
└── apk-analysis/    APK + decompile artifacts (gitignored — large + copyrighted)
```

## Run the web UI

```bash
# Single-camera (default IP):
python3 webui/app.py --bind 192.168.1.10
# Then open http://127.0.0.1:5000

# Mixed sources — one WiFi camera + one USB UVC camera:
python3 webui/app.py \
    --camera 192.168.1.1 --bind 192.168.1.10 \
    --usb /dev/video0
```

See `webui/README.md` for the API endpoints and `docs/architecture.md`
for the multi-camera deployment plan.

## What's in docs/

| File | When to read |
| --- | --- |
| `docs/findings.md` | **Start here.** Current-state reference: protocol quirks, opcodes, recording paradigm, multi-camera status. |
| `docs/architecture.md` | Deciding how to deploy 4 cameras (USB UVC vs WiFi multi-dongle vs STATION). |
| `docs/archive/investigation-log.md` | The full chronological RE story, including dead ends. |
| `docs/archive/original-protocol-notes.md` | The pre-investigation hypothesis (mostly disproved). |

## Acknowledgements

- libgphoto2's `camlibs/ptp2/ptpip.c` — clean reference implementation
  that resolved the packet-type-11-vs-12 spec ambiguity.
- [`clerie/rollei-AC-420`](https://github.com/clerie/rollei-AC-420) — same
  iCatch hardware family; confirmed the RTSP + FTP paths early on.
- [`Linouth/iCatch-V50-Playground`](https://github.com/Linouth/iCatch-V50-Playground)
  — adjacent chipset debug notes.

## License

MIT — see `LICENSE`.
