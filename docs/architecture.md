# Multi-camera architecture — decision and reference

## The problem

Drive 4 Larkfly A6+ cameras simultaneously from one Linux host:
- Live preview from each
- Synchronized photo / video capture across all four

Each camera defaults to its own WiFi AP at `192.168.1.1`. A single host
WiFi radio can associate with only one AP at a time, and all four cameras
share the same IP — so even four parallel radios run into addressing
conflicts. The "obvious" approach (one host, one network) needs help.

## Three viable paths

### Path A — STATION mode (`simpleConfig` push)
Push each camera into WiFi-client mode, joining one shared AP. Each
camera gets a distinct DHCP-assigned IP. Networking is trivial after
setup.

- **Pros:** wireless, cameras can be physically separated up to WiFi
  range, supports high-res capture (4K @ 60 fps) and camera-side
  storage to SD.
- **Cons:** requires `simpleConfig` (one of 6 unidentified vendor PTP
  opcodes). Per-camera one-time setup, factory-reset undoes. **Tested
  cautiously this session — one of the vendor-opcode probes crashed
  the camera's network stack. Not safely identified yet.**
- **Status:** unproven. Needs a controlled AP set up first, then
  user permission to push test creds.

### Path B — Multi-dongle (one USB WiFi per camera)
Buy 3 more RTL8812AU dongles. Each associates with one camera's AP.
Routing per-camera via `/32` host routes through specific interfaces.

- **Pros:** no camera-side changes; all cameras stay in their default
  factory state.
- **Cons:** 3× more hardware (~$60). Routing is fragile — every camera
  has IP 192.168.1.1, distinguished only by which dongle the traffic
  goes out on. Source-IP binding (`--bind 192.168.1.X`) handles
  outgoing; incoming RTSP/event traffic needs careful interface
  binding too.
- **Status:** proven for 1 camera (current setup). Scales mechanically
  to 4, just more wiring.

### Path C — USB UVC ⭐ (the answer)
Plug each camera into a USB port (powered hub for ≥3 cameras). The
camera presents as a standard UVC class device on `/dev/videoN`.

- **Pros:**
  - **No networking complexity** — no IPs, no routing, no WiFi.
  - **No camera-side changes** — the cameras stay factory-default.
  - Up to **1920×1080 @ 30 fps** via UVC (MJPEG or H.264).
  - Standard UVC controls: auto-exposure, focus, white-balance.
  - Vendor extension unit available (32 control bits) — likely how to
    reach photo/4K-record on the camera side, currently undecoded.
  - Recording is host-side (writes `.mp4` files where the host wants),
    so no camera SD-card management.
- **Cons:**
  - Limited to 1920×1080 max via the standard UVC video path. (The
    camera's native 4K-60 / 9216×5184 capture is only accessible
    via the WiFi PTP-IP path until we decode the vendor XU.)
  - USB bandwidth ceiling: 480 Mb/s per bus. 4 × 1080p MJPEG fits
    with margin; H.264 fits with more.
  - Cameras must be physically tethered to the host.
  - Audio is exposed (interfaces 2, 3) but **not yet captured by our
    code** — would need parallel ALSA pipeline.
- **Status:** **working end-to-end as of this commit.** Verified:
  preview at 30 fps, photo capture (413 KB JPEG, 1920×1080),
  burst recording (13 MB MP4 for 3 seconds).

## Recommendation: USB UVC is the primary path

For the 4-camera goal, Path C delivers without the failure modes the
WiFi paths bring (cameras crashing, IP collisions, simpleConfig risk,
hardware purchases). The 4K ceiling is the only meaningful concession
and only matters if you specifically need >1080p output.

**Recommended physical setup:**

```
   ┌──────────────┐
   │ Linux host   │
   │   (4 USB     │
   │    ports OR  │──── Powered USB hub ─┬── Cam 1 (/dev/video0)
   │  powered hub)│                       ├── Cam 2 (/dev/video2)
   └──────┬───────┘                       ├── Cam 3 (/dev/video4)
          │                               └── Cam 4 (/dev/video6)
          │
   Run: python3 webui/app.py \
        --usb /dev/video0 \
        --usb /dev/video2 \
        --usb /dev/video4 \
        --usb /dev/video6
```

When a UVC camera connects, the kernel typically creates *two*
`/dev/videoN` nodes per device (video + metadata), so use the
even-numbered ones (`video0`, `video2`, `video4`, `video6`) — or pass
`--usb auto` once to let the app pick them automatically.

For each camera you need a **data-carrying USB cable** (not the
power-only ones that come with many action-cam packages) **and** the
camera in its "PC Camera" / "Webcam" USB mode (some Larkfly variants
prompt for the mode when you plug them in; others default to it).

## Code layout for the hybrid design

The webui works in mixed mode too — you can run, e.g., 3 USB cameras
plus 1 WiFi camera (or any combination) in the same UI:

```
python3 webui/app.py \
    --camera 192.168.1.1 --bind 192.168.1.10 \
    --usb /dev/video0 \
    --usb /dev/video2
```

This matters when you want the high-res capability of one specific
WiFi-connected camera plus the convenience of UVC for the rest.

| Worker class             | Connection | Preview source | Recording target |
| ------------------------ | ---------- | -------------- | ---------------- |
| `LarkflyWorker`          | WiFi PTP/IP at IP | RTSP from the camera | Camera SD-card (.MOV) |
| `UvcWorker`              | USB UVC at /dev/videoN | V4L2 video frames | Host disk (.mp4)  |

Both expose the same control interface (`start_recording()`,
`stop_recording()`, `take_photo()`, `get_jpeg()`, `get_status()`), and
the webui's burst/photo/record routes fan out concurrently across
every running worker regardless of kind.

## Open items / future work

1. **Decode the iCatch UVC vendor extension unit.** Its GUID
   (`63610682-5070-49ab-b8cc-b3855e8d221d`) probably matches a known
   iCatch XU schema. If decoded, we'd be able to reach 4K recording
   via USB too — best of both worlds.
2. **Audio capture in `UvcWorker`.** The camera exposes audio
   interfaces; currently we silently drop the audio. ALSA via PyAudio
   or an ffmpeg-piped pipeline would close this gap.
3. **Hotplug detection.** When a new USB camera is plugged in, the
   webui should auto-add a slot rather than requiring restart.
4. **Frame sync between cameras.** Software trigger over USB has ~ms
   jitter, fine for most uses. Hardware-trigger sync (genlock) isn't
   exposed on this camera — accept the ms jitter, or post-align in
   the editor.
5. **STATION mode** (Path A) is still worth re-attempting once we
   have a controlled AP set up first, because it would let us mix
   physically-distant cameras into the rig (over WiFi range). Not
   urgent; revisit after USB path is fully proven across 4 units.
