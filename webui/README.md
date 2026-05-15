# webui — multi-camera Larkfly Flask controller

Slot-based architecture (one worker thread per camera, MJPEG previews
streamed to the browser, fan-out control endpoints) targeting PTP-IP
WiFi cameras and UVC USB cameras in the same UI.

## Quick start

```bash
# Single camera at the default 192.168.1.1, using 192.168.1.10 as the
# local source IP (matches the USB dongle setup documented in
# docs/findings.md).
python3 webui/app.py

# Open http://127.0.0.1:5000/
```

For multiple cameras (once you've put them in WiFi STATION mode joined
to a shared AP):

```bash
python3 webui/app.py \
    --camera 192.168.50.11 \
    --camera 192.168.50.12 \
    --camera 192.168.50.13 \
    --camera 192.168.50.14 \
    --bind ""    # if cameras are on separate IPs, no per-IP routing needed
```

## What you get

- A grid of live MJPEG previews (one per camera), pulled from each
  camera's RTSP `/MJPG?W=720&H=400&Q=50&BR=5000000` stream at ~30 fps.
- A control bar at the top: **Photo**, **Record / Stop**, and three
  **Burst** buttons (1s / 3s / 5s).
- Per-camera status: model, firmware, current mode, fps, recording
  indicator.
- A burst-progress bar across the bottom while a synchronized
  recording is in flight.

## API

| Endpoint                   | Method | Notes                                               |
| -------------------------- | ------ | --------------------------------------------------- |
| `/`                        | GET    | UI                                                  |
| `/video_feed/<slot>`       | GET    | MJPEG multipart preview                             |
| `/api/status`              | GET    | All slots + burst state                             |
| `/api/capture`             | POST   | InitiateCapture on every RUNNING worker             |
| `/api/record/start`        | POST   | Start recording on every RUNNING worker             |
| `/api/record/stop`         | POST   | Stop recording on every RUNNING worker              |
| `/api/burst`               | POST   | `{"duration": N}` — start, auto-stop after N sec    |

All control APIs fan out concurrently across slots (threaded), so a
4-camera burst start hits all four cameras within ~ms of each other.

## What's working / what's not

**Working:** preview at ~30 fps, video recording (via D604 mode toggle —
NOT the PTP InitiateOpenCapture op), burst recording with auto-stop,
proper cleanup on disconnect.

**Not working yet:** taking a photo via PTP. The op succeeds at the
protocol level but no JPG appears on the SD card. See `docs/findings.md`
for the trail. Workaround: use the camera's physical shutter button.

**Not implemented:** file browser / gallery (the parent webcam project
has one; we don't yet). Files on the SD card are accessible via FTP at
`ftp://wificam:wificam@<camera-ip>/JPG/` and `/VIDEO/`.

## Architecture

```
webui/app.py             Flask app + routes
webui/worker.py          LarkflyWorker (per-camera background thread)
webui/templates/         HTML
```

Each `LarkflyWorker`:
- Owns a `larkfly.Camera` for PTP control on the command channel.
- Owns an `cv2.VideoCapture` for the RTSP preview frames.
- Holds the latest JPEG-encoded preview frame behind a lock; the Flask
  multipart endpoint pulls from it at up to 15 fps.
- Serializes PTP commands with `_cmd_lock` so the Flask handler thread
  doesn't collide with the RTSP loop.

The shared-PTP-session-state quirk (camera persists session across TCP
disconnections — second OpenSession returns DeviceBusy) is handled in
`larkfly.Camera.connect()` already; nothing extra needed here.
