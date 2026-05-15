# Larkfly A6+ Camera Protocol — Known Facts

Source: prior research, partial reverse-engineering of related iCatch-chipset cameras (Rollei AC 420, iCatch V50). Not yet confirmed against the actual Larkfly A6+ APK — see `findings.md` for verified facts.

## Camera Hardware
- **Brand:** Larkfly A6+
- **Chipset:** iCatch Technology (confirmed by iSmart DV2 app requirement)
- **Companion app:** iSmart DV2 (`com.icatchtek.app.ismartdv2`)

## Network / Connection
- Camera creates a WiFi hotspot. Default password: `1234567890`.
- Client device gets `192.168.1.10` via DHCP.
- Camera IP: `192.168.1.1`.

## Known Interfaces

### 1. RTSP Live Stream — port 554
```
rtsp://192.168.1.1/MJPG?W=720&H=400&Q=50&BR=5000000
```
- Plays in VLC and any RTSP-capable player.
- Playback of saved files: `rtsp://192.168.1.1/VIDEO/<filename>.MOV`.

### 2. FTP File Access — port 21
- Username: `wificam`, password: `wificam` (any credentials may be accepted).
- Filesystem layout:
  ```
  /
  ├── VIDEO/      ← .MOV files
  ├── JPG/        ← .JPG files
  └── SYSTEM~1/
  ```
- Binary mode required for file transfers.

### 3. JSON Control Protocol — TCP port 7878 *(unconfirmed for iCatch — verify in findings.md)*

Newline-delimited JSON messages over a raw TCP socket.

**Session handshake (must be first command):**
```json
SEND: {"msg_id": 257, "token": 0}
RECV: {"rval": 0, "msg_id": 257, "param": 1}
```
The `param` value in the response is the session token. Tag all subsequent messages with it.

**Command reference (msg_id values):**

| Action               | msg_id (hex) | msg_id (dec) |
|----------------------|--------------|--------------|
| Get session token    | 0x101        | 257          |
| Start recording      | 0x201        | 513          |
| Stop recording       | 0x202        | 514          |
| Get recording time   | 0x203        | 515          |
| Take photo           | 0x301        | 769          |
| Get all settings     | 0x003        | 3            |
| Change a setting     | 0x002        | 2            |
| Get battery level    | 0x00D        | 13           |
| Get SD card space    | 0x005        | 5            |
| List directory       | 0x502        | 1282         |
| Get file             | 0x505        | 1285         |
| Get thumb            | 0x401        | 1025         |
| Enter settings mode  | 0x104        | 260          |
| Exit settings mode   | 0x103        | 259          |
| Format SD card       | 0x004        | 4            |

**Return values:**

| Value | Meaning         |
|-------|-----------------|
| 0     | Success         |
| -1    | Failed          |
| -4    | Bad syntax      |
| -14   | Not available   |
| -23   | Not implemented |

**Example — start recording:**
```json
SEND: {"msg_id": 513, "token": 1}
RECV: {"rval": 0, "msg_id": 513}
```

**Example — stop recording:**
```json
SEND: {"msg_id": 514, "token": 1}
RECV: {"rval": 0, "msg_id": 514, "param": "C:\\VIDEO\\20240101_120000AA.MOV"}
```

## Uncertainty / Things to Verify
- **Port 7878 on iCatch:** Well-documented for Ambarella-chip cameras (Xiaomi Yi, ThiEye T5e). At least one forum report says port 7878 didn't respond on an iCatch V50. APK decompile will confirm or refute.
- **Camera IP:** `192.168.1.1` confirmed for Rollei AC 420 (same iCatch hardware family).
- **Additional ports observed in the wild:** UDP 6970/6971 (unknown binary, possibly thumbnails or telemetry), TCP 8787 (receive-only, possibly preview frames), TCP 554 (RTSP, confirmed).

## Sources
- [Rollei AC 420 reverse engineering](https://github.com/clerie/rollei-AC-420) — same iCatch hardware family.
- [iCatch V50 Playground](https://github.com/Linouth/iCatch-V50-Playground) — firmware/debug notes.
- [GoPrawn forum thread](https://www.goprawn.com/forum/ambarella-cams/4867-http-api-thieye-t5e) — Ambarella JSON protocol on port 7878, may apply to iCatch.
