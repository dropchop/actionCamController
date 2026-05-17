# Larkfly A6+ — current state of knowledge

Concise reference for what's known about this camera. The full
chronological investigation that led to these findings — including
the dead ends — is preserved in `archive/investigation-log.md`.

## Camera identity

| Field | Value |
| --- | --- |
| Marketing name | Larkfly A6+ |
| iCatch internal product code | **`V11`** (from `ProductName` property 0x501E) |
| Firmware version | **`20251206`** (from `FwVersion` property 0x501F) |
| WiFi default | SSID `ActionCam_<MAC-suffix>`, WPA2-PSK `1234567890` |
| Default camera IP (AP mode) | `192.168.1.1` |
| Sensor / capabilities | 9216×5184 (~48 MP) photo; 3840×2160@60 video; 62.5 GB SD |

## Network surface

| Port  | Proto | Service                  | Auth                     |
| ----- | ----- | ------------------------ | ------------------------ |
| 15740 | TCP   | **PTP/IP control**       | none after WiFi join     |
| 21    | TCP   | FTP file access          | `wificam` / `wificam`    |
| 554   | TCP   | RTSP live preview        | none                     |

FTP exposes only `/JPG` and `/VIDEO`. The system area (where the
firmware's `G:\SPHOST.BRN` config file lives) is gated off.

## How the PTP/IP protocol works on this camera

It IS standard PIMA 15740-2 PTP/IP — but iCatch's implementation has
**four** quirks that break naïve spec-conforming clients:

1. **No length-prefix on the initiator name in `InitCmdReq`.** The PIMA
   spec wants a `PTP-string` (1-byte char count + UTF-16LE chars + null).
   iCatch wants the chars directly, null-terminated, with no length byte.
2. **The camera whitelists the initiator name.** Only `"localhost"` (the
   libptp2 default) or the empty string are accepted. Anything else →
   `InitFail reason=3`.
3. **PTP-IP packet type `12` is `EndData` (not `Cancel`).** The PTP-IP
   supplement has two interpretations in the wild; iCatch + libgphoto2
   follow this one. A client that has `Cancel=12 / EndData=11` will
   silently drop the data phase of every operation.
4. **`SendObjectInfo.Filename` requires a 4-byte alignment header after
   the length byte.** Standard PIMA PTP STRING is `[u8 length] + [N × u16
   UTF-16LE chars]`. The iCatch ObjectInfo parser instead expects
   `[u8 length] + [4 bytes of padding] + [N × u16 chars]`. Without the
   padding, every uploaded filename loses its first 2 characters:
   "SPHOST.BRN" → "OST.BRN" (= never triggers the bootloader FW UPDATE
   menu); "sta.conf" → "a.conf"; "_BACKDOOR.CONF" → "ACKDOOR.CONF".
   Characterized in `tools/ptp_string_quirk.py`. **Quirk is specific to
   the Filename field** — `SetDevicePropValue` for STRING properties and
   all outgoing PTP strings parse correctly per spec. Helper:
   `larkfly.protocol.encode_ptp_string_icatch_objinfo()`.

All four are handled in `larkfly/protocol.py`.

The camera also persists session state across TCP disconnections —
issuing `OpenSession` again from a fresh socket returns `DeviceBusy
(0x201E)` if a prior session never sent `CloseSession`. `larkfly.Camera`
auto-recovers by sending `CloseSession` then re-trying `OpenSession`.

## Operations / events / properties

The camera advertises (`GetDeviceInfo`):

- **28 PTP operations** — 20 standard + 8 vendor (`0x9601`, `0x9602`,
  `0x9614`, `0x9801`, `0x9802`, `0x9803`, `0x9805`, `0x9812`).
- **9 events** — 8 standard + `0xC601` vendor.
- **56 device properties** — 21 standard + 35 vendor in the 0xD2xx-
  0xD8xx ranges.
- **Capture formats**: `0x3801` (EXIF/JPEG).
- **Image formats**: standard 0x3000-0x300D + vendor `0xB802`, `0xB982`
  (MP4 video).

The full enumerated catalog (with descriptors, allowed values, current
values) is in `analyses/data/properties.json`; live-value walk in
`analyses/data/all_walk.json`.

**Write behaviour** (from `tools/prop_write_probe.py`):

- **35 properties are genuinely RW.** Examples: `0x500F` ISO speed,
  `0x5010` EV compensation (`-2000..+2000`), `0x5003` still resolution,
  `0xD605` video mode, `0xD723` mode-with-sentinels, `0x501A` sleep timer.
- **3 properties are "fake-RW":** `0xD75F`, `0xD7FC`, `0xD7FF` — the
  descriptor says writable boolean (`enum [0,1]`, currently `=1`) but
  `SetDevicePropValue` returns `rc=0x2001 OK` while the value silently
  doesn't change. Verified at raw PTP level. Look like
  factory/debug/service toggles gated behind an unknown unlock; 13
  primer attempts (vendor opcodes, magic strings in `0xD406`, sentinel
  modes in `0xD723`, SendObject of 8 magic filenames) all failed to
  unlock them. See `docs/dev-console-hunt.md`.
- **3 properties error on query**: `0x500A`, `0x500C`, `0xD83F` return
  `rc=0x2002 General_Error` despite being in `properties_supported`.
- **Verify handshake doesn't apply**: `0xD617` (the EncData hidden
  property reversed from libcontrol.so) is **not in this firmware's
  supported list**. Larkfly stripped it.
- **`larkfly` parser caveat**: PropDesc.current_value parsing has a
  bleed bug for STRING-type properties — the actual value via
  `GetDevicePropValue` is authoritative.

### PTP file-upload channel (`SendObject`) confirmed

`SendObjectInfo (0x100C)` + `SendObject (0x100D)` accept arbitrary file
uploads via PTP/IP and persist them to the SD card root with
sequential handles. This bypasses the FTP chroot. **Caution:**
uploading a file named `SPHOST.BRN` triggers the bootloader's
firmware-update menu on next boot; always `DeleteObject` after testing.
Tool: `tools/sendobject_unlock.py`.

### Vendor opcodes — what each is for

| Opcode | Inferred role | How we know |
| --- | --- | --- |
| `0x9601` | **Polling / heartbeat** | iSmart DV2 calls it ~1×/sec with identical params `(0xD001, 0xFFFFFFFF, 0)` — 223/224 calls in the captured session. |
| `0x9614` | **Bulk PropDesc reader** | Returns 12 prop descriptors in one round-trip, plus a stub for `0x500A FocusMode`. See `analyses/decode_9614.py`. |
| `0x9805` | **Bulk current-values dump** | Returns 1388 B of compact "property snapshot" records (different format from `0x9614`). Partially decoded; raw data at `analyses/data/op_9805_response.bin`. |
| `0x9602` | Object-handle lookup, returns nothing useful in this firmware. **Wedges the PTP service when called with first param = 0.** | `tools/ptp_vendor_probe.py` matrix. |
| `0x9801` | SDK stub. Returns `0xA802` for every input. | Same. |
| `0x9802`, `0x9812` | SDK stubs with **delayed-crash bug** — respond cleanly then take the PTP service down ~ms later. Power-cycle required. | Same. |
| `0x9803` | Dual-mode lookup (property code if input ≤ 0x10000, else object handle). Returns proper error codes but no live data in this firmware. | Same. |

The full sweep is documented in `docs/ptp-vendor.md`.

## Recording / capture paradigm

The camera does NOT use the standard PTP `InitiateOpenCapture` / `TerminateOpenCapture`
operations for video, even though they're in the supported list.
Instead, **video recording is gated by writing property `0xD604`** (the
camera operating-mode register).

| `D604` value | Meaning | Behavior |
| --- | --- | --- |
| 1 | `VIDEO_OFF` (idle) | default state |
| 3 | `CAMERA` | photo / still-capture mode |
| 17 | `VIDEO_ON` | **actively recording video to `/VIDEO`** |
| 4, 5, 6, 9, 10 | various | unverified |

So a recording session is:

```python
cam.set_prop_value(0xD604, 17, datatype=DT_UINT16)  # start
time.sleep(...)
cam.set_prop_value(0xD604, 1, datatype=DT_UINT16)   # stop
```

This produces a real `.MOV` file in `/VIDEO/` on the SD card.

**Photo capture via PTP is unresolved.** `InitiateCapture` (`0x100C`)
returns OK and a new object handle, but **no JPG file ever appears on the
SD card** regardless of mode (tried 2, 3, 5, 6, 9, 10). The physical
shutter button works fine. The "maybe one of the vendor opcodes is the
real photo trigger" theory has now been **closed**: the exhaustive
sweep in `docs/ptp-vendor.md` shows none of the five previously-unknown
ops accept a capture-like parameter — three are SDK stubs, two are
empty lookups. Photo capture via the network is currently a dead end.

## Multi-camera / STATION-mode situation

The camera supports a `STATION` mode (joining an external WiFi AP
instead of running its own — see `CameraNetworkMode.STATION = 0` in the
Java SDK), and the SDK contains the function (`simpleConfig`) that
pushes credentials. **But:**

- **iSmart DV2 does NOT expose `simpleConfig` in its UI.** The function
  is dormant — no UI button calls it. Capturing the app cannot tell us
  the wire format because nothing triggers it.
- **`simpleConfig` is NOT a PTP vendor opcode.** Binary RE of
  `libcontrol.so` shows it spawns pthread workers that send **Realtek
  SmartConfig UDP-broadcast packets** (channel-hopping, AES-encrypted,
  multicast). It's an entirely separate protocol from PTP/IP.

What we extracted from `libcontrol.so`:

| Constant | Value |
| --- | --- |
| **Default AES-128 key** | `b"echo1234echo1234"` (first 16 bytes of `encrypt_lenbase` / `encrypt_textbase` tables) |
| **Multicast destination** | `234.168.168.168` |
| **UDP port** | `10000` (likely) |
| Encoding tables | `encrypt_lenbase` / `encrypt_textbase` — both 121 bytes of `"echo1234"`-repeated content, used to map encrypted-credential bytes to packet attributes |

What's still missing for a working SimpleConfig pusher: the exact
mapping from credential bytes to UDP packet length+content. That needs
either more binary RE or a Realtek SDK reference port.

The camera's own default WiFi password `1234567890` appears as a
substring of these same constants — strongly suggests iCatch hardcoded
one string for both uses (WiFi PSK default AND SmartConfig AES default).

## USB UVC mode

The camera presents as a standard UVC class device when plugged in via
a data USB cable (`ID 2aad:6373 Sport Cam`). It exposes:

- 1920×1080 @ 30 fps in both H.264 and MJPEG
- Standard UVC controls (auto-exposure, focus, white-balance)
- Audio in/out (USB interfaces 2,3)
- A vendor extension unit (GUID `63610682-5070-49ab-b8cc-b3855e8d221d`,
  32 control bits) — not decoded

**Important caveat:** in UVC mode the camera doesn't write to its own SD
card. The host receives the video stream; the camera doesn't dual-record.
For uses that need camera-side high-res recording, USB mode is not a
substitute for PTP/IP control.

## What's in this repo

| Path | Purpose |
| --- | --- |
| `larkfly/` | Python client library — protocol framing, codecs, high-level `Camera` class |
| `webui/` | Flask multi-camera controller (preview + burst recording) |
| `tools/` | Operational diagnostics (`ptpip_probe.py`, `decrypt_pcap.py`, monitor-capture scripts) |
| `analyses/` | One-shot RE scripts that produced findings; their outputs are in `analyses/data/` |
| `tests/` | Unit tests for the protocol codec (no hardware required) |
| `examples/quickstart.py` | Library usage demo |
| `docs/findings.md` | This file — current state of knowledge |
| `docs/architecture.md` | Multi-camera design + tradeoffs |
| `docs/archive/` | Stale-but-preserved earlier docs and the chronological investigation log |
| `apk-analysis/` | APK + decompile artifacts (gitignored — large + copyrighted) |
