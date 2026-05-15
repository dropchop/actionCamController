# iSmart DV2 APK — Protocol Findings

**Subject:** `com.icatchtek.app.ismartdv2` (iSmart DV2), v1.x — APK pulled from Google Drive 2026-05-15
**Camera:** Larkfly A6+ (iCatch chipset)
**Tools:** jadx 1.5.5, apktool 3.0.2, OpenJDK Temurin 21
**Method:** Static analysis (Java sources + native lib strings)

---

## TL;DR — The prior hypothesis was wrong

The "JSON-over-TCP on port 7878 with `msg_id: 0x101` handshake" protocol from the project notes is **not** what this camera uses. That protocol is Ambarella-specific (used by Xiaomi Yi, ThiEye T5e). The Larkfly A6+ runs iCatch firmware and speaks a different protocol.

**The Larkfly A6+ control protocol is `PTP/IP` (PIMA 15740-2000 over TCP) on port `15740`, with iCatch vendor-specific extensions.**

The iSmart DV2 app calls into a closed-source iCatch SDK (`libcontrol.so` + `libreliant.so`) that bundles a fork of the GPL `libptp2` library to drive the camera. The Java code is a thin JNI shim — no protocol logic is implemented in Java.

---

## Network surface

| Port      | Proto  | Service          | Auth                          | Status                                       |
| --------- | ------ | ---------------- | ----------------------------- | -------------------------------------------- |
| **15740** | TCP    | **PTP/IP control** | none (open after WiFi join)   | **Confirmed** — `htons(15740)` in libcontrol.so + libreliant.so, plus dozens of `ptp_ptpip_*` symbols. Two sockets are opened (command + event). |
| 554       | TCP    | RTSP live stream | none                          | Confirmed — RTSP MJPEG stream, as documented in `docs/protocol.md`. |
| 21        | TCP    | FTP file access  | `wificam` / `wificam`         | Confirmed — string `wificam` and `__connect_to_icatch_cam_using_ftp` in libcontrol.so. The SDK also uses FTP internally (`ftplib` is statically linked). |
| broadcast | UDP    | Device discovery | none                          | Likely — `broadcast to INADDR_BROADCAST` and `multicast_receive` strings, plus a `DeviceScan` class. Response payload is JSON: `{"id":"...","pwd":"...","ip":"...","mac":"..."}`. Port not yet pinned down (would need dynamic capture). |

### What this means for "msg_id 0x101" port 7878

- Searched all native libs and all Java/smali for the strings `msg_id`, `MSG_ID`, `7878`, `8787` — **zero hits.**
- Searched for `htons(7878)` and `htons(8787)` as byte patterns — no matching constants in libcontrol.so.
- Conclusion: this camera does not speak that protocol. Don't waste time on it.

---

## Protocol architecture

### Layered SDK

```
┌─────────────────────────────────────────────────────────────┐
│  iSmart DV2 app (Kotlin/Java)                                │
│  - com.icatch.mobilecam.*                                    │
│  - Uses `ICatchCameraSession` (high-level API)               │
└──────────────────┬──────────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────────┐
│  iCatch Java SDK — JNI shim                                  │
│  - com.icatchtek.control.customer.* (public interface)       │
│  - com.icatchtek.control.core.jni.JCamera* (native methods)  │
│  - com.icatchtek.reliant.customer.transport.* (transports)   │
└──────────────────┬──────────────────────────────────────────┘
                   │ JNI
┌──────────────────▼──────────────────────────────────────────┐
│  Native libraries (closed source, ARM64 + ARMv7)             │
│  - libcontrol.so   ─ camera commands, PTP-IP plumbing, FTP   │
│  - libreliant.so   ─ transport abstractions (INET / UVC / …) │
│  - libpanorama_vr.so ─ image processing (16 MB; not protocol)│
│  - libdepth_net_transport.so ─ unrelated ToF sensor proto    │
│  - libusb_transport.so ─ libusb-based USB tethering          │
│  - libbugly*.so ─ Tencent Bugly crash reporting              │
└──────────────────┬──────────────────────────────────────────┘
                   │ TCP/UDP
┌──────────────────▼──────────────────────────────────────────┐
│  Camera (192.168.1.1)                                        │
└──────────────────────────────────────────────────────────────┘
```

### Transports the SDK supports

From `com.icatchtek.reliant.customer.transport.*`:

- `ICatchINETTransport(ipAddress)` — **WiFi/network, used by iSmart DV2**
- `ICatchUVCBulkTransport` — USB-attached UVC camera, bulk mode
- `ICatchUVCIsoTransport` — USB-attached UVC camera, isochronous mode
- `ICatchUsbScsiTransport` — USB Mass Storage (older iCatch firmware)
- `ICatchDepthNetTransport` — internal, for a Time-of-Flight depth stream (not relevant to this camera)

### Session creation as called by iSmart DV2

`apk-analysis/jadx-output/sources/com/icatch/mobilecam/MyCamera/LocalSession.java:60-69`:

```java
public boolean prepareCommandSession() {
    this.commandSession = new CommandSession();
    boolean zPrepareSession = this.commandSession.prepareSession(
        new ICatchINETTransport("192.168.1.1"), false);  // <-- enablePTPIP = false
    ...
}
```

The `false` flag is `enablePTPIP`. Inside `CommandSession.prepareSession`:

```java
if (enablePTPIP) {
    ICatchCameraSession.getCameraConfig(transport).enablePTPIP();
} else {
    ICatchCameraSession.getCameraConfig(transport).disablePTPIP();
}
```

**This is not "PTP/IP vs something else."** The PTP-IP protocol is always used at the wire level (`setupPTPIPConnection` is unconditional inside the C++ SDK; `htons(15740)` is the only port constant). The `enablePTPIP` Java flag toggles a higher-level SDK behavior — most likely how the InitCommand/InitEvent handshake is sequenced, or whether auto-reconnect on socket loss is enabled (there is a separate `enablePTPReconnection` config too). The exact semantic would need confirmation via dynamic analysis, but it is **not** a protocol selector.

### PTP/IP confirmation — strings in libcontrol.so

```
Libptp2Client                  (real PTP-2 client, GPL libptp2)
DummyPTPClient                 (fallback / no-op client)
ptp_opensession
ptp_ptpip_connect
ptp_ptpip_sendreq() len = %d
ptp_ptpip_senddata() len = %d
ptp_ptpip_close, cmdfd: %d
ptp_ptpip_close, evtfd: %d        ← dual sockets (command + event)
reading PTPIP hdr
reading PTPIP data
ptpip download file(handle) %s
Vendor Extension Description: %s  ← classic PTP probe
StorageDescription: %s            ← classic PTP probe
connect, host: %s
connect, port(default): %d        ← logs the port at connect time
```

The presence of `Libptp2Client` plus `cmdfd`/`evtfd` is the smoking gun: this is textbook PTP/IP — two TCP sockets to port 15740, one for command/data, one for events.

---

## Vendor PTP opcodes / property codes

Java type tables expose the property and event IDs the SDK uses. These are PTP property codes (16-bit, hex notation).

From `apk-analysis/jadx-output/sources/com/icatchtek/control/customer/type/ICatchCamProperty.java` — properties operated via PTP `GetDevicePropValue` (0x1015) / `SetDevicePropValue` (0x1016):

| Java constant                          | Dec   | Hex      | PTP class        |
| -------------------------------------- | ----- | -------- | ---------------- |
| `ICH_CAM_CAP_BATTERY_LEVEL`            | 20481 | `0x5001` | Standard         |
| `ICH_CAM_CAP_IMAGE_SIZE`               | 20483 | `0x5003` | Standard         |
| `ICH_CAM_CAP_WHITE_BALANCE`            | 20485 | `0x5005` | Standard         |
| `ICH_CAM_CAP_CAPTURE_DELAY`            | 20498 | `0x5012` | Standard         |
| `ICH_CAM_CAP_DIGITAL_ZOOM`             | 20502 | `0x5016` | Standard         |
| `ICH_CAM_CAP_BURST_NUMBER`             | 20504 | `0x5018` | Standard         |
| `ICH_CAM_CAP_TIMELAPSE_STILL`          | 20507 | `0x501B` | Standard         |
| `ICH_CAM_CAP_PRODUCT_NAME`             | 20510 | `0x501E` | Standard         |
| `ICH_CAM_CAP_FW_VERSION`               | 20511 | `0x501F` | Standard         |
| `ICH_CAM_CAP_VIDEO_SIZE`               | 54789 | `0xD605` | **Vendor** (iCatch) |
| `ICH_CAM_CAP_LIGHT_FREQUENCY`          | 54790 | `0xD606` | **Vendor**       |
| `ICH_CAM_CAP_DATE_STAMP`               | 54791 | `0xD607` | **Vendor**       |
| `ICH_CAM_CAP_TIMELAPSE_VIDEO`          | 54801 | `0xD611` | **Vendor**       |
| `ICH_CAM_CAP_UPSIDE_DOWN`              | 54804 | `0xD614` | **Vendor**       |
| `ICH_CAM_CAP_SLOW_MOTION`              | 54805 | `0xD615` | **Vendor**       |
| `ICH_CAM_CAP_GET_NUMBER_OF_SENSORS`    | 55083 | `0xD72B` | **Vendor**       |
| `ICH_CAM_CAP_GET_CAMERA_CAPABILITIES`  | 55084 | `0xD72C` | **Vendor**       |
| `ICH_CAM_CAP_MOVIE_REC`                | 58884 | `0xE604` | **Vendor** (PTP operation, not property) |

Note: `MOVIE_REC = 0xE604` is in the vendor PTP **operation code** range (0xE000-0xFFFF, vs. property-code range 0xD000-0xDFFF), so it's likely an iCatch-defined PTP **operation** for starting/stopping recording, not a property.

From `ICatchCamMode.java`:

| Constant                          | Dec | Hex      |
| --------------------------------- | --- | -------- |
| `ICH_CAM_MODE_VIDEO_OFF`          | 1   | `0x0001` |
| `ICH_CAM_MODE_SHARED`             | 2   | `0x0002` |
| `ICH_CAM_MODE_CAMERA`             | 3   | `0x0003` |
| `ICH_CAM_MODE_IDLE`               | 4   | `0x0004` |
| `ICH_CAM_MODE_TIMELAPSE_STILL`    | 7   | `0x0007` |
| `ICH_CAM_MODE_TIMELAPSE_VIDEO`    | 8   | `0x0008` |
| `ICH_CAM_MODE_VIDEO_ON`           | 17  | `0x0011` |
| `ICH_CAM_MODE_VIDEO`              | 42  | `0x002A` |
| `ICH_CAM_MODE_TIMELAPSE`          | 43  | `0x002B` |

From `ICatchCamEventID.java` — PTP event codes the SDK listens for:

| Constant                                  | Dec | Hex      | Notes                       |
| ----------------------------------------- | --- | -------- | --------------------------- |
| `ICH_CAM_EVENT_FILE_ADDED`                | 1   | `0x0001` | New file on SD              |
| `ICH_CAM_EVENT_FILE_REMOVED`              | 2   | `0x0002` |                             |
| `ICH_CAM_EVENT_FILE_INFO_CHANGED`         | 3   | `0x0003` |                             |
| `ICH_CAM_EVENT_SDCARD_FULL`               | 17  | `0x0011` |                             |
| `ICH_CAM_EVENT_SDCARD_ERROR`              | 18  | `0x0012` |                             |
| `ICH_CAM_EVENT_SDCARD_REMOVED`            | 19  | `0x0013` |                             |
| `ICH_CAM_EVENT_SDCARD_IN`                 | 20  | `0x0014` |                             |
| `ICH_CAM_EVENT_VIDEO_ON`                  | 33  | `0x0021` | Recording started           |
| `ICH_CAM_EVENT_VIDEO_OFF`                 | 34  | `0x0022` | Recording stopped           |
| `ICH_CAM_EVENT_CAPTURE_COMPLETE`          | 35  | `0x0023` | Photo taken                 |
| `ICH_CAM_EVENT_BATTERY_LEVEL_CHANGED`     | 36  | `0x0024` |                             |
| `ICH_CAM_EVENT_DEVICE_INFO_CHANGED`       | 49  | `0x0031` |                             |
| `ICH_CAM_EVENT_*_PROP_CHANGED`            | 50-55 |        | One per property            |
| `ICH_CAM_EVENT_CONNECTION_DISCONNECTED`   | 74  | `0x004A` |                             |
| `ICH_CAM_EVENT_VIDREC_TIME_CHANGE`        | 101 | `0x0065` | Tick every recording second |
| `ICH_CAM_EVENT_VIDEO_THUMB_READY`         | 104 | `0x0068` |                             |

These are *Java enum identifiers* mapped to PTP event codes. The wire-level codes are likely the hex values shown above, but the mapping may go through a translation table inside libcontrol.so. To get the exact wire opcodes, dynamic analysis (Frida hook on `ptp_ptpip_sendreq`) is the fastest route.

---

## Discovery

`libcontrol.so` contains a `DeviceScan` class with `startDeviceScan` / `stopDeviceScan` methods exposed through `ICatchCameraAssist` and exported as JNI as `Java_com_icatchtek_control_core_jni_JCameraAssist_*`. Strings:

```
DeviceScan::deviceScan()
broadcast to INADDR_BROADCAST
[%s, %d]Received %d bytes from %s: multicast_receive
{"id":"%s","pwd":"%s","ip":"%s","mac":"%s"}
```

So the discovery flow is:
1. Client sends a UDP broadcast (port TBD).
2. Each camera on the subnet replies with a JSON blob containing its `id`, `pwd`, `ip`, `mac`.
3. Client picks one and proceeds to TCP 15740.

For our use case (single camera on its own AP, well-known IP `192.168.1.1`), discovery can be skipped entirely.

---

## What's *not* in the protocol but is in the SDK

- **Bluetooth pairing** — there's a full `com.icatchtek.bluetooth.*` package and `libBugly.so`. Used in BT-enabled iCatch cameras to bootstrap WiFi credentials. The Larkfly A6+ may or may not implement this; we have no hardware confirmation. Not relevant to a Linux WiFi-only client.
- **UVC USB tethering** — the SDK supports treating an iCatch camera plugged in over USB as a UVC source. Not relevant to this project.
- **Panorama / VR processing** — `libpanorama_vr.so` (16 MB) does client-side stitching for 360 cameras. The Larkfly A6+ is a regular action cam, not panorama, so this is dead weight on its code path.
- **Tencent Bugly** — crash analytics. Strip from any reimplementation.

---

## Implications for the Python client

### Easy path: use the libgphoto2 PTP/IP backend

`libgphoto2` (and its Python binding `python-gphoto2`) already speaks PTP/IP. The Larkfly A6+ should be reachable as:

```python
import gphoto2 as gp
camera = gp.Camera()
port_info_list = gp.PortInfoList()
port_info_list.load()
idx = port_info_list.lookup_path('ptpip:192.168.1.1')
camera.set_port_info(port_info_list[idx])
camera.init()
# camera.capture(...), camera.trigger_capture(), etc.
```

Standard PTP operations (GetDeviceInfo, OpenSession, GetDevicePropValue/SetDevicePropValue, GetStorageIDs, GetObjectHandles, GetObject) should Just Work.

What **won't** work via libgphoto2 alone: any operation that uses the iCatch vendor opcodes (the 0xD6xx / 0xE6xx range), most importantly:
- `ICH_CAM_CAP_MOVIE_REC` (0xE604) — start/stop recording
- `ICH_CAM_CAP_VIDEO_SIZE` (0xD605) — recording resolution
- The vendor event codes for recording state

For these, we'll need to send raw vendor PTP operations through libgphoto2's `gp_camera_send_data` or a direct PTP/IP socket. The opcode values are in the tables above. Their parameter formats are not documented and would need to be discovered by either:
1. **Frida hooking** the `ptp_ptpip_sendreq` function in libcontrol.so on a running Android device while exercising each feature in iSmart DV2.
2. **Wireshark capture** of iSmart DV2 talking to the camera over WiFi — PTP/IP is unencrypted plaintext, so a raw pcap gives the full byte-level protocol.

The Wireshark route is the cheaper one: it requires only a phone with iSmart DV2 installed and a packet capture (e.g., `tcpdump` on the phone, or routing the phone through a Linux laptop running Wireshark). PTP/IP packets have a clear 4-byte length + 4-byte type header so they're easy to parse.

### Hard path: hand-roll a PTP/IP client in Python

The PIMA 15740-2000 spec is available; PTP/IP is described in the same family of docs and is well-understood (gPhoto2's `libgphoto2/camlibs/ptp2/ptpip.c` is a clean reference implementation, ~500 lines).

Wire format:

```
PTP/IP packet:
  +0  uint32 LE  length (including this header)
  +4  uint32 LE  packet type (1=InitCommand, 2=InitCommandAck, 3=InitEvent,
                              4=InitEventAck, 5=InitFail, 6=Cmd, 7=Data,
                              8=Cancel, 9=DataStart, 10=DataContinue, 11=DataEnd,
                              12=EventInProgress, 13=ProbeRequest, 14=ProbeResponse)
  +8  payload (operation code, transaction ID, params depending on type)
```

The command-channel and event-channel are two separate TCP connections to the same port (15740).

For a quick spike, even a 200-line Python script using `socket` would let us reach `GetDeviceInfo` and confirm the camera responds with PTP — that's the smallest possible test of the hypothesis from this document.

### Recommended next step

Build a small Python "is this really PTP/IP?" probe before committing to the full client architecture:

1. Connect to camera WiFi, confirm `192.168.1.1` pings.
2. Open a TCP socket to `192.168.1.1:15740`.
3. Send a PTP/IP `InitCommand` packet (type=1) with a random GUID and the string "Linux Test Client".
4. If the camera replies with `InitCommandAck` (type=2), the hypothesis in this document is confirmed and we know exactly what we're building against. Total effort: ~30 lines of Python.

If the InitCommand probe succeeds, proceed with the libgphoto2 route for the bulk of the client and only reach for the vendor opcodes once we're capturing movies.

---

## Methodology notes (for reproducibility)

- The APK signature is `META-INF/GOOGPLAY.{SF,RSA}` — this is a Play Store-signed copy, not a sideloaded build.
- jadx 1.5.5 decompiled cleanly with no errors; ~17,000 Java files (mostly third-party deps: Retrofit, OkHttp, Gson, Facebook SDK, Tencent Bugly, AndroidX).
- apktool 3.0.2 produced a clean AndroidManifest.xml and smali dump.
- No `binutils` was available on the analysis host; `apk-analysis/pystrings.py` was used as a `strings` replacement.
- Searched ports as both BE and LE 16-bit constants in raw binaries (see `pystrings.py` companion script if needed). The `htons(15740)` BE pattern `\x3d\x7c` occurred exactly once each in `libcontrol.so` and `libreliant.so` — the signature of a single hardcoded port constant.

All artifacts are under `apk-analysis/` (gitignored).

---

# Live-hardware investigation log — 2026-05-15

First contact with a real Larkfly A6+ camera. Ran the probes from `probes/`.
Confirmed several hypotheses from the static analysis, ruled out several
others, and hit a hard blocker that needs more research before we can
proceed to building a client. **Project is currently paused at this point.**

## Hardware / network setup that worked

The probing required the laptop to talk to the camera over WiFi *without*
losing internet over Cool_Guy WiFi on `wlp1s0`. The final setup:

- USB WiFi dongle: Realtek RTL8812AU (`0bda:8812`), surfaces as
  `wlx00c0caac3206`. Driver: aircrack-ng fork of `rtl8812au` built via DKMS;
  the Ubuntu archive's `rtl8812au-dkms` (2014 vintage) does not build on
  kernel 6.8. Repair script: `/tmp/install_rtl8812au.sh`.
- Dongle joined `ActionCam_1A80DF` (WPA2-PSK, password `1234567890`,
  channel 1). Got `192.168.1.10/24` via DHCP. Camera ARP'd at `192.168.1.1`,
  MAC `00:E0:4C:1A:80:DF`.
- Both interfaces wound up on `192.168.1.0/24` (Cool_Guy gave the laptop
  `192.168.1.185` from a different physical LAN that happens to share the
  same RFC1918 prefix). Resolved by adding a `/32` host route to the camera
  via the dongle, saved into the NM connection profile so it survives
  re-DHCP:
  ```
  sudo nmcli connection modify ActionCam_1A80DF +ipv4.routes "192.168.1.1/32 0.0.0.0"
  ```
- The probe got `--bind SOURCE_IP` (`probes/ptpip_probe.py`) to force the
  TCP socket's source IP. Without that, Linux silently routes via the
  higher-priority interface and returns EHOSTUNREACH because the bound
  source IP doesn't match the chosen route's interface.

## Confirmed by live test

- **TCP 15740 is open on the camera.** Connect succeeds in ~2 ms.
- **TCP 21 (FTP) is open** — FTP banner: `220 Welcomd to iCatch FTP Server`.
  Login `wificam` / `wificam` succeeds; `PWD` returns `/`. The camera is
  alive and the docs/protocol.md FTP path works exactly as documented.
- **TCP 554 (RTSP) is open** — not exercised but reachable.
- **No other interesting TCP ports** are open in the range 21–50000
  (scanned: 22, 23, 53, 67, 68, 69, 80, 443, 554, 631, 873, 1234, 2049, 5000,
  6000, 6970, 7000, 7878, 8000, 8080, 8081, 8443, 8554, 8787, 9000, 9999,
  10000, 12345, 30000, 31415, 50000). **Decisively rules out the
  JSON/7878 "Ambarella" protocol** that was in the original project notes —
  this camera does not speak it.
- **UDP discovery on common ports (8787, 9999, 3333, 5353, 1900, 7777,
  8888, 6970, 30000, 8089, 8000, 8001, 8002, 8088) found nothing**. Tried
  empty, `discover\n`, `{"msg":"discover"}`, `{"key":"ICATCHTEK"}`,
  `WHO_IS_THERE`, and `aabbccdd` as payloads to broadcast, subnet broadcast,
  and unicast targets. Zero replies. **The discovery port + payload are
  not in the obvious candidates.**

## The hard blocker

Every PTP/IP `InitCommand` is rejected with `InitFail reason=3`
(packet bytes: `0c 00 00 00 05 00 00 00 03 00 00 00`). And critically —
**the camera returns the exact same InitFail packet to malformed garbage
input** (we sent `type=999` with `XXXX` payload and got the same `reason=3`
back). This proves the camera is not parsing the InitCommand fields at all;
it is rejecting **the first packet on the connection unconditionally**.

What this rules out:

- The GUID we send. (Tried 0x00...00, 0xFF...FF, MAC-prefixed, random.)
- The initiator name. (Tried empty, "Probe", "iCatch", "iSmartDV2",
  "com.icatchtek.app.ismartdv2", and the JSON token
  `{"key":"ICATCHTEK","id":"00000000000000000000"}` that appears verbatim
  in libcontrol.so.)
- The protocol version field. (Tried 0x00000000, 0x00000100, 0x00010000,
  0x00010001, 0x00020000, 0xFFFFFFFF — all rejected identically.)
- "Camera is busy" — iSmart DV2 was not running on any phone during these
  tests (user confirmed force-kill).
- "FTP login prereq" — opening an authenticated FTP session does not change
  the PTP/IP rejection.

## Current leading hypothesis

The camera requires **`CommandSession.startDeviceScan()` to be called
before PTP/IP is unlocked.** Evidence:

- `AddNewCamFragment.java` in the APK has four "add camera" buttons:
  `bt_pair`, `wifi_connect_camera`, `usb_connect_camera`, and
  `wifi_auto_connect`. All four eventually route through
  `CommandSession.startDeviceScan()` (`LaunchPresenter.java:404-405`).
- `libcontrol.so` strings: `broadcast to INADDR_BROADCAST`,
  `[%s, %d]Received %d bytes from %s: multicast_receive`,
  `{"id":"%s","pwd":"%s","ip":"%s","mac":"%s"}`. So discovery is UDP, the
  client broadcasts and reads multicast replies (or the strings name those
  functions misleadingly), and the response is JSON with an `id` field.
- The `id` from the discovery response is plausibly what gets used as the
  PTP/IP initiator GUID (or as input to a GUID-derivation step), since
  libcontrol also has `ptp_nikon_getptpipguid` and `MediaGUID`.
- Until the camera has been "seen" by the SDK's DeviceScan, it likely
  rejects all PTP/IP connections — a classic "discovery establishes trust"
  pattern from embedded device SDKs.

This is not yet proven. The UDP broadcasts we sent across common ports
returned nothing — either the port is exotic, the payload shape matters
(some embedded discoveries reject malformed magic), or the camera only
responds to multicast (not broadcast). We need to either:
- Locate the exact port + payload in `libcontrol.so` (dynamic analysis
  with radare2 / Frida would do it fastest), or
- Capture a real `iSmart DV2` doing its WiFi discovery once.

## What also went wrong with iSmart DV2

The user attempted to validate "does iSmart DV2 work against this camera"
as a control test. It does not work for them:

- The phone refuses to join `ActionCam_1A80DF` over WiFi (rejects
  `1234567890` as "wrong password"), even though our dongle authenticates
  with the same password against the same BSSID. Most likely: phone has a
  stale saved profile with a corrupted password and needs "Forget network"
  → re-add. Not yet attempted.
- iSmart DV2's Bluetooth "Add new camera" path doesn't see the camera at
  all. Either this camera ships without Bluetooth hardware, or BT is off
  and there's a menu/button to enable it that we haven't found.
- Camera was factory-reset during the session; never paired to anything.

## Specific next steps when resuming

1. **Mine `libcontrol.so` for the discovery UDP port and payload format.**
   The lib has `multicast_receive` in its symbol table; nearby code paths
   should reveal the multicast group, port, and request payload. Without
   real `binutils` installed on this host (`apk-analysis/pystrings.py` was
   used as a strings substitute), this likely needs radare2 or ghidra.
2. **Get iSmart DV2 to actually connect once**, then watch it on the wire.
   With the dongle in monitor mode on channel 1, `tcpdump -i wlanXmon -w
   capture.pcap` will capture frames; with the WPA PSK (`1234567890`)
   loaded into Wireshark and a 4-way EAPOL handshake also captured, the
   PTP/IP and discovery traffic can be decrypted. Two prerequisites:
   - Resolve the phone-side WiFi rejection (Forget + re-add the camera AP
     on the phone, then check the actual displayed network in the app).
   - Decide whether to use the dongle for monitor capture (loses our PTP
     access) or get a second dongle / a Linux box with built-in WiFi we
     can put in monitor mode.
3. **Try multicast targets explicitly** before going down the pcap path.
   Candidates: `239.255.255.250` (SSDP), `224.0.0.251` (mDNS), and the
   reverse — listen on `224.0.0.1` and similar groups after sending the
   broadcast. The string "multicast_receive" in libcontrol.so is the
   strongest signal that the response comes via a multicast group.
4. **Try a Bluetooth menu hunt on the camera.** Some iCatch action cams
   have a long-press or button combo to enable BT advertising. If found,
   the BT pairing path in iSmart DV2 might be a one-time activation that
   "primes" PTP/IP and bypasses everything we're trying to do.

## State of the project

- `probes/ptpip_probe.py` works against a real iCatch FTP server and is
  ready when PTP/IP is unlocked. Successfully reaches the camera, sends
  well-formed PTP/IP framing, parses the InitFail response.
- `probes/wifi_provision.py` cannot be tested until PTP/IP is open.
- Camera setup: factory-reset, broadcasting `ActionCam_1A80DF` (WPA2 PSK
  `1234567890`), responds at 192.168.1.1, FTP and RTSP open, PTP/IP gated.
- Host tooling: dongle driver installed, route fixed, all deps present.
  Picking up from here should require only re-joining the camera AP
  (`nmcli connection up ActionCam_1A80DF ifname wlx00c0caac3206`) — no
  re-setup of the workstation needed.

---

# Breakthrough: iCatch PTP/IP wire-format quirks — 2026-05-15 (continued)

Captured the iSmart DV2 ↔ camera traffic in monitor mode and decrypted it
with the WPA2 PSK. The static-analysis hypothesis (PTP/IP on TCP 15740)
was correct — but the camera implements two **non-spec** quirks that
caused our probes to be rejected, and one important spec-interpretation
detail that the original probe had wrong.

## How the capture was done

- Driver: aircrack-ng/rtl8812au fork (the stock Ubuntu `rtl8812au-dkms`
  doesn't build against kernel 6.x); installer at
  `/tmp/install_rtl8812au.sh`.
- Monitor mode + capture scripts: `probes/monitor_capture.sh` (sudo,
  channel 1 on `wlx00c0caac3206`, output `/tmp/larkfly-capture.pcap`)
  and `probes/monitor_restore.sh` to put the dongle back in managed mode.
- WPA2 decryption: `probes/decrypt_pcap.py`. Stdlib + `cryptography` only;
  derives PMK from `PBKDF2-SHA1(PSK="1234567890", SSID="ActionCam_1A80DF",
  iter=4096, len=32)`, then PTK via `PRF-512(PMK, "Pairwise key
  expansion", min(macs)||max(macs)||min(nonces)||max(nonces))`, then AES
  -CCM decrypts each protected data frame. Two non-obvious things:
  - The capture missed EAPOL Message 1, but **M2 carries SNonce and M3
    re-carries ANonce**, so the PTK can still be derived without M1.
  - The Realtek AP's CCMP **AAD-FC mask is `0xC78F`, not the spec's
    `0x078F`** — i.e., it leaves the Protected bit set in AAD. Took ~30
    minutes to find by brute-force; decryption succeeded once that bit
    was set.
- 11,402 of 11,405 protected frames decrypted (99.97%).

## Quirk 1 — non-standard InitCmdReq wire format

PIMA 15740-2 (PTP-IP) says the initiator name in `InitCmdReq` is a
PTP-string: a 1-byte char count followed by UTF-16LE chars including the
null terminator.

iCatch omits the length byte. The wire payload is:

```
length(4) | type=1(4) | GUID(16) | UTF-16LE chars + 0x0000 null | version(4)
```

Verified by inspecting the phone's accepted `InitCmdReq` (frame 455 of
the pcap, 48 bytes total payload):

```
30000000 01000000             ← length=48, type=1
da8e0a4347f7ade14489899e75df421f ← GUID
6c006f006300610 06c0068006f00730074000000  ← "localhost\0" UTF-16LE,
                                              NO length byte before
00000100                       ← version=0x00010000
```

The standard PTP-string format with the leading length byte makes the
camera read the version field 1 byte off, garbage in the version, reject.

## Quirk 2 — initiator-name whitelist

Even with the iCatch wire format, **the camera whitelists the initiator
name**. Empirical results:

| Name                        | Result                  |
| --------------------------- | ----------------------- |
| `"localhost"`               | **Accept**              |
| `""` (empty)                | **Accept**              |
| `"Probe"`                   | InitFail reason=3       |
| `"iSmartDV2"`               | InitFail reason=3       |
| `"com.icatchtek.app.…"`     | InitFail reason=3       |
| `'{"key":"ICATCHTEK",…}'`   | InitFail reason=3       |

`"localhost"` is libptp2/libgphoto2's default initiator name. iSmart DV2
sends it verbatim. Easiest interpretation: the firmware has a hardcoded
`strcmp(name, "localhost") == 0 || name[0] == 0` check.

## Quirk 3 — PTP-IP packet type values (spec ambiguity)

The PTP-IP supplement is one of those specs where implementations disagree
on whether `11` is `Cancel` and `12` is `EndData`, or vice versa.

iCatch (and libgphoto2) follow:
- `11` = Cancel
- `12` = **End Data Packet**

My original probe had them swapped. With the swap, the camera's
`GetDeviceInfo` data phase looked like:

```
StartData(type 9) → EndData(type 12) → OpResp(type 7)
```

…but my parser only matched data on types `{10, 11}`, so the actual
DeviceInfo bytes inside the type-12 packet were silently dropped, and
the probe reported "GetDeviceInfo returned no data" — even though the
camera was sending it. Fixed.

## Spec quirk — CloseSession isn't optional

After a successful `OpenSession`, the camera **persists session state
across TCP connections**. The next `OpenSession` from any TCP socket
returns `DeviceBusy (0x201E)` instead of opening a new one. Our probe
now sends `CloseSession (op 0x1003)` as a recovery step on `DeviceBusy`,
and always cleans up on exit (success or failure paths).

## Confirmed device fingerprint (Larkfly A6+)

After clearing all the above, `ptpip_probe.py` completes the full
handshake. The camera's `DeviceInfo` (with the model strings empty):

```
Manufacturer / Model / DeviceVersion / SerialNumber = '' (all empty)
PTP standard version: 0x0064 = 1.00
Vendor extension ID:  0x00000000  (NOT iCatch's vendor ID; field unused)
Functional mode:      0x0000
```

### Operations supported (28)

Standard PTP (20): `0x1001-0x100f`, `0x1012`, `0x1014`, `0x1015`,
`0x1016`, `0x101b` — i.e., the usual: `GetDeviceInfo`, `OpenSession`,
`CloseSession`, `GetStorageIDs`, `GetStorageInfo`, `GetNumObjects`,
`GetObjectHandles`, `GetObjectInfo`, `GetObject`, `GetThumb`,
`DeleteObject`, `SendObjectInfo`, `SendObject`, `InitiateCapture`,
`FormatStore`, `GetDevicePropDesc`, `GetDevicePropValue`,
`SetDevicePropValue`, `GetPartialObject`.

Vendor (8): `0x9601`, `0x9602`, `0x9812`, `0x9614`, `0x9801`, `0x9802`,
`0x9803`, `0x9805`.

**Important correction:** I had previously assumed `MOVIE_REC =
0xE604` from the Java SDK enum was a vendor PTP **operation**, but the
camera advertises **no** vendor operations in the `0xE000+` range.
Movie recording is implemented by one of the `0x9xxx` vendor ops, not
`0xE604`. The `0xE604` constant in the Java enum is a *property code*
or capability flag, not an operation.

### Events supported (9)

Standard (8): `0x4002` (CancelTransaction), `0x4003` (ObjectAdded),
`0x4004` (ObjectRemoved), `0x4005` (StoreAdded), `0x4006` (StoreRemoved),
`0x4008` (DeviceInfoChanged), `0x4009` (RequestObjectTransfer),
`0x400d` (StoreFull).

Vendor (1): `0xC601`.

### Device properties supported (56)

Standard (21): `0x5001` (BatteryLevel), `0x5003-0x5018`, `0x501a-0x501f`
- the usual capture-control set.

Vendor (35), in `0xD2xx`-`0xD8xx` ranges:
```
0xD220, 0xD303,
0xD406, 0xD407,
0xD603, 0xD604, 0xD605, 0xD606, 0xD607, 0xD609, 0xD610, 0xD613,
0xD615, 0xD616,
0xD700, 0xD704, 0xD720, 0xD723, 0xD724, 0xD725, 0xD726, 0xD727,
0xD75F, 0xD7AB, 0xD7AC, 0xD7AD, 0xD7AE,
0xD7F0, 0xD7FC, 0xD7FD, 0xD7FE, 0xD7FF,
0xD801, 0xD83E, 0xD83F
```

These cross-reference with the Java `ICatchCamProperty` enum:
- `0xD605` → `ICH_CAM_CAP_VIDEO_SIZE`
- `0xD606` → `ICH_CAM_CAP_LIGHT_FREQUENCY`
- `0xD607` → `ICH_CAM_CAP_DATE_STAMP`

…and many others. The mapping for the `0xD7xx` block is not in the
Java enum we extracted; those are likely Larkfly-specific.

## What iSmart DV2 actually does in a normal session

Across a 217-second capture covering app launch + preview + browse +
snapshot, **769 PTP operations** were issued. Frequency:

| OpCode | Standard name           | Count |
| ------ | ----------------------- | ----- |
| 0x1001 | GetDeviceInfo           | 1     |
| 0x1003 | CloseSession            | 1     |
| 0x1004 | GetStorageIDs           | 17    |
| 0x1005 | GetStorageInfo          | 33    |
| 0x1006 | GetNumObjects           | 3     |
| 0x1008 | GetObjectInfo           | 23    |
| 0x100a | GetThumb                | 2     |
| 0x100e | GetPartialObject        | 1     |
| 0x1014 | GetDevicePropDesc       | 323   |
| 0x1015 | GetDevicePropValue      | 30    |
| 0x1016 | SetDevicePropValue      | 31    |
| 0x9601 | (vendor; see below)     | 303   |
| 0x9805 | (vendor; see below)     | 1     |

So in practice the app uses **standard PTP ops + 2 vendor ops**. The
heavy use of `GetDevicePropDesc` (323× — almost half the session) is the
app polling every property descriptor on every UI update.

`0x9601` is called 303 times — second most common op. First call:
`params=[0xD001, 0xFFFFFFFF, 0x00000000]`. The first param looks like a
property/event/feature ID; this is probably a generic "read vendor
attribute" call. Worth full RE before the controller relies on it.

`0x9805` is called once near the end of the session with
`params=[0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF]` —
shape of a "global/all" query. Purpose unclear; can be left for later.

The other 6 vendor ops advertised in `DeviceInfo` (`0x9602`, `0x9812`,
`0x9614`, `0x9801`, `0x9802`, `0x9803`) are **not used in this capture**.
Either they're for features the user didn't exercise, or they're
inherited from the iCatch SDK template and the firmware doesn't
implement them.

## No UDP discovery happens

The capture shows that **iSmart DV2 does NOT do any UDP broadcast/
multicast discovery before connecting**. It goes straight to TCP 15740
after the phone's WiFi association completes. The pre-PTP/IP packets
are:

1. EAPOL 4-way handshake (WPA2 association)
2. ARP "who has 192.168.1.1?"
3. ~30+ outbound TCP/UDP attempts to the public internet (the phone
   thinks the camera AP has uplink) — all stranded; the camera doesn't
   forward
4. STUN binding requests to Tencent's STUN servers (the phone is also
   confused into thinking it has internet)
5. The PTP/IP `InitCmdReq` to `192.168.1.1:15740`

So the `DeviceScan` UDP broadcast path in `libcontrol.so` is a *separate*
code path used when the phone is on a normal WiFi network and the camera
is in Station mode (joined to that network). It's not used in the
"phone joins the camera's AP directly" flow we care about. The
previous hypothesis that "DeviceScan must precede PTP/IP" was wrong.

## State of the probes after this session

- `probes/ptpip_probe.py` — **works end-to-end** against the real camera.
  Default initiator name is now `"localhost"`. Always cleans up on exit
  so subsequent runs don't get DeviceBusy.
- `probes/decrypt_pcap.py` — generic WPA2-PSK 802.11 monitor-mode pcap
  decrypter. Pure stdlib + `cryptography`. Will be reusable for
  future captures.
- `probes/monitor_capture.sh` / `monitor_restore.sh` — repeatable
  monitor-mode capture pipeline.

## Specific next steps when resuming

(superseded — see the "Overnight autonomous session" section below)

---

# Overnight autonomous session — 2026-05-15 04:00

A roughly 4-hour session run while the user was asleep. Goals: enumerate
every property, mine the existing pcap for vendor opcode patterns, build
a Python client library, and stand up the multi-camera Flask UI.

## What got built

### Property enumeration (`probes/enumerate_props.py` + `probes/data/properties.json`)

All 56 device properties read via `GetDevicePropDesc` (0x1014) +
`GetDevicePropValue` (0x1015). Highlights:

- **`ProductName` (0x501E) = `'V11'`** — that's the iCatch internal
  product code; "Larkfly A6+" is the marketing skin.
- **`FwVersion` (0x501F) = `'20251206'`** (Dec 6, 2025).
- **`ImageSize` (0x5003) = `'9216x5184'`** (~48 MP photos).
- **`VideoSize` (0xD605) = `'3840x2160 60'`** (4K@60 fps).
- Storage: 62.5 GB SD card, fully empty at session start.

### iCatch camera mode = property 0xD604

The biggest discovery of the night. Property `0xD604` has allowed values
`[1, 17, 2, 3, 4, 5, 6, 7, 8, 9, 10]` — these match the
`ICatchCamMode` enum from the Java SDK almost exactly:

| Value | Java SDK name        | Behavior                                    |
| ----- | -------------------- | ------------------------------------------- |
| 1     | `VIDEO_OFF`          | idle (default state)                        |
| 2     | `SHARED`             | (camera forces back to 3 when written)      |
| 3     | `CAMERA`             | photo / still-capture mode                  |
| 4     | `IDLE`               | currently active in 0xD609                  |
| 5–10  | (unnamed)            | accepted but purpose unclear                |
| 17    | `VIDEO_ON`           | **ACTIVELY RECORDING video to /VIDEO/**     |

**Setting `D604=17` is the way to start a video recording.** Setting it
back to `1` stops. Confirmed by writing this and watching a new
`.MOV` file appear on the SD card (via FTP):

```
20260515_035416.MOV  562544 B   (~3s recording)
20260515_035727.MOV  312441 B   (~2s recording)
20260515_040107.MOV  785828 B   (~3s burst via /api/burst)
```

The Java SDK had this paradigm all along — the property gates the
camera's internal recording state machine. Sending `InitiateOpenCapture`
(PTP op `0x100D`) returns OK at the protocol level but doesn't actually
start a recording; it's a no-op against this firmware.

### 0x9601 is a polling op, not a property reader

`mine_pcap.py` walked the decrypted iSmart DV2 capture and reassembled
all 574 PTP transactions. `0x9601` was called **224 times**, but **223
of those used identical params `(0xD001, 0xFFFFFFFF, 0x00000000)`**.
The one anomaly used `(0xD83F, 0, 4)` — `0xD83F` is one of the
properties whose descriptor doesn't parse cleanly, suggesting `0x9601`
is the camera's "vendor read" interface for properties the standard
`GetDevicePropValue` can't handle.

The 223 identical calls happened ~once per second over the 217-second
session — **`0x9601(0xD001, 0xFFFFFFFF, 0)` is a heartbeat/keepalive**,
not a property fetch. The Larkfly camera doesn't strictly require it
(we held a session for many minutes without sending any), but a robust
client should poll it periodically against possible firmware variants.

### Untouched vendor opcodes probed

| Op     | rc with no params | Notes                                            |
| ------ | ----------------- | ------------------------------------------------ |
| 0x9602 | 0x2006 (PNS)      | Needs parameters; purpose unknown.               |
| 0x9614 | 0x2002 + 233 B    | Returns property-table-looking data even on a "GeneralError" rc. Promising. |
| 0x9801 | 0xA802 (vendor)   | Non-standard response code, no data.             |
| 0x9802 | 0xA80A (vendor)   | Non-standard response code, no data.             |
| 0x9803 | 0x2009 (InvObjHandle) | Needs an object handle param.                |
| 0x9812 | 0x2005 (OpNotSup) | Not implemented at all.                          |

`0x9614` is the most interesting — worth examining its returned data
properly in a follow-up. `0x9803` taking an object-handle param hints
at file operations (delete? open?).

### Photo trigger via PTP still unsolved

`InitiateCapture` (op `0x100C`) returns OK and a new object handle, but
**no JPG appears on the SD card** regardless of camera mode (tried
D604 ∈ {2, 3, 5, 6, 9, 10}). The created PTP handles have
`format=0x3000 (Undefined)` and tiny sizes (5–21 bytes) — they're
metadata stubs, not actual files. None of the unknown vendor ops above
appeared to trigger a save either.

The iSmart DV2 capture session didn't include a photo capture (the user
only browsed files), so there's no reference traffic to compare against.
Photos via the camera's physical shutter button continue to work fine
— this is purely a protocol-driven trigger gap.

Next-session moves: (a) capture iSmart DV2 deliberately taking a photo
to see the exact op sequence; (b) try `0x9603`/`0x9604`/etc. (codes the
camera doesn't advertise as supported but might still respond to);
(c) try `SetDevicePropValue` on properties we haven't touched
(`D7xx` block) right before InitiateCapture.

## The `larkfly` Python client library

```
larkfly/
├── __init__.py
├── types.py        constants (op codes, prop codes, mode values, rc names)
├── protocol.py     PTP-IP framing & codecs with all three iCatch quirks baked in
├── exceptions.py   typed exceptions: TransportError, InitFailError, PtpError
└── camera.py       high-level Camera class with context-manager support

tests/test_protocol.py    23 unit tests covering codec roundtrips,
                          InitCmdReq encoding matching real captured bytes,
                          DeviceInfo/ObjectInfo parsing against real bytes,
                          OpResp parsing with iCatch zero-padding.

examples/quickstart.py    runs end-to-end against the live camera; prints
                          DeviceInfo, lists storage, takes a photo,
                          downloads thumb.
```

Usage:

```python
from larkfly import Camera, types

with Camera('192.168.1.1', bind='192.168.1.10') as cam:
    info = cam.device_info()
    print(info['model'])      # always '' on this firmware

    print(cam.get_prop_value(0x501E))  # ProductName -> 'V11'
    print(cam.get_prop_value(0xD605))  # VideoSize   -> '3840x2160 60'

    cam.start_recording()
    time.sleep(5)
    cam.stop_recording()      # produces ~5s .MOV in /VIDEO

    for h in cam.list_objects():
        print(cam.object_info(h))
```

All 23 unit tests pass with no hardware connected — they exercise the
codec logic against real captured bytes.

## The `webui` Flask multi-camera controller

Mirrors the architecture of the parent ClaudesWorld webcam project but
targets PTP-IP cameras:

```
webui/
├── app.py              Flask routes
├── worker.py           LarkflyWorker (per-camera background thread)
├── templates/index.html  UI: preview grid + Photo/Record/Burst buttons
└── README.md
```

Verified end-to-end:

- HTTP `GET /` returns the HTML grid (one slot per `--camera` arg).
- `GET /video_feed/<slot>` streams MJPEG-over-multipart at ~30 fps from
  the camera's RTSP `/MJPG?W=720&H=400&Q=50&BR=5000000` endpoint.
- `POST /api/burst {"duration": 3}` triggers a synchronized recording on
  all RUNNING workers, auto-stops after 3 s, and a new .MOV appears on
  the SD card.
- All control endpoints fan out concurrently to slots (threaded), so a
  4-camera burst hits all cameras within a few ms.

What it does NOT yet have:

- A file browser / gallery (the parent webcam project has one;
  porting is straightforward — use the FTP client).
- Auto-detection of new cameras (currently you pass `--camera <ip>` for
  each).
- The photo button works at the protocol level but does nothing visible
  (see "Photo trigger" above).

## Suggested next steps when resuming

In priority order:

1. **Verify multi-camera scaling.** With one camera the UI works clean.
   The next blocking experiment is whether two cameras on the same
   `192.168.1.x` subnet can be reached from this host simultaneously
   (using the dongle + built-in WiFi, or using the camera STATION mode
   we know is supported but haven't tested).
2. **Crack the photo trigger.** Sniff iSmart DV2 explicitly taking a
   photo via the in-app shutter (NOT the camera's physical button).
   The action will produce 1–2 PTP transactions we can decode directly.
3. **Build the file browser.** FTP at `wificam:wificam@<ip>/JPG/` and
   `/VIDEO/` is the easy path. Bonus: parse `.MOV` thumbnails for the
   gallery view.
4. **Decode `0x9614`'s 233-byte response.** Likely a vendor property
   table; could reveal hidden capabilities.
5. **Implement `simpleConfig`-based STATION setup** to put cameras on
   a shared AP for the production multi-camera rig (see the original
   architecture proposal in the first half of this doc).

## State of the repo

```
.
├── README.md
├── apk-analysis/           # gitignored — APK + decompile artifacts
├── docs/
│   ├── findings.md         # this file
│   └── protocol.md         # original (now partly superseded) facts
├── larkfly/                # Python client library
├── tests/test_protocol.py  # 23 passing unit tests
├── examples/quickstart.py
├── webui/
│   ├── app.py
│   ├── worker.py
│   ├── templates/index.html
│   └── README.md
└── probes/
    ├── ptpip_probe.py      # original probe, still works
    ├── wifi_provision.py
    ├── enumerate_props.py
    ├── mine_pcap.py
    ├── decrypt_pcap.py
    ├── monitor_capture.sh
    ├── monitor_restore.sh
    └── data/               # JSON output from enumerate_props + mine_pcap
```

Git history (chronological):

```
git log --oneline:
  baseline: APK decompile findings + working PTP/IP probe
  ignore .claude/
  full property enumeration
  pcap mining + live capture tests
  larkfly: Python client library + tests + quickstart
  video record via mode toggle (D604=17/1) — confirmed working
  webui: multi-camera Flask controller
```

Nothing has been pushed to a remote — all local commits only.
