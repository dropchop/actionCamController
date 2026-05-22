# Untried attack vectors — Larkfly A6+ (iCatch V11, FW 20251206)

Living document. After exhausting the obvious PTP, MSC-SCSI and standard
network surfaces (see `docs/dev-console-hunt.md`, `docs/findings.md`,
`docs/ptp-vendor.md`), this file inventories what's still worth trying.

Compiled 2026-05-17 from two parallel deep-RE agents (full APK + native-
lib hunt; external/community research) plus targeted re-verification on
the camera. **As of this date, no public writeup of this camera or any
direct Larkfly variant exists on the open web; we appear to be first.**

The agents surfaced ~15 candidate vectors. I then verified the obvious
ones against the live camera; several PROMISING leads turned out to be
**not applicable to this firmware** because Larkfly has stripped the
relevant code paths. Those rule-outs are documented below alongside the
genuine remaining leads, so future researchers don't re-walk them.

The lists are ordered by **cheapness to test × probability of yield**.

---

## Status of broader iCatch surfaces vs THIS firmware

Larkfly removed substantially more of the iCatch reference SDK than
sibling action cams. Specific rule-outs from this round of research:

| iCatch SDK surface | Status on Larkfly A6+ FW20251206 | Evidence |
| --- | --- | --- |
| MSC vendor SCSI (0xC0 + extendCmd) catalog | **Stripped to GUID stub.** Wider 2100-probe sweep confirms no factory hooks. | `docs/dev-console-hunt.md`, `tools/msdc_scsi_wide.py` |
| Property `0xD617` `EncData` + verify-handshake unlock | **Property doesn't exist.** rc=0x200A. | `tools/icatch_verify.py` log |
| Property `0xD834` `STA_MODE_SSID`, `0xD835` `STA_MODE_PASSWORD`, `0xD7FB` `AP_MODE_TO_STA_MODE`, `0xD831/D832/D83C/D83D` (CAMERA_NAME / PASSWORD / ESSID) | **All return rc=0x200A.** The entire Wi-Fi-property control surface from USBCam's PropertyId.java is absent. | This document, raw probe 2026-05-17 |
| Property `0xD7A1` `CAMERA_CONNECT_CHANGE` (SmartConfig listen-mode trigger) | **rc=0x200A.** | Same probe |
| UDP `ICATCHTEK` broadcast discovery on `234.168.168.168:5002` and adjacent ports | **Silent.** No reply on 10 ports × 4 destination groups. | This document |
| FTP server vendor-specific extensions | Only `wificam/wificam` auth confirmed; FTP `SITE` and `E ` command surface NEVER probed (see S4 below). | `docs/findings.md` |

**Takeaway:** Larkfly has aggressively stripped both the dev-console
*and* the AP-management surfaces from the production firmware. What
remains is mostly: standard PTP photo/video controls + bootloader +
basic FTP/RTSP servers. The remaining attack vectors are therefore
either (a) bugs in the surfaces that DO exist, or (b) surfaces we
haven't reached yet from the host side.

---

## Shell-access vectors — UNTRIED, in priority order

### ~~S1. USB endpoint-0 vendor control transfer `0xC0 / 0xB0 / wIndex=0xAA55`~~ — **DEAD END (verified)**

**Fully closed.** Two parallel probes confirmed this:

1. **`bRequest=0xB0 / wIndex=0xAA55` (FRM.exe ISP-mode trigger)** —
   `tools/usb_ep0_vendor_probe.py` sent this in UVC mode (PID 2aad:6373).
   Result: `ETIMEDOUT`, not `EPIPE` (stall). This means the request was
   *recognised* by the firmware but the camera is not in a state that
   allows ISP-mode entry. No re-enumeration, no new USB class.

2. **SPCA_FWUpdate `InitialCamera` sequence captured via usbmon** —
   `InitialCamera` does NOT attempt ISP-mode entry at all. It performs
   **pure ISP register read/write** via `bRequest=0x05` (not `0xB0`):
   reads chip ID at register `0x0d04` → returns `0x0d7c90b1` (little-
   endian). This value matches none of the IDs libspca.so recognises
   (SPCA_2080=10, 2081, 2082, 2085, 2088) — libspca prints "device
   unknown" and exits immediately, well before any flash-write or mode-
   change attempt. The SPCA firmware-update protocol is ISP *register*
   access (image-sensor tuning), not ISP-mode (bootloader) entry. Even
   if adapted, it controls image-processing registers, not WiFi.

   Background ISP register protocol confirmed working on V39A:
   - `bmRequestType=0x40` (OUT), `bRequest=0x05`, `wValue=<reg addr>`,
     `wIndex=0x0000`, 4-byte data = write register
   - `bmRequestType=0xC0` (IN), same shape = read register
   - Heartbeat at register `0x004c` (returns `0x20`/`0x28` alternating
     at ~1 Hz from the UVC driver) confirms the interface is live.

Source: kitor.eu V37M post; captured usbmon traffic 2026-05-20

### ~~S2. Shutter+power USB enter-debug button combo~~ — **DEAD END (verified)**

Tried 2026-05-22. Both variants (camera OFF → hold shutter → plug USB;
camera OFF → hold power → plug USB) enumerate as `2aad:6371` MSC with
one interface — identical to normal MSC mode. No new PID, no bulk-camera
class, no ISP-mode re-enumeration. The V50 combo does not apply to V11.

Source: https://github.com/Linouth/iCatch-V50-Playground

### ~~S3. FTP `SITE` and `E `~~ — **DEAD END (verified)**

This vector is closed: the on-camera FTP server is stripped down to
~5 commands. Tested 25 SITE variants + `E` + HELP + STAT — all return
`500 Syntax error, command unrecognized`. The EKEN H9 `E `-overflow
won't apply because the `E` command parser literally isn't there.

### S4. UVC Bulk XU control transfers (separate from the ISO XU we probed)

The libusb_transport.so disassembly shows BOTH `uvc_xu_cmd_get/set`
(over UVC ISO transport) AND `uvc_bulk_xu_cmd_get/set` (over UVC bulk).
We probed ISO XU via `UVCIOC_CTRL_QUERY` kernel ioctls — bulk has a
DIFFERENT alt-setting and a DIFFERENT control-selector map.

How to test: in UVC mode (PID 2aad:6373), issue `SET_INTERFACE` to the
UVC bulk alt-setting, then send XU GET/SET requests for selectors
0x00..0xFF. Requires pyusb (no `pip` here, so probably libusb via
ctypes).

### S5. Modified `SPHOST.BRN` with attacker payload

The BRN container format is fully documented in
`/tmp/community-re/unified-btc-reverse/tools/python/carve_BTC_BRN.py`
(Browning trail cams, same iCatch family). Header magic `"SUNP BURN
FILE"`, fixed-offset chunk table, CRC. Chunk 2 is the FAT; chunks 0,1,
3..6 load at fixed addresses (some are bootloader, some are firmware).

Strategy: craft a BRN where one chunk contains:
- A small ARM aarch64 stub that copies our shellcode to known SRAM
- Hand-computed CRC over the whole image

Upload via `SendObject` (filename = `SPHOST.BRN`), then power-cycle —
the bootloader will show "FW UPDATE Y/N". If we hit Y, the camera
executes our chunk. If anything is wrong (CRC, load address, alignment)
the camera bricks unless we have the recovery procedure for THIS SoC.

**Risk: highest in the document.** Don't try without having a known-good
`SPHOST.BRN` from somewhere we can flash back via the FW UPDATE menu if
it boots far enough to show the menu, or via S1 (USB ISP mode) if not.

Cost amortizes well: if it works, full code-execution on the camera.

Sources: https://github.com/zoobab/brn (different family; misleading
context) ; the unified-btc-reverse repo locally cloned at
`/tmp/community-re/unified-btc-reverse/tools/python/carve_BTC_BRN.py`.

### S6. Broader SD-card autorun filename battery

We've only tried `SPHOST.BRN` (confirmed trigger) and a handful via
SendObject. The broader factory/recovery-filename battery from sibling
cameras (Ambarella, Anyka, Akaso, Lenovo's iCatch FRM partitions):

```
PDCAM_ISP.brn      AQY022.BIN         Parameter.brn      RawC.brn
Firmware.brn       Firmware 2.brn     A.brn              B.brn
ISP.brn            autoexec.ash       script.ini         rcS
custom_setting.ini upg.bin            upg.bin.enc        loader.bin
uboot.bin          ENV.bin            ICATCH.CFG         hostapd.conf
_BACKDOOR.CONF     factory.bin        DEBUG.LOG          MTKLOG.TXT
```

Special interest: **Parameter.brn** — Lenovo's FRM partition map names
this as the partition holding "Parameter" data (likely SSID/PSK
storage). If our camera honours that partition name and reads from SD
on boot, it could be the path to reading/writing the AP config.

How to test: SendObject each filename with safe payload (zeros or a
SUNP BURN FILE shell with a no-op chunk), boot, observe LED / boot menu
/ new files written to SD. **Always DeleteObject any uploaded files
that look like firmware (`*.brn`, `*.BIN`)** to avoid corrupting the
camera on reboot.

### S7. `0x9802` and `0x9812` PTP vendor opcodes — exploitable wedge

These two ops respond cleanly then crash the PTP service ~ms later
(`docs/ptp-vendor.md`). That's heap or stack corruption from the
response-path code. If a specific parameter shape lets us control the
overwritten data, this is a remote PTP-level memory-corruption bug.

How to test: power-cycle the camera (each test costs one reboot), then
try `0x9802([X])` and `0x9812([X])` with `X` set to controlled garbage:
`[0xDEADBEEF]`, `[0x41414141]`, `[0xFFFFFFFF]`, and successively longer
arg arrays. Watch for: different crash signature, no crash, or hung
PTP-service-but-no-reset (= probably ASLR-friendly heap corruption,
classic exploitation primitive).

This is a multi-day project even after the initial trigger. But it's
the only known memory-corruption bug we've observed on the camera.

### S8. PTP `SendObjectInfo` field-injection

We proved SendObject works (`tools/sendobject_unlock.py`). The
ObjectInfo struct has 4 PTP STRING fields (Filename, CaptureDate,
ModificationDate, Keywords). What we DIDN'T try:

- **Filename with path traversal**: `../FACTORY.BIN`, `/../SPHOST.BRN`,
  `..\..\hostapd.conf` — if the FAT layer strips the directory parts
  but the firmware's logger preserves them, a format-string injection
  is possible via the audit log.
- **Long filenames**: 255-char, 1000-char, 65535-char — does the
  PTP-string length byte work as `u8` (max 255) or does the firmware
  read past it?
- **Unicode trickery**: surrogate pairs, NULs mid-string, RTL marks.
- **Non-canonical extension**: `.brn` lowercase, `.BRN.`, `.brn `
  (trailing space) — bootloader case-sensitivity.

Each is one PTP round-trip + DeleteObject.

### ~~S9. PTP `ResetDevicePropValue`~~ — **DEAD END (verified)**

Returns `0x2005 Operation_Not_Supported` for every property tested
(D75F, D7FC, D7FF, D727). Not implemented; no bypass.

### S10. Audio interfaces (USB interfaces 2 and 3) on UVC device

The UVC device exposes 4 interfaces: UVC (0,1) and audio (2,3). We
probed UVC thoroughly; **the audio interfaces were never probed at
all**. Even just enumerating their alt-settings and feature descriptors
might surface a vendor-specific feature unit with debug controls.

How to test: `lsusb -v -d 2aad:6373` shows all interfaces; then
`amixer -c <card>` and `alsactl scan` to enumerate audio controls.

---

## AP-control vectors — UNTRIED, in priority order

This is the harder category. Larkfly stripped the documented Wi-Fi
property surface (verified above), so PTP-based AP control is dead.
What remains:

### A1. Bluetooth scan and SPP JSON channel

**Highest probability of yield.** The APK's
`com/icatchtek/bluetooth/core/ICatchCoreBluetoothCommand.java` defines
the FULL on-camera Bluetooth command set:

```json
{"mode":"wifi","action":"info","essid":"","pwd":"","ipaddr":""}
   → READ AP creds in plaintext

{"mode":"wifi","action":"set","essid":"<new>","pwd":"<new>",
                "ipaddr":"<new>"}
   → CHANGE AP SSID/PSK/IP

{"mode":"wifi","action":"enable","type":"ap"}
{"mode":"wifi","action":"disable"}
{"mode":"wifi","action":"set"}     # set STA SSID/PSK

{"mode":"bt","action":"set","name":"<>","pwd":"<>"}
{"mode":"system","action":"power","type":"down|hiber"}

# Plus full keypad emulation: "s2", "menu", "up", "down", "set", etc.
# (more buttons than the 2 physical ones — gives access to menus
# we can't otherwise navigate)
```

Channel: RFCOMM channel 1, UUID `00001101-0000-1000-8000-00805F9B34FB`
(standard Bluetooth SPP). No PIN in the source — looks like "Just
Works" pairing.

How to test:
```bash
# With camera powered on, near the host:
bluetoothctl scan on   # look for "iCatchBT*" or similar
# If found:
bluetoothctl pair <addr>
rfcomm connect 0 <addr> 1
# Then JSON over the rfcomm channel
echo '{"mode":"wifi","action":"info"}' > /dev/rfcomm0
cat /dev/rfcomm0
```

**Cost: 5 minutes if the camera has BT.** This camera's hardware
includes a wireless module (uncertain if BT capable — the apk-analysis
suggests it does). If BT isn't physically present, this fails fast.

Source: APK at `apk-analysis/jadx-output/sources/com/icatchtek/bluetooth/`

### A2. SimpleConfig packet injection — known AES key

**The AES key is in the APK in cleartext:**
```
21 7E 1A 16 28 DE D2 A7 AB E7 85 88 09 CA 40 3C
```
Found in `ICatchCameraAssistImpl.java:40`. This is the AES-128-CBC key
used by SimpleConfig to push WiFi credentials to a camera in
"listening" mode.

The catch: the camera has to be in SimpleConfig listen mode for this to
land. The trigger is property `0xD7A1 CAMERA_CONNECT_CHANGE` — which
we verified is NOT IN this firmware's property list. So the official
trigger path is gone.

**But:** an unconfigured camera (no saved WiFi) might enter SimpleConfig
listen mode automatically on first boot. If you factory-reset the
camera and it forgets its WiFi config, it might come up listening for
SimpleConfig packets in some default state.

How to test (no factory reset yet — destructive):
1. Reference: ESP32 SmartConfig packet format
   (https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/network/esp_smartconfig.html)
2. Adapt to use the iCatch AES key from above
3. Capture iSmart DV2 app driving a real SimpleConfig session
   (monitor-mode pcap; we have `tools/monitor_capture.sh` already)
4. Reproduce / fuzz from `tools/decrypt_pcap.py`

Sources:
- AES key: APK `ICatchCameraAssistImpl.java`
- Family writeup: https://www.shielder.com/blog/2020/04/notsosmartconfig-broadcasting-wifi-credentials-over-the-air/

### A3. Camera's broadcast frames may leak info

The AP-mode camera broadcasts 802.11 beacon frames at ~10 Hz. Beacons
contain SSID, supported rates, vendor-specific IEs. Some iCatch cameras
embed a small JSON object in the vendor IE for app-side discovery (the
iSmart DV2 app's mDNS-less discovery has to come from somewhere).

How to test: monitor-mode capture on the camera's channel for 30
seconds (`tools/monitor_capture.sh`), then dissect beacon frames in
Wireshark looking for vendor-specific IEs (tag 221) with unusual OUIs.

If we find one, the IE format is a probable AP-control side-channel
once we figure out how to inject our own frames with matching IEs.

### A4. Static analysis of the AP-control code path

The camera's WiFi-AP-mode is presumably driven by `hostapd` (standard
embedded-Linux choice) or a custom AP implementation. The native libs
mention paths like `/HOSTAPD/` and `D:/HOSTAPD/_BACKDOOR.CONF` (the
latter from prior research). 

How to investigate:
1. Strings-grep the .so files for `hostapd`, `wpa_supplicant`,
   `iwconfig`, `iwpriv`, `nl80211`, `/HOSTAPD/`, `*.conf` 
2. Cross-reference any file paths with what we can SendObject to via
   PTP (SendObject lands in SD root, but if any internal logic copies
   files from SD root into the system area...)
3. Specifically search for `_BACKDOOR.CONF` references — that filename
   was surfaced in earlier research as a candidate hostapd-override
   path. Drop it on SD via SendObject (after S6 SD-card battery).

### A5. The camera's mode property `0xD700` (currently 7, enum [1,3,7])

Read-only on this firmware but might be writable via a code path we
haven't tried (e.g., a vendor opcode we didn't fully test). The enum
[1, 3, 7] is suggestive — those are bitmask values, where:
- bit 0 (1) = photo
- bit 1 (2) = video
- bit 2 (4) = ???
- 7 = all three bits set

If we can flip from `7` to `1` (photo only) or some other value via
a code path that bypasses RO, we might enable / disable subsystems
(e.g., the WiFi-AP subsystem).

How to test: try writing 0xD700 via every advertised set-style op
(0x1016 confirmed RO, but also try 0x1012 if it's supported — that's
SetObjectProtection per some specs, but in iCatch it might be a
property-write variant).

### A6. PTP op `0x101B InitiateOpenCapture` — implemented, params unknown

`0x1012` turned out to be standard `SetObjectProtection` (verified —
see rule-out section).

`0x101B InitiateOpenCapture` is implemented (returns `0x2006 PNS` not
`0x2005 ONS`) but rejects every standard param shape we tried
(`[storage_id]`, `[storage_id, format_code]` with formats 0x3000,
0x3801, 0xB982, plus zeros and 0xFFFFFFFF sentinels).

How to test further:
- Enumerate the camera's `capture_formats_supported` field from
  DeviceInfo (we know 0x3801 EXIF/JPEG and the MP4 vendor codes are
  listed; might also be others)
- Try with a real-looking dataset payload (the spec allows a data phase)
- Try with the iSmart DV2 app's known calls captured in monitor-mode
  pcap (`tools/decrypt_pcap.py`) — they probably never call it either,
  but if there's a stream-start handshake we don't know about, it's
  visible there

---

## Hardware paper-route (still out-of-scope per user)

Documented for future researchers — none of these have been tried:

### H1. UART pads on the PCB
- Per kitor.eu (iCatch V37M sibling): **3.3V, 115200 8N1**
- "SP-Boot" boot prompt that drops to a command shell on any-key:
  `cachef, chksum, clktree, cpuinv, cpuwb, dump, etfdump, fill, j,
  loadfw, loadhdr, memcpy, mmapdrm, mmapini, mmapuni, nandblk, nandrd,
  rampara, ramsize, readid, rtcreg, search, uartld, usbld, w`
- `uartld <addr>` and `usbld` are unauthenticated arbitrary-code-
  execution primitives.
- Akaso M50 Pro SE PCB photos (closest documented sibling) show UART
  pad locations: https://github.com/Linouth/iCatch-V50-Playground/tree/main/images
- Source: https://blog.kitor.eu/lenovo-thinksmart-cam-unbricking-after-a-failed-firmare-upda

### H2. SPI flash dump via CH341A
- The firmware lives on an external SPI flash (typically 16-32 MB).
- CH341A programmer + SOIC-8 clip = $10 total.
- Reads the entire firmware image (`SUNP BURN FILE` magic at offset
  0x0). Run through `carve_BTC_BRN.py` from
  `/tmp/community-re/unified-btc-reverse/tools/python/`.

### H3. JTAG
- iCatch SoCs typically expose ARM JTAG via 4 pads near the SoC
  (TCK/TMS/TDI/TDO + optional TRST).
- JTAGulator or Pi + OpenOCD identifies pinout.
- Once attached: halt CPU, dump RAM, single-step. Bypasses all
  software security.

---

## What we ruled out in the follow-up session (2026-05-17 PM, post quirk-#4 fix)

- **SendObject magic-filename battery** — re-ran with the patched
  encoder so filenames land intact. 24 candidates (`sta.conf`,
  `wifi.conf`, `WIFI.CFG`, `AP.CFG`, `STA.CFG`, `_BACKDOOR.CONF`,
  `autoexec.sh`/`.ash`, `bootcmd.sh`, `XCServer`, `script.ini`,
  `custom_setting.ini`, `rcS`, `hostapd.conf`, `wpa_supplicant.conf`,
  `SERVICE.CFG`, `DEBUG.CFG`, `FACTORY.CFG`, `DEBUG.RUN`, `MFG.OVR`,
  `ENV.bin`, `upg.bin`, `update.bin`, `factory.bin`). All uploaded
  with exact names — zero recognition, zero file consumption, no
  property change, no SSID change. Closes both **S6** (SD-card
  filename battery, partial — `SPHOST.BRN` still untested) and
  **A2-adjacent** WiFi-config-on-SD theory. Tool:
  `tools/sendobject_magic_v2.py`.
- **A1 Bluetooth** — 3-min continuous scan across 2 controllers
  spanning 2 power-cycles, 1320 BT events captured. No iCatchBT, no
  camera OUI, no advertisement at any phase. **Closed.**
- **Factory test files on SD** — three escalating experiments
  (rename `FACTORY.RUN`, flip 6 flag values from `1`→`0`, delete all
  13 inert files + modify MAC/SERIAL to non-placeholders). All
  negative across 3 reboots. The 16 factory files Larkfly shipped
  with are decorative — firmware doesn't read them. The MAC.CFG flip
  in particular proved the camera's WiFi BSSID is NOT sourced from
  the file. See `docs/dev-console-hunt.md` for full results.

## What we ruled out this round (don't re-walk)

- All 10 USBCam SDK Wi-Fi properties (`0xD834`/D835/D831/D832/D83C/D83D/
  D836/D837/D7FB/D7A1) — every one returns `rc=0x200A`.
- UDP discovery on 10 ports × 4 dest groups with `ICATCHTEK` payload
  (plain + JSON) — no replies.
- 0xD801 IS the `G:\SPHOST.BRN` path (real value; the previous
  parser-bleed concern was specific to 0xD83E).
- **FTP server is heavily stripped.** Only `SYST` succeeds; HELP, STAT,
  SITE, XHELP, XDBG, `E` all return `500 Syntax error, command
  unrecognized`. Kills S3a (SITE) and S3b (EKEN E-command overflow).
- **PTP `0x1017 ResetDevicePropValue` returns `0x2005 ONS`.** Genuinely
  not implemented. Kills S9.
- **PTP `0x1012` is `SetObjectProtection`** (confirmed: `[handle, 1]`
  protects, subsequent DeleteObject returns `0x200D Access_Denied`;
  `[handle, 0]` unprotects). Standard PTP op that wasn't advertised
  in DeviceInfo. Not useful for shell-access.
- **PTP `0x101B InitiateOpenCapture` is implemented but returns
  `0x2006 Parameter_Not_Supported`** for every param shape we tried
  (`[storage_id]`, `[storage_id, format_code]`, `[0,0]`, `[0xFFFFFFFF, ...]`).
  Possibly needs a specific format code we haven't enumerated; could
  hide a streaming-start code path we haven't reached.

## Cross-reference

| Vector | Type   | Cheap? | Risk     | First-stop reference |
| ------ | ------ | ------ | -------- | -------------------- |
| ~~S1~~ | ~~shell~~ | -   | -        | **dead end** (ETIMEDOUT; ISP reg ≠ ISP mode; chip ID 0xb17c0d0d unknown) |
| ~~S2~~ | ~~shell~~ | -   | -        | **dead end** (shutter+USB and power+USB both enumerate as 2aad:6371 MSC) |
| ~~S3~~ | ~~shell~~ | -   | -        | **dead end** (FTP stripped) |
| S4     | shell  | ★★     | none     | libusb_transport.so strings |
| S5     | shell  | ★      | brick    | unified-btc-reverse carve_BTC_BRN.py |
| S6     | shell  | ★★     | brick if BRN-named | This doc |
| S7     | shell  | ★      | reboot/probe | docs/ptp-vendor.md |
| S8     | shell  | ★★★    | none     | tools/sendobject_unlock.py |
| ~~S9~~ | ~~shell~~ | -   | -        | **dead end** (0x1017 ONS) |
| S10    | shell  | ★★★    | none     | lsusb output |
| A1     | AP     | ★★★    | none     | APK BluetoothCommand.java |
| A2     | AP     | ★      | factory-reset | Shielder NotSoSmartConfig |
| A3     | AP     | ★★★    | none     | This doc |
| A4     | AP     | ★★★    | none     | apk-analysis/native/.strings |
| A5     | AP     | ★★★    | none     | analyses/data/prop_walk_all.json |
| A6     | AP     | ★★★    | none     | properties.json (0x101B only) |

**Recommended order of attack** (assuming user remains case-closed),
post-verification:

1. **S10** — Audio interfaces on UVC device (`lsusb -v -d 2aad:6373`
   + `amixer -c <card>`). Zero risk, 5 minutes.
2. **S4** — UVC bulk alt-setting XU controls (separate from ISO XU probed).
4. **S10** — Audio interfaces on UVC device (`lsusb -v` + `amixer`).
5. **S4** — UVC bulk-XU enumeration (different alt-setting from the
   ISO XU we probed).
6. **S8** — PTP SendObjectInfo field-injection (long filenames, path
   traversal, etc.).
7. **A3** — Beacon-frame vendor-IE capture in monitor mode (background
   while doing other things).
8. **A4** — More native-lib string mining for `/HOSTAPD/`,
   `_BACKDOOR.CONF`, file-path references.
9. **A6** — `0x101B InitiateOpenCapture` with iSmart-DV2-captured
   format codes (need a real pcap first).
10. **S6** — SD-card filename battery (skip BRN-suffixed names until S1
    works, since BRN parsing is what eventually risks brick).
11. **A2** — SimpleConfig packet injection (requires factory-reset to
    put camera into listen mode — destructive).
12. **S7** — Exploit-engineering on `0x9802`/`0x9812` wedge ops
    (multi-day project; each test costs one reboot).
13. **S5** — Modified `SPHOST.BRN` payload (requires S1 working for
    recovery path; otherwise brick risk).

If all of those exhaust, the conclusion is concrete: the network/USB
attack surface of this firmware is closed, and only hardware (H1 UART,
H2 SPI dump, H3 JTAG) remains.
