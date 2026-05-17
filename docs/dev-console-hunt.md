# Developer-console hunt — running log

Living document tracking the exploration described in plan
`/home/micah/.claude/plans/jiggly-jingling-adleman.md`. Updated after
each step.

## 2026-05-17 PM — Property surface fully mapped; SendObject works; three "fake-RW" properties identified

Walked all **56 advertised PTP properties** with live values
(`tools/prop_walk.py`, full dump `analyses/data/all_walk.json` and
`d7xx_walk.json`). Headline:

- **35 properties are genuinely RW** (descriptor says RW *and* writes
  persist + read back).
- **3 properties are "fake-RW"** — `0xD75F`, `0xD7FC`, `0xD7FF` — the
  descriptor advertises them as writable booleans (currently all `=1`),
  but `SetDevicePropValue` returns `rc=0x2001 OK` while the value
  silently does not change. Confirmed at the raw PTP level
  (`tools/prop_write_probe.py`). This is firmware-level deception, not
  a client bug: write succeeds with OK, read-back is unchanged. These
  look like **factory-debug / service-mode toggles** that require an
  unlock mechanism we don't have.
- **18 properties errored / unimplemented** in the D7xx block
  (advertised but `GetDevicePropDesc` returns `0x2002 General_Error`).
  Three confirmed: `0x500A` (FocusMode), `0x500C`, `0xD83F`.
- Plus a `larkfly` parser bug surfaced: `0xD83E`'s PropDesc.current_value
  bleeds the prior property's string into the parse. The actual
  `0xD83E` value via `GetDevicePropValue` is a 5-byte struct, not the
  `'G:\\SPHOST.BRN'` path. The path lives only at `0xD801` (RO).

### Unlock-hunt: 13 primer attempts, all negative

`tools/unlock_hunt.py` opened a fresh PTP session for each of:

- vendor ops `0x9601`, `0x9614`, `0x9805` as primers
- `SetDevicePropValue(0xD406, "FACTORY"|"SERVICE"|"DEBUG"|"ICATCH"|"ENG"|"ROOT"|"TEST")`
- `SetDevicePropValue(0xD723, 0x80000001)` and `0x80000002` (sentinels)
- a combo: `0x9805 + 0xD406="FACTORY" + 0xD723=0x80000001`

After each, attempted to write the three locked booleans. **Every
attempt silent-rejected exactly as the baseline.** No primer changed
the lock state.

### SendObject works — full PTP write-channel confirmed

`tools/sendobject_unlock.py` proved that **`SendObjectInfo` (0x100C) +
`SendObject` (0x100D) accept arbitrary file uploads** to the camera's
SD card with full success (rc=0x2001, sequential handles assigned).
Tested 8 filenames (`FACTORY.BIN`, `UNLOCK.BIN`, `SERVICE.BIN`,
`DEBUG.BIN`, `SPHOST.BRN`, `FACTORY.CFG`, `ICATCH.KEY`, `UNLOCK.KEY`).

**Significance:**
- We now have a PTP-side file-write channel that bypasses the FTP
  chroot. Files appear in the SD root.
- **Caution: `SPHOST.BRN` is the bootloader's firmware-update trigger.**
  Uploading a 16-byte zero file via SendObject is enough to make the
  next boot show the "FW UPDATE Y/N" menu. Always `DeleteObject` after
  any SendObject test, *especially* on `SPHOST.BRN`.

But: none of the uploaded magic filenames unlocked the three fake-RW
properties. SendObject is not the unlock path.

### Verify handshake (0xD617) doesn't apply to this firmware

`tools/icatch_verify.py` ran the full handshake reversed from
libcontrol.so. Result: `0xD617` is **not in this firmware's
properties-supported list** (56 properties enumerated, none at D617).
`SetDevicePropValue(0xD617, ...)` returns `rc=0x200A DeviceProp_Not_Supported`.

Larkfly stripped the `EncData` property entirely. The handshake
reversed by the overnight agent applies to other iCatch SDK variants
but not this build.

### Where the lock probably lives

The three fake-RW booleans (`0xD75F`, `0xD7FC`, `0xD7FF`) require an
unlock that is not reachable from the PTP wire surface. Candidates:

- A privileged session opened differently (different session ID range,
  different OpenSession parameters) — but PTP session IDs are
  ordinarily 1-3 and OpenSession takes only the ID.
- A different transport entirely — UART on the PCB, or the factory
  tool firmware (a separate image flashed during QC then replaced
  with the production firmware before shipping).
- A vendor opcode we've never called (`0x9802` / `0x9812` crash the
  PTP service on call, so testing them costs a power-cycle each).

The PTP network surface is now **exhausted**. Remaining attack vectors
are hardware-only (UART pads on the PCB) or unobtainable (factory tool).

## 2026-05-17 — MSC vendor-SCSI vector ruled out

Empirically confirmed the iCatch vendor-SCSI surface is **stripped on
this firmware**. `tools/msdc_scsi_diag.py` swept seven axes (opcode
byte, CDB length, parameter3, OUT direction, INQUIRY baseline,
extendCmd-in-other-positions, READ_CAPACITY) — full results in
session log. The dispatcher does only this:

```
if (cdb[0] in {0xC0..0xFF} && cdb[2] != 0)   → return 76-byte device GUID buffer
                                                (truncated to whatever dlen was requested,
                                                 same regardless of cdb[1..2] value
                                                 and regardless of cdb[0] from 0xC0..0xF0)
if (cdb[0] == 0xC0 && cdb[2] == 0)           → falls through to standard SCSI;
                                                returns INQUIRY page (`Sport Ca…`)
standard SCSI (INQUIRY 0x12, READ_CAPACITY    → all work correctly
0x25, etc.)
```

So the entire lingkun `UsbScsiCommand.java` catalog
(`CAM_VER_GET`, `CAM_SD_CARD_STATUS`, `CAM_FW_UPDATE`, `formatStorage`,
`capturePhoto`, etc.) is **not implemented** on this V11 firmware.
There is no SCSI-vendor path to control, status, or firmware updates.

The 76-byte device GUID (`{6A74EE0D-31FE-43F2-A782-4A38A04714A5}` in
UTF-16LE) is a stable per-camera fingerprint we hadn't surfaced before
— useful as an identity gate but provides no control. It is the same
value that the verify handshake calls `sdCardId`, which means **the
"SD card ID" is per-camera, not per-card**.

Vector closed; nothing more to try over MSC.

## NIGHT-RESEARCH UPDATE — major reframing

Four parallel research agents (H9R deep-RE, libusb_transport
disassembly, libcontrol verify-handshake disassembly, web research)
ran overnight while the camera was unattended. Big results:

### 1. The "AES verify-handshake" is not AES. It's arithmetic.

`Ptp2CameraControl::ptpip_iCatch_device_verify()` was fully reversed.
The misleading `"Enc vierfy!"` error string calls it "Enc" because the
hidden data lives in property `0xD617` which the SDK names **`EncData`**,
*not* because it's encrypted. The actual flow:

```
1. getSDCardId()       → sdCardId (32-bit)
2. ptp_getstorageinfo() → imageCnt
3. ptp_getdeviceallpropdescs(buf, &count)   ← vendor op 0x9614 (the one we know)
4. parse the response, extract:
     timeDate (string)
     remVid   (u32)
     enc[0..3] = EncData u32s at offsets 0, 16, 32, 48 of property 0xD617
5. arithmetic checks:
     calc0 = enc[0] + sdCardId
     calc1 = remVid - enc[1]
     calc2 = enc[2] * devPropCnt
     calc3 = enc[3] + calc0
   mismatch → fail
6. SetDevicePropValue(0x5011 DateTime, STRING, timeDate)    ← std PTP
7. SetDevicePropValue(0xD617, AUINT8, b"\x00"*16)           ← unlocks the hidden prop
8. done → 0xD617 now readable via GetDevicePropValue(0xD617)
```

So we can run the verify ourselves in `larkfly` with no AES. After
step 7, all hidden surface behind 0xD617 unlocks. **What that
unlocks is the real unknown** — possibly nothing useful, possibly
the dev console.

The 16-byte buffer written to 0xD617 is allocated, byte 0 zeroed,
rest is uninitialised heap garbage. So the firmware almost certainly
just checks that the SET succeeded, not what bytes were sent.
**Sending 16 zero bytes is safe and correct.**

### 2. The MSC vendor-SCSI table is now fully extracted.

Universal vendor opcode is **`0xC0`** (CDB byte 0). The discriminator
is `extendCmd` (CDB bytes 1-2, big-endian). The full per-cmd_id
mapping was reversed from `getUsb_Transport_ScsiCommandInfo()`:

| cmd_id | method               | extendCmd | dir  | param1 | CDB (16 B)                                          |
| ------ | -------------------- | --------- | ---- | ------ | --------------------------------------------------- |
| 0x00   | getSupportedStreams  | 0x0000    | IN   | 0      | `C0 00 00 00 …`                                     |
| 0x06   | startMovieRecord     | 0x0005    | —    | 1      | `C0 00 05 00 00 00 01 00 00 …`                      |
| 0x07   | stopMovieRecord      | 0x0005    | —    | 0      | `C0 00 05 00 …`                                     |
| 0x08   | **capturePhoto**     | 0x0007    | —    | 0      | `C0 00 07 00 …`                                     |
| 0x09   | switchToPlayback     | 0x0006    | —    | 1      | `C0 00 06 00 00 00 01 00 …`                         |
| 0x10   | switchToPreview      | 0x0006    | —    | 0      | `C0 00 06 00 …`                                     |
| 0x12   | setEventTrigger      | 0x0009    | OUT  | 0      | `C0 00 09 …`                                        |
| 0x13   | setAudioMute         | 0x000A    | OUT  | 1      | `C0 00 0A 00 00 00 01 …`                            |
| 0x14   | setAudioUnMute       | 0x000A    | OUT  | 0      | `C0 00 0A …`                                        |
| 0x15   | setSeamless          | 0x0100    | OUT  | 0      | `C0 01 00 …`                                        |
| 0x16   | formatStorage        | 0x0012    | OUT  | 0      | `C0 00 12 …`                                        |
| 0x17   | **updateFw**         | 0x0102    | OUT  | 0      | `C0 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00`   |
| 0x18   | getVideoRecordStatus | 0x0008    | IN   | 0      | `C0 00 08 …`                                        |

Cross-confirmed via `lingkun/USBCam` (a different iCatch camera
control app that publishes its SCSI table in Java):

| Java constant            | extendCmd | Notes                                              |
| ------------------------ | --------- | -------------------------------------------------- |
| `CAM_TIME_UPDATE`        | `0x000B`  | takes (yy, mm, dd, hh, mm, ss) — not in our table  |
| `CAM_VER_GET`            | `0x000C`  | returns 18 ASCII bytes — firmware version          |
| `CAM_PARA_RESET`         | `0x000D`  | factory-reset settings                             |
| `CAM_SET_SCREEN_RES`     | `0x000E`  | takes 4B BE width/height                            |
| `CAM_SD_CARD_STATUS`     | `0x0010`  | returns 32-byte status struct                       |
| `CAM_STREAM_STATUS`      | `0x0011`  |                                                     |
| `CAM_FW_UPDATE`          | `0x0013`  | takes param1=1 (do) / 0 (ignore)                    |
| `CAM_CHECK_FW_UPDATE`    | `0x0014`  | pre-flight check                                    |
| `SCSI_EXT_GET_DISK_INFO` | `0x0103`  |                                                     |
| `CAM_EXCEPTION_RECOVERY` | `0x0201`  | suggests there's a recovery mode reachable by SCSI! |

So we now have a much wider menu of SCSI commands to test — in
particular **`CAM_VER_GET (0x000C)` is a perfect smoke test** (no
side-effects, returns 18 ASCII bytes), and **`CAM_EXCEPTION_RECOVERY
(0x0201)` is intriguing** — its name suggests entry to a recovery
mode that's distinct from normal updateFw.

### 3. The H9R firmware reveals SD-card overrides we missed in our fuzz.

`/tmp/research_h9r/` work shows the iCatch SDK reads (and respects)
several SD-card paths we never tried — most notably:

- **`D:/HOSTAPD/_BACKDOOR.CONF`** — literal fallback path baked into
  the hostapd init code. Dropping this file with a custom hostapd
  config (different SSID/PSK, or `ctrl_interface=hapd` enabled)
  would let us reconfigure the WiFi AP from SD without firmware
  modification. The string `BACKDOOR` is in the binary verbatim.
- **`D:/HAPD0.CFG`** and **`D:/sta.txt`** — hostapd / wpa_supplicant
  SD-card defaults read by the `hapd`/`wpas` NDK shell commands.
- **`C:\ATSCRIPT.TXT`** and **`C:\CPSCRIPT.TXT`** — AT/CP scripts
  read at boot. Grammar: `loop N keydown s1 key s2 sleep 20 loopend`
  — i.e. **a scripting language that simulates button presses**
  including `keydown`, `keyup`, `sleep`, `wakeup`, `loop/loopend`.
  Means we can script the camera into any state reachable via
  buttons, including hidden menus, *if* C: maps to SD.
- **`C:\KEYLOG.TXT`** — output of `script rec` (button-press
  recorder). Would let us record a real user's button sequence into
  a service menu and replay it.

### 4. Our V11 is likely an iCatch V39 (SPCA63xx) marketing rebrand.

PIDs `0x6371` / `0x6373` sit right next to documented PID
`0x6370 = V39 debug mode` (Akaso Brave 7LE blog confirms). V11 does
not exist in iCatch's catalog. The chipset is MIPS little-endian
(via `mheistermann/spca-fun`'s use of `mipsel-linux-gnu`).

That means the FRM.exe tool we already have (V37/SPCA6350 from the
Eken H9R rar) is the WRONG SDK for our V11, but the convention is
shared and the protocol is the same — the bundle
`icatch_v3000_For_V37_V50_V35_V33_K33.7z` is the production tool
for the whole family.

### 5. Public RE community is small but active and useful

Top resources discovered:

- **`mheistermann/spca-fun`** (★★★ — GitHub) — has a complete Python
  parser `sunp.py` for SPHOST.BRN, an FTP-exploit ROP chain that
  drops a shell on EKEN H9, and MIPS softmod toolchain. **Same
  firmware family as our H9R reference.**
- **`robertzak133/unified-btc-reverse`** (★★★ — active 2025-11) —
  Browning trail cams on iCatch V35, full RELEASE firmware images,
  BTC_BURN_Maker.py, codePatcher.py.
- **`lingkun/USBCam`** (★★★) — Android app driving iCatch over UVC+
  XU, **publishes the full SCSI vendor opcode table in Java** plus
  references `ICatchtekControl.jar` (the iCatch SDK Java jar).
- **`sunplusit/SPCA_FWUpdate`** (★★★) — official iCatch/Sunplus
  Linux libusb tool for firmware update. The C source implements
  the same FRM.exe protocol on Linux. Means we can build a Linux
  firmware-update binary without Wine.
- **`Linouth/iCatch-V50-Playground`** — V50 RE, Ghidra project files.
- **`kitor.eu` blog** — best practical FRM.exe + UART walkthrough.
  Documents the "SP-Boot" bootloader, UART commands `uartld`/`usbld`,
  RAM load address 0x3F000000, FRM.exe bundle URL.

### 6. Brick recovery is now better understood

The kitor.eu writeup confirms SP-Boot is the bootloader name. It
supports `usbld` (USB firmware download) and `uartld` (UART
firmware download). To enter SP-Boot recovery mode you short an
ISP/MP testpad on the PCB (V37) or hold a button combo (V39). Once
in SP-Boot, FRM.exe can re-flash any image. So Vector 3 hardware
(opening the case) has a confirmed recovery path via SP-Boot — but
that's still out of scope per user.

## NEW TOOLS BUILT TONIGHT

### `tools/icatch_verify.py`
Implements the verify handshake per Agent 3's RE. Run against the
camera (WiFi mode, PTP up) to:
1. Read `EncData` from property 0xD617 via vendor op 0x9614
2. Set DateTime back (PTP std)
3. Write 16 zero bytes to 0xD617 (the magic unlock)
4. Re-query 0xD617 directly + re-enumerate DeviceInfo to see if any
   new ops or properties unlocked

If 0xD617 yields data after the SET, that's the first new surface
unlocked in this hunt. If `DeviceInfo` reports new ops_supported,
that's the dev console.

Usage:
```bash
python3 tools/icatch_verify.py --host 192.168.1.1 --bind 192.168.1.10
```

Output: `analyses/data/icatch_verify.json` + raw 0x9614 capture at
`/tmp/op_9614_during_verify.bin`.

### `tools/msdc_scsi_runner.py`
Sends *named* vendor SCSI commands (not brute-force) using the
table cross-confirmed from `libusb_transport.so` disassembly +
`lingkun/USBCam` Java source. Requires camera in MSC mode (PID
`2aad:6371`) + sudo for `/dev/sg0`.

Highest-value experiments to run, in this order:

```bash
# 1. Smoke test — proves the SCSI vendor protocol works on V11.
#    Returns 18 ASCII bytes of firmware version.
sudo python3 tools/msdc_scsi_runner.py --cmd ver

# 2. Read 32-byte SD-card status struct — confirms structure decode.
sudo python3 tools/msdc_scsi_runner.py --cmd sd-card-status

# 3. Check if camera thinks it has a pending firmware update.
sudo python3 tools/msdc_scsi_runner.py --cmd check-fw-update

# 4. Read disk info (FAT vs exFAT marker etc).
sudo python3 tools/msdc_scsi_runner.py --cmd disk-info

# 5. Trigger photo capture via SCSI (PTP path was broken — SCSI may work).
sudo python3 tools/msdc_scsi_runner.py --cmd capture-photo

# Full catalog (no sudo needed):
python3 tools/msdc_scsi_runner.py --cmd list
```

### Cloned community repos at `/tmp/community-re/`
- `spca-fun/` — Heistermann's EKEN H9 toolkit. `firmware-analysis/tools/sunp.py` is a complete SUNP BURN file parser (needs `python3-construct`; install via apt if you want to run it). `eken-ftp-exploit/exploit.py` is a working FTP-based RCE for SPCA6350 — could potentially be ported to V11.
- `USBCam/` — Lingkun's iCatch USB control Android app. `UsbCam/app/src/main/java/com/icatch/usbcam/sdkapi/UsbScsiCommand.java` is the SCSI opcode bible (the table is now in our runner).
- `SPCA_FWUpdate/` — Official Sunplus Linux firmware-update tool for OLDER SPCA-20xx chips. **Not our chipset family** (targets the USB Video Control interface, not MSC), but the protocol-design ideas inform thinking. Includes pre-compiled `libspca.so` for x86/x64/arm — official binary not directly usable for V11 but worth keeping around.
- `unified-btc-reverse/` — Browning trail cam RE (V35 family). Has `BTC_BURN_Maker.py`, `codePatcher.py`, full released firmware images. Most actively maintained iCatch RE project; closest cousin to our chipset.

## Confirmed SCSI command table (cross-validated, ready to call)

| Cmd name                | CDB hex (16 B)                                          | Dir | Data | Notes |
| ----------------------- | ------------------------------------------------------- | --- | ---- | ----- |
| **ver (CAM_VER_GET)**   | `C0 00 0C 00 …`                                         | IN  | 18 B ASCII | **SMOKE TEST — run this first** |
| sd-card-status          | `C0 00 10 00 …`                                         | IN  | 32 B struct | rich diagnostic |
| stream-status           | `C0 00 11 00 …`                                         | IN  | 4 B  | byte[0] = 0/1/2/3 |
| check-fw-update         | `C0 00 14 00 …`                                         | IN  | 1+ B | byte[0]=1 if pending FW update detected |
| disk-info               | `C0 01 03 00 …`                                         | IN  | 16 B | FAT32 vs exFAT marker etc |
| time-update             | `C0 00 0B 00 …` + 6 bytes data                          | OUT | 6 B  | (YY-2000, M+1, D, H, M, S) |
| set-screen-res          | `C0 00 0E 00 …` + 4 bytes (W_hi, W_lo, H_hi, H_lo)      | OUT | 4 B  |  |
| capture-photo           | `C0 00 07 00 …`                                         | OUT | 0    | **PTP failed; SCSI may work** |
| mode-preview            | `C0 00 06 00 00 00 00 …`                                | OUT | 0    | param1=0 |
| mode-playback           | `C0 00 06 00 00 00 01 …`                                | OUT | 0    | param1=1 |
| rec-start               | `C0 00 05 00 00 00 01 …`                                | OUT | 0    |  |
| rec-stop                | `C0 00 05 00 00 00 00 …`                                | OUT | 0    |  |
| mute / unmute           | `C0 00 0A 00 00 00 0{1,0} …`                            | OUT | 0    |  |
| param-reset             | `C0 00 0D 00 …`                                         | OUT | 6    | factory-reset settings (no SD wipe) |
| **fw-update**           | `C0 00 13 00 00 00 01 …`                                | OUT | 0    | **camera enters update flow** |
| fw-update-ignore        | `C0 00 13 00 00 00 00 …`                                | OUT | 0    | the "No" choice |
| format                  | `C0 00 12 00 …`                                         | OUT | 0    | **WIPES SD** |
| **recovery (0x0201)**   | `C0 02 01 00 00 00 0{1,0} …`                            | OUT | 6    | **exception-recovery — unknown effect on V11** |

The pair `fw-update` + `fw-update-ignore` is the **same trigger as
the bootloader's SD-card FW UPDATE menu** but reachable over USB
without needing a `SPHOST.BRN` on the SD. So in MSC mode the camera
exposes the firmware-update path through SCSI directly. We don't
yet know if it requires a `SPHOST.BRN` on the SD card to actually
proceed, or whether the data buffer carries the firmware bytes.

## When you wake — recommended order

1. **Run `tools/msdc_scsi_runner.py --cmd ver` in MSC mode.**
   Quickest, safest, definitively proves the SCSI vendor protocol
   works on V11. Should return 18 ASCII bytes containing your
   firmware version `20251206` (or similar).
2. **Run `tools/msdc_scsi_runner.py --cmd sd-card-status`** to see
   the decoded camera state struct.
3. **Try `tools/msdc_scsi_runner.py --cmd capture-photo`** — this
   is the SCSI capture path that PTP couldn't drive. If it actually
   produces a JPG on the SD card, we've solved the photo bug as a
   side effect.
4. **Switch the camera back to WiFi mode** and run
   `python3 tools/icatch_verify.py`. The whole verify handshake
   completes in a couple of seconds. The script reports whether
   0xD617 became readable AND whether DeviceInfo shows new ops.
5. **If verify unlocks a new op, run it.** That op is the most
   likely path to a dev surface.

## Brick-risk recap (DO NOT run unless committed)

- `--cmd format` → wipes SD (low cost; 3 MOV files lost)
- `--cmd fw-update` → enters FW update flow; without a valid
  `SPHOST.BRN` on the SD, almost certainly bails out. But it's
  uncharted on V11 — could leave the camera in update mode
  requiring physical recovery.
- `--cmd param-reset` → wipes camera settings (recoverable)
- `--cmd recovery-pb` / `recovery-pv` → unknown effect on V11
- `tools/icatch_verify.py` is **safe** — it never sends arbitrary
  bytes, only the documented zero-buffer.

---

## Headline findings (running summary)

1. **SD-card `SPHOST.BRN` triggers the iCatch bootloader's
   FW UPDATE menu** (Yes / No). Empty file is enough; the bootloader
   does not validate the header before prompting. Selecting No
   powers the camera off; recovery requires deleting the file from
   the SD before next boot.
2. **PTP `SendObjectInfo` + `SendObject` give us unauthenticated,
   uncomplaining write access to the SD root.** The FTP "chroot" we
   thought existed is actually only a listing filter — files at the
   SD root are visible via FTP once they exist. Combined with (1),
   this means we can drop SPHOST.BRN onto the camera over WiFi
   without ever touching the SD card physically.
3. **Property `0xD617` is hidden behind the device-verify
   handshake** (AES-based, references in `libcontrol.so` strings).
   Unlocking it might expose additional control surface.
4. **Properties `0xD801` / `0xD83E` are STR-typed and contain
   `G:\SPHOST.BRN`** — the firmware's own path to its own
   firmware blob. `0xD83E` is RW.
5. **No network dev console (SSH/telnet/HTTP/SNMP/...) on our V11**,
   **no useful unknown PTP vendor opcode**, **no on-disk debug
   property**. All "easy" runtime surface ruled out.
6. **iCatch firmware IS statically reachable via PTP file-upload**.
   The .BRN container format is now known.
7. **The iCatch firmware ships with a TI NDK command shell + a
   telnetd implementation baked in** (binwalk of Eken H9R V37
   reference firmware confirms it). The dev console code exists
   in every iCatch SDK build; what differs by camera is whether
   it's auto-started or how it's gated. **Our V11 doesn't expose
   it on the network**, so the gate is closed by default. If we
   can flip the gate (patched firmware → SPHOST.BRN push) we get
   the shell.

## Status

| Step  | Description                                              | State   | Outcome |
| ----- | -------------------------------------------------------- | ------- | ------- |
| 1.5   | `libcontrol.so` symbol mining                            | done    | **Lead** — 0xD617, 0xD700, 0xD7AE named; AES verify path |
| 1.1a  | Targeted probe of 0xD617 / 0xD700 / 0xD7AE               | done    | 0xD617 hidden; 0xD7AE locked to 30 fps |
| 1.1b  | Sweep 21 unmapped 0xD7xx / 0xD8xx properties             | done    | **Major lead** — `G:\SPHOST.BRN` firmware path discovered |
| 1.2   | Decode 0x9805 snapshot                                   | done    | **Rules out** — it's bulk MTP `ObjectPropList`, not device props |
| 1.4   | PTP SendObjectInfo / SendObject write-access test        | done    | **Major** — full SD-root write access via PTP; FTP chroot is read-only |
| 1.5b  | SPHOST.BRN drop-test via PTP                             | done    | **CONFIRMED — bootloader scans SD for SPHOST.BRN and presents a FW UPDATE menu** |
| 1.5c  | binwalk a reference iCatch .BRN (Eken H9R, V37 chipset)  | done    | **HUGE** — found telnetd + NDK shell + AES verify in firmware, decoded the .BRN container format |
| 1.1c  | SD-card config-fuzz (rounds 1 + 2, 16 candidate files)   | done    | **Cleanly negative** — camera ignores all SD-root config patterns; SPHOST.BRN is the *only* SD trigger |
| 1.3   | iSmart DV2 firmware-update wire capture (next priority)  | pending | Still needed — only path to a V11-specific .BRN we can patch |
| 1.1c  | Sweep `set` operations on safe boolean RW flags          | pending | — |
| 1.4   | PTP `SendObject` write-access test                       | pending | — |
| 1.3   | iSmart DV2 firmware-update wire capture (needs phone)    | pending | — |
| 2.1   | USB enumeration (needs camera plugged in)                | pending | — |
| 2.2   | UVC XU decode (needs camera plugged in)                  | pending | — |
| 2.3   | Camera on-screen menu walk (needs user at camera)        | pending | — |
| 2.4   | SD card baseline image (needs user to pull card)         | pending | — |
| 2.6   | Capture camera's own SD writes (needs user)              | pending | — |
| 2.5   | SD autorun fuzzing (needs user)                          | pending | — |

## 1.5 — libcontrol.so symbol mining (done)

Raw dump: `analyses/data/libcontrol_debug_symbols.txt` (734 lines).

### Properties named by the SDK that aren't fully understood

Only three D6xx-D8xx codes appear as literal strings in `libcontrol.so`:

| Property | Role per SDK string                              | In our enum? |
| -------- | ------------------------------------------------ | ------------ |
| `0xD617` | `iCatch Device Verify Failed at 0xd617 set.`     | **No — hidden** |
| `0xD700` | `get camera mode from 0xD700`                    | Yes (no name) |
| `0xD7AE` | `FW cannot support 0xD7AE(get fps/hevc)`         | Yes (no name) |

Implications:

- **`0xD617` is the prime hidden-surface lead.** It's not advertised
  in `DeviceInfo.properties_supported`, but the SDK SET-writes it
  during its device-verify handshake. The camera firmware accepts the
  write or the verify wouldn't succeed for the official app. This is
  exactly the kind of behind-the-curtain property a dev console would
  hang off of.
- **`0xD700` = camera mode.** Distinct from `0xD604` (the VIDEO_OFF /
  VIDEO_ON / CAMERA mode-toggle we already use). Likely a higher-level
  "what is the camera doing" register.
- **`0xD7AE` = "get fps/hevc".** Suggests an H.265 enable lives here.
  Worth probing — could expose a higher-quality preview stream.

### Verify handshake (`Ptp2CameraControl::ptpip_iCatch_device_verify`)

The SDK runs a multi-step verify after PTPIP InitCommand. Error
strings show the steps:

1. `iCatch Device Verify Failed at Enc vierfy!` — AES-based encryption
   check (`AES_cbc_decrypt_sdk`, `AES_cbc_encrypt_sdk`,
   `AES_set_key` are all linked in). The "16 bits AES Key" option
   parameter is referenced — that's a 128-bit AES key.
2. `iCatch Device Verify Failed at 0xd617 set.` — sets property
   `0xD617` to something. Possibly the result of the AES challenge.
3. `iCatch Device Vierfy Failed at timeDate set.` — sets the device
   clock (we know `Date:` headers from RTSP show `2012/1/1`, i.e. the
   camera's clock is never set unless this verify runs).
4. `Device -> APP verify OK` / `iCatch Device verify success.`

`larkfly` skips this whole flow today and the camera serves PTP
fine anyway, but **if running the verify unlocks additional
properties or commands, that's the answer.** Worth implementing.

### Logging infrastructure

The Phoenix_library logger (`_ZN15Phoenix_library17Phoenix_libLogger*`)
is the iCatch SDK logger, statically linked **on the app side**, not
the camera side. The JNI exports `JCameraLog_setDebugMode`,
`_setFileLogPath`, `_setLogLevel`, `_setSystemLogOutput`, `_writeLog`
all configure logging *in the app*. They write to
`icatch_%s_sdk_%s_%s.log` on the phone, not the camera.

So this doesn't give us a camera-side log directly — but it does
confirm:
- The same `Phoenix_library` SDK is almost certainly running on the
  camera firmware (BSP convention).
- If we can flip its file-output flag on the camera side via some
  property, we'd get logs on the SD card.

### Other JNI methods of interest (160 total)

- `JCameraControl_capturePhotoA` / `capturePhotoB` / `triggerCapturePhoto`
  — three photo paths. We've only tried the standard PTP
  `InitiateCapture` (0x100C). The "B" path or the `triggerCapturePhoto`
  variant might be what actually works for stills.
- `JCameraControl_extensionUnitGet` / `_extensionUnitSet` /
  `_extensionUnitGetLength` / `_setExtensionUnitID` — explicit UVC XU
  API. Confirms vector 2.2 is a productive path.
- `JCameraControl_changePreviewMode` — switches between preview modes
  (we currently only see the 640x360 preview). Setting this might
  unlock 1080p or 4K preview over RTSP.
- `JCameraControl_formatStorage1` / `_formatStorage2` — two format
  paths suggest two storages. The "second" one might be internal
  flash (i.e. the firmware partition).
- `JCameraConfig_disablePTPIP` / `_enablePTPIP`,
  `_disableSocketIO` / `_enableSocketIO` — runtime knobs to switch
  the SDK's transport. **Suggests there's a non-PTPIP transport
  (SocketIO?) we haven't seen.**
- `JCameraAssist_simpleConfig*` — known SmartConfig flow.
- `JCameraAssist_updateFw` / `_notifyUpdateFw` — firmware update,
  already on our list (step 1.3).
- `JCameraAssist_wakeUpCamera` — implies the camera can be "asleep"
  and woken via the network. Could be a magic packet or a property
  write.

### Followups derived from this mining

1. Probe `0xD617` directly — try `GetDevicePropDesc(0xD617)` and
   `GetDevicePropValue(0xD617)`. The camera may answer despite not
   advertising it.
2. Read `0xD700`, list its allowed enum values, then sweep them
   (step 1.1).
3. Read `0xD7AE`, see if writing values changes the codec of the
   `/MJPG` RTSP stream from H.264 → H.265.
4. Look up the AES key used in the verify path (likely
   `echo1234echo1234` from prior simpleConfig RE, or one of the keys
   in libcontrol.so strings — `attri_key`, `keydata`).
5. Implement the verify handshake in `larkfly` and see if any
   property descriptors change after running it.
6. Test `triggerCapturePhoto` style photo path — find the underlying
   PTP op (read the disassembly around `Libptp2Client::triggerCapturePhoto`
   in `libcontrol.so`).
7. Investigate the "SocketIO" path hinted at by
   `JCameraConfig_disableSocketIO`. If there's a Socket.IO-style
   transport, it would be on a port other than 15740 / 554 / 21 —
   but our port scan ruled out everything in 1-65535. So it's
   probably **a multiplexed transport over one of the known ports**,
   or it's app-side only.

## 1.1a — Targeted 0xD617 / 0xD700 / 0xD7AE probe (done)

| Prop      | Direct PTP read result                                |
| --------- | ----------------------------------------------------- |
| `0xD617`  | `0x200A DeviceProp_Not_Supported` — **confirmed hidden** until the verify handshake unlocks it. Cannot read or describe it from a fresh session. |
| `0xD700`  | UINT32, **READ-ONLY**, enum `{1, 3, 7}`, current = 7. Distinct from `0xD604`. Likely a "system state" register the firmware updates internally. |
| `0xD7AE`  | UINT32, **READ/WRITE**, current = 30, enum has 9 slots **all equal to 30**. Firmware stubbed out the HEVC option; only 30 fps is selectable. Won't unlock H.265 from here. |

## 1.1b — Sweep of 21 unmapped properties (done)

Read via `GetDevicePropDesc` against the live camera. Raw JSON saved
in `/tmp/d7xx_walk.json` (move to `analyses/data/d7xx_walk.json`
when the campaign is over).

| Prop      | DT      | R/W | cur   | factory | shape / enum                                  | inferred role                       |
| --------- | ------- | --- | ----- | ------- | --------------------------------------------- | ----------------------------------- |
| `0xD700`  | UINT32  | R   | 7     | 3       | enum `{1, 3, 7}`                              | camera state register               |
| `0xD704`  | UINT32  | R   | 1     | 1       | enum `{0, 1}`                                 | ready / online flag                 |
| `0xD720`  | UINT32  | RW  | 0     | 0       | enum `{0, 60, 180, 300}` (seconds)            | **auto-off / sleep timer** (1/3/5 min) |
| `0xD723`  | UINT32  | RW  | 0     | 0       | enum `{−2, −1, 0, 1, 2}` (as signed)          | EV compensation / brightness        |
| `0xD724`  | UINT32  | RW  | 0     | 0       | enum `{0, 1}`                                 | boolean flag (currently OFF)        |
| `0xD725`  | UINT32  | RW  | 0     | 0       | enum `{0, 60, 180, 300}`                      | another auto-off timer (LCD?)       |
| `0xD726`  | UINT32  | RW  | 0     | 0       | enum `{0, 2, 4, 6, 10, 15}`                   | self-timer / burst count (seconds)  |
| `0xD727`  | UINT32  | RW  | 1     | 0       | enum `{0, 1}`                                 | boolean flag (currently ON)         |
| `0xD75F`  | UINT32  | RW  | 1     | 1       | enum `{0, 1}`                                 | boolean flag (currently ON)         |
| `0xD7AB`  | UINT32  | RW  | 335636492 | … | enum [all identical to 335636492]             | `0x14010E0C` — looks packed (date / version) |
| `0xD7AC`  | UINT32  | RW  | 1     | 1       | range [1, 1, 1]                               | fixed (placeholder)                 |
| `0xD7AD`  | UINT32  | RW  | 1     | 1       | range [1, 1, 1]                               | fixed                               |
| `0xD7AE`  | UINT32  | RW  | 30    | 30      | enum [9× 30] — see 1.1a                       | fps (HEVC stub)                     |
| `0xD7F0`  | UINT32  | R   | 1     | 1       | enum `{0, 1}`                                 | boolean status                      |
| `0xD7FC`  | UINT32  | RW  | 1     | 1       | enum `{0, 1}`                                 | boolean (currently ON)              |
| `0xD7FD`  | UINT32  | RW  | 0     | 0       | range [0, 153600, step 0xFFFFFFFF]            | unused / freeform numeric           |
| `0xD7FE`  | UINT32  | R   | 204   | 100     | range [0, 153600, step 1]                     | counter (drifts on read)            |
| `0xD7FF`  | UINT32  | RW  | 1     | 1       | enum `{0, 1}`                                 | boolean (currently ON)              |
| `0xD801`  | STR     | R   | `G:\SPHOST.BRN`             |                                | **firmware filename on internal flash** |
| `0xD83E`  | STR     | RW  | `G:\SPHOST.BRN`             |                                | same path, writable — possibly the "next firmware to install" pointer |
| `0xD83F`  | —       | —   | error |         | `rc=0x2002 General_Error` on `GetDevicePropDesc` | exists but reads fault — likely a write-only setter |

### Critical finding — `G:\SPHOST.BRN`

The camera's firmware ships at the Windows-style path `G:\SPHOST.BRN`
on what it considers its internal flash (drive letter `G:`). This is
the standard iCatch firmware blob name (`SPHOST` = SP host firmware;
`.BRN` is iCatch's "burn image" extension — the bootloader writes
this file's contents into NOR flash on update).

Two crucial implications:

1. **SD-card autorun filename (Vector 2.5):** placing a file named
   `SPHOST.BRN` at the SD-card root is overwhelmingly likely to be
   the trigger the iCatch bootloader looks for to enter
   firmware-update mode. This is the single highest-value
   filename to fuzz with at Step 2.5. (Brick warning: this is
   exactly the kind of file we said we'd start with empty/junk
   payload, not real firmware.)
2. **`0xD83E` is RW** and contains the same path. Writing a
   *different* path to it (e.g. `H:\TEST.BRN`) and rebooting would
   confirm the bootloader honours that pointer — and, if so, may
   let us redirect the firmware load to anything we can stage.

### Candidate "debug-flag" properties

Among the RW booleans, three are factory=0 but currently 1
(`0xD727`, `0xD83E`-ish) or factory=1 but worth flipping
(`0xD75F`, `0xD7FC`, `0xD7FF`). Without writes, we don't know what
any of them control. Plan 1.1c will set each in turn, observe the
side effects (LED, RTSP stream change, FTP listing change, PTP event
0xC601), and restore. Even one revealing "verbose log" or "factory
mode" would be a win.

## 1.1c — SD config-fuzz (rounds 1 + 2, done — negative)

We dropped 16 candidate sentinel/config files at the SD root via the
PTP `SendObject` write path proven in 1.4 — and ran two full reboot
cycles. **The camera ignored every one of them.** Specifically:

**Round 1** (7 files at SD root):
`DEBUG.CFG`, `TELNET.CFG`, `SVC.CFG`, `SYS_SET.CFG` (text, with
`enable=1`/`telnet=1`-style keys), plus 3 zero-byte sentinels
`ENG.MODE`, `FACTORY.MODE`, `DEBUG.ENABLE`. Result: text files
unchanged after reboot, no new TCP ports, no new files. Note: the
3 zero-byte sentinels turned out **not to persist** — PTP
`SendObject` with a 0-byte payload returns OK but doesn't actually
create a FAT entry. Only the 4 text files were genuinely tested.

**Round 2** (9 files: retest sentinels + new candidates + subdir):
- Sentinels with 2-byte payload (`"1\n"`): `ENG.MODE`,
  `FACTORY.MODE`, `DEBUG.ENABLE` — now persist on FAT.
- Alternate filename patterns: `SETTING.DAT`, `USERSET.CFG`,
  `BOOTCFG.TXT`, `AUTOEXEC.BAT`, `SCRIPT.TXT`.
- Subdir mirror of the H9R internal-flash layout: `/ADF/SYS_SET.CFG`.

All 9 files identical timestamps + sizes after reboot. **No
behavior change anywhere**: TCP still 21/554/15740, UDP silent,
PTP enumeration unchanged.

### Conclusions

The camera firmware's boot-time SD-card scan is **strictly** for:

1. **`SPHOST.BRN` at SD root** → triggers FW UPDATE menu
   (confirmed earlier).
2. **DCF-style media** (`/VIDEO/*.MOV`, `/JPG/*.JPG`) → re-indexed
   into the PTP object database.

Nothing else is processed. No magic "debug mode" filename, no
override config path, no `/ADF/`-mirror trick. The dev console
gate is **not** SD-side-openable.

### Bonus findings from the fuzz work

- **FTP `DELE` works.** The chroot is actually a listing filter
  only — FTP allows file CREATE (via STOR, untested) and DELETE
  (confirmed via cleanup). The unauthenticated `wificam:wificam`
  FTP login plus PTP `SendObject` give us TWO independent paths to
  modify the SD-card filesystem at will.
- **FTP `RMD` works** (we deleted the `/ADF/` directory we'd
  created via PTP).
- **PTP can create directories** (object format `0x3001`
  Association). `SendObjectInfo` with `parent=0` and
  `object_format=0x3001` creates a directory at SD root that PTP
  and FTP can both navigate.
- **PTP-created objects don't survive a reboot** in the PTP index.
  The underlying FAT entries persist, but on boot the camera does
  a fresh `D:` scan and only re-catalogs DCF-style media into PTP
  handles. So `GetObjectHandles` after a reboot returns just the
  original 5 items, even though FTP can see everything else.
- **FTP listing hides 0-byte files but `SIZE` reports them** (or
  reports `550` if truly missing). Useful for testing whether
  `SendObject` writes actually persisted.

### Remaining surfaces for a dev console (after config-fuzz ruled out)

- **Capture a V11-specific `SPHOST.BRN`** via the iSmart DV2
  firmware update flow (step 1.3). Then patch it to call
  `telnetd_start()` at boot. Push via the same PTP `SendObject`
  path we proved in 1.4 / 1.5b. This remains the only network-side
  path to a dev shell — but **high brick risk** without a recovery
  procedure (we don't have a V11-compatible `FRM.exe`).
- **PTP property writes** on the unmapped 0xD7xx block — try
  flipping each boolean RW property in turn and watch for service
  changes. Lower-yield: most probably control mundane camera
  settings (auto-rotate, beep, etc), not debug enables. We have
  catalog `analyses/data/d7xx_walk.json` to drive this.
- **`0xD83E` rewrite + reboot** — change the firmware path string
  (currently `G:\SPHOST.BRN`) to something else and see whether the
  bootloader honours the override. If yes, we can redirect the
  flash read at boot. Risky but informative.
- **`0xD83F` write-only check** — `GetDevicePropDesc(0xD83F)`
  returned `0x2002 General_Error`, suggesting it's write-only. Try
  `SetDevicePropValue` with various payloads.
- **`0xD617` via verify handshake** — implement the AES verify
  handshake in `larkfly` (per the libcontrol.so error-string trail)
  and see whether properties that 404 today become readable after
  the verify completes.
- **Hardware (Vector 3)** — UART/SPI/JTAG, currently deferred.

## 2.1 / 2.2 — USB enumeration + UVC XU decode (done)

### USB mode landscape

The camera presents at least **two distinct USB modes** with
different `idProduct` values. Mode selection is via the camera's
on-screen menu when plugged in:

| Mode    | VID:PID         | Class                                  | What it gives us                                          |
| ------- | --------------- | -------------------------------------- | --------------------------------------------------------- |
| MSC     | `2aad:6371`     | USB Mass Storage (8 / SCSI / Bulk)     | SD card as `/dev/sda` block device + auto-mount; vendor SCSI command surface (see 2.2c). WiFi is OFF in this mode. |
| UVC     | `2aad:6373`     | Video class + Audio class              | `/dev/video0` v4l2 device with H.264/MJPG/YUYV; XU vendor controls (see 2.2b). WiFi is OFF. |
| (Recovery — hypothetical) | unknown | iCatch bulk-camera class | Per Eken/AKASO community: triggered by holding a button while plugging in. Talks the iCatch bootloader protocol that `FRM.exe` drives. **Not yet found on our V11.** |

### 2.2a — Raw USB enumeration (done)

`lsusb -v -d 2aad:6371` (MSC mode): single bulk-only interface, 2
endpoints (EP 2 IN, EP 3 OUT, 512 B each). Vendor "Sport Cam",
Product "Sport Cam", Revision "00.0", Serial "00.00.01".

`lsusb -v -d 2aad:6373` (UVC mode): IAD for Video (interfaces 0+1)
plus IAD for Audio (interfaces 3+4 with 8 alternate settings).
Video formats: H.264 1080p30/15 + 720p30/15, MJPEG same matrix,
YUYV up to 1080p5 / 640x480 @ 30. Audio: PCM 16-bit mono at 48 kHz
with bitrate selectable via alt setting (32-224 B/packet).

### 2.2b — UVC vendor extension unit (done)

XU at GUID `63610682-5070-49ab-b8cc-b3855e8d221d`, Unit ID 3, on
Interface 0 (Video Control). Probe via `tools/uvc_xu_probe.py`.

Descriptor declares `bNumControls = 0` (lies) but `bmControls`
bitmap has all 32 selectors enabled. Of the 32, only **5 are
actually implemented** (raw data: `analyses/data/uvc_xu_dump.json`):

| Sel | Len | Caps     | Behavior                                                                  |
| --- | --- | -------- | ------------------------------------------------------------------------- |
| 1   | 2 B | GET/SET  | **Response/status register.** `byte 0 = 0x01` always ("ready"); `byte 1 = echo of byte 1 of the last command written to sel 6`. SET attempts to write zero are silently rejected. |
| 2   | 1 B | GET/SET  | Stable 8-bit value (currently `0x08`); purpose unknown.                   |
| 3   | 4 B | GET/SET  | Two u16-LE fields packed as `[width, height]`; currently `1280x720`. Writes stick — we tested `1920x1080` and it persisted. |
| 4   | 1 B | GET/SET  | Currently `30`. Almost certainly **frame rate**.                          |
| 6   | 8 B | GET/SET  | **Command pipe.** Writes succeed; reads always show zeros (camera consumes the command and clears the buffer). Confirmation lands in sel 1's low byte. |

The sel 6 command pipe is the most interesting surface, but the
8-byte command opcodes the firmware accepts are not documented and
we have no way to enumerate them without USB capture of iSmart DV2.

### 2.2c — MSC vendor-SCSI command surface (partially mapped)

When the camera is in MSC mode it exposes vendor SCSI commands on
`/dev/sg0` alongside standard READ/WRITE. We extracted the command
ID table from `libusb_transport.so` disassembly:

| Method                | Cmd ID  | Notes                                                  |
| --------------------- | ------- | ------------------------------------------------------ |
| `startMovieRecord`    | `0x06`  |                                                        |
| `stopMovieRecord`     | `0x07`  |                                                        |
| `capturePhoto`        | `0x08`  | The photo trigger that PTP can't drive                 |
| `switchToPlayback`    | `0x09`  |                                                        |
| `switchToPreview`     | `0x10`  | Also reported for `getCurrentMode` (probably same op with different semantics) |
| `setEventTrigger`     | `0x12`  |                                                        |
| `setAudioMute`        | `0x13`  |                                                        |
| `setAudioUnMute`      | `0x14`  |                                                        |
| `setSeamless`         | `0x15`  |                                                        |
| `formatStorage`       | `0x16`  | Destructive                                            |
| **`updateFw`**        | `0x17`  | **The USB equivalent of FRM.exe** — direct firmware flash without going through `SPHOST.BRN`. Same brick risk as the SD-card path. |

All commands use a 4,147,200-byte data buffer (1920×1080×2 — full
frame), confirming this is the unified-photo-buffer SDK pattern.

CDB byte layout extracted from `prepareScsiCDB` disassembly:
`CDB[0] = scsiCmd; CDB[1..2] = extendCmd (u16 BE); CDB[3..6] = parameter1; …`

**However** — `getUsb_Transport_ScsiCommandInfo(cmd_id)` does a
dynamic `std::map` lookup to translate cmd_id → CDB fields, with the
map populated at runtime. The cmd_id → SCSI opcode mapping is not a
static table we can read off, and brute-force probing fails because
the camera's MSC bridge **silently returns INQUIRY-shaped data for
any unrecognized opcode** (verified via two-round probe — see
`analyses/data/msdc_scsi_probe.json` and `..._probe2.json`).

### 2.2d — Where the USB hunt bottlenecks

We have two ready USB attack surfaces — UVC sel-6 command pipe and
MSC vendor SCSI — and proven Sing/Get plumbing for both. What we
**don't** have is the wire format of the actual commands. The
remaining unknowns:

- UVC: the 8-byte sel-6 command opcode dictionary.
- MSC: the SCSI CDB bytes (`scsiCmd`, `extendCmd`, `parameter1`)
  for each of the 12 enumerated command IDs.

Both can only be cracked by **capturing the iSmart DV2 app talking
to the camera over USB**: an Android phone + USB OTG cable + the
laptop running `usbmon` while bridging. That's also step 1.3 in the
plan, with the same prerequisites.

And critically: even if we had both wire formats, the **endgame is
the same** — flash a patched firmware. Without acquiring a V11
`.BRN` (only available through iSmart DV2's update flow), we can't
patch anything. So **step 1.3 remains the gating step for the entire
dev-console hunt**, with or without USB.

## Final state — what's done, what's left

**Confirmed reachable (won't help directly):**
- Network: PTP, RTSP, FTP — fully mapped, no dev surface
- USB MSC: SD-card access, vendor SCSI command framework
- USB UVC: 5 XU controls including command pipe (sel 6)
- Bootloader's SD-card firmware-update menu (`SPHOST.BRN` trigger)

**Implemented in the firmware but ungated/undocumented:**
- `telnetd` (in code, not auto-started)
- TI NDK command shell (in code, not network-exposed)
- AES verify handshake → unlocks property `0xD617`

**Sole remaining productive paths (all converge on step 1.3):**
1. **Acquire a V11 `.BRN`** via iSmart DV2 firmware-update wire
   capture. Without this, every other path is blocked.
2. Patch the .BRN to enable `telnetd` at boot, or to dump UART
   output to SD, or to skip the AES verify and unlock `0xD617`.
3. Push the patched .BRN via either:
   - SD-card `SPHOST.BRN` trigger (slow, requires SD removal on
     failure), or
   - SCSI `updateFw` (cmd ID 0x17) once we have its full CDB bytes.

**Brick recovery:** 8-second power-hold after battery pull
(community-known), or `FRM.exe` USB recovery mode (we don't have a
V11-compatible binary). Risk floor is non-trivial.

## 1.2 — 0x9805 decoded (done)

Index file: `analyses/data/op_9805_code_index.json`.

The 1388-byte response is **bulk MTP `ObjectPropList`** — exactly the
same role as PTP op `0x9805 GetObjectPropList` in the upstream MTP
spec. Records use prop codes in the `0xDCxx` namespace (StorageID,
ObjectFormat, ObjectFileName, ParentObject, DateCreated, etc.), not
the camera's `0xD6xx`/`0xD7xx` device-property namespace.

Record-group boundaries match exactly the 5 PTP object handles we
enumerated via `GetObjectHandles`:

- Objects 1, 2 (positions 8 and 126, 118-byte groups): the two
  directories `/VIDEO` and `/JPG`. They expose 8 properties each —
  no `DateCreated`/`Width`/`Height`/`Duration` because they're
  directories, not media files.
- Objects 3, 4, 5 (positions 252, 632, 1012, 380-byte groups): the
  three `.MOV` files. They have the full 13 properties including
  `0xDC87`/`0xDC88` (likely Width/Height) and `0xDC89` (likely
  Duration or another media metadata).

**Verdict for our hunt:** 0x9805 is not a device-debug path. It's an
optimization that lets the app fetch all file metadata in one round-trip
instead of N round-trips. **No hidden device properties live here.**
The hidden surface remains exactly: `0xD617` (verify-gated) and
whatever the firmware update flow exposes (step 1.3).

## 1.4 — PTP write access (done) — **MAJOR BREAKTHROUGH**

`SendObjectInfo` + `SendObject` against storage `0x50001` work
without authentication. We:

1. Created `TEST.TXT` at SD root (parent=0) with payload `"test\n"`.
   - `SendObjectInfo` returned `rc=0x2001, rp=[0x50001, 0x0, 0x6]`
     (new handle 0x6).
   - `SendObject` returned `rc=0x2001`.
   - Read-back via `GetObject(0x6)` returned the exact bytes.
   - **The file appeared in FTP listing of `/`** — even though FTP's
     default `LIST /` had previously shown only `/VIDEO` and `/JPG`.

2. Created `INVIDEO.TXT` *inside* `/VIDEO` (parent=handle 0x1).
   - Also `rc=0x2001` with new handle 0x7.

3. Tried path-traversal in the filename (`../ESCAPE.TXT`).
   - Accepted at the PTP level but the FTP listing didn't show
     anything escaped — firmware sanitizes the filename string.

4. `DeleteObject(handle, 0)` cleanly removes objects.

Implications:

- **The FTP chroot is a listing filter, not a real chroot.** Any file
  PTP creates at parent=0 is visible at FTP `/` if you list it.
- **PTP write access can place arbitrary filenames at the SD-card
  root without a card-reader.** This collapses much of Vector 2.5
  (SD-autorun fuzzing) into a network-only operation: drop a file,
  ask the user to power-cycle, observe.
- The MOV file handles (0x3, 0x4, 0x5) report `parent=0x0`, not
  parent=handle-of-/VIDEO — so the PTP and FTP views of the
  directory hierarchy are *not* the same tree. PTP sees a flat
  namespace with directories as parallel objects; FTP organises by
  filesystem.
- The single advertised storage is `0x50001`. `StorageInfo` reports
  ~261 MB total / ~260 MB free — small enough that this is likely
  the **internal SP-host partition** (`G:` in the firmware's path
  strings), not the user's SD card. Confirms `G:\SPHOST.BRN` lives
  here. The MOVs we see may be on a separate FAT volume that the
  camera mounts on demand and exposes via the same handle space.

### Step 1.5b — `SPHOST.BRN` drop-test (planned, not executed)

The plan: use PTP `SendObjectInfo` to create `SPHOST.BRN` at
parent=0 (SD root) with a zero-byte payload. Then power-cycle the
camera and observe.

Reasoning: `SPHOST.BRN` is the firmware filename the iCatch
bootloader looks for on internal flash. If the bootloader also scans
SD card for an updated `SPHOST.BRN`, a zero-byte file is *not* a
valid firmware blob — any sane bootloader will checksum-fail and
either ignore it or show a "bad firmware" message. No flash write
should occur. If the camera shows an update screen or any new
behaviour, we know the trigger filename and can iterate on payload
shapes. If nothing changes, try variants (`UPDATE.BIN`, `MV.BIN`,
`MERGEFW.BIN`, the libcontrol `iCatch` string-prefixed names).

Cleanup after the test: PTP `DeleteObject` removes the file
remotely.

### Result — confirmed bootloader trigger

We dropped an empty `SPHOST.BRN` (0 bytes) at SD root via PTP. On
power-up the camera displayed a **"FW UPDATE  Yes / No"** menu —
i.e. the iCatch bootloader scans the SD card root for that exact
filename and, if present, enters firmware-update mode before normal
boot.

Selecting **No** powers the camera off instead of falling through
to normal boot — the bootloader treats SPHOST.BRN's presence as
"stay in update mode until either consumed or removed". Recovery
required pulling the SD card and deleting the file by hand, then
booting without it.

We did **not** select Yes (would have attempted to flash a 0-byte
"firmware" over the working internal blob; very plausible brick).

This is the strongest dev-console-shaped lead so far:

- We now have a definitive **trigger filename** (`SPHOST.BRN`) for
  the iCatch bootloader's firmware-update path.
- The bootloader has a **screen-rendered UI** outside the main
  firmware (Yes/No menu before main boot), which means we know it
  has at least minimal HID code reachable independently of the
  application firmware. Not a shell, but a confirmed pre-boot
  surface we can talk to via SD presence.
- The update flow is hard-anchored to an SD-card file — so if we
  obtain a real `SPHOST.BRN` (e.g. via the iSmart DV2 wire capture
  in step 1.3) and modify it to enable a debug shell, we can push
  that via the same PTP `SendObject` mechanism we just proved
  works.

### Critical safety lessons recorded

- **Never write `SPHOST.BRN` to the SD without an immediate, tested
  recovery plan.** The boot menu loops; selecting No powers off
  instead of skipping update. Recovery currently requires pulling
  the SD card.
- **Empty `SPHOST.BRN` is not a no-op** at the menu level — the
  bootloader prompts as soon as it exists, regardless of payload.
  We didn't get as far as the actual flash attempt, so we don't
  know whether the bootloader checksum-validates before writing
  (probably yes — iCatch firmware blobs have CRC headers — but
  unconfirmed).
- **PTP DeleteObject is the safe cleanup path** while the camera is
  still on the WiFi. We didn't get to use it this run because the
  camera shut off before we could reach it; future runs should
  either (a) leave the camera running and connected before the boot
  test, or (b) drop the file, immediately shut down the camera, and
  do the boot test in one cycle.
- **Brick-recovery trick (from upstream EKEN H9 community):** pull
  the battery for 5 s, re-insert, then hold the power button for
  ≥8 s. This is a hardware-level reset that the EKEN H9 community
  documented as the "freeze recovery" path on the same iCatch SDK
  family. Worth trying first if the camera ever appears bricked,
  before reaching for the Vector-3 hardware tools.
- **iCatch ships a Windows tool `FRM.exe`** that fully restores a
  bricked camera via USB by talking to the bootloader's USB
  recovery mode (the camera enumerates as "Icatch(X) KX Series Bulk
  Camera Device"). Requires the SPCA6350 drivers (for V35/V37
  family — our V11 may have a different identifier but the recovery
  *concept* — USB bootloader mode — is likely shared). If we ever
  get desperate, this is the official rescue path.

### Followups

12. **Get a real `SPHOST.BRN`** — step 1.3 (iSmart DV2 firmware
    update wire capture) is now the highest-leverage next move.
    With a real firmware blob we can:
    - `binwalk` it to find filesystems, init scripts, telnet
      binaries, etc.
    - Patch it to enable a debug surface (telnet, UART output) and
      push the patched copy via the same PTP path we proved.
13. **Filename-variant fuzz** (only with the camera prepared for a
    full reset cycle): try `MERGEFW.BIN`, `MV.BIN`, `UPDATE.BIN`,
    `ICATCH.BRN`, lowercase versions, etc. Most likely only the
    literal `SPHOST.BRN` works (the libcontrol.so string is exact),
    but a quick fuzz confirms.
14. **Bootloader-banner inspection** — the FW UPDATE menu must be
    drawn by the bootloader. Does it show any version string,
    serial number, or build identifier on screen alongside Yes/No?
    Worth photographing the menu next time.
15. **Confirm whether a non-empty payload changes the menu**, e.g.
    256 bytes of random — does the bootloader still show Yes/No,
    or does it pre-validate the header and skip the menu entirely?
    Each test is one battery / SD swap cycle.

## 1.5c — Eken H9R reference firmware binwalk (done)

Source: `https://github.com/hevnsnt/EKEN-FIRMWARE` →
`H9R-720P120FPS-160627LY.rar` →
`Card update/SPHOST.BRN` (8 578 266 bytes).

**Different chipset than ours** — the Eken H9R is iCatch
SPCA6350 (V37 family) running ThreadX RTOS on MIPS32_4Kx. Our
Larkfly is V11 (different SoC, likely different OS). But the
iCatch SDK is shared between V-series chipsets, so the binwalk
gives us strong hints about what the V11 firmware almost certainly
contains too.

### `.BRN` container format

| Offset      | Bytes / value                            | Meaning                                      |
| ----------- | ---------------------------------------- | -------------------------------------------- |
| `0x000000`  | `"SUNP BURN FILE\0\0"` (16 bytes)        | Magic header — SUNP = Sunplus, iCatch's parent |
| `0x000010`  | `da e4 82 00 00 06 09 00 ...`            | Likely size + offset table — needs more RE |
| `~0x000200` | start of code/data                       | Bootloader / RTOS payload                   |
| `0x09038C`  | "Copyright (c) 1996-2005 Express Logic Inc. * ThreadX MIPS32_4Kx/GNU Version G4.0c.4.0 *" | First ThreadX banner |
| `0x185720+` | JPEG / TIFF assets                       | Splash screens + UI icons                    |
| `0x6F85A4+` | AES S-Box & inverse                      | AES tables (used by verify-handshake)        |
| `0x76FC1B`  | hostapd copyright (Jouni Malinen)        | hostapd from open-source                     |
| `0x797E7C`  | bash shebang #1                          | Embedded DRAM bandwidth-monitor script       |
| `0x82D8A4`  | ThreadX banner #2                        | Second copy / second region                  |
| `0x82E410`  | `"DRAMPAR1"` + last bytes                | DRAM parameter footer                        |

### Things baked into iCatch firmware (confirmed via strings)

- **`telnetd session closed`** — telnetd implementation is present
  in the binary. The fact this string exists strongly implies a
  `telnetd_start()` (or NDK equivalent) is linked in too.
- **TI NDK command shell** at `ndk/ndk_common.c` and
  `ndk/ndk_cmd.c`. Banner text: `NDK Command List:` / `NDK command
  shell`. Built-in commands include `sw`, `dbglvl`, `Memory`,
  `Restart monitor.`, `exit/quit`. Plus extensive sensor-tuning
  CLI (`agclist`, `pvexp`, `pvagc`, `explist`, `dual` — full image
  pipeline control).
- **hostapd + wpa_supplicant** — full open-source builds linked in
  (`_ndk_wpas_start_daemon`, `__ndk_hapd_start`, `call hostapd_cli`,
  `call wpa_cli`, `wpas_conf`, `wext`).
- **Realtek MP/production-test mode** — `iwpriv wlan0 mp_start`,
  `mp_query_psd`, `oid_rt_pro_start_test_hdl`. This is the
  manufacturing test mode for the WiFi chip; if reachable, it
  exposes raw chip-level operations.
- **EFUSE access** — `EFUSE WRITE`, `EFUSE READ` ioctls. eFuse is
  one-time-programmable chip memory; if writable, this is a
  hardware-level surface.
- **FTP daemon** (`_ndk_ftpd_start`) — confirms FTP runs through
  NDK. Command-line options exist: `ftpd -x(exit) -pnnn(port
  number) -rdir(root dir) -T(TUTK)`.
- **`ftpd -T(TUTK)`** — TUTK is a cloud streaming protocol. The
  FTP daemon can be configured to route through TUTK. Not used on
  our V11 (no Internet access from camera AP mode) but worth
  knowing.
- **MIPS32_4Kx GCC build** — confirms toolchain. Our V11 may use a
  different MIPS / ARM build, but the build conventions are
  similar.
- **Reads `D:\` (SD card) at runtime for many files** — `AE_RUN.TXT`,
  `AWB_WIN.RAW`, `BAT_CURV.TXT`, `bayer*.raw`, `bin.bin`,
  `CIPA_LOG.TXT`, `CP_LV*.TXT`, `D:\edgewin_testmode.yuv`,
  `D:\2.JPG`, `D:\AGCTSCAN.TXT`. These are debug / calibration
  files that the firmware *writes* to SD when in certain test
  modes, OR reads as alternative-source overrides. Worth fuzzing
  with empty placeholder versions to see which trigger modes.

### Plain-text config files in the .BRN that mirror SD overrides

| File              | Format    | Notable contents                                       |
| ----------------- | --------- | ------------------------------------------------------ |
| `A:\ADF\VER.CFG`  | plain text | `ActionCam H9R\n160627LY` — model and build           |
| `A:\ADF\SSID_PW.CFG` | plain text | 2 lines: SSID, then 10-digit password (`1234567890` — iCatch default across the family) |
| `A:\ADF\SYS_SET.CFG` | plain text | 18 key-value pairs — videosize, loopvideo, language, etc. No `debug`/`telnet` keys in *this* firmware. |
| `A:\ADF\HAPD0.CFG`   | hostapd config | Full hostapd conf — driver=rtl871xdrv, hw_mode=g, wpa_key_mgmt=WPA-PSK. Has commented `ctrl_interface=hapd`. |
| `A:\ADF\ZOOM_SET.CFG` | plain text | Sensor type 4689, zoom factors |
| `A:\ADF\APMODE.CFG` | 1 byte | `0x32` (= ASCII '2')                                   |
| `A:\ADF\ADF.BIN`    | binary 24 B | Packed flags                                       |
| `B:\UDF\UDF.BIN`    | binary 16 B | `0e 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e fe` — increment sequence; likely a calibration / index table |
| `B:\UDF\CUSTOMER_ID.CFG` | 16 B | `## #$##!.## "!!%` — looks like a packed/printable serial |

These are the firmware's **factory-default copies**. The camera
also has writeable versions at runtime that get persisted across
reboots and override the defaults.

### Implications for V11 dev-console hunt

The Eken H9R is NOT our chipset, but the iCatch SDK ships these
components across the V-series:

- A `telnetd` is almost certainly linked into our V11 firmware too.
- An NDK shell with a similar command set is almost certainly
  present.
- The shell is gated off-by-default in our V11 (we proved no TCP
  ports beyond 21/554/15740 listen).
- The gate is likely either: a config file knob in SYS_SET.CFG or
  similar; a vendor PTP op that calls `__ndk_telnet_start`; or a
  UART command at boot.

To open the gate we need either:
- A V11-specific .BRN we can patch (to force `telnetd_start` at
  boot). Capturing one via the iSmart DV2 update flow is the only
  network-side path — step 1.3.
- UART boot console access (Vector 3 hardware — currently out of
  scope per user).
- A config-fuzz campaign: write candidate SYS_SET.CFG keys (`debug
  1`, `telnet 1`, `console 1`, `service 1`, …) to the camera's
  filesystem via PTP and reboot, see if any flip the gate. Each
  failed key costs one reboot.

### Brick-recovery now better understood

The iCatch SDK has a USB recovery path: the bootloader (when in
trouble) enumerates as `Icatch(X) KX Series Bulk Camera Device` and
the Windows tool `FRM.exe` (shipped in the same .rar) talks to it
to reflash. The same .rar carries the SPCA6350 USB drivers. If we
ever brick our V11 via a botched `SPHOST.BRN` push, the recovery
path is:

1. Hold power for 8 s after a battery pull (community-known reset).
2. If that fails, the camera's bootloader USB-recovery mode is the
   official rescue — but we'd need V11-compatible `FRM.exe` +
   drivers, which we don't have.

That second path is the brick-risk floor: if step (1) fails, we
have no remote recovery for our V11 specifically. Worth weighing
before any patched-firmware push.
