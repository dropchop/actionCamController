# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo actually is

A reverse-engineering project against the **Larkfly A6+** action camera (iCatch SoC, internal product code `V11`, firmware `20251206`). The `larkfly/` Python package is the production output; everything else (`tools/`, `analyses/`, `apk-analysis/`) is investigation infrastructure that produced it. Treat investigation tools as one-shot artifacts — the conclusions they reach get folded into `docs/findings.md` and the `larkfly` code, and the tools live on as reproducible references rather than as code to be polished.

**Read `docs/findings.md` before changing anything in `larkfly/`.** The protocol-level behavior is non-obvious, off-spec, and has cost us multiple wasted experiments to characterize. The README has a high-level summary; `findings.md` has the wire details.

## Quick commands

```bash
# Install (core lib is pure stdlib; extras pull in Flask + cryptography)
pip install -e '.[all]'

# Run the test suite (stdlib unittest, NOT pytest)
python3 -m unittest tests/test_protocol.py

# Run a single test
python3 -m unittest tests.test_protocol.TestContainerFraming.test_encode_container

# Smoke-test against a live camera (the prerequisite for everything else)
python3 tools/ptpip_probe.py 192.168.1.1 --bind 192.168.1.10
```

There is no linter or formatter configured. Tests have no external deps — the codec is pure-stdlib by design.

## Architectural facts that take multiple files to discover

### iCatch wire-format quirks (in `larkfly/protocol.py`)

The camera speaks PIMA 15740-2 PTP/IP, but with **four** undocumented departures from spec. Any naïve client breaks immediately:

1. **`InitCmdReq` initiator-name has no length prefix** — raw UTF-16LE + null, NOT PTP-string format.
2. **The initiator name is whitelisted** to `"localhost"` or empty. Any other name → `InitFail reason=3`.
3. **PTP-IP packet type 12 = `EndData`** (not `Cancel`). The PTP-IP supplement is ambiguous; iCatch + libgphoto2 use this interpretation. A client with `Cancel=12 / EndData=11` silently drops every data phase.
4. **`SendObjectInfo.Filename` needs a 4-byte alignment header** after the length byte. Standard PIMA is `[u8 len] + [UTF-16LE chars]`; iCatch is `[u8 len] + [4 zero bytes] + [UTF-16LE chars]`. Without padding, every uploaded filename loses its first 2 characters (`SPHOST.BRN` → `OST.BRN`, etc.). The quirk is **specific to this one field** — `SetDevicePropValue` for STRING properties uses the spec encoding. Use `larkfly.protocol.encode_ptp_string_icatch_objinfo()` for ObjectInfo filenames only.

All four are handled in `larkfly/protocol.py`. Tests in `tests/test_protocol.py` cover them.

### Session-state quirk

The camera persists PTP session state across TCP disconnects. Opening a fresh socket and sending `OpenSession` returns `DeviceBusy (0x201E)` if the prior session never sent `CloseSession`. `larkfly.Camera.connect()` auto-recovers by sending `CloseSession` then retrying. Don't reimplement this naively.

### Recording paradigm — NOT what PTP suggests

The camera advertises `InitiateOpenCapture (0x101B)` but doesn't use it for video. **Video recording is controlled by toggling property `0xD604`**: write `17` to start, `1` to stop. `Camera.start_recording()` / `stop_recording()` wrap this. The advertised standard ops are red herrings.

Photo capture via `InitiateCapture (0x100E)` returns OK but produces no JPG on the SD card — unsolved. Use the physical shutter button as a workaround.

### Why `bind=192.168.1.10` shows up everywhere

The camera's AP uses `192.168.1.0/24`. Many home routers also use this subnet. When the host has multiple interfaces on the same subnet (built-in WiFi to home network + USB dongle to camera AP), unbound sockets pick the wrong interface. **All `larkfly.Camera` calls and tools take a `bind=` / `--bind` argument** to source-bind to the dongle IP. Always pass it.

### FTP visibility ≠ filesystem

The camera's FTP server (`wificam:wificam` on port 21) shows the SD card root, but with a stripped command set — only `SYST`, `LIST`, `RETR`, `STOR`, `DELE`, `RENAME` work. No `SITE`, no `HELP`. Root has 16+ factory test files (`FACTORY.RUN`, `MFG.CFG`, `MAC.CFG`, `SERIAL.CFG`, `CALIB.CFG`, etc.) that are inert decorations Larkfly forgot to remove before shipping — modifying them does nothing observable. PTP `list_objects()` is a different view: it filters to media files only (videos/photos), so SD-card text files won't appear there even though they exist.

## Landmines

**DO NOT upload a file named `SPHOST.BRN` via PTP `SendObjectInfo` with the corrected encoder.** This is the bootloader's firmware-update trigger filename. On next boot, the camera shows a "FW UPDATE Y/N" menu. If a user accidentally selects Y on a malformed file, the camera bricks. This was safe historically only because quirk #4 truncated the name to `OST.BRN` — now that the fix is in `larkfly/protocol.py`, the filename will actually land. Always `DeleteObject` after any SendObject test, and never test bootloader-trigger filenames without explicit recovery plan.

**Do not "fix" the `bind=` parameter as unnecessary.** It is necessary; see above.

**Do not assume PTP property writes that return `rc=0x2001 OK` actually persisted.** Three properties (`0xD75F`, `0xD7FC`, `0xD7FF`) silently reject writes — the response says OK but the value doesn't change. `tools/prop_write_probe.py` classifies properties correctly via write-and-revert.

**`tools/ptp_vendor_probe.py` will wedge the camera's PTP service** on three of the eight vendor opcodes (`0x9602`, `0x9802`, `0x9812`). It's crash-safe (per-request health check + `--resume`), but each wedge requires a power-cycle.

## Repo layout, focused on architectural roles

- **`larkfly/`** — production library. Pure-stdlib core. `protocol.py` = wire codec (where the four quirks live); `camera.py` = high-level orchestration; `types.py` = constants; `exceptions.py` = typed errors.
- **`webui/`** — Flask + OpenCV multi-camera viewer; orthogonal to the protocol work.
- **`tools/`** — operational utilities that talk to the camera live. `tools/README.md` is the canonical catalog. New diagnostic scripts go here; promote findings into `larkfly/` once stable.
- **`analyses/`** — offline RE scripts + their data outputs. `analyses/data/*.json` are large reference dumps (property catalog, vendor probe matrix, 0x9805 binary). Don't re-generate without reason.
- **`docs/`** — `findings.md` is canonical; `dev-console-hunt.md` is the running log of the shell-access hunt; `untried-vectors.md` is the forward-looking attack inventory; `archive/` is the chronological RE story.
- **`apk-analysis/`** — gitignored. Contains the iSmart DV2 APK, jadx/apktool output, and the SDK's native libs. Re-extract via `apktool` if missing.

## Conventions worth knowing

- Hex codes in code and docs use uppercase: `0xD75F`, `0x501E`. Lowercase appears only in raw byte dumps.
- Property codes start with `0xD` (vendor) or `0x5` (standard PTP); opcodes start with `0x9` (vendor) or `0x1` (standard).
- "MOV" filenames on the camera are `YYYYMMDD_HHMMSS.MOV` in UTC-ish camera-local time (camera RTC drifts).
- `MEMORY.md` and the `memory/` directory in `~/.claude/projects/...` are separate from this repo — that's a session-management feature, not project state. Don't mix.

## When camera state gets weird

The camera's firmware has multiple ways to deadlock: PTP service wedges (after specific vendor opcodes), GUI freezes during media re-index (network services stay alive), FTP service catatonic after rapid hammering. **Recovery is always: power-cycle.** This costs one reboot but resets all in-RAM weirdness without losing SD card state. Don't try to debug deadlocks past the first occurrence — power-cycle and retry with adjusted timing.

**Before modifying the SD card root**, mirror the factory files locally with `curl --user wificam:wificam ftp://192.168.1.1/...` for each — they're inert per the experiments documented in `docs/dev-console-hunt.md`, but having a backup means accidental damage is recoverable via FTP STOR. `docs/dev-console-hunt.md` lists the original filenames + sizes.
