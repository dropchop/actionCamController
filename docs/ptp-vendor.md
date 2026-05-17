# PTP/IP vendor opcodes — full surface map

The camera's `DeviceInfo.operations_supported` advertises 8 vendor
opcodes in the iCatch `0x9xxx` range. Earlier work documented three
that the iSmart DV2 app actually uses (`0x9601`, `0x9614`, `0x9805`);
the other five (`0x9602`, `0x9801`, `0x9802`, `0x9803`, `0x9812`) were
unexplored because blind probing previously hung the PTP service. This
file documents the result of an exhaustive crash-safe sweep across all
8 ops × 7 parameter shapes, run via `tools/ptp_vendor_probe.py` in May
2026. Raw data: `analyses/data/ptp_vendor_probe.json` (45 probes),
plus binary captures `analyses/data/op_9614_response.bin` and
`analyses/data/op_9805_response.bin`.

## TL;DR — there is no dev console / shell here either

Of the five previously-unknown vendor ops:

- **`0x9801` is dead-firmware**. All 7 parameter shapes return vendor
  error `0xA802` in under 10 ms with no data. Looks like a SDK-template
  stub that was never wired up.
- **`0x9602` and `0x9803` are real lookup ops** but never return useful
  data in this firmware. They parse parameters (returning proper
  `Invalid_ObjectHandle` / `DeviceProp_Not_Supported` rejections), but
  every input we tried — including real object handles enumerated via
  `GetObjectHandles` — got back either `Undefined` or "not supported".
  Either the lookup table is empty in this build, or we're missing a
  parameter we haven't guessed.
- **`0x9802` and `0x9812` have a delayed-crash bug**. They respond
  cleanly (`0xA80A` and `0x2005 Operation_Not_Supported` respectively),
  but the PTP service dies a few hundred ms later — every health
  check that ran *after* one of these aborted. Power-cycle required.
- **None of them expose a shell, log endpoint, or photo-trigger.**

So the same conclusion as `docs/ports.md`: the camera has no
network-side debug surface. The only remaining avenue is a UART/JTAG
header on the PCB.

## Per-opcode summary

| Op       | Behaviour                                                                                   | Crash? |
| -------- | ------------------------------------------------------------------------------------------- | ------ |
| `0x9601` | Polling op (3 params). Returns vendor "error" `0xA601` with response-params `[0xD002, 3, 0, 0, 0]` — *the response-code field is informational*, encoding "next prop to ask about + state". | no     |
| `0x9602` | Wants params (no-params → `Parameter_Not_Supported`). Parses param 1 as either object handle or sentinel. Returns `Invalid_ObjectHandle` for prop-codes, `Undefined` for real handles. | **yes — on `[0]` and `[0,0]`** |
| `0x9614` | Bulk PropDesc reader; returns 233 B of concatenated PropDesc records. Reply uses `rc=0x2002 General_Error` despite carrying valid data — firmware quirk, decoded in `analyses/decode_9614.py`. | no     |
| `0x9801` | Stub. Every param shape → `0xA802` with no data. | no |
| `0x9802` | Stub-with-bug. Returns `0xA80A` then crashes the PTP service ~ms later. | **yes — always (delayed)** |
| `0x9803` | Dual-mode lookup. First param < ~0x10000 → treated as property code (`DeviceProp_Not_Supported`); larger → treated as object handle (`Invalid_ObjectHandle`). No input found anything in this firmware. | no |
| `0x9805` | Bulk "global query" (5 params, all-Fs + zeros). Returns **1388 B** of compact property-snapshot records — see "0x9805 data format" below. | no |
| `0x9812` | Stub-with-bug. First 3 calls return `0x2005 Operation_Not_Supported`; a subsequent call crashes the PTP service. | **yes (delayed)** |

## Parameter-shape matrix — exact results

Each unknown opcode was probed with seven parameter shapes (a no-params
call, single zero, single all-Fs, single property-code-shaped value,
two zeros, the 3-param polling shape, and the 5-param global-query
shape). Numbers below are response codes.

| Shape           | `0x9602`         | `0x9801`         | `0x9802`         | `0x9803`         | `0x9812`         |
| --------------- | ---------------- | ---------------- | ---------------- | ---------------- | ---------------- |
| no-params       | `0x2006 PNS`     | `0xA802`         | `0xA80A`         | `0x200A DPNS`    | `0x2005 ONS`     |
| `[0]`           | **WEDGE**        | `0xA802`         | skip ¹           | `0x200A DPNS`    | `0x2005 ONS`     |
| `[0xFFFFFFFF]`  | `0x2000 Undef`   | `0xA802`         | skip ¹           | `0x2009 IOH`     | `0x2005 ONS`     |
| `[0xD001]`      | `0x2009 IOH`     | `0xA802`         | skip ¹           | `0x2009 IOH`     | skip ²           |
| `[0, 0]`        | **WEDGE**        | `0xA802`         | skip ¹           | `0x200A DPNS`    | skip ²           |
| `[0xD001,F,0]`  | `0x2009 IOH`     | `0xA802`         | skip ¹           | `0x2009 IOH`     | skip ²           |
| `[F,0,F,0,F]`   | `0x2000 Undef`   | `0xA802`         | skip ¹           | `0x2009 IOH`     | skip ²           |

¹ `0x9802` delayed-crashed on the no-params call; we did not retry
the other shapes. Each retry would cost one power-cycle for the same
expected result.
² Same story for `0x9812` — three shapes returned cleanly, the fourth
crashed.

Legend: `PNS` = `Parameter_Not_Supported`, `DPNS` =
`DeviceProp_Not_Supported`, `IOH` = `Invalid_ObjectHandle`,
`ONS` = `Operation_Not_Supported`, `Undef` = `0x2000 Undefined`.

Follow-up single-shot probes:

- `0x9602(1)` (real object handle from `GetObjectHandles`) → `0x2000 Undefined`
- `0x9803(1)` → `0x200A DeviceProp_Not_Supported` (treats `1` as prop code,
  not handle)
- `0x9803(1, 1)`, `0x9803(1, 0xFFFFFFFF)` → same `0x200A` (second
  param doesn't change route)

## Wedge taxonomy

| Trigger                                                                | Recovery       |
| ---------------------------------------------------------------------- | -------------- |
| `0x9602` with first param `0x00000000`                                 | Power-cycle    |
| `0x9602` with `[0, 0]`                                                 | Power-cycle    |
| **Any** call to `0x9802`                                               | Power-cycle    |
| **Any** call to `0x9812` (third call onward, possibly cumulative)      | Power-cycle    |

The pattern is the same one observed in RTSP: a parameter parser
dereferences something it shouldn't on certain inputs. The PTP service
keeps the TCP socket listening for several seconds after the crash
(replies still come back) but then the whole service goes dark — TCP
RST on subsequent connects, PTP port `15740` no longer accepts
sessions, no recovery within 60 s without a hard reset.

`tools/ptp_vendor_probe.py` does TCP-level *and* session-level health
checks between every probe to catch this — and saves after every
probe so re-runs `--resume` from where the camera last died.

## 0x9805 data format — partially decoded

The 1388-byte response to `0x9805(F, 0, F, 0, F)` is a stream of
compact "property snapshot" records, not the same record format as
`0x9614`. We did not finish decoding it; the rough header looks like:

```
Offset 0:    98 00 00 00      ─ u32 LE = 152 (purpose unclear; not total length)
Offset 4:    02 00 00 00      ─ u32 LE = 2   (purpose unclear; not record count)
Offset 8:    01 dc 06 00 01   ─ first record: code=0xDC01 datatype=0x0006 (UINT32) getset=1
Offset 13:   05 00 00 00      ─ first record value = 0x00000005
Offset 17:   02 00 00 00      ─ ???
Offset 21:   02 dc 04 00 01   ─ next record: code=0xDC02 datatype=0x0004 (UINT16) getset=1
...
```

So each record is roughly `u16 prop_code + u16 datatype + u8 getset +
value_of_size_dtsize`, no factory_default and no form data (unlike
PropDesc) — making it a "current values" bulk-dump rather than a
descriptors dump. There are inlined PTP-strings (datatype `0xFFFF`,
length-prefixed UTF-16LE) at offsets 188, 314, 375, 434, 694, 1074
that complicate the walk; a clean parser would need the firmware's
record-delimiter rules.

The raw bytes are at `analyses/data/op_9805_response.bin` for
follow-up work. Pairing them against `analyses/data/properties.json`
(56 PropDesc records from the standard enumeration) is the next step:
that mapping would tell us the value type for every record and let us
walk the stream definitively.

## What this means for the project

- **No new functionality was unlocked.** The unknown opcodes are
  either stubs, gated off, or backed by empty lookup tables. The
  "photo capture via vendor op" hypothesis from `findings.md` is
  effectively closed: none of these ops accept a "capture" semantic
  parameter and none triggered any side effect on the camera.
- **`larkfly` already uses the only two productive ones** (`0x9601`
  via `Camera.poll()`, `0x9614` via `Camera.bulk_prop_desc()`).
  `0x9805` could be wired up once decoded — a single round-trip that
  reports current values for all properties would be cheaper than the
  current property-by-property polling loop.
- **`webui` does not need to touch any of these.** The recording
  mode-toggle on property `0xD604` remains the only path; vendor ops
  do not provide a shortcut.
- **Do not call `0x9602` with a zero first parameter, ever.** Same for
  `0x9802` / `0x9812` from any client. The probe is the only thing
  that touches these.

## Reproducing

```bash
# Full sweep, crash-safe, ~1 reset per crashy opcode (3 expected: 0x9602, 0x9802, 0x9812):
python3 tools/ptp_vendor_probe.py

# After a power-cycle:
python3 tools/ptp_vendor_probe.py --resume

# Single targeted shot (useful for follow-up):
python3 tools/ptp_vendor_probe.py --op 0x9602 --params 0x1
```
