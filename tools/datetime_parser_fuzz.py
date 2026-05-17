#!/usr/bin/env python3
"""Fuzz the DateTime parser on PTP property 0x5011.

Discovered via fmtstr_fuzz.py: writing a non-format-string-vulnerable
property reveals an sscanf-style parser. Every payload produces a
DIFFERENT read-back, meaning our input is reaching the parser.

Strategy: send payloads designed to trigger integer overflow, buffer
overflow, edge cases in the date arithmetic, and embedded format
strings shaped as a valid-looking date prefix. After each batch,
health-check the camera.

What to watch for:
  - Non-OK set_rc → camera rejected the input (= parser has validation)
  - Crashes / health-check failures → exploitable parser bug
  - Read-back of '20170131T210000.0' → parser fell through to default
    (camera's internal epoch start? worth noting which payloads do this)
  - Read-back of dates with weird years (-1, -50580702, etc) → parser
    did partial parse with garbage state — controllable input?
  - Read-back of the SAME date for different payloads → equivalence
    classes; we can study the parser by its outputs.
"""
from __future__ import annotations
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import Camera
from larkfly.exceptions import PtpError, TransportError


# Payload batteries — each in priority order, easiest crash classes first
BOUNDARY = [
    '00000000T000000.0',                # all zeros
    '00010101T000000.0',                # PTP DateTime spec minimum
    '99999999T999999.9',                # max digits
    '00000000T000000.999999999',        # max fraction
    '20260229T000000.0',                # Feb 29 in non-leap year
    '20240229T000000.0',                # Feb 29 in leap year (valid)
    '20260231T000000.0',                # Feb 31 (impossible)
    '20261301T000000.0',                # month 13
    '20261232T000000.0',                # day 32
    '20260517T253733.0',                # hour 25
    '20260517T186073.0',                # minute 60
    '20260517T183799.0',                # second 99
    '99999999T235959.9',                # year overflow
]

NEGATIVE = [
    '-1',                               # tiny negative
    '-9999',                            # short negative
    '-99999999T-1-1.-1',                # all negative
    '-20260517T183733.0',               # negative year
    '20260517T-183733.0',               # negative time
]

LONG = [
    'A' * 50,                           # long ascii
    'A' * 100,                          # longer
    'A' * 200,                          # near PTP STRING max (254 chars)
    'A' * 250,                          # PTP STRING max
    '1' * 100,                          # long digits (sscanf might consume all)
    '9' * 200,                          # max-digit overflow attempt
    '9' * 250,                          # bigger overflow
    '20260517T' + '9' * 200 + '.0',     # massive HHMMSS field
    '2' * 100 + '0517T183733.0',        # massive YYYYMMDD field
]

EMBEDDED_FMT = [
    '20%n0517T183733.0',                # %n inside valid-shaped date
    '20%s0517T183733.0',                # %s inside
    '20260517%n183733.0',               # %n in time field
    '20260517T%p3733.0',                # %p in middle
    '%n%n%n%n%n%n%n%n%n.0',             # %n chain shaped like a date
    '20260517T183733.%n',               # %n in fraction
]

SPECIAL = [
    '20260517T183733.0\x00JUNK',        # NUL injection
    '20260517T183733.0\n20260517',      # newline injection
    '20260517T18\x0937:33.0',           # tab injection
    '\xff\xff\xff\xff\xff\xff\xff\xff', # binary garbage (will be valid UTF-16LE per char)
    '',                                  # empty
    'A',                                 # single char
    '𠀀𠀀𠀀',                            # surrogate-pair UTF-16
]


def camera_alive(host: str, bind: str) -> tuple[bool, str]:
    try:
        c = Camera(host, bind=bind)
        c.connect()
        info = c.device_info()
        nprops = len(info['device_properties_supported'])
        c.close()
        return True, f"{nprops} props"
    except Exception as e:
        return False, f"{type(e).__name__}: {str(e)[:80]}"


def fuzz_batch(cam: Camera, label: str, payloads: list[str], code: int = 0x5011) -> dict:
    """Try each payload, log set_rc + read_back. Return summary."""
    print(f"\n--- {label} ({len(payloads)} payloads) ---")
    results = {}
    for p in payloads:
        # Render the payload safely for printing
        try:
            display = p if len(p) < 60 else (p[:30] + '...' + p[-20:])
            display = display.encode('unicode_escape').decode()
        except Exception:
            display = repr(p)[:80]
        try:
            cam.set_prop_value(code, p)
            set_rc = 'OK'
        except PtpError as e:
            set_rc = f'0x{e.response_code:04X}'
            print(f"  rejected     {display!r:60s} set_rc={set_rc}")
            results[p] = ('rejected', set_rc, None)
            continue
        except Exception as e:
            set_rc = f'EXC:{type(e).__name__}'
            print(f"  exception    {display!r:60s} {e}")
            results[p] = ('exception', set_rc, None)
            continue

        try:
            rb = cam.get_prop_value(code)
        except Exception as e:
            rb = f'<read-failed: {e}>'
        print(f"  set/rb        {display!r:60s} → {rb!r}")
        results[p] = ('ok', set_rc, rb)
    return results


def main():
    host = '192.168.1.1'
    bind = '192.168.1.10'

    ok, diag = camera_alive(host, bind)
    print(f"[*] Baseline health: {'OK' if ok else 'FAIL'} ({diag})")
    if not ok:
        return 1

    cam = Camera(host, bind=bind)
    cam.connect()
    original = cam.get_prop_value(0x5011)
    print(f"[*] Original 0x5011 DateTime: {original!r}")

    all_results = {}
    for label, payloads in [('BOUNDARY', BOUNDARY),
                             ('NEGATIVE', NEGATIVE),
                             ('LONG', LONG),
                             ('EMBEDDED_FMT', EMBEDDED_FMT),
                             ('SPECIAL', SPECIAL)]:
        try:
            all_results[label] = fuzz_batch(cam, label, payloads)
        except (TransportError, Exception) as e:
            print(f"\n[!] {label} batch died: {e}")
            print("    Camera state changed — bailing out.")
            break

        # Try to restore between batches
        try:
            cam.set_prop_value(0x5011, original)
        except Exception:
            pass

        # Health check
        try:
            cam.close()
        except Exception:
            pass
        time.sleep(0.5)
        ok, diag = camera_alive(host, bind)
        print(f"  Health after {label}: {'OK' if ok else '!!! DOWN'} ({diag})")
        if not ok:
            print(f"[!] STOPPING — camera went down after {label}.")
            print(f"    Last payload-batch may contain an exploitable parser bug.")
            return 0
        # Reconnect for next batch
        cam = Camera(host, bind=bind)
        cam.connect()

    # Final cleanup
    try:
        cam.set_prop_value(0x5011, original)
        print(f"\n[*] Restored 0x5011 to {original!r}")
    except Exception as e:
        print(f"\n[!] Restore failed: {e}")
    cam.close()

    # Analysis: any payloads that produced unique outputs
    print("\n=== Output equivalence-class analysis ===")
    output_to_inputs = {}
    for batch, results in all_results.items():
        for payload, (status, set_rc, rb) in results.items():
            if status != 'ok':
                continue
            output_to_inputs.setdefault(rb, []).append((batch, payload))
    print(f"  {len(output_to_inputs)} distinct read-back outputs across {sum(len(r) for r in all_results.values())} payloads")
    # Most common outputs (likely "default" or "error" states)
    sorted_outputs = sorted(output_to_inputs.items(), key=lambda kv: -len(kv[1]))
    print(f"\n  Top equivalence classes:")
    for output, inputs in sorted_outputs[:10]:
        sample = ', '.join(f"{b}:{repr(p)[:30]}" for b, p in inputs[:3])
        more = f" (+{len(inputs)-3} more)" if len(inputs) > 3 else ''
        print(f"    {output!r:40s} ← {len(inputs):2d} inputs: {sample}{more}")

    print("\n[*] Fuzz complete. Camera survived all batches.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
