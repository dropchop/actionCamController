#!/usr/bin/env python3
"""Carefully probe whether writable-descriptor properties actually accept
writes. Pattern: read original → write candidate → read back → revert.
Reports per property whether write was accepted, whether read-back differs,
and whether revert succeeded.

Targets the most informative properties first:
  - 0xD83E (SPHOST.BRN path)
  - 0xD406 (empty string)
  - 0xD75F (RW boolean currently 1)
  - 0xD723 (mode with sentinel values)
  - 0xD727 (persistent boolean currently 1)
"""
from __future__ import annotations
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import Camera
from larkfly.exceptions import PtpError


def test_write(cam, code, candidate, label):
    """Try writing candidate and reverting. Returns (accepted, persists, behavior)."""
    try:
        orig = cam.get_prop_value(code)
    except Exception as e:
        return print(f"  0x{code:04X} {label:25s}: can't read orig — {e}")

    print(f"  0x{code:04X} {label:25s}: orig={orig!r}")
    try:
        cam.set_prop_value(code, candidate)
        # Some firmwares accept but ignore — check by reading back
        rb = cam.get_prop_value(code)
        if rb == candidate:
            print(f"           ACCEPTED + READS BACK as {rb!r}")
        elif rb == orig:
            print(f"           ACCEPTED but READS BACK as orig (silent ignore)")
        else:
            print(f"           ACCEPTED but READS BACK as {rb!r} (transformed!)")
        # Restore
        try:
            cam.set_prop_value(code, orig)
            rb2 = cam.get_prop_value(code)
            print(f"           reverted to {rb2!r}")
        except PtpError as e:
            print(f"           REVERT FAILED rc=0x{e.response_code:04X} — value is now {rb!r}")
    except PtpError as e:
        print(f"           REJECTED rc=0x{e.response_code:04X}")
    except Exception as e:
        print(f"           ERROR {e!r}")


def main():
    cam = Camera('192.168.1.1', bind='192.168.1.10')
    cam.connect()
    print("[*] Connected\n")

    print("== Safe write-and-revert tests ==\n")
    # 0xD83E SPHOST.BRN path — try a benign different string
    test_write(cam, 0xD83E, 'G:\\FACTORY.BRN', 'fw-update path')
    print()
    # 0xD406 empty string — try a label
    test_write(cam, 0xD406, 'HELLO', 'empty-string prop')
    print()
    # 0xD75F boolean — flip to 0 (currently 1)
    test_write(cam, 0xD75F, 0, 'boolean RW (was 1)')
    print()
    # 0xD723 mode — try value 1 (was 0)
    test_write(cam, 0xD723, 1, 'mode (sentinels)')
    print()
    # 0xD727 boolean — try flipping back to factory_default=0
    test_write(cam, 0xD727, 0, 'persistent bool')
    print()
    # 0x501A: currently 65535 (sentinel), enum [65535, 5..60] — try a real value
    test_write(cam, 0x501A, 30, 'sleep timer? (=65535)')
    print()
    # 0xD7FC: RW bool currently 1, default 1
    test_write(cam, 0xD7FC, 0, 'bool RW (D7FC)')
    print()
    # 0xD7FF: RW bool currently 1, default 1
    test_write(cam, 0xD7FF, 0, 'bool RW (D7FF)')

    cam.close()
    print("\n[*] done")


if __name__ == '__main__':
    sys.exit(main())
