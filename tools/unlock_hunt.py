#!/usr/bin/env python3
"""Try to find what unlocks the silently-rejected RW booleans
0xD75F, 0xD7FC, 0xD7FF.

Strategy: for each candidate "primer" action, open a fresh session,
apply the primer, then try writing 0xD75F=0, 0xD7FC=0, 0xD7FF=0 (all
currently 1). For each, read back to see whether the write actually
took. Revert any successful change. Close the session between tests
to ensure no state leaks between primers.

Primers tested (only safe vendor opcodes per docs/ptp-vendor.md):
  - none (baseline)
  - 0x9601 polling op
  - 0x9614 GetAllPropDescs
  - 0x9805 global snapshot
  - 0xD406 = "FACTORY" / "SERVICE" / "DEBUG" / "ICATCH" / "ENG"
  - 0xD723 = 0x80000001 / 0x80000002 (sentinel-mode candidates)
"""
from __future__ import annotations
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import Camera
from larkfly.exceptions import PtpError
from larkfly import types as t

TARGETS = [0xD75F, 0xD7FC, 0xD7FF]  # currently all = 1
TARGET_NEW = 0


def fresh():
    cam = Camera('192.168.1.1', bind='192.168.1.10')
    cam.connect()
    return cam


def try_unlock(primer_label, primer_fn):
    """Run one primer + test all 3 targets. Return list of results."""
    cam = fresh()
    print(f"\n  === Primer: {primer_label} ===")
    primer_result = None
    try:
        primer_result = primer_fn(cam)
        print(f"      primer ok: {primer_result}")
    except PtpError as e:
        print(f"      primer rc=0x{e.response_code:04X}")
    except Exception as e:
        print(f"      primer EXC: {e!r}")

    for code in TARGETS:
        try:
            orig = cam.get_prop_value(code)
            try:
                cam.set_prop_value(code, TARGET_NEW)
            except PtpError as e:
                print(f"      0x{code:04X}: write rejected rc=0x{e.response_code:04X}")
                continue
            rb = cam.get_prop_value(code)
            if rb == TARGET_NEW:
                print(f"      0x{code:04X}: 🔓 ACCEPTED (orig={orig} -> {rb})")
                # revert
                try:
                    cam.set_prop_value(code, orig)
                    print(f"               reverted to {cam.get_prop_value(code)}")
                except Exception as e:
                    print(f"               REVERT FAIL: {e!r}")
            else:
                print(f"      0x{code:04X}: silent-ignore (orig={orig}, rb={rb})")
        except Exception as e:
            print(f"      0x{code:04X}: exc {e!r}")

    try:
        cam.close()
    except Exception:
        pass


def main():
    print("[*] Hunting unlock for silently-locked booleans 0xD75F, 0xD7FC, 0xD7FF")
    print("    (all currently =1; will try to write =0 after each primer)")

    # Baseline (no primer)
    try_unlock("baseline (no primer)", lambda c: None)

    # Vendor opcode primers
    try_unlock("vendor op 0x9601 (poll)",
               lambda c: c._raw_op(0x9601, [0xD001, 0xFFFFFFFF, 0])[0])
    try_unlock("vendor op 0x9614 (GetAllPropDescs)",
               lambda c: c._raw_op(0x9614, [])[0])
    try_unlock("vendor op 0x9805 (global snapshot)",
               lambda c: c._raw_op(0x9805,
                                   [0xFFFFFFFF, 0, 0xFFFFFFFF, 0, 0xFFFFFFFF])[0])

    # 0xD406 magic strings
    for s in ["FACTORY", "SERVICE", "DEBUG", "ICATCH", "ENG", "ROOT", "TEST"]:
        try_unlock(f"set 0xD406 = '{s}'",
                   lambda c, s=s: c.set_prop_value(0xD406, s))

    # 0xD723 sentinel modes
    for v in [0x80000001, 0x80000002]:
        try_unlock(f"set 0xD723 = 0x{v:08X}",
                   lambda c, v=v: c.set_prop_value(0xD723, v))

    # Combo: 0x9805 + 0xD406="FACTORY" + 0xD723=0x80000001
    def combo(c):
        c._raw_op(0x9805, [0xFFFFFFFF, 0, 0xFFFFFFFF, 0, 0xFFFFFFFF])
        c.set_prop_value(0xD406, "FACTORY")
        c.set_prop_value(0xD723, 0x80000001)
        return "combo ok"
    try_unlock("combo: 0x9805 + FACTORY + sentinel-mode-1", combo)


if __name__ == '__main__':
    sys.exit(main())
