#!/usr/bin/env python3
"""PTP/IP smoke test against a real Larkfly A6+.

Opens a session, reads DeviceInfo, prints the camera's identity and the
full inventory of supported operations / events / properties, then
disconnects cleanly. Returns exit code 0 on success.

This is a thin CLI over the `larkfly` library — see `larkfly/protocol.py`
for the wire-format details (the three iCatch quirks documented in
docs/findings.md are handled there).

Usage:
    python3 tools/ptpip_probe.py [HOST] [--bind LOCAL_IP] [--verbose]

Exit codes:
    0   PTP/IP confirmed end-to-end
    1   could not reach the host
    2   InitCommand was rejected
    3   protocol error after the handshake (PtpError)
"""
from __future__ import annotations

import argparse
import os
import sys

# Make `larkfly` importable from the repo root when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from larkfly import (
    Camera, LarkflyError, TransportError, InitFailError, PtpError,
)
from larkfly import types as t


def _print_codes(label: str, codes: list) -> None:
    standard = [c for c in codes if c < 0x9000]
    vendor   = [c for c in codes if c >= 0x9000]
    print(f"  {label} ({len(codes)}):")
    if standard:
        print("    standard:  " + ", ".join(f"0x{c:04x}" for c in standard))
    if vendor:
        print("    vendor:    " + ", ".join(f"0x{c:04x}" for c in vendor))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('host', nargs='?', default='192.168.1.1',
                    help='camera IP (default: 192.168.1.1)')
    ap.add_argument('--bind', default=None,
                    help='local source IP — needed when multiple interfaces '
                         'share 192.168.1.0/24 (e.g. dongle + main WiFi)')
    ap.add_argument('--timeout', type=float, default=5.0)
    ap.add_argument('--name', default='localhost',
                    help='initiator name (only "localhost" or "" are '
                         'accepted by iCatch firmware; default: localhost)')
    args = ap.parse_args()

    print(f"Probing PTP/IP at {args.host}:{t.PTPIP_PORT}  "
          f"(bind={args.bind or 'default routing'})")

    try:
        with Camera(args.host, bind=args.bind, timeout=args.timeout,
                    name=args.name) as cam:
            print(f"[+] Session open (connection #{cam._connection_number})")

            info = cam.device_info()
            print()
            print("=" * 70)
            print("Camera identity")
            print("=" * 70)
            print(f"  Manufacturer        : {info['manufacturer']!r}")
            print(f"  Model               : {info['model']!r} "
                  f"(firmware-reported)")
            try:
                product_name = cam.get_prop_value(0x501E)
                print(f"  ProductName (0x501E): {product_name!r}")
            except PtpError:
                pass
            try:
                fw_version = cam.get_prop_value(0x501F)
                print(f"  FwVersion   (0x501F): {fw_version!r}")
            except PtpError:
                pass
            print(f"  Device version      : {info['device_version']!r}")
            print(f"  Serial number       : {info['serial_number']!r}")
            print(f"  PTP standard version: 0x{info['standard_version']:04x}")
            print(f"  Vendor extension ID : 0x{info['vendor_extension_id']:08x}")
            print(f"  Vendor extension    : {info['vendor_extension_desc']!r}")
            print()
            _print_codes("Operations supported",
                          info['operations_supported'])
            _print_codes("Events supported",
                          info['events_supported'])
            _print_codes("Device properties supported",
                          info['device_properties_supported'])
            if info['capture_formats']:
                _print_codes("Capture formats", info['capture_formats'])
            if info['image_formats']:
                _print_codes("Image formats", info['image_formats'])

            print()
            print("=" * 70)
            print("RESULT: PTP/IP confirmed end-to-end")
            print("=" * 70)
            return 0

    except TransportError as e:
        print(f"FAIL: transport error — {e}", file=sys.stderr)
        return 1
    except InitFailError as e:
        print(f"FAIL: camera rejected the InitCommand — {e}", file=sys.stderr)
        if e.hint:
            print(f"  Hint: {e.hint}", file=sys.stderr)
        return 2
    except PtpError as e:
        print(f"FAIL: PTP error after handshake — {e}", file=sys.stderr)
        return 3
    except LarkflyError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 3


if __name__ == '__main__':
    sys.exit(main())
