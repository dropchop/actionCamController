#!/usr/bin/env python3
"""Minimal demo of the larkfly client. Connects to a camera, prints its
DeviceInfo / storage / object list, then exercises the photo path (a
no-op on this firmware — see the note below), and disconnects.

Usage:
    python3 examples/quickstart.py [HOST] [--bind LOCAL_IP]

Defaults: HOST=192.168.1.1, bind=192.168.1.10 (the configuration this
project uses with the USB dongle on the dedicated camera AP).
"""
import argparse
import os
import sys
import time

# Add repo root so 'larkfly' resolves when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from larkfly import Camera, PtpError, types as t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('host', nargs='?', default='192.168.1.1')
    ap.add_argument('--bind', default='192.168.1.10')
    ap.add_argument('--no-photo', action='store_true',
                    help="skip taking a photo (just show DeviceInfo + storage)")
    args = ap.parse_args()

    with Camera(args.host, bind=args.bind) as cam:
        print(f"Connected to {args.host} (initiator GUID = random per session)")
        print()

        info = cam.device_info()
        print(f"PTP standard:       0x{info['standard_version']:04x}")
        print(f"Operations:         {len(info['operations_supported'])} "
              f"({sum(1 for o in info['operations_supported'] if o >= 0x9000)} vendor)")
        print(f"Properties:         {len(info['device_properties_supported'])}")
        print(f"Events:             {len(info['events_supported'])}")
        print()

        # Read some known properties
        print("Some named property values:")
        for code, name in [(0x501E, 'ProductName'),
                            (0x501F, 'FwVersion'),
                            (0x5001, 'BatteryLevel'),
                            (0x5003, 'ImageSize'),
                            (0xD605, 'VideoSize'),
                            (0x5011, 'DateTime')]:
            if code in info['device_properties_supported']:
                try:
                    v = cam.get_prop_value(code)
                    print(f"  0x{code:04x} {name:<20} = {v!r}")
                except PtpError as e:
                    print(f"  0x{code:04x} {name:<20} = <error: {e}>")
        print()

        # Storage
        sids = cam.storage_ids()
        print(f"Storage IDs: {[hex(s) for s in sids]}")
        for sid in sids:
            si = cam.storage_info(sid)
            free_gb = si['free_space_bytes'] / 2**30
            cap_gb = si['max_capacity'] / 2**30
            print(f"  0x{sid:08x}: {cap_gb:.1f} GB total, "
                  f"{free_gb:.1f} GB free, "
                  f"{si['free_space_objects']} object slots remaining")
        print()

        # Objects
        handles = cam.list_objects()
        print(f"Objects on storage ({len(handles)}):")
        for h in handles[:10]:
            try:
                obj = cam.object_info(h)
                fmt_name = {0x3000: 'Undefined', 0x3001: 'Association/Dir',
                            0x3801: 'EXIF/JPEG', 0xB982: 'MP4'}.get(
                            obj['object_format'], f"0x{obj['object_format']:04x}")
                print(f"  Handle {h}: {fmt_name:<16} "
                      f"{obj['image_pix_width']}x{obj['image_pix_height']} "
                      f"size={obj['object_compressed_size']}b "
                      f"name={obj['filename']!r}")
            except PtpError as e:
                print(f"  Handle {h}: <error: {e}>")
        print()

        if args.no_photo:
            return

        # NOTE: photo capture over PTP does not work on this firmware —
        # InitiateCapture (0x100E) returns rc=OK but produces no JPG, event
        # or object (see docs/findings.md). take_photo() will return None.
        print("=== Taking a photo (known no-op on this firmware) ===")
        new_handle = cam.take_photo()
        if new_handle:
            print(f"  Photo handle: {new_handle}")
            # Wait a beat for the file to be written
            for delay in (0.5, 1.0, 2.0, 4.0):
                time.sleep(delay)
                try:
                    obj = cam.object_info(new_handle)
                    if obj['object_compressed_size'] > 0:
                        print(f"  After {delay}s: filename={obj['filename']!r} "
                              f"size={obj['object_compressed_size']}b")
                        break
                except PtpError:
                    continue
                print(f"  After {delay}s: still writing...")

            # Try to grab thumbnail
            try:
                thumb = cam.get_thumb(new_handle)
                out = f"/tmp/larkfly_thumb_{new_handle}.jpg"
                with open(out, 'wb') as f:
                    f.write(thumb)
                print(f"  Thumbnail: {len(thumb)} bytes → {out}")
            except PtpError as e:
                print(f"  Thumbnail not available: {e}")
        else:
            print("  Photo trigger sent but no handle returned (sometimes "
                  "happens — check storage with another tool)")


if __name__ == '__main__':
    main()
