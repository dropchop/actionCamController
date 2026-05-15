#!/usr/bin/env python3
"""Enumerate every device property the camera supports.

For each property in the camera's `device_properties_supported` list,
calls GetDevicePropDesc (op 0x1014) and GetDevicePropValue (op 0x1015)
and writes the parsed result to a JSON file. Pure read-only — no state
changes on the camera.

Usage:
    python3 analyses/enumerate_props.py [HOST] [--bind SOURCE_IP]
        [-o OUTPUT.json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

# Make `larkfly` importable when run from the repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from larkfly import Camera, PtpError, types as t


# Property codes the iCatch Java SDK gives meaningful names — useful for
# cross-checking our descriptor parsing.
KNOWN_PROP_NAMES = {
    0x5001: 'BatteryLevel',
    0x5003: 'ImageSize',
    0x5004: 'CompressionSetting',
    0x5005: 'WhiteBalance',
    0x5007: 'FNumber',
    0x500A: 'FocusMode',
    0x500B: 'ExposureMeteringMode',
    0x500C: 'FlashMode',
    0x500D: 'ExposureTime',
    0x500E: 'ExposureProgramMode',
    0x500F: 'ExposureIndex',
    0x5010: 'ExposureBiasCompensation',
    0x5011: 'DateTime',
    0x5012: 'CaptureDelay',
    0x5013: 'StillCaptureMode',
    0x5015: 'Contrast',
    0x5018: 'BurstNumber',
    0x501A: 'TimelapseNumber',
    0x501B: 'TimelapseInterval',
    0x501E: 'ProductName',
    0x501F: 'FwVersion',
    0xD604: 'CameraMode',
    0xD605: 'VideoSize',
    0xD606: 'LightFrequency',
    0xD607: 'DateStamp',
    0xD615: 'SlowMotion',
}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('host', nargs='?', default='192.168.1.1')
    ap.add_argument('--bind', default='192.168.1.10')
    ap.add_argument('--timeout', type=float, default=5.0)
    ap.add_argument('-o', '--output', default='analyses/data/properties.json')
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)

    with Camera(args.host, bind=args.bind, timeout=args.timeout) as cam:
        info = cam.device_info()
        props = info['device_properties_supported']
        print(f"Camera supports {len(props)} device properties")

        results = {}
        for i, code in enumerate(props):
            entry = {
                'propcode': code,
                'propcode_hex': f"0x{code:04x}",
                'name': KNOWN_PROP_NAMES.get(code),
                'is_vendor': code >= 0xD000,
            }
            try:
                desc = cam.get_prop_desc(code)
                entry['desc'] = {
                    'datatype': desc['datatype'],
                    'datatype_name': desc['datatype_name'],
                    'getset': desc['getset'],
                    'getset_str': ('R', 'RW')[desc['getset']] if desc['getset'] < 2 else f"?{desc['getset']}",
                    'factory_default': desc.get('factory_default'),
                    'current': desc.get('current_value'),
                    'form': desc.get('form'),
                }
                if 'allowed_values' in desc:
                    entry['desc']['allowed'] = desc['allowed_values']
                if 'min' in desc:
                    entry['desc']['min'] = desc['min']
                    entry['desc']['max'] = desc['max']
                    entry['desc']['step'] = desc['step']
                entry['desc_raw_hex'] = None  # the high-level API doesn't expose raw bytes
            except PtpError as e:
                entry['desc_error'] = str(e)

            try:
                v = cam.get_prop_value(code)
                entry['value'] = v
            except PtpError as e:
                entry['value_error'] = str(e)

            results[f"0x{code:04x}"] = entry

            d = entry.get('desc', {}) or {}
            name = entry.get('name') or '?'
            cur = d.get('current')
            cur_s = repr(cur)[:60] if cur is not None else '?'
            print(f"  [{i+1:2}/{len(props)}] 0x{code:04x} {name:<28} "
                  f"{d.get('datatype_name','?'):<8} "
                  f"{d.get('getset_str','?'):<3} cur={cur_s}")

        with open(args.output, 'w') as f:
            json.dump({
                'host': args.host,
                'captured_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
                'standard_version': info['standard_version'],
                'operations_supported': info['operations_supported'],
                'events_supported': info['events_supported'],
                'properties_supported': info['device_properties_supported'],
                'properties': results,
            }, f, indent=2)
        print(f"\nWrote {args.output}")
        return 0


if __name__ == '__main__':
    sys.exit(main())
