#!/usr/bin/env python3
"""Walk every property the camera advertises in DeviceInfo, dumping
current value + parsed descriptor. Read-only; safe to run.

Targets the 0xD7xx block first since those have no SDK names and are
the most likely place for hidden factory / debug / calibration toggles.

Usage:
    python3 tools/prop_walk.py                      # all 56 props
    python3 tools/prop_walk.py --block d7           # just D7xx
    python3 tools/prop_walk.py --json /tmp/walk.json
"""
from __future__ import annotations
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import Camera
from larkfly import types as t
from larkfly.exceptions import PtpError


def fmt_form(desc: dict) -> str:
    f = desc.get('form_flag')
    if f == 0 or f is None:
        return 'NONE'
    if f == 1:
        return f"RANGE [{desc.get('min','?')}..{desc.get('max','?')}] step {desc.get('step','?')}"
    if f == 2:
        vals = desc.get('enum') or desc.get('values') or []
        return f"ENUM {vals}"
    return f"form={f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='192.168.1.1')
    ap.add_argument('--bind', default='192.168.1.10')
    ap.add_argument('--block', help='hex prefix to filter (e.g. "d7" for D7xx)')
    ap.add_argument('--json', default=None)
    args = ap.parse_args()

    cam = Camera(args.host, bind=args.bind)
    cam.connect()
    print(f"[*] Connected to {args.host}")
    info = cam.device_info()
    props = info['device_properties_supported']

    if args.block:
        prefix = int(args.block, 16)
        props = [c for c in props if (c >> 8) & 0xFF == prefix]
        print(f"[*] Filter block 0x{prefix:02X}xx: {len(props)} properties")
    else:
        print(f"[*] Walking all {len(props)} advertised properties")

    results = []
    for code in props:
        row = {'code': f'0x{code:04X}'}
        desc = None
        try:
            desc = cam.get_prop_desc(code)
            row['desc'] = desc
            row['datatype'] = f"0x{desc.get('data_type', 0):04X}"
            row['get_set'] = 'RW' if desc.get('get_set') == 1 else 'RO'
            row['default'] = desc.get('default_value')
            row['current_from_desc'] = desc.get('current_value')
            row['form'] = fmt_form(desc)
        except PtpError as e:
            row['desc_rc'] = f"0x{e.response_code:04X}"
        except Exception as e:
            row['desc_error'] = repr(e)

        # GetDevicePropValue: sometimes reveals state that the desc lies about
        try:
            v = cam.get_prop_value(code)
            row['live_value'] = v if isinstance(v, (int, str, bytes, list, dict)) else repr(v)
        except PtpError as e:
            row['value_rc'] = f"0x{e.response_code:04X}"
        except Exception as e:
            row['value_error'] = repr(e)

        results.append(row)
        # one-line summary
        dt = row.get('datatype', '----')
        gs = row.get('get_set', '?? ')
        cur = row.get('live_value', row.get('current_from_desc', '?'))
        form = row.get('form', '?')
        # Truncate long values
        cur_s = repr(cur)
        if len(cur_s) > 40:
            cur_s = cur_s[:37] + '...'
        print(f"  0x{code:04X}  dt={dt} {gs:3s}  cur={cur_s:42s}  form={form}")

    if args.json:
        with open(args.json, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] JSON: {args.json}")

    cam.close()


if __name__ == '__main__':
    sys.exit(main())
