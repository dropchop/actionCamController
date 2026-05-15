#!/usr/bin/env python3
"""Decode the 233-byte response from vendor opcode 0x9614.

Initial inspection suggested it's a concatenation of length-prefixed
PropertyDescriptor records. Confirmed below by parsing record-by-record
and cross-referencing each property's already-known datatype + current
value from analyses/data/properties.json.

Usage:
    python3 decode_9614.py [--live]   # --live reissues the call (camera)
                                       # default uses the captured bytes
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import types as t
from larkfly import protocol as p


# Default: read the 233-byte response captured to disk. Generate via
# analyses/data/op_9614_response.bin (the script saves it on --live runs).
CAPTURED_BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             'data', 'op_9614_response.bin')


def parse_records(data: bytes) -> list[dict]:
    """Walk the data as a sequence of length-prefixed PropDesc records.

    Layout (per record):
        u32 LE   record_length (total bytes including this header)
        bytes    PropDesc payload (length - 4 bytes)

    The camera's firmware appears to truncate the response when it hits a
    malformed PropDesc (e.g., 0x500A FocusMode comes back with only the
    prop_code + datatype + getset bytes and no value fields). In that case
    the last record has a short body and the response ends with a
    partial-record fragment.
    """
    records = []
    pos = 0
    while pos < len(data):
        if pos + 4 > len(data):
            records.append({'_fragment': True, '_at': pos,
                            '_remaining_hex': data[pos:].hex(),
                            '_remaining_bytes': len(data) - pos})
            break
        rlen = struct.unpack_from('<I', data, pos)[0]
        if rlen < 4 or pos + rlen > len(data):
            # Unparseable length — record is truncated
            records.append({'_fragment': True, '_at': pos,
                            '_claimed_len': rlen,
                            '_remaining_hex': data[pos:].hex(),
                            '_remaining_bytes': len(data) - pos})
            break
        body = data[pos + 4:pos + rlen]
        pos += rlen

        rec = {'record_len': rlen}
        try:
            parsed = p.parse_prop_desc(body)
            rec.update(parsed)
            rec['_body_hex'] = body.hex()
        except Exception as e:
            rec['parse_error'] = f"{type(e).__name__}: {e}"
            rec['_body_hex'] = body.hex()
            # Try to at least pull prop_code + datatype + getset if there's
            # enough for those three fields
            if len(body) >= 5:
                rec['property_code'] = struct.unpack_from('<H', body, 0)[0]
                rec['datatype'] = struct.unpack_from('<H', body, 2)[0]
                rec['datatype_name'] = t.DT_NAMES.get(rec['datatype'],
                                                      f"0x{rec['datatype']:04x}")
                rec['getset'] = body[4]
                rec['form'] = 'truncated'
        records.append(rec)
    return records


def format_value(v, dt: int) -> str:
    """Compact human formatting for an attribute value."""
    if isinstance(v, list):
        if len(v) > 8:
            return f"[{v[0]}…{v[-1]}, {len(v)} items]"
        return repr(v)
    if isinstance(v, str):
        return repr(v[:40] + ('…' if len(v) > 40 else ''))
    return repr(v)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--live', action='store_true',
                    help="reissue op 0x9614 against the live camera "
                         "instead of using the captured 233 bytes")
    ap.add_argument('--host', default='192.168.1.1')
    ap.add_argument('--bind', default='192.168.1.10')
    args = ap.parse_args()

    if args.live:
        from larkfly import Camera
        with Camera(args.host, bind=args.bind) as cam:
            rc, rp, data = cam._raw_op(0x9614, [])
            print(f"Live response: rc=0x{rc:04x} data_len={len(data)}")
            with open(CAPTURED_BIN, 'wb') as f:
                f.write(data)
            print(f"Saved to {CAPTURED_BIN}")
    else:
        if not os.path.exists(CAPTURED_BIN):
            print(f"ERROR: {CAPTURED_BIN} not found. Run with --live first to "
                  f"capture, or place a 0x9614 response there manually.",
                  file=sys.stderr)
            return 1
        with open(CAPTURED_BIN, 'rb') as f:
            data = f.read()
        print(f"Using {CAPTURED_BIN}: {len(data)} bytes")

    records = parse_records(data)
    print(f"Parsed {len(records)} records\n")

    # Load the known property catalog (from earlier enumeration) for cross-ref
    known = {}
    cat_path = 'analyses/data/properties.json'
    if os.path.exists(cat_path):
        cat = json.load(open(cat_path))
        for code_str, p_data in cat['properties'].items():
            try:
                code = int(code_str, 16)
                known[code] = p_data
            except ValueError:
                pass

    # Table header
    print(f"{'#':>2} {'len':>4} {'code':>8} {'dt':<7} {'gs':<3} {'default':>16} "
          f"{'current':>16} {'form':<6} match-known")
    print('-' * 90)

    matches = 0
    mismatches = 0
    parse_errors = 0
    for i, r in enumerate(records, 1):
        if r.get('_fragment'):
            n = r.get('_remaining_bytes', 0)
            hex_str = r.get('_remaining_hex', '')[:40]
            print(f"{i:>2}  -- fragment ({n} bytes): {hex_str}"
                  + ('...' if len(r.get('_remaining_hex', '')) > 40 else ''))
            continue
        rlen = r.get('record_len', 0)
        if 'parse_error' in r:
            parse_errors += 1
            code = r.get('property_code', 0)
            dt = r.get('datatype', 0)
            dt_name = t.DT_NAMES.get(dt, f"0x{dt:04x}")
            gs = ('R', 'RW')[r['getset']] if 'getset' in r else '?'
            print(f"{i:>2} {rlen:>4} 0x{code:04x} {dt_name:<7} {gs:<3} "
                  f"(stub — only header bytes; firmware bug for this prop)")
            continue

        code = r.get('property_code', -1)
        dt = r.get('datatype', 0)
        dt_name = t.DT_NAMES.get(dt, f"0x{dt:04x}")
        getset = r.get('getset', 0)
        gs = ('R', 'RW', '?')[getset] if getset < 2 else f"?{getset}"
        default = format_value(r.get('factory_default'), dt)
        current = format_value(r.get('current_value'), dt)
        form = r.get('form', '?')

        # Cross-reference against the JSON catalog
        ref = known.get(code)
        match_str = ''
        if ref is None:
            match_str = '(not in catalog)'
        else:
            ref_desc = ref.get('desc') or {}
            ref_cur = ref_desc.get('current')
            if r.get('current_value') == ref_cur:
                match_str = '✓ matches catalog'
                matches += 1
            else:
                match_str = f'✗ catalog says cur={format_value(ref_cur, dt)}'
                mismatches += 1

        print(f"{i:>2} {r['record_len']:>4} 0x{code:04x} {dt_name:<7} {gs:<3} "
              f"{default:>16} {current:>16} {form:<6} {match_str}")

    print()
    print(f"Summary: {matches} match catalog, {mismatches} differ, "
          f"{parse_errors} parse errors")

    # Calculate which properties are in 0x9614 vs the full enumeration
    in_9614 = {r.get('property_code') for r in records if r.get('property_code') is not None}
    if known:
        in_catalog = set(known.keys())
        only_in_9614 = in_9614 - in_catalog
        only_in_catalog = in_catalog - in_9614
        print(f"\nCoverage: {len(in_9614)} props in 0x9614 dump, "
              f"{len(in_catalog)} props in catalog")
        if only_in_9614:
            print(f"  Properties ONLY in 0x9614: {sorted(hex(c) for c in only_in_9614)}")
        if only_in_catalog:
            sample = sorted(only_in_catalog)[:10]
            print(f"  Properties ONLY in catalog ({len(only_in_catalog)}): "
                  f"{[hex(c) for c in sample]}...")


if __name__ == '__main__':
    sys.exit(main())
