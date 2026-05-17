#!/usr/bin/env python3
"""Implement the iCatch device-verify handshake — the SDK's "AES verify"
that's actually just arithmetic. Reversed from
`Ptp2CameraControl::ptpip_iCatch_device_verify()` in libcontrol.so.

Flow (per Agent 3 reverse-engineering, see docs/dev-console-hunt.md
"NIGHT-RESEARCH UPDATE" section):

  1. Get sdCardId (from PTP storage)
  2. Get storage info (imageCnt etc.)
  3. Call vendor op 0x9614 to dump every property descriptor at once
  4. From the 0x9614 response, extract:
        - timeDate string (property 0x5011 DateTime)
        - remVid u32
        - EncData 4 u32s at offsets 0/16/32/48 of property 0xD617
  5. Arithmetic check (calc0..calc3); if mismatch, the SDK errors
  6. Set DateTime back to the camera (echo it)
  7. Set 0xD617 to 16 zero bytes (this is what "unlocks" the property)
  8. After this, GetDevicePropValue(0xD617) should return data

Usage:
    python3 tools/icatch_verify.py [--host 192.168.1.1] [--bind 192.168.1.10]

After successful verify, this script also re-queries 0xD617 directly
and enumerates the camera's properties / vendor-op surface to see if
any new surface unlocked.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from larkfly import Camera
from larkfly import types as t

# PTP opcodes we use
OP_GET_DEVICE_PROP_DESC  = 0x1014
OP_GET_DEVICE_PROP_VALUE = 0x1015
OP_SET_DEVICE_PROP_VALUE = 0x1016
OP_GET_STORAGE_IDS       = 0x1004
OP_GET_STORAGE_INFO      = 0x1005
OP_ICATCH_GETALLPROPDESCS = 0x9614  # the bulk PropDesc reader

# PTP property codes
PROP_DATETIME = 0x5011
PROP_ENCDATA  = 0xD617

# PTP datatypes
DT_AUINT8 = 0x4002
DT_STR    = 0xFFFF


def parse_ptp_string(buf: bytes, offset: int) -> tuple[str, int]:
    """Parse a PTP string (u8 char_count + count * u16 UTF-16LE, terminator included)."""
    n = buf[offset]
    if n == 0:
        return '', 1
    raw = buf[offset+1 : offset+1 + 2*n]
    try:
        s = raw[:-2].decode('utf-16-le', errors='replace')
    except Exception:
        s = raw.hex()
    return s, 1 + 2*n


def walk_propdesc_records(data: bytes) -> list[dict]:
    """The 0x9614 response is a stream of length-prefixed PropDesc records.
    Each record:
        u32 record_length (including this header)
        PropDesc payload (length-4 bytes):
            u16 prop_code
            u16 datatype
            u8 getset
            <factory_default (datatype-sized)>
            <current_value (datatype-sized)>
            u8 form_flag
            [form data depending on form]
    """
    DT_SIZE = {0x01:1, 0x02:1, 0x03:2, 0x04:2, 0x05:4, 0x06:4,
               0x07:8, 0x08:8, 0x09:16, 0x0a:16,
               0x4002:None}  # AUINT8 = array, prefix-counted

    records = []
    pos = 0
    while pos + 4 <= len(data):
        rlen = struct.unpack_from('<I', data, pos)[0]
        if rlen < 4 or pos + rlen > len(data):
            records.append({'_fragment': True, 'pos': pos,
                            '_rest': data[pos:].hex()})
            break
        body = data[pos+4 : pos+rlen]
        pos += rlen

        rec = {'record_len': rlen, 'body_hex': body.hex()}
        try:
            code = struct.unpack_from('<H', body, 0)[0]
            dt   = struct.unpack_from('<H', body, 2)[0]
            gs   = body[4]
            rec['code'] = code
            rec['code_hex'] = f'0x{code:04x}'
            rec['datatype'] = dt
            rec['getset'] = gs
            sz = DT_SIZE.get(dt)
            p = 5
            if dt == DT_STR:
                # PTP string for factory_default + current_value
                rec['factory'], used = parse_ptp_string(body, p); p += used
                rec['current'],  used = parse_ptp_string(body, p); p += used
            elif dt == DT_AUINT8:
                # AUINT8 array — length prefix u32 LE
                n = struct.unpack_from('<I', body, p)[0]; p += 4
                rec['factory'] = body[p:p+n].hex(); p += n
                n = struct.unpack_from('<I', body, p)[0]; p += 4
                rec['current'] = body[p:p+n].hex(); p += n
            elif sz:
                rec['factory'] = int.from_bytes(body[p:p+sz], 'little'); p += sz
                rec['current'] = int.from_bytes(body[p:p+sz], 'little'); p += sz
        except Exception as e:
            rec['parse_err'] = f'{type(e).__name__}: {e}'
        records.append(rec)
    return records


def run_verify(host: str, bind: str | None) -> dict:
    out = {'host': host}
    with Camera(host, bind=bind) as cam:
        print('[*] Connected to camera. Reading storage…')
        rc, _, data = cam._raw_op(OP_GET_STORAGE_IDS, [])
        if rc != t.RC_OK:
            return {'error': f'GetStorageIDs failed rc=0x{rc:04x}'}
        n = struct.unpack_from('<I', data, 0)[0]
        sids = [struct.unpack_from('<I', data, 4+i*4)[0] for i in range(n)]
        if not sids:
            return {'error': 'no storage'}
        out['storage_ids'] = [hex(s) for s in sids]
        sid = sids[0]
        rc, _, sinfo = cam._raw_op(OP_GET_STORAGE_INFO, [sid])
        out['storage_info_hex'] = sinfo.hex()

        # SD card "ID" — the verify code calls getSDCardIdPrivate which
        # likely returns the storage_id itself (0x50001 in our case)
        sd_card_id = sid
        # imageCnt is in the storage info at offset 24 (per PTP StorageInfo
        # FreeSpaceInImages u32)
        image_cnt = struct.unpack_from('<I', sinfo, 24)[0] if len(sinfo) >= 28 else 0
        out['sd_card_id'] = hex(sd_card_id)
        out['image_cnt'] = image_cnt

        print('[*] Calling vendor op 0x9614 GetAllPropDescs…')
        rc, _, descs = cam._raw_op(OP_ICATCH_GETALLPROPDESCS, [])
        out['op_9614_rc'] = hex(rc)
        out['op_9614_len'] = len(descs)
        # Save raw response for follow-up
        with open('/tmp/op_9614_during_verify.bin', 'wb') as f:
            f.write(descs)
        print(f'    rc=0x{rc:04x} len={len(descs)} saved /tmp/op_9614_during_verify.bin')

        # Walk records
        records = walk_propdesc_records(descs)
        out['record_count'] = len(records)
        # Find DateTime (0x5011), EncData (0xD617)
        rec_5011 = next((r for r in records if r.get('code') == 0x5011), None)
        rec_d617 = next((r for r in records if r.get('code') == 0xD617), None)
        rec_rem  = next((r for r in records
                         if r.get('code_hex','').startswith('0xd')
                         and r.get('datatype') == 0x06), None)
        # remVid is in some other property of UINT32 type — agent says
        # "DeviceAllPropDescs.getRemVid()" but didn't name the prop code.
        # Likely 0xD303 or 0xD406 (those are the UINT32 props we know about
        # in the lower-D range). For now we'll attempt verify anyway —
        # the arithmetic check is informational.
        timeDate = rec_5011.get('current') if rec_5011 else None
        out['timeDate'] = timeDate
        if rec_d617:
            print(f'[+] property 0xD617 FOUND in 0x9614 response — body bytes:')
            print(f'    {rec_d617["body_hex"]}')
            out['encdata_found'] = True
            out['encdata_body_hex'] = rec_d617['body_hex']
            # Try to extract EncData u32s at offsets 0/16/32/48 of the property
            cur = rec_d617.get('current')
            if isinstance(cur, str) and all(c in '0123456789abcdef' for c in cur.lower()):
                # cur is hex
                cur_bytes = bytes.fromhex(cur)
                if len(cur_bytes) >= 52:
                    enc = [int.from_bytes(cur_bytes[i:i+4], 'little')
                           for i in (0, 16, 32, 48)]
                    out['enc'] = [hex(e) for e in enc]
                    print(f'    enc[0..3] (LE u32 at off 0,16,32,48) = {out["enc"]}')
        else:
            print('[!] property 0xD617 NOT in 0x9614 response — may not exist on this firmware')
            out['encdata_found'] = False

        # Step 6: SetDevicePropValue(0x5011 DateTime, STRING, timeDate)
        if timeDate:
            print(f'[*] Setting DateTime (0x5011) back to camera: "{timeDate}"')
            # PTP string format
            tx = bytes([len(timeDate)+1]) + (timeDate + '\x00').encode('utf-16-le')
            try:
                rc, _, _ = cam._raw_op(OP_SET_DEVICE_PROP_VALUE, [0x5011], tx)
                print(f'    rc=0x{rc:04x}')
                out['set_5011_rc'] = hex(rc)
            except Exception as e:
                print(f'    error: {e}')
                out['set_5011_err'] = str(e)

        # Step 7: SetDevicePropValue(0xD617, AUINT8, b"\x00"*16)
        print('[*] Setting 0xD617 to 16 zero bytes (the magic unlock SET)…')
        tx = struct.pack('<I', 16) + b'\x00' * 16
        try:
            rc, _, _ = cam._raw_op(OP_SET_DEVICE_PROP_VALUE, [0xD617], tx)
            print(f'    rc=0x{rc:04x} {"(OK — verify completed!)" if rc == t.RC_OK else ""}')
            out['set_d617_rc'] = hex(rc)
        except Exception as e:
            print(f'    error: {e}')
            out['set_d617_err'] = str(e)

        # After verify, retry the previously-blocked direct queries
        print()
        print('[*] Post-verify probes:')
        for code in [0xD617]:
            try:
                rc, _, data = cam._raw_op(OP_GET_DEVICE_PROP_DESC, [code])
                print(f'    GetDevicePropDesc(0x{code:04x}): rc=0x{rc:04x} '
                      f'len={len(data)}')
                if rc == t.RC_OK:
                    out[f'post_verify_desc_{code:04x}'] = data.hex()
            except Exception as e:
                print(f'    GetDevicePropDesc(0x{code:04x}) err: {e}')
            try:
                rc, _, data = cam._raw_op(OP_GET_DEVICE_PROP_VALUE, [code])
                print(f'    GetDevicePropValue(0x{code:04x}): rc=0x{rc:04x} '
                      f'len={len(data)} hex={data[:64].hex()}')
                if rc == t.RC_OK:
                    out[f'post_verify_val_{code:04x}'] = data.hex()
            except Exception as e:
                print(f'    GetDevicePropValue(0x{code:04x}) err: {e}')

        # Also re-run device_info to see if ops/props list changed
        try:
            info = cam.device_info()
            ops = info.get('operations_supported', [])
            props = info.get('properties_supported', [])
            print(f'    DeviceInfo: {len(ops)} ops, {len(props)} props '
                  f'({len([p for p in props if p == 0xD617])} D617)')
            out['post_verify_ops_count'] = len(ops)
            out['post_verify_props_count'] = len(props)
            out['post_verify_has_d617'] = 0xD617 in props
            # New ops?
            known_ops = {0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006,
                         0x1007, 0x1008, 0x1009, 0x100a, 0x100b, 0x100c,
                         0x100d, 0x100e, 0x100f, 0x1012, 0x1014, 0x1015,
                         0x1016, 0x101b, 0x9601, 0x9602, 0x9812, 0x9614,
                         0x9801, 0x9802, 0x9803, 0x9805}
            new_ops = sorted(set(ops) - known_ops)
            if new_ops:
                print(f'    ** NEW OPS UNLOCKED: {[hex(o) for o in new_ops]} **')
                out['new_ops'] = [hex(o) for o in new_ops]
        except Exception as e:
            print(f'    DeviceInfo err: {e}')

    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--host', default='192.168.1.1')
    ap.add_argument('--bind', default='192.168.1.10')
    ap.add_argument('--json-out', default='analyses/data/icatch_verify.json')
    args = ap.parse_args()

    result = run_verify(args.host, args.bind)
    os.makedirs(os.path.dirname(args.json_out) or '.', exist_ok=True)
    with open(args.json_out, 'w') as f:
        json.dump(result, f, indent=2, default=str)
    print()
    print(f'[+] JSON: {args.json_out}')


if __name__ == '__main__':
    sys.exit(main())
