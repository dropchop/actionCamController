#!/usr/bin/env python3
"""Enumerate every device property the camera supports by calling
GetDevicePropDesc (op 0x1014) and GetDevicePropValue (op 0x1015) for each
property code in the supported list.

Outputs a JSON map: {propcode_hex -> {datatype, getset, form, default,
current, raw_desc_hex, raw_value_hex}} and prints a human-readable summary.

Pure read-only — no state changes on the camera.

Usage:
  python3 enumerate_props.py [HOST] [-o OUTPUT.json] [--bind SOURCE_IP]
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import time
import uuid

from ptpip_probe import (
    PT_INIT_CMD_REQ, PT_INIT_CMD_ACK, PT_INIT_FAIL, PT_OP_RESP,
    OP_GET_DEVICE_INFO, OP_OPEN_SESSION, OP_CLOSE_SESSION, RC_OK,
    PTPIP_PORT, PROTOCOL_VERSION,
    send_packet, recv_packet, connect_tcp, init_command, init_event,
    operation, parse_device_info,
)

# PTP standard data type codes (PIMA 15740 §5.2.2)
DATATYPE_NAMES = {
    0x0000: 'UNDEF',
    0x0001: 'INT8',    0x0002: 'UINT8',
    0x0003: 'INT16',   0x0004: 'UINT16',
    0x0005: 'INT32',   0x0006: 'UINT32',
    0x0007: 'INT64',   0x0008: 'UINT64',
    0x0009: 'INT128',  0x000A: 'UINT128',
    0x4001: 'AINT8',   0x4002: 'AUINT8',
    0x4003: 'AINT16',  0x4004: 'AUINT16',
    0x4005: 'AINT32',  0x4006: 'AUINT32',
    0x4007: 'AINT64',  0x4008: 'AUINT64',
    0x4009: 'AINT128', 0x400A: 'AUINT128',
    0xFFFF: 'STRING',
}

# Property codes we know names for, from the iCatch Java SDK enum.
# These should let us cross-check the descriptor parsing.
KNOWN_PROP_NAMES = {
    # Standard PTP (PIMA 15740 §5.5.4)
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
    # iCatch vendor (from ICatchCamProperty.java)
    0xD605: 'CAP_VIDEO_SIZE',
    0xD606: 'CAP_LIGHT_FREQUENCY',
    0xD607: 'CAP_DATE_STAMP',
    0xD611: 'CAP_TIMELAPSE_VIDEO',
    0xD614: 'CAP_UPSIDE_DOWN',
    0xD615: 'CAP_SLOW_MOTION',
    0xD72B: 'CAP_GET_NUMBER_OF_SENSORS',
    0xD72C: 'CAP_GET_CAMERA_CAPABILITIES',
}


def datatype_size(dt: int) -> int:
    """Return bytes per element; -1 for variable-length (string/array)."""
    return {
        0x0001: 1, 0x0002: 1,
        0x0003: 2, 0x0004: 2,
        0x0005: 4, 0x0006: 4,
        0x0007: 8, 0x0008: 8,
        0x0009: 16, 0x000A: 16,
    }.get(dt, -1)


def decode_value(buf: bytes, off: int, dt: int) -> tuple:
    """Decode one value of the given PTP data type. Returns (value, new_offset)."""
    sz = datatype_size(dt)
    if dt == 0xFFFF:  # STRING (UTF-16LE, length-prefixed)
        n = buf[off]
        off += 1
        if n == 0:
            return '', off
        s = buf[off:off + n * 2 - 2].decode('utf-16-le', errors='replace')
        return s, off + n * 2
    if 0x4001 <= dt <= 0x400A:  # array
        elem_dt = dt - 0x4000
        elem_sz = datatype_size(elem_dt)
        n = struct.unpack_from('<I', buf, off)[0]
        off += 4
        vals = []
        for _ in range(n):
            v, off = decode_value(buf, off, elem_dt)
            vals.append(v)
        return vals, off
    if sz < 0:
        return None, off
    raw = buf[off:off + sz]
    off += sz
    if dt in (0x0001, 0x0003, 0x0005, 0x0007):  # signed
        return int.from_bytes(raw, 'little', signed=True), off
    if dt in (0x0009, 0x000A):  # 128-bit, just hex
        return raw.hex(), off
    return int.from_bytes(raw, 'little'), off


def parse_propdesc(data: bytes) -> dict:
    """PTP DevicePropDesc dataset format."""
    out = {'raw_len': len(data), 'parse_error': None}
    try:
        off = 0
        out['property_code'] = struct.unpack_from('<H', data, off)[0]; off += 2
        out['datatype'] = struct.unpack_from('<H', data, off)[0]; off += 2
        out['datatype_name'] = DATATYPE_NAMES.get(out['datatype'], f"unknown 0x{out['datatype']:04x}")
        out['getset'] = data[off]; off += 1
        out['getset_str'] = ('get-only', 'get/set')[out['getset']] if out['getset'] < 2 else f"?{out['getset']}"
        default, off = decode_value(data, off, out['datatype'])
        out['factory_default'] = default
        current, off = decode_value(data, off, out['datatype'])
        out['current'] = current
        form_flag = data[off]; off += 1
        out['form_flag'] = form_flag
        if form_flag == 0:
            out['form'] = 'none'
        elif form_flag == 1:
            mn, off = decode_value(data, off, out['datatype'])
            mx, off = decode_value(data, off, out['datatype'])
            step, off = decode_value(data, off, out['datatype'])
            out['form'] = 'range'
            out['min'], out['max'], out['step'] = mn, mx, step
        elif form_flag == 2:
            n = struct.unpack_from('<H', data, off)[0]; off += 2
            vals = []
            for _ in range(n):
                v, off = decode_value(data, off, out['datatype'])
                vals.append(v)
            out['form'] = 'enum'
            out['allowed'] = vals
        else:
            out['form'] = f'unknown {form_flag}'
    except Exception as e:
        out['parse_error'] = f"{type(e).__name__}: {e}"
    return out


def parse_propvalue(data: bytes, datatype: int) -> dict:
    out = {'raw_hex': data.hex(), 'datatype': datatype}
    try:
        v, _ = decode_value(data, 0, datatype)
        out['value'] = v
    except Exception as e:
        out['parse_error'] = f"{type(e).__name__}: {e}"
    return out


# ---- session setup ------------------------------------------------------
def open_session(host: str, port: int, bind: str, timeout: float, verbose: bool):
    cmd = connect_tcp(host, port, timeout, bind_source=bind)
    guid = uuid.uuid4().bytes
    conn = init_command(cmd, "localhost", guid, verbose)
    evt = connect_tcp(host, port, timeout, bind_source=bind)
    init_event(evt, conn, verbose)
    rc, _, _ = operation(cmd, OP_OPEN_SESSION, txid=0, params=[1], verbose=verbose)
    if rc == 0x201E:  # DeviceBusy — stuck session
        operation(cmd, OP_CLOSE_SESSION, txid=99, params=[], verbose=verbose)
        rc, _, _ = operation(cmd, OP_OPEN_SESSION, txid=0, params=[1], verbose=verbose)
    if rc != RC_OK:
        raise RuntimeError(f"OpenSession failed: 0x{rc:04x}")
    return cmd, evt


def close_session(cmd, evt, verbose):
    try:
        operation(cmd, OP_CLOSE_SESSION, txid=999, params=[], verbose=verbose)
    except Exception:
        pass
    try: cmd.close()
    except Exception: pass
    if evt:
        try: evt.close()
        except Exception: pass


# ---- main ---------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('host', nargs='?', default='192.168.1.1')
    ap.add_argument('--port', type=int, default=PTPIP_PORT)
    ap.add_argument('--bind', default='192.168.1.10')
    ap.add_argument('--timeout', type=float, default=5.0)
    ap.add_argument('-o', '--output', default='probes/data/properties.json')
    ap.add_argument('--verbose', '-v', action='store_true')
    args = ap.parse_args()

    # Set up output dir
    import os
    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)

    cmd, evt = open_session(args.host, args.port, args.bind, args.timeout, args.verbose)
    try:
        # Get DeviceInfo to harvest supported property list
        rc, _, data = operation(cmd, OP_GET_DEVICE_INFO, txid=1, params=[],
                                 verbose=args.verbose)
        if rc != RC_OK:
            print(f"FAIL: GetDeviceInfo rc=0x{rc:04x}", file=sys.stderr)
            return 1
        info = parse_device_info(data)
        props = info['device_properties_supported']
        print(f"Camera supports {len(props)} device properties")

        # Enumerate each
        results = {}
        txid = 2
        for i, pc in enumerate(props):
            entry = {
                'propcode': pc,
                'propcode_hex': f"0x{pc:04x}",
                'name': KNOWN_PROP_NAMES.get(pc),
                'is_vendor': pc >= 0xD000,
            }
            # PropDesc
            try:
                rc, _, ddata = operation(cmd, 0x1014, txid=txid, params=[pc],
                                          verbose=args.verbose)
                txid += 1
                entry['desc_rc'] = f"0x{rc:04x}"
                if rc == RC_OK and ddata:
                    entry['desc_raw_hex'] = ddata.hex()
                    entry['desc'] = parse_propdesc(ddata)
            except Exception as e:
                entry['desc_error'] = str(e)
            # PropValue
            try:
                rc, _, vdata = operation(cmd, 0x1015, txid=txid, params=[pc],
                                          verbose=args.verbose)
                txid += 1
                entry['value_rc'] = f"0x{rc:04x}"
                if rc == RC_OK and vdata:
                    entry['value_raw_hex'] = vdata.hex()
                    dt = entry.get('desc', {}).get('datatype', 0)
                    entry['value_parsed'] = parse_propvalue(vdata, dt)
            except Exception as e:
                entry['value_error'] = str(e)

            results[f"0x{pc:04x}"] = entry
            # Short progress line
            name = entry.get('name') or '?'
            d = entry.get('desc', {}) or {}
            cur = d.get('current')
            cur_s = repr(cur) if cur is not None else '?'
            print(f"  [{i+1:2}/{len(props)}] 0x{pc:04x} {name:<28} "
                  f"{d.get('datatype_name','?'):<8} "
                  f"{d.get('getset_str','?'):<8} cur={cur_s[:60]}")
        # Save
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
    finally:
        close_session(cmd, evt, args.verbose)


if __name__ == '__main__':
    sys.exit(main())
