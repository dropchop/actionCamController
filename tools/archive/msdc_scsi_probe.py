#!/usr/bin/env python3
"""Vendor SCSI command probe for the Larkfly A6+ in USB Mass Storage mode
(VID:PID 2aad:6371).

When the camera is in MSC mode it exposes a real SD-card disk for
standard READ/WRITE — BUT also accepts vendor SCSI commands that drive
camera operations. libusb_transport.so reveals the method set:

    switchToPreview/Playback, startMovieRecord, stopMovieRecord,
    capturePhoto, formatStorage, updateFw, setAudioMute, setAudioUnMute,
    setEventTrigger, setSeamless, getCurrentMode, getVideoRecordStatus,
    executeScsiCommand (generic).

The debug format strings tell us the wire format:

    scsiCmd: %02x, extendCmd: %04x. parameter: %u
    scsi command: %x, extendCommand: %x, parameter1: %d, durationMS: %d

So a vendor CDB looks roughly like:
    byte 0     scsiCmd (vendor opcode, typically 0xC0-0xFF)
    bytes 1-3  extendCommand   (likely u16 big-endian + 1 pad byte)
    bytes 4-7  parameter1      (u32)
    bytes 8-11 durationMS      (u32)
    bytes 12-15  padding to a 16-byte CDB (SCSI WRITE_16-style)

This probe:
  1. Reads INQUIRY + serial via sg_inq.
  2. Brute-forces opcodes 0xC0..0xFF with all-zero CDB tail. Each
     opcode returns either GOOD STATUS (vendor opcode is implemented)
     or CHECK CONDITION with INVALID_OPCODE (sense key 0x05, ascq 0x2000).
  3. For each implemented opcode, records the sense bytes and any data
     phase result.

Requires root for /dev/sg0. Usage:

    sudo python3 tools/msdc_scsi_probe.py
    sudo python3 tools/msdc_scsi_probe.py --dev /dev/sg0 --json-out ...

SAFETY:
  - We send no parameters (all zeros after the opcode), so commands
    that would otherwise do something destructive (formatStorage,
    updateFw) get the most benign possible argument shape. **There is
    still some risk** — if an opcode is e.g. "format SD when arg=0",
    we'd start formatting. To minimize: this probe ONLY enumerates
    opcodes — it doesn't try the more advanced functions with
    non-zero parameters. Caller can use `--max-opcode` to abort early
    if a probe is taking too long or returning unexpected data.
"""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import json
import os
import struct
import subprocess
import sys
from ctypes import c_int, c_void_p, c_uint, c_ushort, c_ubyte

# SG_IO ioctl number on Linux x86_64
SG_IO = 0x2285

# sg_io_hdr_t direction flags
SG_DXFER_NONE     = -1
SG_DXFER_TO_DEV   = -2
SG_DXFER_FROM_DEV = -3
SG_DXFER_TO_FROM_DEV = -4

# sg_io_hdr_t structure (Linux <scsi/sg.h>) — size 88 bytes on x86_64
class SgIoHdr(ctypes.Structure):
    _fields_ = [
        ('interface_id',   c_int),
        ('dxfer_direction',c_int),
        ('cmd_len',        c_ubyte),
        ('mx_sb_len',      c_ubyte),
        ('iovec_count',    c_ushort),
        ('dxfer_len',      c_uint),
        ('dxferp',         c_void_p),
        ('cmdp',           c_void_p),
        ('sbp',            c_void_p),
        ('timeout',        c_uint),
        ('flags',          c_uint),
        ('pack_id',        c_int),
        ('usr_ptr',        c_void_p),
        ('status',         c_ubyte),
        ('masked_status',  c_ubyte),
        ('msg_status',     c_ubyte),
        ('sb_len_wr',      c_ubyte),
        ('host_status',    c_ushort),
        ('driver_status',  c_ushort),
        ('resid',          c_int),
        ('duration',       c_uint),
        ('info',           c_uint),
    ]


def parse_sense(sb: bytes) -> dict:
    """Parse SCSI fixed-format sense data (10/18 bytes)."""
    if len(sb) < 8:
        return {'raw': sb.hex(), 'len': len(sb)}
    response_code = sb[0] & 0x7F
    if response_code in (0x70, 0x71):  # fixed-format
        sense_key = sb[2] & 0x0F
        asc = sb[12] if len(sb) > 12 else 0
        ascq = sb[13] if len(sb) > 13 else 0
        return {
            'response_code': hex(response_code),
            'sense_key': sense_key,
            'sense_key_name': SENSE_KEY_NAMES.get(sense_key, hex(sense_key)),
            'asc': hex(asc),
            'ascq': hex(ascq),
            'asc_name': ASC_NAMES.get((asc, ascq), 'unknown'),
            'raw': sb.hex(),
        }
    elif response_code in (0x72, 0x73):  # descriptor-format
        sense_key = sb[1] & 0x0F
        asc = sb[2] if len(sb) > 2 else 0
        ascq = sb[3] if len(sb) > 3 else 0
        return {
            'response_code': hex(response_code),
            'sense_key': sense_key,
            'sense_key_name': SENSE_KEY_NAMES.get(sense_key, hex(sense_key)),
            'asc': hex(asc),
            'ascq': hex(ascq),
            'asc_name': ASC_NAMES.get((asc, ascq), 'unknown'),
            'raw': sb.hex(),
        }
    return {'raw': sb.hex(), 'unparsed': True}


SENSE_KEY_NAMES = {
    0x00: 'NO_SENSE',
    0x01: 'RECOVERED_ERROR',
    0x02: 'NOT_READY',
    0x03: 'MEDIUM_ERROR',
    0x04: 'HARDWARE_ERROR',
    0x05: 'ILLEGAL_REQUEST',
    0x06: 'UNIT_ATTENTION',
    0x07: 'DATA_PROTECT',
    0x08: 'BLANK_CHECK',
    0x09: 'VENDOR_SPECIFIC',
    0x0A: 'COPY_ABORTED',
    0x0B: 'ABORTED_COMMAND',
    0x0D: 'VOLUME_OVERFLOW',
    0x0E: 'MISCOMPARE',
}

ASC_NAMES = {
    (0x20, 0x00): 'INVALID_COMMAND_OPCODE',
    (0x24, 0x00): 'INVALID_FIELD_IN_CDB',
    (0x25, 0x00): 'LOGICAL_UNIT_NOT_SUPPORTED',
    (0x26, 0x00): 'INVALID_FIELD_IN_PARAMETER_LIST',
    (0x2C, 0x00): 'COMMAND_SEQUENCE_ERROR',
    (0x28, 0x00): 'NOT_READY_TO_READY_CHANGE',
    (0x29, 0x00): 'POWER_ON_OR_RESET',
}


def send_scsi(fd: int, cdb: bytes, data_in_len: int = 0,
              data_out: bytes | None = None, timeout_ms: int = 5000) -> dict:
    """Send one SCSI command via SG_IO. Returns dict with status, sense,
    data, etc."""
    sb_buf = (ctypes.c_ubyte * 32)()
    cmd_buf = (ctypes.c_ubyte * len(cdb)).from_buffer_copy(cdb)
    data_buf = None
    dxfer_dir = SG_DXFER_NONE
    if data_in_len > 0:
        data_buf = (ctypes.c_ubyte * data_in_len)()
        dxfer_dir = SG_DXFER_FROM_DEV
    elif data_out:
        data_buf = (ctypes.c_ubyte * len(data_out)).from_buffer_copy(data_out)
        dxfer_dir = SG_DXFER_TO_DEV
        data_in_len = len(data_out)

    hdr = SgIoHdr()
    hdr.interface_id = ord('S')
    hdr.dxfer_direction = dxfer_dir
    hdr.cmd_len = len(cdb)
    hdr.mx_sb_len = 32
    hdr.iovec_count = 0
    hdr.dxfer_len = data_in_len if data_buf else 0
    hdr.dxferp = ctypes.cast(data_buf, c_void_p) if data_buf else None
    hdr.cmdp = ctypes.cast(cmd_buf, c_void_p)
    hdr.sbp = ctypes.cast(sb_buf, c_void_p)
    hdr.timeout = timeout_ms
    hdr.flags = 0

    try:
        fcntl.ioctl(fd, SG_IO, hdr)
    except OSError as e:
        return {'ioctl_err': str(e), 'errno': e.errno}

    sense = parse_sense(bytes(sb_buf[:hdr.sb_len_wr])) if hdr.sb_len_wr else {}
    data = bytes(data_buf[:hdr.dxfer_len - hdr.resid]) if (data_buf and dxfer_dir == SG_DXFER_FROM_DEV) else b''
    return {
        'status': hdr.status,
        'host_status': hdr.host_status,
        'driver_status': hdr.driver_status,
        'sb_len_wr': hdr.sb_len_wr,
        'resid': hdr.resid,
        'duration_ms': hdr.duration,
        'sense': sense,
        'data_hex': data.hex(),
        'data_len': len(data),
    }


def inquiry(fd: int) -> dict:
    """Standard SCSI INQUIRY (opcode 0x12)."""
    cdb = bytes([0x12, 0x00, 0x00, 0x00, 0x60, 0x00])
    return send_scsi(fd, cdb, data_in_len=0x60)


def build_vendor_cdb(opcode: int, extend_cmd: int = 0,
                     parameter1: int = 0, duration_ms: int = 0) -> bytes:
    """Build a 16-byte vendor CDB matching the iCatch debug-string format."""
    # Best guess at layout. SCSI traditionally packs multi-byte fields
    # big-endian, so use big-endian for extend_cmd / parameter1.
    return struct.pack('>B B H I I HH',
                       opcode,
                       0,          # reserved
                       extend_cmd, # u16 BE
                       parameter1, # u32 BE
                       duration_ms,# u32 BE
                       0, 0)       # 4 bytes of padding


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--dev', default='/dev/sg0')
    ap.add_argument('--json-out', default='analyses/data/msdc_scsi_probe.json')
    ap.add_argument('--min-opcode', type=lambda s: int(s, 16), default=0xC0)
    ap.add_argument('--max-opcode', type=lambda s: int(s, 16), default=0xFF)
    ap.add_argument('--data-in', type=int, default=64,
                    help='Expected response data length (bytes)')
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("[!] This probe needs root for /dev/sg0. Re-run with sudo.")
        return 2

    print(f"[*] Opening {args.dev}")
    try:
        fd = os.open(args.dev, os.O_RDWR)
    except OSError as e:
        print(f"[!!] Cannot open {args.dev}: {e}")
        return 2

    results = {'dev': args.dev, 'opcodes': {}}

    try:
        print("[*] Standard INQUIRY")
        r = inquiry(fd)
        results['inquiry'] = r
        if r.get('status') == 0 and r['data_len'] >= 36:
            data = bytes.fromhex(r['data_hex'])
            print(f"   peripheral_type=0x{data[0]:02x} ({data[0] & 0x1f}) "
                  f"vendor={data[8:16]!r} product={data[16:32]!r} rev={data[32:36]!r}")

        print()
        print(f"[*] Vendor opcode brute-force {args.min_opcode:#04x}..{args.max_opcode:#04x}")
        invalid_count = 0
        impl = []
        for opcode in range(args.min_opcode, args.max_opcode + 1):
            cdb = build_vendor_cdb(opcode)
            r = send_scsi(fd, cdb, data_in_len=args.data_in, timeout_ms=2000)
            results['opcodes'][hex(opcode)] = r
            status = r.get('status', '?')
            asc = r.get('sense', {}).get('asc', '-')
            ascq = r.get('sense', {}).get('ascq', '-')
            asc_name = r.get('sense', {}).get('asc_name', '')
            if asc == '0x20' and ascq == '0x0':
                invalid_count += 1
            else:
                impl.append(opcode)
                key = r.get('sense', {}).get('sense_key_name', '-')
                data_preview = r['data_hex'][:32]
                print(f"   {opcode:#04x}: status={status:>3} key={key:<20} "
                      f"asc={asc}/{ascq} ({asc_name}) "
                      f"data={data_preview}{'…' if len(r['data_hex'])>32 else ''}")

        print()
        print(f"[+] {len(impl)} opcodes implemented (rest = invalid)")
        print(f"    Implemented: {[hex(o) for o in impl]}")
    finally:
        os.close(fd)

    os.makedirs(os.path.dirname(args.json_out) or '.', exist_ok=True)
    with open(args.json_out, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"[+] JSON: {args.json_out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
