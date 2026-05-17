#!/usr/bin/env python3
"""Run iCatch MSC vendor SCSI commands using the table cross-confirmed
from libusb_transport.so disassembly + lingkun/USBCam Java source.

CDB layout (16 bytes) — confirmed empirically on V11 2026-05-17:
  byte 0       = 0xC0 (universal vendor opcode)
  bytes 1-2    = extendCmd (u16, big-endian — the actual command)
  bytes 3-6    = parameter1 (u32, big-endian)
  bytes 7-10   = parameter2 / duration (u32, big-endian — often zero)
  bytes 11-15  = padding (5 bytes)

NOTE: extendCmd = 0x0000 (the "default" CDB when fields are mis-shifted)
returns a 76-byte device GUID in UTF-16LE — that's how we found this bug.

Use SAFE commands (--cmd ver / status / stream-status / disk-info /
check-fw-update / cardstatus) for read-only smoke tests.
Use --cmd set-time / set-res / mode-switch / mute / unmute for low-risk
writes. Use --cmd fw-update or recovery only when you know what you're
doing.

Camera must be in MSC mode (PID 2aad:6371). Requires sudo for /dev/sg0.
"""

import argparse, ctypes, fcntl, json, os, struct, sys
from ctypes import c_int, c_void_p, c_uint, c_ushort, c_ubyte

# ─── SCSI / SG_IO scaffolding ────────────────────────────────────────────
SG_IO = 0x2285
SG_DXFER_NONE     = -1
SG_DXFER_TO_DEV   = -2
SG_DXFER_FROM_DEV = -3

class SgIoHdr(ctypes.Structure):
    _fields_ = [
        ('interface_id', c_int), ('dxfer_direction', c_int),
        ('cmd_len', c_ubyte), ('mx_sb_len', c_ubyte),
        ('iovec_count', c_ushort), ('dxfer_len', c_uint),
        ('dxferp', c_void_p), ('cmdp', c_void_p), ('sbp', c_void_p),
        ('timeout', c_uint), ('flags', c_uint), ('pack_id', c_int),
        ('usr_ptr', c_void_p), ('status', c_ubyte),
        ('masked_status', c_ubyte), ('msg_status', c_ubyte),
        ('sb_len_wr', c_ubyte), ('host_status', c_ushort),
        ('driver_status', c_ushort), ('resid', c_int),
        ('duration', c_uint), ('info', c_uint),
    ]


def build_cdb(extend_cmd: int, param1: int = 0, param2: int = 0, param3: int = 0) -> bytes:
    """16-byte iCatch vendor CDB (confirmed via libusb_transport.so disasm 2026-05-17).

    Layout: opcode(1=0xC0) extendCmd(2 BE) param1(4 BE) param2(4 BE) param3(4 BE) pad(1).
    """
    return struct.pack('>BHIIIB', 0xC0, extend_cmd, param1, param2, param3, 0)


def scsi(fd, cdb: bytes, data_in: int = 0, data_out: bytes | None = None,
         timeout_ms: int = 2000):
    """Send one SCSI command; returns (status, data_bytes, sense_hex)."""
    sb = (c_ubyte*32)()
    cmd = (c_ubyte*len(cdb)).from_buffer_copy(cdb)
    if data_out is not None:
        data = (c_ubyte*len(data_out)).from_buffer_copy(data_out)
        dir_ = SG_DXFER_TO_DEV
        dlen = len(data_out)
    elif data_in:
        data = (c_ubyte*data_in)()
        dir_ = SG_DXFER_FROM_DEV
        dlen = data_in
    else:
        data = None
        dir_ = SG_DXFER_NONE
        dlen = 0
    h = SgIoHdr()
    h.interface_id = ord('S')
    h.dxfer_direction = dir_
    h.cmd_len = len(cdb); h.mx_sb_len = 32
    h.dxfer_len = dlen
    h.dxferp = ctypes.cast(data, c_void_p) if data else None
    h.cmdp = ctypes.cast(cmd, c_void_p)
    h.sbp = ctypes.cast(sb, c_void_p)
    h.timeout = timeout_ms
    try:
        fcntl.ioctl(fd, SG_IO, h)
    except OSError as e:
        return -e.errno, b'', ''
    out = b''
    if data is not None and dir_ == SG_DXFER_FROM_DEV:
        out = bytes(data[:dlen - h.resid])
    return h.status, out, bytes(sb[:h.sb_len_wr]).hex()


# ─── Command catalog (from USBCam + libusb_transport extraction) ──────────
# (extend_cmd, default_data_in_len, direction, default_param1, description, parse_fn)
CMDS = {
    # --- SAFE READS ---
    'ver':              (0x000C, 18, 'IN',  0, 'CAM_VER_GET — firmware version (18 ASCII bytes)', None),
    'sd-card-status':   (0x0010, 32, 'IN',  0, 'CAM_SD_CARD_STATUS — 32-byte status struct', 'parse_sd_status'),
    'stream-status':    (0x0011, 4,  'IN',  0, 'CAM_STREAM_STATUS — 4 bytes, [0]=0/1/2/3', None),
    'check-fw-update':  (0x0014, 32, 'IN',  0, 'CAM_CHECK_FW_UPDATE — [0]=1 if FW update available', None),
    'disk-info':        (0x0103, 16, 'IN',  0, 'SCSI_EXT_GET_DISK_INFO — 16-byte disk info', None),
    # --- LOW-RISK WRITES (camera state changes) ---
    'mode-preview':     (0x0006, 0,  'OUT', 0, 'switchToPreview',                                   None),
    'mode-playback':    (0x0006, 0,  'OUT', 1, 'switchToPlayback',                                   None),
    'mute':             (0x000A, 0,  'OUT', 1, 'setAudioMute',                                       None),
    'unmute':           (0x000A, 0,  'OUT', 0, 'setAudioUnMute',                                     None),
    'reset-timer':      (0x000F, 6,  'OUT', 0, 'CAM_RETET_TIMER',                                    None),
    # --- HIGH-RISK / DESTRUCTIVE (use with care) ---
    'capture-photo':    (0x0007, 0,  'OUT', 0, 'capturePhoto (NB: PTP path failed earlier; SCSI may work!)', None),
    'rec-start':        (0x0005, 0,  'OUT', 1, 'startMovieRecord',                                   None),
    'rec-stop':         (0x0005, 0,  'OUT', 0, 'stopMovieRecord',                                    None),
    'param-reset':      (0x000D, 6,  'OUT', 0, 'CAM_PARA_RESET — factory reset settings (no SD wipe)', None),
    'format':           (0x0012, 0,  'OUT', 0, 'formatStorage — WIPES SD CARD',                       None),
    'fw-update':        (0x0013, 0,  'OUT', 1, 'CAM_FW_UPDATE — start FW update (needs valid SPHOST.BRN on SD)', None),
    'fw-update-ignore': (0x0013, 0,  'OUT', 0, 'CAM_FW_UPDATE arg=0 — IGNORE pending FW update',     None),
    'recovery-pb':      (0x0201, 6,  'OUT', 1, 'CAM_EXCEPTION_RECOVERY for playback',                None),
    'recovery-pv':      (0x0201, 6,  'OUT', 0, 'CAM_EXCEPTION_RECOVERY for preview',                 None),
}


def parse_sd_status(buf: bytes) -> dict:
    """Decode CAM_SD_CARD_STATUS (32-byte) per USBCam UsbScsiCommand.java."""
    if len(buf) < 32:
        return {'_short': len(buf)}
    s = buf[3]
    streaming_map = {0: 'neither', 1: 'rec_only', 2: 'pv_only', 3: 'rec+pv'}
    return {
        'exist': bool(buf[0]),
        'sd_state_info': buf[1],
        'error_info': buf[2],
        'streaming': streaming_map.get(s, f'?{s}'),
        'is_recording': s in (1, 3),
        'is_pv_streaming': s in (2, 3),
        'event_trigger_status': buf[4],
        'audio_mute': bool(buf[5]),
        'fw_update_status': buf[6],
        'switch_mode_status': buf[7],
        'sd_insert_status': buf[10],
        'raw': buf.hex(),
    }


PARSERS = {'parse_sd_status': parse_sd_status}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--dev', default='/dev/sg0')
    ap.add_argument('--cmd', required=True, choices=list(CMDS.keys()) + ['list', 'raw'],
                    help="command name from catalog (or 'list' to print catalog, 'raw' for arbitrary)")
    ap.add_argument('--param1', type=int, default=None,
                    help='override default parameter1')
    ap.add_argument('--data-in', type=int, default=None,
                    help='override expected data_in length')
    ap.add_argument('--data-out', default=None,
                    help='hex-encoded data to send (for OUT commands)')
    ap.add_argument('--extend-cmd', type=lambda s: int(s, 0), default=None,
                    help='override extend_cmd (e.g. 0x000B)')
    ap.add_argument('--json-out', default=None)
    args = ap.parse_args()

    if args.cmd == 'list':
        print("Available commands:")
        for name, (ext, dlen, dir_, p1, desc, _) in CMDS.items():
            risk = 'SAFE-READ' if dir_ == 'IN' and dlen > 0 else ('LOW' if dir_ == 'OUT' and p1 == 0 else 'HIGH')
            print(f"  {name:20s} ext={hex(ext):>6s} {dir_:<3s} param1={p1} dlen={dlen} [{risk}] {desc}")
        return 0

    if os.geteuid() != 0:
        print("Need sudo for /dev/sg0; re-run with sudo.", file=sys.stderr)
        return 2

    if args.cmd == 'raw':
        if args.extend_cmd is None:
            print("--cmd raw requires --extend-cmd", file=sys.stderr)
            return 2
        ext, dlen, dir_, p1, desc, parser = (args.extend_cmd, args.data_in or 0,
                                              'OUT' if args.data_out else 'IN',
                                              args.param1 or 0, 'raw', None)
    else:
        ext, dlen, dir_, p1, desc, parser = CMDS[args.cmd]

    if args.param1 is not None: p1 = args.param1
    if args.data_in is not None: dlen = args.data_in
    data_out = bytes.fromhex(args.data_out) if args.data_out else None
    if data_out: dir_ = 'OUT'; dlen = 0

    cdb = build_cdb(ext, p1)
    print(f"[*] CMD: {args.cmd} — {desc}")
    print(f"    CDB: {cdb.hex()}")
    print(f"    dir={dir_} param1={p1} data_in_len={dlen} data_out_len={len(data_out) if data_out else 0}")

    fd = os.open(args.dev, os.O_RDWR)
    try:
        status, data, sense = scsi(fd, cdb,
                                    data_in=dlen if dir_ == 'IN' else 0,
                                    data_out=data_out)
    finally:
        os.close(fd)

    print(f"[+] status=0x{status:02x} ({'OK' if status == 0 else 'CHECK'})")
    print(f"    data_len: {len(data)} bytes")
    if sense:
        print(f"    sense: {sense}")
    if data:
        print(f"    hex: {data.hex()}")
        try:
            ascii_view = data.decode('ascii', errors='replace').replace('\x00', '·')
            print(f"    ascii: {ascii_view!r}")
        except Exception:
            pass
    if parser:
        parsed = PARSERS[parser](data)
        print(f"    parsed: {json.dumps(parsed, indent=2, default=str)}")
    if args.json_out:
        with open(args.json_out, 'w') as f:
            json.dump({
                'cmd': args.cmd, 'desc': desc,
                'cdb_hex': cdb.hex(),
                'status': status, 'data_hex': data.hex(),
                'sense_hex': sense,
                'parsed': PARSERS[parser](data) if parser else None,
            }, f, indent=2, default=str)
        print(f"[+] JSON: {args.json_out}")
    return 0 if status == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
