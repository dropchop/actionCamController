#!/usr/bin/env python3
"""Wider SCSI surface sweep — read-only, designed to find a QC/factory
backdoor that doesn't use the iCatch `0xC0` extendCmd convention.

We test five families that are commonly co-opted by manufacturers as
backdoor / diag surfaces:

  1. Vendor opcode IN sweep 0xC0..0xFF, with cdb[1..2] varied to
     catch any non-zero discriminator we missed.
  2. INQUIRY VPD pages 0x00, 0x80-0xFF — the standard SCSI place for
     vendor-specific identity / capability data.
  3. READ BUFFER (0x3C) — every mode 0x00..0x0A — the standard SCSI
     debug-data and echo-back hook.
  4. MODE SENSE 6 (0x1A) pages 0x00..0x3F + all subpages — vendor
     pages live above 0x20.
  5. RECEIVE DIAGNOSTIC RESULTS (0x1C) page 0x00..0xFF — the standard
     SCSI built-in self-test / diag results hook.
  6. LOG SENSE (0x4D) page 0x00..0x3F — manufacturer log pages.

All are READ direction, all are safe. We compare each response against
the known GUID-stub baseline and flag any response that DIFFERS, plus
any non-zero-status result.

Run: sudo python3 tools/msdc_scsi_wide.py
"""
import ctypes, fcntl, os, struct, sys
from ctypes import c_int, c_void_p, c_uint, c_ushort, c_ubyte

SG_IO = 0x2285
SG_DXFER_NONE     = -1
SG_DXFER_TO_DEV   = -2
SG_DXFER_FROM_DEV = -3

GUID_BASELINE_HEAD = bytes.fromhex(
    "7b00360041003700340045004500300044002d0033003100460045002d003400"
)
INQUIRY_BASELINE_HEAD = bytes.fromhex("008004021f00000053706f7274204361")


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


def scsi(fd, cdb, data_in=0, timeout=1500):
    sb = (c_ubyte*32)()
    cmd = (c_ubyte*len(cdb)).from_buffer_copy(cdb)
    data = (c_ubyte*data_in)() if data_in else None
    h = SgIoHdr()
    h.interface_id = ord('S')
    h.dxfer_direction = SG_DXFER_FROM_DEV if data_in else SG_DXFER_NONE
    h.cmd_len = len(cdb); h.mx_sb_len = 32
    h.dxfer_len = data_in
    h.dxferp = ctypes.cast(data, c_void_p) if data else None
    h.cmdp = ctypes.cast(cmd, c_void_p)
    h.sbp = ctypes.cast(sb, c_void_p)
    h.timeout = timeout
    try:
        fcntl.ioctl(fd, SG_IO, h)
    except OSError as e:
        return -e.errno, b'', ''
    out = bytes(data[:data_in - h.resid]) if data else b''
    return h.status, out, bytes(sb[:h.sb_len_wr]).hex()


def classify(data: bytes) -> str:
    if not data:
        return "empty"
    if data[:len(GUID_BASELINE_HEAD)] == GUID_BASELINE_HEAD[:len(data)]:
        return "GUID-stub"
    if data[:len(INQUIRY_BASELINE_HEAD)] == INQUIRY_BASELINE_HEAD[:len(data)]:
        return "INQUIRY-stub"
    if all(b == 0 for b in data):
        return "all-zero"
    return "NEW!"


def report(label, cdb_hex, status, data, sense, force_print=False):
    cls = classify(data)
    if cls == "NEW!" or status != 0 or force_print:
        head = data[:32].hex()
        try:
            ascii_view = data[:32].decode('ascii', errors='replace').replace('\x00', '.')
        except Exception:
            ascii_view = ''
        tag = '★' if cls == 'NEW!' else ('✗' if status != 0 else '·')
        sense_s = f" sense={sense}" if sense else ''
        print(f"  {tag} {label:38s} cdb={cdb_hex:40s} st=0x{status:02x} cls={cls:12s} hex={head} '{ascii_view}'{sense_s}")


def main():
    dev = sys.argv[1] if len(sys.argv) > 1 else '/dev/sg0'
    if os.geteuid() != 0:
        print("Need sudo."); return 2

    fd = os.open(dev, os.O_RDWR)
    try:
        # --- 1. Vendor opcode IN sweep, cdb[1..2] varied ---
        print("\n== 1. Vendor opcode sweep 0xC0..0xFF (extendCmd varied) ==")
        for op in range(0xC0, 0x100):
            for ec_high in (0x00, 0x01, 0x10, 0x80, 0xFF):
                for ec_low in (0x00, 0x42, 0x80, 0xCC, 0xFE):
                    cdb = bytes([op, 0, ec_high, ec_low]) + b'\x00'*12
                    st, data, sense = scsi(fd, cdb, 64)
                    report(f"op=0x{op:02X} ec={ec_high:02X}{ec_low:02X}",
                           cdb.hex(), st, data, sense)

        # --- 2. INQUIRY VPD pages ---
        print("\n== 2. INQUIRY VPD pages ==")
        for page in [0x00] + list(range(0x80, 0x100)):
            cdb = bytes([0x12, 0x01, page, 0x00, 0xFF, 0x00])
            st, data, sense = scsi(fd, cdb, 255)
            report(f"INQUIRY VPD page=0x{page:02X}", cdb.hex(), st, data, sense)

        # --- 3. READ BUFFER (0x3C) ---
        print("\n== 3. READ BUFFER modes ==")
        for mode in range(0x00, 0x0B):
            for bufid in [0x00, 0x01]:
                cdb = bytes([0x3C, mode, bufid, 0,0,0, 0,0xFF,0, 0])
                st, data, sense = scsi(fd, cdb, 255)
                report(f"READ_BUFFER mode={mode:02X} id={bufid:02X}", cdb.hex(), st, data, sense)

        # --- 4. MODE SENSE 6 — vendor pages > 0x20 ---
        print("\n== 4. MODE SENSE 6 pages ==")
        for page in range(0x00, 0x40):
            cdb = bytes([0x1A, 0x00, page, 0x00, 0xFF, 0x00])
            st, data, sense = scsi(fd, cdb, 255)
            report(f"MODE_SENSE6 page=0x{page:02X}", cdb.hex(), st, data, sense)

        # --- 5. RECEIVE DIAGNOSTIC RESULTS (0x1C) ---
        print("\n== 5. RECEIVE DIAGNOSTIC RESULTS pages ==")
        for page in range(0x00, 0x100):
            cdb = bytes([0x1C, 0x01, page, 0xFF, 0xFF, 0x00])
            st, data, sense = scsi(fd, cdb, 255)
            report(f"RECV_DIAG page=0x{page:02X}", cdb.hex(), st, data, sense)

        # --- 6. LOG SENSE (0x4D) ---
        print("\n== 6. LOG SENSE pages ==")
        for page in range(0x00, 0x40):
            cdb = bytes([0x4D, 0x00, 0x40 | page, 0,0,0,0, 0xFF,0xFF, 0])
            st, data, sense = scsi(fd, cdb, 255)
            report(f"LOG_SENSE page=0x{page:02X}", cdb.hex(), st, data, sense)

        print("\n[*] Sweep complete. Anything marked ★ NEW! or ✗ non-zero status is a lead.")
        print("    Bare-dot rows would be GUID-stub / INQUIRY-stub responses (suppressed).")
    finally:
        os.close(fd)


if __name__ == '__main__':
    sys.exit(main())
