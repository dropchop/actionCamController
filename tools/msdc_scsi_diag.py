#!/usr/bin/env python3
"""Diagnostic: discover what the camera's vendor-SCSI dispatcher actually
keys on. We've established that extendCmd at CDB[1..2] is ignored — all
`C0 ?? ?? ..` reads return the same buffer (device GUID, truncated to N).

This sweeps several axes in one shot:

A. Opcode byte (CDB[0]) — try 0xC0, 0xC1, 0xCE, 0xCF, 0xD0, 0xE0
   to see if a different vendor opcode is the real dispatch.

B. CDB length — try 6, 10, 12, 16. Some vendor stacks gate on the
   CBWCBLength field.

C. parameter3 (CDB[11..14]) non-zero — to test if the dispatch is
   actually at bytes 11..14 rather than 1..2.

D. Direction OUT instead of IN — sometimes vendor cmds dispatch only
   when there's an outbound payload.

E. Standard INQUIRY (opcode 0x12) baseline — confirms the SCSI path
   is healthy.

For each, print the first 16 bytes of the response (or short data),
status, sense, and a short label.
"""
import ctypes, fcntl, os, struct, sys
from ctypes import c_int, c_void_p, c_uint, c_ushort, c_ubyte

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


def scsi(fd, cdb: bytes, data_in: int = 0, data_out: bytes | None = None, timeout=2000):
    sb = (c_ubyte*32)()
    cmd = (c_ubyte*len(cdb)).from_buffer_copy(cdb)
    if data_out is not None:
        data = (c_ubyte*len(data_out)).from_buffer_copy(data_out)
        dir_, dlen = SG_DXFER_TO_DEV, len(data_out)
    elif data_in:
        data = (c_ubyte*data_in)()
        dir_, dlen = SG_DXFER_FROM_DEV, data_in
    else:
        data, dir_, dlen = None, SG_DXFER_NONE, 0
    h = SgIoHdr()
    h.interface_id = ord('S')
    h.dxfer_direction = dir_
    h.cmd_len = len(cdb); h.mx_sb_len = 32
    h.dxfer_len = dlen
    h.dxferp = ctypes.cast(data, c_void_p) if data else None
    h.cmdp = ctypes.cast(cmd, c_void_p)
    h.sbp = ctypes.cast(sb, c_void_p)
    h.timeout = timeout
    try:
        fcntl.ioctl(fd, SG_IO, h)
    except OSError as e:
        return -e.errno, b'', ''
    out = b''
    if data is not None and dir_ == SG_DXFER_FROM_DEV:
        out = bytes(data[:dlen - h.resid])
    return h.status, out, bytes(sb[:h.sb_len_wr]).hex()


def run(fd, label, cdb_hex, data_in=32, data_out=None):
    cdb = bytes.fromhex(cdb_hex)
    st, data, sense = scsi(fd, cdb, data_in if data_out is None else 0, data_out)
    ok = '✓' if st == 0 else '✗'
    short = data[:16].hex() if data else ''
    extra = f" len={len(data)}" if data else ''
    sense_s = f" sense={sense}" if sense else ''
    print(f"  {ok} {label:40s} cdb={cdb_hex:36s} st=0x{st:02x}{extra} hex={short}{sense_s}")
    return data


def main():
    dev = sys.argv[1] if len(sys.argv) > 1 else '/dev/sg0'
    if os.geteuid() != 0:
        print("Need sudo.", file=sys.stderr); return 2
    fd = os.open(dev, os.O_RDWR)
    try:
        print("\n== A. Vary opcode byte (CDB[0]) ==")
        run(fd, "0xC0 baseline (ver)",        "c0000c00000000000000000000000000")
        for op in [0xC1, 0xC2, 0xCB, 0xCE, 0xCF, 0xD0, 0xE0, 0xF0]:
            run(fd, f"opcode=0x{op:02X}",      f"{op:02x}000c00000000000000000000000000")

        print("\n== B. Vary CDB length (same extendCmd 0x000C) ==")
        run(fd, "len=6",                       "c0000c000000")
        run(fd, "len=10",                      "c0000c00000000000000")
        run(fd, "len=12",                      "c0000c0000000000000000000000")
        run(fd, "len=16 baseline",             "c0000c00000000000000000000000000")

        print("\n== C. parameter3 != 0 (CDB[11..14]) ==")
        run(fd, "param3=0x00000001",           "c0000c000000000000000000000001000000")
        run(fd, "param3=0xDEADBEEF",           "c0000c0000000000000000deadbeef00")
        run(fd, "param3=0xCAFEBABE",           "c0000c0000000000000000cafebabe00")

        print("\n== D. Direction OUT with payload (extendCmd 0x0006 = switchToPreview) ==")
        run(fd, "C0 0006 dir=OUT len=4 payload=00000000",
            "c000060000000000000000000000000000", data_in=0,
            data_out=b'\x00\x00\x00\x00')
        # follow up with sd-card-status — see if state changed
        run(fd, "follow-up sd-card-status",    "c0001000000000000000000000000000")

        print("\n== E. Standard INQUIRY baseline ==")
        run(fd, "INQUIRY (op 0x12)",           "12000000ff00", data_in=255)

        print("\n== F. Vendor extendCmd in non-low byte (try 0xC0 with prepend) ==")
        # what if dispatch is on bytes 7..10 (parameter2)?
        run(fd, "param2=0x0000000C @ [7..10]", "c000000000000000000c000000000000")
        run(fd, "param1=0x0000000C @ [3..6]", "c00000000000000c0000000000000000")

        print("\n== G. Read-capacity (standard 0x25) ==")
        run(fd, "READ_CAP10 (op 0x25)",        "2500000000000000", data_in=8)
        print("\nDone.")
    finally:
        os.close(fd)


if __name__ == '__main__':
    sys.exit(main())
