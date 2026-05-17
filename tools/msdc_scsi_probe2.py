#!/usr/bin/env python3
"""Refined SCSI vendor-command probe — round 2.

Round 1 (msdc_scsi_probe.py) showed every opcode in 0xC0-0xFF returns
identical INQUIRY-shaped data. Two possibilities the disassembly of
prepareScsiCDB rules in:

  CDB[0] = scsiCmd  (read from obj offset 4)
  CDB[1..2] = extendCmd (u16, byte-swapped to BE)
  CDB[3..6] = parameter1 (u32-ish)

So CDB[0] really is the opcode and varying it should produce different
behavior — unless the *firmware* rejects any opcode where the
discriminator extendCmd is zero. This refined probe:

  Phase A: try a couple of candidate opcodes (0xCB, 0xCC, 0xCD — common
           Sunplus/iCatch wrappers) with varying extendCmd (32 picks)

  Phase B: try MMC standard READ_BUFFER (0x3C) / WRITE_BUFFER (0x3B)
           with vendor mode bits — another common iCatch transport.

  Phase C: try READ_LONG_10 (0x3E) and a few less-common opcodes.

All probes use data_in_len=128 to give the device room to send a longer
response if it has one (any response length other than 64 / 128 padded
with zeros = something real).

Requires sudo.
"""
import argparse, ctypes, fcntl, json, os, struct, sys
from ctypes import c_int, c_void_p, c_uint, c_ushort, c_ubyte

SG_IO = 0x2285
SG_DXFER_FROM_DEV = -3
SG_DXFER_NONE = -1

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

def send(fd, cdb, dlen=128):
    sb = (c_ubyte*32)()
    cmd = (c_ubyte*len(cdb)).from_buffer_copy(cdb)
    data = (c_ubyte*dlen)() if dlen else None
    h = SgIoHdr()
    h.interface_id = ord('S')
    h.dxfer_direction = SG_DXFER_FROM_DEV if dlen else SG_DXFER_NONE
    h.cmd_len = len(cdb); h.mx_sb_len = 32
    h.dxfer_len = dlen; h.dxferp = ctypes.cast(data, c_void_p) if data else None
    h.cmdp = ctypes.cast(cmd, c_void_p); h.sbp = ctypes.cast(sb, c_void_p)
    h.timeout = 2000
    try:
        fcntl.ioctl(fd, SG_IO, h)
    except OSError as e:
        return {'err': str(e)}
    return {
        'status': h.status, 'host': h.host_status, 'drv': h.driver_status,
        'sb_len': h.sb_len_wr, 'resid': h.resid, 'dur_ms': h.duration,
        'sb_hex': bytes(sb[:h.sb_len_wr]).hex() if h.sb_len_wr else '',
        'data_hex': bytes(data[:dlen-h.resid]).hex() if data else '',
    }


def build_icatch(opcode: int, extend_cmd: int = 0, param: int = 0,
                 duration: int = 0) -> bytes:
    """16-byte CDB matching prepareScsiCDB layout."""
    return struct.pack('>BBHIIHH', opcode, 0, extend_cmd, param,
                       duration, 0, 0)


def fingerprint(resp: dict) -> tuple:
    """Reduce a response to a comparable fingerprint."""
    return (resp.get('status'), resp.get('resid'),
            resp.get('data_hex', '')[:80])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dev', default='/dev/sg0')
    ap.add_argument('--json-out', default='/home/micah/analyses/data/msdc_scsi_probe2.json')
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("Need sudo for /dev/sg0", file=sys.stderr); return 2

    fd = os.open(args.dev, os.O_RDWR)
    results = {'phases': {}}

    # Reference: standard INQUIRY response (to detect "silent reject")
    ref_inq = send(fd, bytes([0x12, 0, 0, 0, 0x60, 0]), 0x60)
    ref_fp = fingerprint(ref_inq)
    results['inquiry_ref'] = ref_inq
    print(f"[ref] INQUIRY data starts: {ref_inq['data_hex'][:80]}")
    print(f"[ref] resid={ref_inq['resid']} status={ref_inq['status']}")
    print()

    def differs_from_inquiry(r):
        # Different if status non-zero, or data clearly distinct
        if r.get('status', 0) != 0: return True
        # Different data than INQUIRY (length or content)
        rd = r.get('data_hex', '')
        if not rd: return True
        # Trim trailing zeros from both
        ri = ref_inq['data_hex']
        return rd.rstrip('0') != ri.rstrip('0') or r.get('resid') != ref_inq.get('resid')

    # Phase A: vary extendCmd for popular wrapper opcodes
    print("[Phase A] iCatch wrapper opcodes 0xCB/0xCC/0xCD × extendCmd sweep")
    for op in (0xCB, 0xCC, 0xCD, 0xCE, 0xCF):
        phase_a = []
        for ext in (0x0001, 0x0002, 0x0010, 0x0100, 0x1000, 0xFFFF,
                    0xA1A1, 0x5A5A, 0xC001, 0xD001):
            cdb = build_icatch(op, ext)
            r = send(fd, cdb)
            phase_a.append({'op': hex(op), 'ext': hex(ext), **r})
            if differs_from_inquiry(r):
                print(f"   ** DIFFERENT ** op={hex(op)} ext={hex(ext):>6} "
                      f"status={r['status']} resid={r['resid']} "
                      f"data={r['data_hex'][:80]}")
            elif r.get('status'):
                # also report any non-0 status
                print(f"   op={hex(op)} ext={hex(ext):>6} status={r['status']} "
                      f"sb={r['sb_hex']}")
        results['phases'][f'A_op_{hex(op)}'] = phase_a

    # Phase B: SCSI standard READ_BUFFER / WRITE_BUFFER with vendor mode
    print()
    print("[Phase B] READ_BUFFER (0x3C) sweep with vendor mode bits + buffer IDs")
    phase_b = []
    # READ_BUFFER CDB: opcode(1) + mode(1) + bufferID(1) + offset(3) + alloc_len(3) + control(1) = 10 bytes
    for mode in (0x00, 0x02, 0x03, 0x0A, 0x1A, 0x2A):  # 0,2,3 standard; 0x1A=vendor read
        for buf_id in (0x00, 0x01, 0x02, 0x10, 0x80, 0xFF):
            cdb = struct.pack('>BBBBBBBBBB',
                              0x3C, mode, buf_id, 0, 0, 0, 0, 0, 0x80, 0)
            r = send(fd, cdb, 128)
            phase_b.append({'mode': hex(mode), 'buf_id': hex(buf_id), **r})
            if differs_from_inquiry(r):
                print(f"   ** DIFFERENT ** mode={hex(mode)} buf={hex(buf_id)} "
                      f"status={r['status']} data={r['data_hex'][:80]}")
    results['phases']['B_read_buffer'] = phase_b

    # Phase C: a few specific suspicious opcodes
    print()
    print("[Phase C] specific high-interest opcodes")
    phase_c = []
    candidates = [
        (0x12, 'INQUIRY (sanity)'), (0x1A, 'MODE_SENSE_6'),
        (0x5A, 'MODE_SENSE_10'),
        (0x4D, 'LOG_SENSE'), (0xA0, 'REPORT_LUNS'),
        (0xC0, 'iCatch C0'), (0xCA, 'C-A vendor'),
        (0xCB, 'C-B vendor'), (0xE6, 'iCatch event?'),
        (0xF0, 'F0 vendor'),
    ]
    for op, label in candidates:
        # Use a generic 12-byte CDB layout
        cdb = struct.pack('>BBBBBBBBBBBB', op, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0)
        r = send(fd, cdb, 128)
        phase_c.append({'op': hex(op), 'label': label, **r})
        marker = 'DIFF' if differs_from_inquiry(r) else 'same'
        print(f"   {hex(op):>5} {label:<25s} status={r.get('status')} resid={r.get('resid')} [{marker}]")
        if marker == 'DIFF':
            print(f"      data={r.get('data_hex','')[:100]}")
    results['phases']['C_specific'] = phase_c

    os.close(fd)
    os.makedirs(os.path.dirname(args.json_out) or '.', exist_ok=True)
    with open(args.json_out, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] JSON: {args.json_out}")


if __name__ == '__main__':
    sys.exit(main())
