#!/usr/bin/env python3
"""Media parser fuzz v2 — correct the v1 methodology errors.

v1 finding: FTP-planted files (incl valid JPEG/MP4) NEVER show up in
PTP list_objects(). Either PTP enumeration is boot-time-only, or
filename-pattern-filtered.

v2 changes:
  - PART A: re-test with date-formatted filenames (YYYYMMDD_HHMMSS.JPG/MOV
    matching existing media naming). If PTP enumerates these, the filter
    is filename-pattern-based and we can reach the parser via FTP.
  - PART B: try PTP SendObject with malformed JPEG/MP4 payloads. PTP
    SendObject ALWAYS assigns a handle; the camera receives the bytes
    via its own protocol stack, which might (a) validate or (b) hand
    off to a thumbnail/index parser. Either path is reachable.
  - PART C: report PTP handles BEFORE / AFTER. We're hunting for the
    enumeration trigger.

Cleanup is mandatory. We test ONE payload at a time + health-check
between, so a crash is contained.
"""
from __future__ import annotations
import ftplib, io, os, struct, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import Camera
from larkfly import protocol as p
from larkfly.exceptions import PtpError

HOST = '192.168.1.1'
BIND = '192.168.1.10'
USER = 'wificam'
PASS = 'wificam'

# Use the v1 payloads — already built
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from media_parser_fuzz import (
    jpeg_minimal_valid, jpeg_giant_sof, jpeg_huge_exif_length,
    jpeg_recursive_ifd, jpeg_only_markers, jpeg_truncated, jpeg_giant_quant,
    mp4_minimal_valid, mp4_huge_mdat, mp4_neg_size, mp4_recursive_moov, mp4_truncated,
    fresh_ftp, health_check
)


def list_handles_with_names() -> dict[int, str]:
    """Returns {handle: filename}."""
    try:
        c = Camera(HOST, bind=BIND, timeout=8); c.connect()
        out = {}
        for h in c.list_objects():
            rc, _, data = c._raw_op(0x1008, [h])
            if rc != 0x2001:
                continue
            n = data[52]
            fname = (data[53:53+2*n].decode('utf-16-le', errors='replace').rstrip('\x00')
                     if n else '')
            out[h] = fname
        c.close()
        return out
    except Exception as e:
        return {-1: f'ERROR: {e}'}


# ─── PART A: FTP STOR with date-pattern filenames ───

def part_A():
    print("\n" + "="*72)
    print("PART A: FTP STOR with date-pattern filenames")
    print("="*72)

    base_handles = list_handles_with_names()
    print(f"  Baseline handles: {sorted(base_handles.keys())}")

    # Use a future date so it sorts after existing files
    date_name_jpg = '20270101_120000.JPG'
    date_name_mov = '20270101_120000.MOV'

    for filename, payload, dirname, desc in [
        (date_name_jpg, jpeg_minimal_valid(), '/JPG', 'valid JPEG, date-pattern'),
        (date_name_mov, mp4_minimal_valid(), '/VIDEO', 'valid MP4, date-pattern'),
    ]:
        print(f"\n  → STOR {filename} in {dirname} ({desc})")
        full = f'{dirname}/{filename}'
        try:
            ftp = fresh_ftp()
            ftp.storbinary(f'STOR {full}', io.BytesIO(payload))
            ftp.quit()
            print(f"    stor=ok ({len(payload)}B)")
        except Exception as e:
            print(f"    stor=FAIL: {e}")
            continue

        # Probe PTP — did it enumerate?
        after = list_handles_with_names()
        new = set(after) - set(base_handles)
        if new:
            print(f"    ★★★ NEW PTP HANDLES: {sorted(new)}")
            for h in new:
                print(f"      h={h} fname={after[h]!r}")
        else:
            print(f"    no new PTP handles (camera didn't enumerate FTP-planted file)")

        # cleanup
        try:
            ftp = fresh_ftp(); ftp.delete(full); ftp.quit()
            print(f"    cleanup=ok")
        except Exception as e:
            print(f"    cleanup=FAIL: {e}")

    h = health_check()
    print(f"\n  health: {h}")


# ─── PART B: PTP SendObject with malformed payloads ───

def encode_ptp_string_icatch_objinfo(s: str) -> bytes:
    """The fixed encoder for ObjectInfo.Filename (PTP quirk #4)."""
    if not s:
        return b'\x00' + b'\x00' * 4
    encoded = (s + '\x00').encode('utf-16-le')
    n = len(s) + 1
    return bytes([n]) + b'\x00' * 4 + encoded


def encode_ptp_string(s: str) -> bytes:
    if not s:
        return b'\x00'
    encoded = (s + '\x00').encode('utf-16-le')
    n = len(s) + 1
    return bytes([n]) + encoded


def build_object_info(filename: str, payload_len: int, storage_id: int,
                      object_format: int = 0x3801) -> bytes:
    """ObjectFormat 0x3801 = EXIF/JPEG (vs 0x3000 Undefined we used before)."""
    out = struct.pack('<I', storage_id)
    out += struct.pack('<H', object_format)
    out += struct.pack('<H', 0)
    out += struct.pack('<I', payload_len)
    out += struct.pack('<H', 0) + struct.pack('<I', 0) * 5
    out += struct.pack('<I', 0)
    out += struct.pack('<H', 0)
    out += struct.pack('<I', 0)
    out += struct.pack('<I', 0)
    out += encode_ptp_string_icatch_objinfo(filename)
    out += encode_ptp_string('') * 3
    return out


def part_B():
    print("\n" + "="*72)
    print("PART B: PTP SendObject with malformed payloads")
    print("="*72)
    print("(Each: SendObjectInfo+SendObject → GetObjectInfo → GetThumb → health → DeleteObject)\n")

    TESTS = [
        # JPEG variants — declared as EXIF/JPEG format 0x3801
        ('GIANT_SOF.JPG',    0x3801, jpeg_giant_sof(),        '65535×65535 SOF'),
        ('HUGE_EXIF.JPG',    0x3801, jpeg_huge_exif_length(), 'APP1 65535B'),
        ('RECURSIVE.JPG',    0x3801, jpeg_recursive_ifd(),    'IFD self-cycle'),
        ('ONLY_MARKERS.JPG', 0x3801, jpeg_only_markers(),     'SOI+EOI only'),
        ('TRUNCATED.JPG',    0x3801, jpeg_truncated(),        'cuts mid-APP0'),
        ('GIANT_QUANT.JPG',  0x3801, jpeg_giant_quant(),      'DQT 0xFFFF len'),
        # MP4 variants — declared as B982 vendor video
        ('HUGE_MDAT.MOV',    0xB982, mp4_huge_mdat(),         'mdat 4GB'),
        ('NEG_SIZE.MOV',     0xB982, mp4_neg_size(),          'size=0 atom'),
        ('RECURSIVE.MOV',    0xB982, mp4_recursive_moov(),    'moov×10 nested'),
        ('TRUNCATED.MOV',    0xB982, mp4_truncated(),         'mid-moov cut'),
    ]
    for filename, fmt, payload, desc in TESTS:
        print(f"  → {filename} (fmt=0x{fmt:04X}): {desc}")
        try:
            c = Camera(HOST, bind=BIND, timeout=10); c.connect()
            sid = c.storage_ids()[0]
            info = build_object_info(filename, len(payload), sid, fmt)
            rc, rp, _ = c._raw_op(0x100C, [sid, 0xFFFFFFFF], tx_data=info)
            if rc != 0x2001:
                print(f"    SendObjectInfo rc=0x{rc:04X} REJECTED")
                c.close()
                continue
            h = rp[2]
            rc, _, _ = c._raw_op(0x100D, [], tx_data=payload)
            print(f"    SendObject rc=0x{rc:04X} handle={h}")
            # Probe: GetObjectInfo (parses the object header in firmware)
            try:
                rc, _, data = c._raw_op(0x1008, [h], )
                print(f"    GetObjectInfo rc=0x{rc:04X} len={len(data)}")
            except Exception as e:
                print(f"    GetObjectInfo failed: {type(e).__name__}")
            # Probe: GetThumb (THIS triggers the JPEG/MP4 parser to generate thumbnail!)
            try:
                rc, _, data = c._raw_op(0x100A, [h])
                if rc == 0x2001:
                    print(f"    GetThumb ★ returned {len(data)}B (parser ran)")
                else:
                    print(f"    GetThumb rc=0x{rc:04X}")
            except Exception as e:
                print(f"    GetThumb failed: {type(e).__name__}")
            # Cleanup
            try:
                rc, _, _ = c._raw_op(0x100B, [h])
                print(f"    DeleteObject rc=0x{rc:04X}")
            except Exception as e:
                print(f"    DeleteObject failed: {type(e).__name__}")
            c.close()
        except Exception as e:
            print(f"    PTP SESSION ERROR: {type(e).__name__}: {e}")

        # Health check after each payload
        h = health_check()
        if 'DOWN' in h['ftp'] or 'DOWN' in h['ptp']:
            print(f"    ★★★ HEALTH DEGRADED: {h}")
            print(f"    [!] STOPPING — bug found in parser via {filename} ({desc})")
            return
        time.sleep(0.3)


def main():
    h = health_check()
    print(f"[*] Baseline: FTP={h['ftp']}, PTP={h['ptp']}")
    if 'DOWN' in h['ftp'] or 'DOWN' in h['ptp']:
        return 1

    part_A()
    part_B()

    print(f"\n[*] Final health: {health_check()}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
