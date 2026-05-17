#!/usr/bin/env python3
"""Media parser fuzz — plant crafted JPEG / MP4 files in /JPG/ and
/VIDEO/, then probe how the camera reacts via PTP enumeration and
thumbnail generation.

This attacks code paths we haven't touched: the camera's image and
video decoders. These are typically the highest-CVE class in any
camera (CVE-2020-* etc. all live here).

Phase 1 — INFORMATIONAL:
  Plant a valid minimal JPEG. Does PTP list_objects() pick it up?
  Does GetObjectInfo work? Does GetThumb generate a thumbnail (=
  the parser ran)? Same for MP4.

Phase 2 — JPEG FUZZ:
  - Valid SOI/EOI but garbage middle
  - APP1/EXIF with massive declared length
  - APP1/EXIF with recursive IFD pointer
  - SOF0 claiming 65535x65535 image
  - Truncated mid-frame
  - JPEG file shorter than minimum (just SOI+EOI)
  - JPEG with absurd quantization tables

Phase 3 — MP4 FUZZ:
  - Valid minimal MP4 (ftyp + moov + mdat)
  - mdat atom claiming 4GB but file is 100B
  - Negative atom size (signed integer overflow → 0xFFFFFFFF interp)
  - Recursive moov-in-moov
  - Truncated mid-atom

After each plant: health check (PTP + FTP responsive). Each file
deleted via FTP between tests.

Per user authorization 2026-05-17 evening: anything resettable via
power-cycle or SD-card edit is in-scope. A malformed file CRASHING
the firmware is the expected best-case outcome (= exploitable bug).
"""
from __future__ import annotations
import ftplib, io, os, struct, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import Camera
from larkfly.exceptions import PtpError, TransportError

HOST = '192.168.1.1'
BIND = '192.168.1.10'
USER = 'wificam'
PASS = 'wificam'


def fresh_ftp() -> ftplib.FTP:
    ftp = ftplib.FTP()
    ftp.connect(HOST, 21, timeout=10)
    ftp.login(USER, PASS)
    return ftp


def health_check() -> dict:
    """Returns {ptp: bool/diag, ftp: bool/diag, ports: [...]}."""
    out = {}
    # FTP
    try:
        ftp = ftplib.FTP()
        ftp.connect(HOST, 21, timeout=5)
        ftp.login(USER, PASS)
        ftp.voidcmd('SYST')
        ftp.quit()
        out['ftp'] = 'OK'
    except Exception as e:
        out['ftp'] = f'DOWN ({type(e).__name__})'
    # PTP
    try:
        c = Camera(HOST, bind=BIND, timeout=5)
        c.connect()
        info = c.device_info()
        out['ptp'] = f"OK ({len(info['device_properties_supported'])} props)"
        c.close()
    except Exception as e:
        out['ptp'] = f'DOWN ({type(e).__name__})'
    return out


# ─── JPEG builders ────────────────────────────────────────────────────

def jpeg_minimal_valid() -> bytes:
    """Tiniest valid-looking JPEG: SOI, APP0/JFIF, SOF0 (1x1), DHT, DQT, SOS, EOI."""
    out = bytearray()
    out += b'\xff\xd8'                                # SOI
    out += b'\xff\xe0\x00\x10' + b'JFIF\x00' + b'\x01\x01\x00\x00\x01\x00\x01\x00\x00'  # APP0
    out += b'\xff\xdb\x00\x43\x00' + b'\x08'*64       # DQT
    out += b'\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00'  # SOF0 1x1, 1 component
    out += b'\xff\xc4\x00\x14\x00' + b'\x00'*16 + b'\x00\x00\x00'   # DHT minimal
    out += b'\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00'  # SOS
    out += b'\x00'                                    # 1 byte compressed data
    out += b'\xff\xd9'                                # EOI
    return bytes(out)


def jpeg_giant_sof() -> bytes:
    """Valid JPEG framing but SOF0 claims 65535x65535 image."""
    out = bytearray()
    out += b'\xff\xd8'                                # SOI
    out += b'\xff\xe0\x00\x10' + b'JFIF\x00' + b'\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    out += b'\xff\xc0\x00\x0b\x08\xff\xff\xff\xff\x01\x01\x11\x00'  # SOF0 65535x65535
    out += b'\xff\xd9'
    return bytes(out)


def jpeg_huge_exif_length() -> bytes:
    """APP1 (EXIF) declares 65535-byte length but file is 30B."""
    out = bytearray()
    out += b'\xff\xd8'
    out += b'\xff\xe1\xff\xff' + b'Exif\x00\x00'      # APP1 with HUGE declared length
    out += b'\x00' * 10
    out += b'\xff\xd9'
    return bytes(out)


def jpeg_recursive_ifd() -> bytes:
    """EXIF IFD pointer points back into itself."""
    out = bytearray()
    out += b'\xff\xd8'
    # APP1 with EXIF header + TIFF header with recursive IFD0 offset
    exif = b'Exif\x00\x00'
    tiff = b'II*\x00' + struct.pack('<I', 8)  # IFD0 at offset 8 (= start of TIFF)
    # IFD0: 1 entry — pointer back to offset 8
    ifd0 = struct.pack('<H', 1)
    ifd0 += struct.pack('<HHII', 0x8769, 4, 1, 8)  # ExifIFDPointer tag, type LONG, count 1, value=8
    ifd0 += struct.pack('<I', 0)  # next IFD offset
    body = exif + tiff + ifd0
    out += b'\xff\xe1' + struct.pack('>H', len(body) + 2) + body
    out += b'\xff\xd9'
    return bytes(out)


def jpeg_only_markers() -> bytes:
    """Just SOI and EOI, no body."""
    return b'\xff\xd8\xff\xd9'


def jpeg_truncated() -> bytes:
    """Valid start but cut off mid-segment."""
    return b'\xff\xd8' + b'\xff\xe0\x00\x10' + b'JFIF\x00' + b'\x01\x01\x00\x00\x01'  # cuts off mid-APP0


def jpeg_giant_quant() -> bytes:
    """DQT claiming 65535-byte length."""
    out = bytearray()
    out += b'\xff\xd8'
    out += b'\xff\xdb\xff\xff\x00' + b'\x08'*100  # huge DQT
    out += b'\xff\xd9'
    return bytes(out)


# ─── MP4 builders ─────────────────────────────────────────────────────

def atom(name: bytes, payload: bytes) -> bytes:
    return struct.pack('>I', 8 + len(payload)) + name + payload


def mp4_minimal_valid() -> bytes:
    """ftyp + moov(mvhd+trak(tkhd+mdia(mdhd+hdlr+minf))) + mdat"""
    ftyp = atom(b'ftyp', b'isom' + b'\x00\x00\x02\x00' + b'isomiso2avc1mp41')
    mvhd = atom(b'mvhd', b'\x00\x00\x00\x00' + b'\x00'*16 + b'\x00\x00\x03\xe8' + b'\x00\x00\x00\x01' + b'\x01\x00\x00\x00' + b'\x00\x00' + b'\x00'*70)
    minf = atom(b'minf', b'')
    mdhd = atom(b'mdhd', b'\x00'*24)
    hdlr = atom(b'hdlr', b'\x00'*12 + b'vide' + b'\x00'*12)
    mdia = atom(b'mdia', mdhd + hdlr + minf)
    tkhd = atom(b'tkhd', b'\x00'*84)
    trak = atom(b'trak', tkhd + mdia)
    moov = atom(b'moov', mvhd + trak)
    mdat = atom(b'mdat', b'\x00\x01\x02\x03')
    return ftyp + moov + mdat


def mp4_huge_mdat() -> bytes:
    """mdat atom declares 4GB size but file is tiny."""
    return atom(b'ftyp', b'isomiso2avc1mp41') + (struct.pack('>I', 0xFFFFFFFF) + b'mdat' + b'\x00'*8)


def mp4_neg_size() -> bytes:
    """Atom with size=0 (= 'extends to end of file' in spec) followed by garbage."""
    return atom(b'ftyp', b'isomiso2avc1mp41') + (struct.pack('>I', 0) + b'mdat' + b'\x00'*8)


def mp4_recursive_moov() -> bytes:
    """moov contains moov contains moov..."""
    inner = atom(b'moov', b'\x00'*4)
    for _ in range(10):
        inner = atom(b'moov', inner + b'\x00'*4)
    return atom(b'ftyp', b'isomiso2') + inner


def mp4_truncated() -> bytes:
    """Valid ftyp then cut mid-moov."""
    return atom(b'ftyp', b'isomiso2') + b'\x00\x00\x10\x00moov\x00\x00\x00'


# ─── Test runner ──────────────────────────────────────────────────────

def plant_and_probe(filename: str, payload: bytes, dir_path: str) -> dict:
    """Upload payload to dir_path/filename via FTP, then probe via PTP.
    Always cleanup. Returns result dict."""
    full_path = f'{dir_path}/{filename}'
    result = {'filename': filename, 'dir': dir_path, 'size': len(payload)}

    # STEP 1: pre-state (so we can diff PTP handles)
    try:
        c = Camera(HOST, bind=BIND, timeout=5); c.connect()
        pre_handles = set(c.list_objects())
        c.close()
        result['pre_handles'] = len(pre_handles)
    except Exception as e:
        result['pre_handles_error'] = f'{type(e).__name__}'
        pre_handles = set()

    # STEP 2: plant the file via FTP
    try:
        ftp = fresh_ftp()
        ftp.storbinary(f'STOR {full_path}', io.BytesIO(payload))
        ftp.quit()
        result['stor'] = 'ok'
    except Exception as e:
        result['stor'] = f'{type(e).__name__}: {str(e)[:60]}'
        return result

    # STEP 3: probe PTP — did the camera enumerate it?
    new_handles = set()
    try:
        c = Camera(HOST, bind=BIND, timeout=10); c.connect()
        post_handles = set(c.list_objects())
        new_handles = post_handles - pre_handles
        result['post_handles'] = len(post_handles)
        result['new_handles'] = sorted(new_handles)
        # For any new handle, try ObjectInfo + Thumb
        for h in new_handles:
            try:
                rc, _, data = c._raw_op(0x1008, [h])  # GetObjectInfo
                result[f'oi_rc_h{h}'] = f'0x{rc:04X} ({len(data)}B)'
            except Exception as e:
                result[f'oi_err_h{h}'] = type(e).__name__
            try:
                rc, _, data = c._raw_op(0x100A, [h])  # GetThumb
                result[f'thumb_rc_h{h}'] = f'0x{rc:04X} ({len(data)}B)'
            except Exception as e:
                result[f'thumb_err_h{h}'] = type(e).__name__
        c.close()
    except Exception as e:
        result['ptp_probe_error'] = f'{type(e).__name__}: {str(e)[:80]}'

    # STEP 4: cleanup via FTP
    try:
        ftp = fresh_ftp()
        ftp.delete(full_path)
        ftp.quit()
        result['cleanup'] = 'ok'
    except Exception as e:
        result['cleanup'] = f'fail: {type(e).__name__}'

    return result


def fmt_result(r: dict) -> str:
    parts = [f"{r['filename']:30s}", f"{r['size']:5d}B", f"stor={r.get('stor','?')}"]
    if r.get('new_handles'):
        parts.append(f"new_h={r['new_handles']}")
        for h in r['new_handles']:
            oi = r.get(f'oi_rc_h{h}', '?')
            th = r.get(f'thumb_rc_h{h}', '?')
            parts.append(f"h{h}: oi={oi} thumb={th}")
    elif 'post_handles' in r:
        parts.append("no-new-handle")
    if r.get('ptp_probe_error'):
        parts.append(f"PTP_ERR: {r['ptp_probe_error']}")
    parts.append(f"clean={r.get('cleanup','?')}")
    return ' | '.join(parts)


def main():
    # Baseline health
    h = health_check()
    print(f"[*] Baseline: FTP={h['ftp']}, PTP={h['ptp']}")
    if 'DOWN' in h['ftp'] or 'DOWN' in h['ptp']:
        print("[!] Baseline unhealthy. Aborting.")
        return 1

    # ─── PHASE 1: minimal valid media ───
    print("\n" + "="*72)
    print("PHASE 1: valid minimal media (does the camera enumerate it?)")
    print("="*72)
    print(fmt_result(plant_and_probe('PROBE_VALID.JPG', jpeg_minimal_valid(), '/JPG')))
    print(fmt_result(plant_and_probe('PROBE_VALID.MOV', mp4_minimal_valid(), '/VIDEO')))
    print(f"  health: {health_check()}")

    # ─── PHASE 2: malformed JPEG ───
    print("\n" + "="*72)
    print("PHASE 2: malformed JPEGs in /JPG/")
    print("="*72)
    JPEG_TESTS = [
        ('PROBE_GIANT_SOF.JPG',  jpeg_giant_sof,        '65535×65535 SOF dims'),
        ('PROBE_HUGE_EXIF.JPG',  jpeg_huge_exif_length, 'APP1 declares 65535-byte length, file 30B'),
        ('PROBE_RECURSIVE.JPG',  jpeg_recursive_ifd,    'EXIF IFD pointer cycles back to itself'),
        ('PROBE_ONLY_MARKERS.JPG', jpeg_only_markers,   'SOI+EOI only'),
        ('PROBE_TRUNCATED.JPG',  jpeg_truncated,        'truncated mid-APP0'),
        ('PROBE_GIANT_QUANT.JPG', jpeg_giant_quant,     'DQT length=0xFFFF'),
    ]
    for fname, builder, desc in JPEG_TESTS:
        print(f"\n  → {desc}")
        r = plant_and_probe(fname, builder(), '/JPG')
        print(f"  {fmt_result(r)}")
        h = health_check()
        if 'DOWN' in h['ftp'] or 'DOWN' in h['ptp']:
            print(f"  ★★★ HEALTH DEGRADED: {h}")
            print(f"  [!] STOPPING — bug found in JPEG parser via '{fname}' ({desc})")
            return 0

    # ─── PHASE 3: malformed MP4 ───
    print("\n" + "="*72)
    print("PHASE 3: malformed MP4s in /VIDEO/")
    print("="*72)
    MP4_TESTS = [
        ('PROBE_HUGE_MDAT.MOV',  mp4_huge_mdat,       'mdat claims 4GB size, file 24B'),
        ('PROBE_NEG_SIZE.MOV',   mp4_neg_size,        'atom size=0 (= extends to EOF)'),
        ('PROBE_RECURSIVE.MOV',  mp4_recursive_moov,  'moov-in-moov ×10 deep'),
        ('PROBE_TRUNCATED.MOV',  mp4_truncated,       'truncated mid-moov'),
    ]
    for fname, builder, desc in MP4_TESTS:
        print(f"\n  → {desc}")
        r = plant_and_probe(fname, builder(), '/VIDEO')
        print(f"  {fmt_result(r)}")
        h = health_check()
        if 'DOWN' in h['ftp'] or 'DOWN' in h['ptp']:
            print(f"  ★★★ HEALTH DEGRADED: {h}")
            print(f"  [!] STOPPING — bug found in MP4 parser via '{fname}' ({desc})")
            return 0

    print("\n[*] All payloads completed; camera survived.")
    print("    Either: (a) the parsers are robust, (b) malformed files")
    print("    aren't reached unless we trigger gallery viewing on-camera,")
    print("    or (c) the parsers crash silently/safely without taking")
    print("    down PTP/FTP service.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
