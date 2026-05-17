#!/usr/bin/env python3
"""Characterize the iCatch PTP-string encoding quirk in SendObjectInfo.

OBSERVATION:
  Uploading filename "sta.conf" via SendObjectInfo + SendObject results
  in the file being stored as "a.conf" on the SD card — first 2 chars
  dropped. Across 17 different filenames, this is consistent: every
  one loses exactly the first 2 characters.

THIS TOOL EXPLORES:
  1. Verify the "2 chars dropped" rule with short/long edge cases.
  2. Test the compensation strategy: prefix filename with "XX" to
     pre-eat the discarded chars.
  3. Test alternative PTP-string encodings the firmware might prefer
     (no-length-byte iCatch style; length-as-u16; length-as-byte-count;
     extra padding).
  4. Cross-check: what does GetObjectInfo report as the Filename for
     the stored object? Same as the FTP filename, or different?
  5. Test whether the quirk affects OTHER PTP-string fields in
     SendObjectInfo (Keywords, CaptureDate, ModificationDate).

Each test uploads → reads back filename via FTP LIST + PTP GetObjectInfo
→ deletes the test object. Safe to run.

Run: python3 tools/ptp_string_quirk.py
"""
from __future__ import annotations
import ftplib, io, struct, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import Camera
from larkfly.exceptions import PtpError


# ---------- PTP-string encoders to test ----------

def enc_spec(s: str) -> bytes:
    """Standard PIMA-15740 PTP STRING: u8 count incl-null + UTF-16LE chars + \\0\\0"""
    if not s:
        return b'\x00'
    return bytes([len(s) + 1]) + (s + '\x00').encode('utf-16-le')

def enc_no_length(s: str) -> bytes:
    """iCatch InitCmdReq-style: NO length byte, raw UTF-16LE null-term."""
    if not s:
        return b'\x00\x00'
    return (s + '\x00').encode('utf-16-le')

def enc_u16_length(s: str) -> bytes:
    """u16-LE count + UTF-16LE chars + null."""
    if not s:
        return b'\x00\x00'
    return struct.pack('<H', len(s) + 1) + (s + '\x00').encode('utf-16-le')

def enc_u32_length(s: str) -> bytes:
    """u32-LE count + UTF-16LE chars + null."""
    if not s:
        return b'\x00\x00\x00\x00'
    return struct.pack('<I', len(s) + 1) + (s + '\x00').encode('utf-16-le')

def enc_byte_count(s: str) -> bytes:
    """u8 BYTE-count (not char count) + UTF-16LE chars + null."""
    if not s:
        return b'\x00'
    body = (s + '\x00').encode('utf-16-le')
    return bytes([len(body)]) + body

def enc_spec_padded(s: str, pad: int = 4) -> bytes:
    """Standard spec encoding + N bytes of trailing zero padding after length."""
    if not s:
        return b'\x00' + b'\x00' * pad
    return bytes([len(s) + 1]) + b'\x00' * pad + (s + '\x00').encode('utf-16-le')


ENCODERS = {
    'spec':        enc_spec,
    'no_length':   enc_no_length,
    'u16_length':  enc_u16_length,
    'u32_length':  enc_u32_length,
    'byte_count':  enc_byte_count,
    'spec_pad4':   lambda s: enc_spec_padded(s, 4),
    'spec_pad2':   lambda s: enc_spec_padded(s, 2),
}


# ---------- Build SendObjectInfo with a chosen filename encoder ----------

def build_object_info(filename: str, payload_len: int, storage_id: int,
                      fn_encoder=enc_spec) -> bytes:
    out = struct.pack('<I', storage_id)
    out += struct.pack('<H', 0x3000)    # ObjectFormat Undefined
    out += struct.pack('<H', 0)         # ProtectionStatus
    out += struct.pack('<I', payload_len)
    out += struct.pack('<H', 0) + struct.pack('<I', 0)*5
    out += struct.pack('<I', 0)         # ParentObject (root)
    out += struct.pack('<H', 0)         # AssociationType
    out += struct.pack('<I', 0)         # AssociationDesc
    out += struct.pack('<I', 0)         # SequenceNumber
    out += fn_encoder(filename)
    out += enc_spec('') * 3             # CaptureDate, ModificationDate, Keywords (empty, spec form)
    return out


def upload(cam, filename: str, fn_encoder, storage_id: int,
           payload: bytes = b'X') -> int | None:
    """Returns assigned handle, or None on failure."""
    info = build_object_info(filename, len(payload), storage_id, fn_encoder)
    try:
        rc, rp, _ = cam._raw_op(0x100C, [storage_id, 0xFFFFFFFF], tx_data=info)
        if rc != 0x2001:
            return None
        h = rp[2]
        rc, _, _ = cam._raw_op(0x100D, [], tx_data=payload)
        if rc != 0x2001:
            return None
        return h
    except Exception:
        return None


def ftp_list_names(ftp) -> set:
    lines = []
    try:
        ftp.retrlines('LIST', lines.append)
    except Exception:
        return set()
    return {ln.split()[-1] for ln in lines}


def get_object_info_filename(cam, handle: int) -> str | None:
    try:
        rc, _, data = cam._raw_op(0x1008, [handle])
        if rc != 0x2001:
            return None
        # ObjectInfo layout: fixed 52 bytes then 4 PTP strings.
        # Skip to byte 52 for Filename.
        off = 52
        n = data[off]; off += 1
        if n == 0:
            return ''
        return data[off:off + 2*n].decode('utf-16-le', errors='replace').rstrip('\x00')
    except Exception:
        return None


# ---------- Tests ----------

def test_standard_truncation(cam, ftp, sid):
    print("\n=== Test 1: confirm 'first 2 chars dropped' across edge cases ===")
    cases = ['abc', 'abcd', 'abcde', 'ab', 'a', '', 'XYZsta.conf']
    for fname in cases:
        if not fname:
            print(f"  '' (empty)  → SKIP (camera may reject)")
            continue
        pre = ftp_list_names(ftp)
        h = upload(cam, fname, enc_spec, sid)
        if h is None:
            print(f"  {fname!r:25s} upload FAILED")
            continue
        post = ftp_list_names(ftp)
        new = post - pre
        oi_name = get_object_info_filename(cam, h)
        print(f"  sent={fname!r:25s} ftp_stored={list(new)!r:20s} GetObjectInfo={oi_name!r}")
        # cleanup
        cam._raw_op(0x100B, [h])


def test_compensation(cam, ftp, sid):
    print("\n=== Test 2: compensation — prefix 'XX' to pre-eat dropped chars ===")
    targets = ['SPHOST.BRN', 'WIFI.CFG', 'sta.conf']
    for target in targets:
        # Use spec encoder with XX prefix
        prefixed = 'XX' + target
        pre = ftp_list_names(ftp)
        h = upload(cam, prefixed, enc_spec, sid)
        if h is None:
            print(f"  XX+{target!r:15s} upload FAILED")
            continue
        post = ftp_list_names(ftp)
        new = list(post - pre)
        oi_name = get_object_info_filename(cam, h)
        match = '✓ EXACT MATCH' if new and new[0] == target else '✗'
        print(f"  sent={prefixed!r:25s} stored={new!r:20s} oi={oi_name!r}  {match}")
        cam._raw_op(0x100B, [h])


def test_alternative_encoders(cam, ftp, sid):
    print("\n=== Test 3: try alternative PTP-string encodings ===")
    target = 'TESTFILE.TXT'
    for name, encoder in ENCODERS.items():
        pre = ftp_list_names(ftp)
        h = upload(cam, target, encoder, sid)
        if h is None:
            print(f"  encoder={name:12s} upload FAILED")
            continue
        post = ftp_list_names(ftp)
        new = list(post - pre)
        oi_name = get_object_info_filename(cam, h)
        match = ''
        if new:
            if new[0] == target: match = '🎯 EXACT (no truncation!)'
            elif new[0] == target[2:]: match = '(2 chars eaten — same as spec)'
            elif new[0] == target[4:]: match = '(4 chars eaten)'
            elif new[0] == target[1:]: match = '(1 char eaten)'
            else: match = f'(unexpected: {new[0]!r})'
        print(f"  encoder={name:12s} stored={new!r:20s} oi={oi_name!r}  {match}")
        cam._raw_op(0x100B, [h])


def test_other_string_fields(cam, ftp, sid):
    """Check whether the Keywords / CaptureDate fields also get truncated.
    We can't read them via FTP, so use GetObjectInfo to inspect."""
    print("\n=== Test 4: do CaptureDate/ModificationDate/Keywords also truncate? ===")
    # Build ObjectInfo with named fields we can identify
    storage_id = sid
    payload = b'X'
    info = struct.pack('<I', storage_id)
    info += struct.pack('<H', 0x3000)
    info += struct.pack('<H', 0)
    info += struct.pack('<I', len(payload))
    info += struct.pack('<H', 0) + struct.pack('<I', 0)*5
    info += struct.pack('<I', 0)
    info += struct.pack('<H', 0)
    info += struct.pack('<I', 0)
    info += struct.pack('<I', 0)
    info += enc_spec('XXFILE.TST')      # Filename (with our compensation)
    info += enc_spec('CAPTURE_DATE')    # CaptureDate
    info += enc_spec('MOD_DATE')        # ModificationDate
    info += enc_spec('KEYWORDS_FIELD')  # Keywords

    try:
        rc, rp, _ = cam._raw_op(0x100C, [storage_id, 0xFFFFFFFF], tx_data=info)
        if rc != 0x2001:
            print(f"  SendObjectInfo failed rc=0x{rc:04X}")
            return
        h = rp[2]
        cam._raw_op(0x100D, [], tx_data=payload)
        # Read back via GetObjectInfo
        rc, _, data = cam._raw_op(0x1008, [h])
        if rc == 0x2001:
            # Parse all 4 strings
            off = 52
            results = {}
            for label in ['Filename','CaptureDate','ModificationDate','Keywords']:
                n = data[off]; off += 1
                if n == 0:
                    results[label] = ''
                else:
                    s = data[off:off + 2*n].decode('utf-16-le', errors='replace').rstrip('\x00')
                    results[label] = s
                    off += 2*n
            for k, v in results.items():
                print(f"  {k:18s}: {v!r}")
        cam._raw_op(0x100B, [h])
    except Exception as e:
        print(f"  error: {e}")


def main():
    cam = Camera('192.168.1.1', bind='192.168.1.10')
    cam.connect()
    sid = cam.storage_ids()[0]
    print(f"[*] Camera connected. Storage ID 0x{sid:08X}")

    ftp = ftplib.FTP()
    ftp.connect('192.168.1.1', 21, timeout=10)
    ftp.login('wificam', 'wificam')

    test_standard_truncation(cam, ftp, sid)
    test_compensation(cam, ftp, sid)
    test_alternative_encoders(cam, ftp, sid)
    test_other_string_fields(cam, ftp, sid)

    ftp.quit()
    cam.close()


if __name__ == '__main__':
    sys.exit(main())
