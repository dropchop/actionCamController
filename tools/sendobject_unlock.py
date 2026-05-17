#!/usr/bin/env python3
"""Final unlock attempt: try PTP SendObjectInfo + SendObject with magic
filenames, then re-test if the locked booleans 0xD75F/0xD7FC/0xD7FF
become writable.

PTP file-upload flow per ISO 15740:
  1. SendObjectInfo (0x100C, params=[storage_id, parent_handle]) +
     data_phase containing the ObjectInfo struct.
     Camera returns assigned_handle in response_params[2].
  2. SendObject (0x100D) + data_phase containing the file bytes.

ObjectInfo struct (fixed fields then 4 PTP strings):
  StorageID (u32), ObjectFormat (u16), ProtectionStatus (u16),
  ObjectCompressedSize (u32), ThumbFormat (u16), ThumbCompressedSize
  (u32), ThumbPixWidth (u32), ThumbPixHeight (u32), ImagePixWidth
  (u32), ImagePixHeight (u32), ImageBitDepth (u32), ParentObject (u32),
  AssociationType (u16), AssociationDesc (u32), SequenceNumber (u32),
  Filename, CaptureDate, ModificationDate, Keywords (all PTP strings).
"""
from __future__ import annotations
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import Camera
from larkfly.exceptions import PtpError

TARGETS = [0xD75F, 0xD7FC, 0xD7FF]


def encode_ptp_string(s: str) -> bytes:
    """Standard PTP STRING — used for non-Filename ObjectInfo fields."""
    if not s:
        return b'\x00'
    encoded = (s + '\x00').encode('utf-16-le')
    n = len(s) + 1
    return bytes([n]) + encoded


def encode_ptp_string_icatch_objinfo(s: str) -> bytes:
    """iCatch quirk for ObjectInfo.Filename: 4 bytes of padding after the
    length byte. Without this, every filename loses its first 2 chars.
    See docs/findings.md PTP quirk #4 + tools/ptp_string_quirk.py."""
    if not s:
        return b'\x00' + b'\x00' * 4
    encoded = (s + '\x00').encode('utf-16-le')
    n = len(s) + 1
    return bytes([n]) + b'\x00' * 4 + encoded


def build_object_info(filename: str, payload_len: int,
                      object_format: int = 0x3000,  # PTP "Undefined"
                      storage_id: int = 0x00010001,
                      parent: int = 0) -> bytes:
    out = b''
    out += struct.pack('<I', storage_id)
    out += struct.pack('<H', object_format)     # 0x3000 = generic file
    out += struct.pack('<H', 0)                 # ProtectionStatus
    out += struct.pack('<I', payload_len)       # ObjectCompressedSize
    out += struct.pack('<H', 0)                 # ThumbFormat
    out += struct.pack('<I', 0)                 # ThumbCompressedSize
    out += struct.pack('<I', 0)                 # ThumbPixWidth
    out += struct.pack('<I', 0)                 # ThumbPixHeight
    out += struct.pack('<I', 0)                 # ImagePixWidth
    out += struct.pack('<I', 0)                 # ImagePixHeight
    out += struct.pack('<I', 0)                 # ImageBitDepth
    out += struct.pack('<I', parent)            # ParentObject
    out += struct.pack('<H', 0)                 # AssociationType
    out += struct.pack('<I', 0)                 # AssociationDesc
    out += struct.pack('<I', 0)                 # SequenceNumber
    out += encode_ptp_string_icatch_objinfo(filename)  # Filename (4-byte-padded; iCatch quirk)
    out += encode_ptp_string('')                       # CaptureDate
    out += encode_ptp_string('')                       # ModificationDate
    out += encode_ptp_string('')                       # Keywords
    return out


def upload_and_test(cam, filename: str, payload: bytes) -> dict:
    out = {'filename': filename, 'payload_len': len(payload)}
    storage_ids = cam.storage_ids()
    sid = storage_ids[0] if storage_ids else 0x00010001
    out['storage_id'] = f'0x{sid:08X}'

    info = build_object_info(filename, len(payload), storage_id=sid)
    # SendObjectInfo
    try:
        rc, rp, data = cam._raw_op(0x100C, [sid, 0xFFFFFFFF], tx_data=info)
        out['SendObjectInfo_rc'] = f'0x{rc:04X}'
        out['SendObjectInfo_params'] = rp
    except Exception as e:
        out['SendObjectInfo_exc'] = repr(e)
        return out
    if rc != 0x2001:
        return out
    # SendObject
    try:
        rc, rp, data = cam._raw_op(0x100D, [], tx_data=payload)
        out['SendObject_rc'] = f'0x{rc:04X}'
    except Exception as e:
        out['SendObject_exc'] = repr(e)
        return out
    if rc != 0x2001:
        return out
    # Probe the locked booleans
    for code in TARGETS:
        try:
            orig = cam.get_prop_value(code)
            cam.set_prop_value(code, 0 if orig == 1 else 1)
            rb = cam.get_prop_value(code)
            if rb != orig:
                out[f'0x{code:04X}'] = f'🔓 UNLOCKED: {orig} -> {rb}'
                # revert
                try:
                    cam.set_prop_value(code, orig)
                except Exception:
                    pass
            else:
                out[f'0x{code:04X}'] = 'still-locked'
        except Exception as e:
            out[f'0x{code:04X}'] = f'exc {e!r}'
    return out


def main():
    cam = Camera('192.168.1.1', bind='192.168.1.10')
    cam.connect()
    print(f"[*] Connected. Storage IDs: {cam.storage_ids()}")
    print()

    # Filenames worth trying
    targets = [
        ('FACTORY.BIN',   b'\x00' * 16),
        ('UNLOCK.BIN',    b'\x00' * 16),
        ('SERVICE.BIN',   b'\x00' * 16),
        ('DEBUG.BIN',     b'\x00' * 16),
        ('SPHOST.BRN',    b'\x00' * 16),         # bootloader filename
        ('FACTORY.CFG',   b'\x00' * 16),
        ('ICATCH.KEY',    b'\x00' * 16),
        ('UNLOCK.KEY',    b'\xFF' * 16),         # different payload
    ]

    for filename, payload in targets:
        print(f"=== Upload {filename} ({len(payload)} bytes) ===")
        result = upload_and_test(cam, filename, payload)
        for k, v in result.items():
            print(f"   {k}: {v}")
        print()

    cam.close()


if __name__ == '__main__':
    sys.exit(main())
