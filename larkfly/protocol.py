"""Low-level PTP-IP framing and codecs, with the three iCatch quirks
documented in docs/findings.md baked in.

This module is the wire layer. Higher-level orchestration (sessions,
events, transaction IDs) lives in `camera.py`.
"""
from __future__ import annotations

import socket
import struct
from typing import Optional

from . import types as t
from .exceptions import TransportError, InitFailError


# ---------- container framing ----------------------------------------
def encode_container(ptype: int, payload: bytes) -> bytes:
    """Wrap payload in PTP-IP container framing (u32 length + u32 type)."""
    length = 8 + len(payload)
    return struct.pack('<II', length, ptype) + payload


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from sock or raise TransportError."""
    buf = b''
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError as e:
            raise TransportError(f"recv after {len(buf)}/{n} bytes: {e}") from e
        if not chunk:
            raise TransportError(
                f"socket closed after {len(buf)}/{n} bytes (camera "
                f"disconnect, WiFi sleep, or session timeout)")
        buf += chunk
    return buf


def recv_container(sock: socket.socket) -> tuple[int, bytes]:
    """Read one PTP-IP container. Returns (packet_type, payload_bytes)."""
    header = recv_exact(sock, 8)
    length, ptype = struct.unpack('<II', header)
    if length < 8 or length > 16 * 1024 * 1024:
        raise TransportError(f"insane PTP-IP packet length {length}")
    payload = recv_exact(sock, length - 8) if length > 8 else b''
    return ptype, payload


def send_container(sock: socket.socket, ptype: int, payload: bytes) -> None:
    sock.sendall(encode_container(ptype, payload))


# ---------- iCatch-specific name encoding ----------------------------
# The PIMA 15740-2 PTP-IP spec uses "PTP string" for the initiator name in
# InitCmdReq (1-byte char count + UTF-16LE chars including null). iCatch
# omits the length byte — the name is just raw UTF-16LE null-terminated.
# Confirmed by inspecting iSmart DV2's accepted handshake (frame 455 of
# the decrypted capture). Sending the spec format causes the camera to
# read the protocol version field 1 byte off and reject with InitFail.
def encode_icatch_name(name: str) -> bytes:
    return name.encode('utf-16-le') + b'\x00\x00'


def decode_icatch_name(buf: bytes, off: int) -> tuple[str, int]:
    """Scan UTF-16LE until null terminator. Returns (name, new_offset past null)."""
    end = off
    while end + 1 < len(buf):
        if buf[end] == 0 and buf[end + 1] == 0:
            break
        end += 2
    name = buf[off:end].decode('utf-16-le', errors='replace')
    return name, end + 2


# ---------- standard PTP "PTP string" (used inside operation datasets) ----
# The PTP STRING type INSIDE operation data (e.g., DeviceInfo, ObjectInfo)
# does follow the spec: u8 char_count_incl_null + UTF-16LE + null terminator.
def decode_ptp_string(buf: bytes, off: int) -> tuple[str, int]:
    if off >= len(buf):
        return '', off
    count = buf[off]
    off += 1
    if count == 0:
        return '', off
    chunk = buf[off:off + count * 2]
    off += count * 2
    return chunk[:-2].decode('utf-16-le', errors='replace'), off


def encode_ptp_string(s: str) -> bytes:
    if not s:
        return b'\x00'
    encoded = s.encode('utf-16-le') + b'\x00\x00'
    char_count = len(s) + 1
    if char_count > 255:
        raise ValueError("PTP string too long (>254 chars)")
    return bytes([char_count]) + encoded


# iCatch quirk for SendObjectInfo Filename field ONLY: the firmware's
# ObjectInfo parser consumes [u8 length] + [4 bytes 'alignment header']
# + [N × UTF-16LE chars]. Standard PTP STRING (used in DeviceInfo,
# property values, etc.) parses correctly — this is specific to
# ObjectInfo.Filename. Characterized 2026-05-17 via tools/ptp_string_quirk.py
# — see docs/findings.md "iCatch wire-format quirks".
# Without the 4-byte padding, every filename loses its first 2 chars
# (e.g. "SPHOST.BRN" becomes "OST.BRN" on disk, and never triggers
# the bootloader's FW UPDATE menu).
def encode_ptp_string_icatch_objinfo(s: str) -> bytes:
    if not s:
        return b'\x00' + b'\x00' * 4
    encoded = s.encode('utf-16-le') + b'\x00\x00'
    char_count = len(s) + 1
    if char_count > 255:
        raise ValueError("PTP string too long (>254 chars)")
    return bytes([char_count]) + b'\x00' * 4 + encoded


# ---------- typed value codec (used in property descriptors etc.) ----
def decode_value(buf: bytes, off: int, dt: int) -> tuple:
    """Decode one value of PTP data type `dt`. Returns (value, new_offset)."""
    if dt == t.DT_STRING:
        return decode_ptp_string(buf, off)
    if 0x4001 <= dt <= 0x400A:  # array of fixed-width
        elem_dt = dt - 0x4000
        n = struct.unpack_from('<I', buf, off)[0]
        off += 4
        vals = []
        for _ in range(n):
            v, off = decode_value(buf, off, elem_dt)
            vals.append(v)
        return vals, off
    sz = t.DT_SIZE.get(dt)
    if sz is None:
        raise ValueError(f"unknown PTP datatype 0x{dt:04x}")
    raw = buf[off:off + sz]
    off += sz
    if dt in (t.DT_INT8, t.DT_INT16, t.DT_INT32, t.DT_INT64):
        return int.from_bytes(raw, 'little', signed=True), off
    if dt in (t.DT_INT128, t.DT_UINT128):
        return raw.hex(), off
    return int.from_bytes(raw, 'little'), off


def encode_value(v, dt: int) -> bytes:
    """Encode a Python value as PTP datatype `dt`."""
    if dt == t.DT_STRING:
        return encode_ptp_string(str(v))
    if 0x4001 <= dt <= 0x400A:
        elem_dt = dt - 0x4000
        out = struct.pack('<I', len(v))
        for x in v:
            out += encode_value(x, elem_dt)
        return out
    sz = t.DT_SIZE[dt]
    if dt in (t.DT_INT8, t.DT_INT16, t.DT_INT32, t.DT_INT64):
        return int(v).to_bytes(sz, 'little', signed=True)
    if dt in (t.DT_INT128, t.DT_UINT128):
        # accept hex string or int
        if isinstance(v, str):
            return bytes.fromhex(v)[:sz].rjust(sz, b'\x00')
        return int(v).to_bytes(sz, 'little')
    return int(v).to_bytes(sz, 'little')


# ---------- DeviceInfo dataset parser --------------------------------
def parse_device_info(data: bytes) -> dict:
    """Decode the PTP DeviceInfo dataset (PIMA §5.1.1)."""
    off = 0
    info = {}
    info['standard_version']           = struct.unpack_from('<H', data, off)[0]; off += 2
    info['vendor_extension_id']        = struct.unpack_from('<I', data, off)[0]; off += 4
    info['vendor_extension_version']   = struct.unpack_from('<H', data, off)[0]; off += 2
    info['vendor_extension_desc'], off = decode_ptp_string(data, off)
    info['functional_mode']            = struct.unpack_from('<H', data, off)[0]; off += 2
    info['operations_supported'], off  = _decode_array_u16(data, off)
    info['events_supported'], off      = _decode_array_u16(data, off)
    info['device_properties_supported'], off = _decode_array_u16(data, off)
    info['capture_formats'], off       = _decode_array_u16(data, off)
    info['image_formats'], off         = _decode_array_u16(data, off)
    info['manufacturer'], off          = decode_ptp_string(data, off)
    info['model'], off                 = decode_ptp_string(data, off)
    info['device_version'], off        = decode_ptp_string(data, off)
    info['serial_number'], off         = decode_ptp_string(data, off)
    return info


def _decode_array_u16(buf: bytes, off: int) -> tuple[list[int], int]:
    n = struct.unpack_from('<I', buf, off)[0]
    off += 4
    arr = list(struct.unpack_from(f'<{n}H', buf, off))
    off += 2 * n
    return arr, off


def parse_object_info(data: bytes) -> dict:
    """Decode a PTP ObjectInfo dataset (PIMA §5.5.5).

    Fixed-layout prefix is 52 bytes, then 4 PTP strings (filename,
    capture date, modification date, keywords).
    """
    if len(data) < 52:
        raise ValueError("ObjectInfo dataset too short")
    o = {}
    o['storage_id']            = struct.unpack_from('<I', data,  0)[0]
    o['object_format']         = struct.unpack_from('<H', data,  4)[0]
    o['protection_status']     = struct.unpack_from('<H', data,  6)[0]
    o['object_compressed_size']= struct.unpack_from('<I', data,  8)[0]
    o['thumb_format']          = struct.unpack_from('<H', data, 12)[0]
    o['thumb_compressed_size'] = struct.unpack_from('<I', data, 14)[0]
    o['thumb_pix_width']       = struct.unpack_from('<I', data, 18)[0]
    o['thumb_pix_height']      = struct.unpack_from('<I', data, 22)[0]
    o['image_pix_width']       = struct.unpack_from('<I', data, 26)[0]
    o['image_pix_height']      = struct.unpack_from('<I', data, 30)[0]
    o['image_bit_depth']       = struct.unpack_from('<I', data, 34)[0]
    o['parent_object']         = struct.unpack_from('<I', data, 38)[0]
    o['association_type']      = struct.unpack_from('<H', data, 42)[0]
    o['association_desc']      = struct.unpack_from('<I', data, 44)[0]
    o['sequence_number']       = struct.unpack_from('<I', data, 48)[0]
    off = 52
    o['filename'], off          = decode_ptp_string(data, off)
    o['capture_date'], off      = decode_ptp_string(data, off)
    o['modification_date'], off = decode_ptp_string(data, off)
    o['keywords'], off          = decode_ptp_string(data, off)
    return o


def parse_storage_info(data: bytes) -> dict:
    """Decode a PTP StorageInfo dataset (PIMA §5.2.1)."""
    o = {}
    o['storage_type']      = struct.unpack_from('<H', data, 0)[0]
    o['filesystem_type']   = struct.unpack_from('<H', data, 2)[0]
    o['access_capability'] = struct.unpack_from('<H', data, 4)[0]
    o['max_capacity']      = struct.unpack_from('<Q', data, 6)[0]
    o['free_space_bytes']  = struct.unpack_from('<Q', data, 14)[0]
    o['free_space_objects']= struct.unpack_from('<I', data, 22)[0]
    off = 26
    o['storage_description'], off = decode_ptp_string(data, off)
    o['volume_label'], off        = decode_ptp_string(data, off)
    return o


def parse_prop_desc(data: bytes) -> dict:
    """Decode a PTP DevicePropDesc dataset (§5.5.4)."""
    out = {'raw_len': len(data)}
    off = 0
    out['property_code']  = struct.unpack_from('<H', data, off)[0]; off += 2
    out['datatype']       = struct.unpack_from('<H', data, off)[0]; off += 2
    out['datatype_name']  = t.DT_NAMES.get(out['datatype'], f"0x{out['datatype']:04x}")
    out['getset']         = data[off]; off += 1
    out['factory_default'], off = decode_value(data, off, out['datatype'])
    out['current_value'], off   = decode_value(data, off, out['datatype'])
    if off >= len(data):
        out['form'] = 'none'
        return out
    form_flag = data[off]; off += 1
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
        out['allowed_values'] = vals
    else:
        out['form'] = f'unknown_form_flag_{form_flag}'
    return out


# ---------- InitCommand handshake ------------------------------------
def encode_init_cmd_req(guid: bytes, name: str) -> bytes:
    """Build the InitCmdReq payload in the iCatch format (no PTP-string
    length prefix on the name)."""
    if len(guid) != 16:
        raise ValueError("GUID must be exactly 16 bytes")
    return guid + encode_icatch_name(name) + struct.pack('<I', t.PROTOCOL_VERSION)


def parse_init_cmd_ack(body: bytes) -> dict:
    """Parse an InitCmdAck body. iCatch's responder name field may be
    empty + 2 padding bytes; we read defensively."""
    conn_num = struct.unpack_from('<I', body, 0)[0]
    cam_guid = body[4:20]
    cam_name, off = decode_icatch_name(body, 20)
    # iCatch pads to 4-byte alignment in some responses
    if off + 4 > len(body) and off + 2 <= len(body):
        off += 2
    cam_proto = struct.unpack_from('<I', body, off)[0] if off + 4 <= len(body) else 0
    return {
        'connection_number': conn_num,
        'guid': cam_guid,
        'name': cam_name,
        'protocol_version': cam_proto,
    }


# ---------- operation request/response ------------------------------
def encode_op_req(opcode: int, txid: int, params: list[int],
                  data_phase: int = 1) -> bytes:
    """Build an OpReq payload (data_phase: 1=no data, 2=data going out)."""
    p = struct.pack('<I', data_phase) + struct.pack('<H', opcode) + struct.pack('<I', txid)
    for x in params:
        p += struct.pack('<I', x)
    return p


def parse_op_resp(body: bytes) -> dict:
    """Parse an OpResp body. iCatch pads the body with trailing zeros up
    to ~26 bytes; the actual params are valid only up to 5×u32."""
    rc = struct.unpack_from('<H', body, 0)[0]
    txid = struct.unpack_from('<I', body, 2)[0]
    params = []
    for i in range(6, min(len(body), 26), 4):
        if i + 4 > len(body):
            break
        params.append(struct.unpack_from('<I', body, i)[0])
    return {'response_code': rc, 'transaction_id': txid, 'params': params}


def parse_event(body: bytes) -> dict:
    """Parse an Event packet body."""
    if len(body) < 6:
        raise ValueError("event packet too short")
    code = struct.unpack_from('<H', body, 0)[0]
    txid = struct.unpack_from('<I', body, 2)[0]
    params = []
    for i in range(6, len(body), 4):
        if i + 4 > len(body):
            break
        params.append(struct.unpack_from('<I', body, i)[0])
    return {'event_code': code, 'transaction_id': txid, 'params': params}
