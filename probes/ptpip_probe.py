#!/usr/bin/env python3
"""PTP/IP probe — confirms the camera speaks PIMA 15740 PTP/IP on TCP 15740.

What it does:
  1. Opens the command TCP channel to <host>:15740.
  2. Sends Init Command Request; expects Init Command Ack.
  3. Opens the event TCP channel; sends Init Event Request; expects Init Event Ack.
  4. PTP OpenSession (op 0x1002) on the command channel.
  5. PTP GetDeviceInfo (op 0x1001) — the moment of truth: the camera
     identifies itself with manufacturer/model/firmware + lists every PTP
     operation, event, and property code it supports.
  6. PTP CloseSession (op 0x1003) and disconnects.

Run:
  python3 ptpip_probe.py                    # defaults to 192.168.1.1
  python3 ptpip_probe.py 192.168.1.1
  python3 ptpip_probe.py 192.168.50.11 --name "rig-cam-1" --verbose

Exit codes:
  0   PTP/IP confirmed end-to-end.
  1   TCP refused or unreachable — camera is NOT speaking PTP/IP here.
  2   TCP open but no Init Command Ack (timeout or wrong reply).
  3   Init Command Ack received but later step failed.

Spec refs: PIMA 15740-2000 (PTP) and the PTP-IP extension as implemented by
libgphoto2 (camlibs/ptp2/ptpip.c).
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
import uuid

# ---- PTP/IP container packet types --------------------------------------
PT_INIT_CMD_REQ = 1
PT_INIT_CMD_ACK = 2
PT_INIT_EVT_REQ = 3
PT_INIT_EVT_ACK = 4
PT_INIT_FAIL    = 5
PT_OP_REQ       = 6
PT_OP_RESP      = 7
PT_EVENT        = 8
PT_START_DATA   = 9
PT_DATA         = 10
PT_CANCEL       = 11  # NOTE: PIMA 15740-2 spec — 11=Cancel, 12=EndData.
PT_END_DATA     = 12  # libgphoto2 uses these values; the PTP-IP supplement
PT_PROBE_REQ    = 13  # is one of those specs where conventions vary by
PT_PROBE_RESP   = 14  # implementation. Confirmed empirically against iCatch.

TYPE_NAMES = {
    1: "InitCmdReq", 2: "InitCmdAck", 3: "InitEvtReq", 4: "InitEvtAck",
    5: "InitFail",   6: "OpReq",      7: "OpResp",     8: "Event",
    9: "StartData", 10: "Data",      11: "Cancel",    12: "EndData",
    13: "ProbeReq", 14: "ProbeResp",
}

# ---- PTP operation codes (subset we use) --------------------------------
OP_GET_DEVICE_INFO = 0x1001
OP_OPEN_SESSION    = 0x1002
OP_CLOSE_SESSION   = 0x1003

# ---- PTP response codes -------------------------------------------------
RC_OK                      = 0x2001
RC_NAMES = {0x2001: "OK", 0x2002: "General error", 0x2003: "Session not open",
            0x2004: "Invalid transaction ID", 0x2005: "Operation not supported",
            0x2006: "Parameter not supported", 0x2007: "Incomplete transfer",
            0x2008: "Invalid storage ID", 0x2009: "Invalid object handle",
            0x200A: "Device prop not supported", 0x200B: "Invalid object format code",
            0x200C: "Store full"}

PTPIP_PORT = 15740
PROTOCOL_VERSION = 0x00010000  # PTP/IP v1.0


# ---- container framing --------------------------------------------------
def send_packet(sock: socket.socket, ptype: int, payload: bytes, verbose=False) -> None:
    """Send one PTP/IP container: u32 length + u32 type + payload."""
    length = 8 + len(payload)
    pkt = struct.pack('<II', length, ptype) + payload
    if verbose:
        _hexdump(f"--> {TYPE_NAMES.get(ptype, ptype)} ({len(payload)} bytes)", pkt)
    sock.sendall(pkt)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Block until n bytes received or socket closes."""
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"socket closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def recv_packet(sock: socket.socket, verbose=False) -> tuple[int, bytes]:
    """Read one PTP/IP container. Returns (packet_type, payload_bytes)."""
    header = recv_exact(sock, 8)
    length, ptype = struct.unpack('<II', header)
    if length < 8 or length > 16 * 1024 * 1024:
        raise ValueError(f"insane packet length {length}")
    payload = recv_exact(sock, length - 8) if length > 8 else b''
    if verbose:
        _hexdump(f"<-- {TYPE_NAMES.get(ptype, ptype)} ({len(payload)} bytes)",
                 header + payload)
    return ptype, payload


def _hexdump(label: str, data: bytes) -> None:
    print(label)
    for i in range(0, min(len(data), 96), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  {i:04x}  {hex_part:<48}  {ascii_part}")
    if len(data) > 96:
        print(f"  ... ({len(data) - 96} more bytes)")


# ---- PTP string and array codecs ---------------------------------------
def encode_ptp_string(s: str) -> bytes:
    """PTP string: u8 char_count_including_null + UTF-16LE chars including
    null terminator. Empty string is a single 0x00 byte."""
    if not s:
        return b'\x00'
    chars = s.encode('utf-16-le') + b'\x00\x00'
    char_count = len(s) + 1
    if char_count > 255:
        raise ValueError("PTP string too long (>254 chars)")
    return bytes([char_count]) + chars


def decode_ptp_string(buf: bytes, off: int) -> tuple[str, int]:
    """Returns (string, new_offset)."""
    if off >= len(buf):
        return '', off
    count = buf[off]
    off += 1
    if count == 0:
        return '', off
    raw = buf[off:off + count * 2]
    off += count * 2
    # count includes the null terminator
    return raw[:-2].decode('utf-16-le', errors='replace'), off


def decode_ptp_array_u16(buf: bytes, off: int) -> tuple[list[int], int]:
    n = struct.unpack_from('<I', buf, off)[0]
    off += 4
    arr = list(struct.unpack_from(f'<{n}H', buf, off))
    off += 2 * n
    return arr, off


# ---- DeviceInfo parser -------------------------------------------------
def parse_device_info(data: bytes) -> dict:
    """Decode the PTP DeviceInfo dataset (PIMA 15740 §5.1.1)."""
    off = 0
    info = {}
    info['standard_version'] = struct.unpack_from('<H', data, off)[0]; off += 2
    info['vendor_extension_id'] = struct.unpack_from('<I', data, off)[0]; off += 4
    info['vendor_extension_version'] = struct.unpack_from('<H', data, off)[0]; off += 2
    info['vendor_extension_desc'], off = decode_ptp_string(data, off)
    info['functional_mode'] = struct.unpack_from('<H', data, off)[0]; off += 2
    info['operations_supported'], off = decode_ptp_array_u16(data, off)
    info['events_supported'], off = decode_ptp_array_u16(data, off)
    info['device_properties_supported'], off = decode_ptp_array_u16(data, off)
    info['capture_formats'], off = decode_ptp_array_u16(data, off)
    info['image_formats'], off = decode_ptp_array_u16(data, off)
    info['manufacturer'], off = decode_ptp_string(data, off)
    info['model'], off = decode_ptp_string(data, off)
    info['device_version'], off = decode_ptp_string(data, off)
    info['serial_number'], off = decode_ptp_string(data, off)
    info['_extra_bytes'] = len(data) - off
    return info


# ---- the probe itself --------------------------------------------------
def connect_tcp(host: str, port: int, timeout: float,
                bind_source: str | None = None) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    if bind_source:
        # Bind to a local source IP. Forces routing via whichever interface
        # owns that IP — necessary when two interfaces share a subnet.
        sock.bind((bind_source, 0))
    sock.connect((host, port))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def encode_icatch_name(name: str) -> bytes:
    """iCatch InitCmdReq uses UTF-16LE null-terminated, WITHOUT the 1-byte
    PTP-string length prefix that the PIMA spec requires. Confirmed against
    decrypted iSmart DV2 capture (frame 455 has no length byte before
    'localhost\\0')."""
    return name.encode('utf-16-le') + b'\x00\x00'


def decode_icatch_name(buf: bytes, off: int) -> tuple[str, int]:
    """Scan UTF-16LE chars until null terminator. Returns (name, new_off)."""
    end = off
    while end + 1 < len(buf):
        if buf[end] == 0 and buf[end + 1] == 0:
            break
        end += 2
    name = buf[off:end].decode('utf-16-le', errors='replace')
    return name, end + 2  # past the UTF-16 null


def init_command(cmd_sock: socket.socket, name: str, guid: bytes,
                 verbose: bool) -> int:
    """Init Command Request → Ack. Returns connection number.

    iCatch firmware whitelists initiator name: only 'localhost' (the
    libptp2 default) or empty are accepted; anything else returns
    InitFail reason=3. Confirmed empirically against Larkfly A6+."""
    payload = guid + encode_icatch_name(name) + struct.pack('<I', PROTOCOL_VERSION)
    send_packet(cmd_sock, PT_INIT_CMD_REQ, payload, verbose)
    ptype, body = recv_packet(cmd_sock, verbose)
    if ptype == PT_INIT_FAIL:
        reason = struct.unpack_from('<I', body, 0)[0]
        if reason == 3 and name not in ('localhost', ''):
            raise RuntimeError(
                f"InitFail reason=3 — iCatch firmware rejects initiator "
                f"name {name!r}; try --name localhost (or empty).")
        raise RuntimeError(f"InitFail reason=0x{reason:08x}")
    if ptype != PT_INIT_CMD_ACK:
        raise RuntimeError(f"expected InitCmdAck, got {TYPE_NAMES.get(ptype, ptype)}")
    conn_num = struct.unpack_from('<I', body, 0)[0]
    cam_guid = body[4:20]
    cam_name, off = decode_icatch_name(body, 20)
    # iCatch sometimes pads to 4-byte alignment before protocol version
    if off + 4 > len(body) and off + 2 <= len(body):
        off += 2  # try aligning
    if off + 4 <= len(body):
        cam_proto = struct.unpack_from('<I', body, off)[0]
    else:
        cam_proto = 0
    print(f"  Init Command Ack: connection={conn_num}, "
          f"camera GUID={cam_guid.hex()}, "
          f"camera name={cam_name!r}, "
          f"protocol=0x{cam_proto:08x}")
    return conn_num


def init_event(evt_sock: socket.socket, conn_num: int, verbose: bool) -> None:
    send_packet(evt_sock, PT_INIT_EVT_REQ, struct.pack('<I', conn_num), verbose)
    ptype, _body = recv_packet(evt_sock, verbose)
    if ptype != PT_INIT_EVT_ACK:
        raise RuntimeError(f"expected InitEvtAck, got {TYPE_NAMES.get(ptype, ptype)}")


def operation(cmd_sock: socket.socket, opcode: int, txid: int,
              params: list[int], verbose: bool) -> tuple[int, list[int], bytes]:
    """Send an operation; collect any data phase + the final response.
    Returns (response_code, response_params, data_bytes)."""
    # data_phase_info: 1 = no data phase (we never send data outbound in this probe)
    payload = struct.pack('<I', 1) + struct.pack('<H', opcode) + struct.pack('<I', txid)
    for p in params:
        payload += struct.pack('<I', p)
    send_packet(cmd_sock, PT_OP_REQ, payload, verbose)

    data_buf = b''
    while True:
        ptype, body = recv_packet(cmd_sock, verbose)
        if ptype == PT_START_DATA:
            # body: u32 txid, u64 total_length
            _txid, total = struct.unpack_from('<IQ', body, 0)
            if verbose:
                print(f"  StartData total={total}")
            continue
        if ptype == PT_DATA:
            data_buf += body[4:]  # skip txid
            continue
        if ptype == PT_END_DATA:
            data_buf += body[4:]  # skip txid
            continue
        if ptype == PT_OP_RESP:
            rcode = struct.unpack_from('<H', body, 0)[0]
            _txid = struct.unpack_from('<I', body, 2)[0]
            resp_params = []
            for i in range(6, len(body), 4):
                if i + 4 > len(body):
                    break
                resp_params.append(struct.unpack_from('<I', body, i)[0])
            return rcode, resp_params, data_buf
        # ignore unsolicited events on the command channel (shouldn't happen)


def print_device_info(info: dict) -> None:
    print()
    print("=" * 70)
    print("Camera DeviceInfo:")
    print("=" * 70)
    print(f"  Manufacturer            : {info['manufacturer']!r}")
    print(f"  Model                   : {info['model']!r}")
    print(f"  Device version          : {info['device_version']!r}")
    print(f"  Serial number           : {info['serial_number']!r}")
    print(f"  PTP standard version    : 0x{info['standard_version']:04x} "
          f"({info['standard_version']/100:.2f})")
    print(f"  Vendor extension ID     : 0x{info['vendor_extension_id']:08x}")
    print(f"  Vendor extension ver    : 0x{info['vendor_extension_version']:04x}")
    print(f"  Vendor extension desc   : {info['vendor_extension_desc']!r}")
    print(f"  Functional mode         : 0x{info['functional_mode']:04x}")
    print()
    _print_codes("Operations supported", info['operations_supported'])
    _print_codes("Events supported", info['events_supported'])
    _print_codes("Device properties supported", info['device_properties_supported'])
    if info['capture_formats']:
        _print_codes("Capture formats", info['capture_formats'])
    if info['image_formats']:
        _print_codes("Image formats", info['image_formats'])
    if info['_extra_bytes']:
        print(f"  (note: {info['_extra_bytes']} extra trailing bytes in dataset)")


def _print_codes(label: str, codes: list[int]) -> None:
    print(f"  {label} ({len(codes)}):")
    standard = [c for c in codes if c < 0x9000]
    vendor   = [c for c in codes if c >= 0x9000]
    if standard:
        print("    standard:  " + ", ".join(f"0x{c:04x}" for c in standard))
    if vendor:
        print("    vendor:    " + ", ".join(f"0x{c:04x}" for c in vendor))


def _cleanup_and_return(cmd_sock, evt_sock, exit_code: int, verbose: bool) -> int:
    """Close the PTP session and TCP sockets. Best-effort; never raises."""
    try:
        operation(cmd_sock, OP_CLOSE_SESSION, txid=999, params=[], verbose=verbose)
    except Exception:
        pass
    try:
        cmd_sock.close()
    except Exception:
        pass
    if evt_sock:
        try:
            evt_sock.close()
        except Exception:
            pass
    return exit_code


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('host', nargs='?', default='192.168.1.1',
                    help='camera IP (default: 192.168.1.1)')
    ap.add_argument('--port', type=int, default=PTPIP_PORT,
                    help='PTP/IP port (default: 15740)')
    ap.add_argument('--name', default='localhost',
                    help="initiator name (default: 'localhost' — iCatch "
                         "firmware whitelists this; any other name returns "
                         "InitFail reason=3)")
    ap.add_argument('--timeout', type=float, default=5.0,
                    help='per-socket timeout in seconds (default: 5)')
    ap.add_argument('--no-event-channel', action='store_true',
                    help="skip the event-channel handshake (some cameras are "
                         "fussy about it; useful for triage)")
    ap.add_argument('--bind', default=None, metavar='SOURCE_IP',
                    help="bind the probe socket to this local IP — forces "
                         "routing via the interface that owns the IP. Needed "
                         "when two interfaces share the 192.168.1.0/24 subnet.")
    ap.add_argument('--verbose', '-v', action='store_true',
                    help='hexdump every packet sent and received')
    args = ap.parse_args()

    guid = uuid.uuid4().bytes
    print(f"Probing PTP/IP at {args.host}:{args.port}")
    print(f"  initiator name = {args.name!r}")
    print(f"  initiator GUID = {guid.hex()}")
    print()

    # Step 1: TCP to command channel
    t0 = time.monotonic()
    try:
        cmd_sock = connect_tcp(args.host, args.port, args.timeout,
                               bind_source=args.bind)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"FAIL: cannot open TCP {args.host}:{args.port} — {e}", file=sys.stderr)
        print("This camera is not speaking PTP/IP on this port.", file=sys.stderr)
        return 1
    print(f"[+] TCP command channel up ({(time.monotonic()-t0)*1000:.1f} ms)")

    # Step 2: InitCommand handshake
    try:
        conn_num = init_command(cmd_sock, args.name, guid, args.verbose)
    except Exception as e:
        print(f"FAIL: InitCommand handshake — {e}", file=sys.stderr)
        return 2
    print(f"[+] InitCommandAck (connection #{conn_num})")

    # Step 3: optional event channel
    evt_sock = None
    if not args.no_event_channel:
        try:
            evt_sock = connect_tcp(args.host, args.port, args.timeout,
                                   bind_source=args.bind)
            init_event(evt_sock, conn_num, args.verbose)
            print(f"[+] Event channel up")
        except Exception as e:
            print(f"WARN: event-channel setup failed ({e}); continuing on "
                  f"command channel only", file=sys.stderr)
            if evt_sock:
                evt_sock.close()
                evt_sock = None

    # Step 4: OpenSession. If a prior session is stuck open from a prior
    # probe that didn't clean up, the camera returns DeviceBusy (0x201E).
    # Close-then-open recovers cleanly.
    try:
        rcode, _params, _data = operation(cmd_sock, OP_OPEN_SESSION,
                                          txid=0, params=[1], verbose=args.verbose)
        if rcode == 0x201E:  # DeviceBusy — session already open
            print(f"  (got DeviceBusy — closing stale session and retrying)")
            operation(cmd_sock, OP_CLOSE_SESSION, txid=99, params=[],
                      verbose=args.verbose)
            rcode, _params, _data = operation(cmd_sock, OP_OPEN_SESSION,
                                              txid=0, params=[1],
                                              verbose=args.verbose)
        if rcode != RC_OK:
            print(f"FAIL: OpenSession returned 0x{rcode:04x} "
                  f"({RC_NAMES.get(rcode, '?')})", file=sys.stderr)
            return 3
        print(f"[+] OpenSession OK")
    except Exception as e:
        print(f"FAIL: OpenSession exception — {e}", file=sys.stderr)
        return 3

    # Step 5: GetDeviceInfo — the actual identification. Always run cleanup
    # afterwards (success or failure) so we don't leave a stuck session.
    try:
        rcode, _params, data = operation(cmd_sock, OP_GET_DEVICE_INFO,
                                         txid=1, params=[], verbose=args.verbose)
        if rcode != RC_OK:
            print(f"FAIL: GetDeviceInfo returned 0x{rcode:04x} "
                  f"({RC_NAMES.get(rcode, '?')})", file=sys.stderr)
            return _cleanup_and_return(cmd_sock, evt_sock, 3, args.verbose)
        if not data:
            print("FAIL: GetDeviceInfo returned no data", file=sys.stderr)
            return _cleanup_and_return(cmd_sock, evt_sock, 3, args.verbose)
        info = parse_device_info(data)
        print_device_info(info)
    except Exception as e:
        print(f"FAIL: GetDeviceInfo exception — {e}", file=sys.stderr)
        return _cleanup_and_return(cmd_sock, evt_sock, 3, args.verbose)

    _cleanup_and_return(cmd_sock, evt_sock, 0, args.verbose)

    print()
    print("=" * 70)
    print("RESULT: PTP/IP confirmed end-to-end.")
    print("Next:   feed this opcode list to docs/findings.md and start building")
    print("        the libgphoto2 client.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
