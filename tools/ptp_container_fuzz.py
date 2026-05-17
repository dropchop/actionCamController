#!/usr/bin/env python3
"""PTP-IP container / packet-type fuzz — hits the wire parser BEFORE
the handler dispatch, the deepest pre-auth code on TCP 15740.

Container format: u32 length (BE? actually LE per iCatch impl) + u32
packet_type + payload. Spec-defined packet types: 1..14. Anything
else is undefined.

Per `larkfly/types.py`:
  PT_INIT_CMD_REQ=1, PT_INIT_CMD_ACK=2, PT_INIT_EVT_REQ=3,
  PT_INIT_EVT_ACK=4, PT_INIT_FAIL=5, PT_OP_REQ=6, PT_OP_RESP=7,
  PT_EVENT=8, PT_START_DATA=9, PT_DATA=10, PT_CANCEL=11 (or 12 per
  iCatch), PT_END_DATA=12 (= 11 per iCatch — that's quirk #3),
  PT_PROBE_REQ=13, PT_PROBE_RESP=14.

Four phases, each with health-check between:

  PHASE 1: PRE-INIT garbage — open fresh socket, send malformed
    container, see if camera RSTs / hangs / responds. Hits the very
    first stage of the wire parser.
  PHASE 2: PRE-INIT with wrong ptype but valid InitCmdReq payload —
    might cause confused-handler dispatch.
  PHASE 3: After valid InitCmdReq, send op containers with wrong
    ptype (e.g. ptype=PT_INIT_CMD_REQ post-init).
  PHASE 4: Weird container LENGTH values — 0, 4, 7, 0xFFFFFFFF.
    Camera may try to alloc 4GB or skip header parsing.
"""
from __future__ import annotations
import os, socket, struct, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import Camera
from larkfly import types as t
from larkfly import protocol as p
from larkfly.exceptions import PtpError, TransportError

HOST = '192.168.1.1'
BIND = '192.168.1.10'


def health_check(label: str = '') -> bool:
    try:
        c = Camera(HOST, bind=BIND, timeout=5)
        c.connect()
        info = c.device_info()
        c.close()
        print(f"  [HEALTH {label}] OK ({len(info['device_properties_supported'])} props)")
        return True
    except Exception as e:
        print(f"  [HEALTH {label}] !!! DOWN: {type(e).__name__}: {str(e)[:80]}")
        return False


def fresh_socket(timeout: float = 4.0) -> socket.socket:
    """Open a fresh TCP connection to the camera."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((BIND, 0))
    s.settimeout(timeout)
    s.connect((HOST, 15740))
    return s


def send_raw(sock: socket.socket, data: bytes) -> tuple[bytes, str]:
    """Send raw bytes; return (response, error_or_status). Always closes sock."""
    try:
        sock.sendall(data)
    except Exception as e:
        sock.close()
        return b'', f'send-err:{type(e).__name__}'
    # Try to read response
    try:
        sock.settimeout(3.0)
        resp = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            resp += chunk
            if len(resp) > 65536: break
    except socket.timeout:
        sock.close()
        return resp, 'recv-timeout'
    except Exception as e:
        sock.close()
        return resp, f'recv-err:{type(e).__name__}'
    sock.close()
    return resp, 'closed-by-peer' if not resp else 'ok'


def container(ptype: int, payload: bytes, length_override: int | None = None) -> bytes:
    """Build a PTP-IP container with optional length override."""
    length = length_override if length_override is not None else (8 + len(payload))
    return struct.pack('<II', length, ptype) + payload


def parse_response(resp: bytes) -> str:
    """Best-effort summary of what the camera replied with."""
    if not resp:
        return '<empty>'
    if len(resp) < 8:
        return f'<short:{len(resp)}B: {resp.hex()}>'
    length, ptype = struct.unpack_from('<II', resp, 0)
    name = t.PT_NAMES.get(ptype, f'pt={ptype}')
    return f'len={length} ptype={ptype}({name}) +{len(resp)-8}B'


# ─── PHASE 1: PRE-INIT garbage ─────────────────────────────────────

def phase_1():
    print("\n" + "="*72)
    print("PHASE 1: PRE-INIT garbage on fresh sockets")
    print("="*72)
    TESTS = [
        ('len=0 ptype=0',             container(0, b'', length_override=0)),
        ('len=4 ptype=0',             container(0, b'', length_override=4)),
        ('len=7 ptype=0',             container(0, b'', length_override=7)),
        ('len=8 ptype=0 (header only, undefined ptype)', container(0, b'')),
        ('len=8 ptype=99',            container(99, b'')),
        ('len=8 ptype=255',           container(255, b'')),
        ('len=8 ptype=0xFFFFFFFF',    container(0xFFFFFFFF, b'')),
        ('len=8 ptype=13 (PROBE_REQ)', container(13, b'')),
        ('len=0xFFFFFFFF ptype=1',    container(1, b'', length_override=0xFFFFFFFF)),
        ('len=0x10000000 ptype=1',    container(1, b'', length_override=0x10000000)),
        ('len=8 ptype=1 (InitCmdReq with no payload)', container(1, b'')),
        ('len=24 ptype=1 (InitCmdReq but says len=24, only 16B follow)',
            struct.pack('<II', 24, 1) + b'\x00'*8),
        ('len=4 ptype=trash, only sends header',
            struct.pack('<II', 4, 0x12345678)),
        ('just one byte 0xff',          b'\xff'),
        ('TCP-RST-style (FIN then garbage)', b''),
    ]
    for label, payload in TESTS:
        try:
            sock = fresh_socket()
            resp, status = send_raw(sock, payload)
            print(f"  {label:55s} status={status} resp={parse_response(resp)}")
        except Exception as e:
            print(f"  {label:55s} CONNECT-FAIL: {type(e).__name__}: {e}")


# ─── PHASE 2: PRE-INIT with wrong ptype but valid payload ──────────

def phase_2():
    print("\n" + "="*72)
    print("PHASE 2: Wrong ptype + InitCmdReq-shaped payload")
    print("="*72)
    init_payload = p.encode_init_cmd_req(b'\x00'*16, 'localhost')
    for ptype in [0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 99, 0xFFFFFFFF]:
        try:
            sock = fresh_socket()
            pkt = container(ptype, init_payload)
            resp, status = send_raw(sock, pkt)
            name = t.PT_NAMES.get(ptype, f'pt={ptype}')
            print(f"  ptype={ptype:>5} ({name:15s}) status={status:<18s} resp={parse_response(resp)}")
        except Exception as e:
            print(f"  ptype={ptype}: {type(e).__name__}: {e}")


# ─── PHASE 3: After valid init, send weird op containers ──────────

def phase_3():
    print("\n" + "="*72)
    print("PHASE 3: After valid Init, send op containers with weird ptype")
    print("="*72)
    for ptype in [0, 1, 2, 5, 8, 9, 10, 11, 12, 13, 14, 99, 0xFFFFFFFF]:
        try:
            sock = fresh_socket()
            # Valid Init handshake
            init_payload = p.encode_init_cmd_req(b'\x00'*16, 'localhost')
            sock.sendall(container(t.PT_INIT_CMD_REQ, init_payload))
            # Read InitCmdAck
            try:
                resp_hdr = sock.recv(8)
                length, _ = struct.unpack('<II', resp_hdr)
                _ = sock.recv(length - 8)
            except Exception as e:
                print(f"  ptype={ptype}: init-recv-failed: {e}")
                sock.close()
                continue
            # Now send op container with wrong ptype
            # Valid OpRequest body for GetDeviceInfo (op=0x1001, txid=1, no params, data_phase=1)
            op_body = struct.pack('<I', 1) + struct.pack('<H', 0x1001) + struct.pack('<I', 1)
            pkt = container(ptype, op_body)
            resp, status = send_raw(sock, pkt)
            name = t.PT_NAMES.get(ptype, f'pt={ptype}')
            print(f"  post-init op-pkt ptype={ptype:>5} ({name:15s}) status={status:<18s} resp={parse_response(resp)}")
        except Exception as e:
            print(f"  ptype={ptype}: {type(e).__name__}: {e}")


# ─── PHASE 4: Weird container LENGTH values ──────────

def phase_4():
    print("\n" + "="*72)
    print("PHASE 4: Weird container LENGTH values")
    print("="*72)
    init_payload = p.encode_init_cmd_req(b'\x00'*16, 'localhost')
    op_body = struct.pack('<I', 1) + struct.pack('<H', 0x1001) + struct.pack('<I', 1)

    LENGTH_TESTS = [
        ('len=0 ptype=1 + 32B init payload',
            struct.pack('<II', 0, 1) + init_payload),
        ('len=4 ptype=1 + 32B init payload',
            struct.pack('<II', 4, 1) + init_payload),
        ('len=0xFFFFFFFE ptype=1 + 32B payload',
            struct.pack('<II', 0xFFFFFFFE, 1) + init_payload),
        ('len=actual+1000 (camera waits for bytes that never come)',
            struct.pack('<II', 8 + len(init_payload) + 1000, 1) + init_payload),
        ('len=actual-1 (truncated frame)',
            struct.pack('<II', 8 + len(init_payload) - 1, 1) + init_payload),
        ('two containers concat (1 InitCmdReq + 1 garbage)',
            container(1, init_payload) + container(0xFFFFFFFF, b'\x00'*4)),
        ('valid InitCmdReq but length lies (says 100, payload 50)',
            struct.pack('<II', 100, 1) + init_payload),
    ]
    for label, pkt in LENGTH_TESTS:
        try:
            sock = fresh_socket()
            resp, status = send_raw(sock, pkt)
            print(f"  {label:65s} status={status:<18s} resp={parse_response(resp)}")
        except Exception as e:
            print(f"  {label:65s} {type(e).__name__}: {e}")


def main():
    if not health_check('baseline'):
        print("Baseline unhealthy, aborting.")
        return 1

    phase_1()
    if not health_check('after phase 1'):
        print("[!] STOPPED — phase 1 broke the camera.")
        return 0

    phase_2()
    if not health_check('after phase 2'):
        print("[!] STOPPED — phase 2 broke the camera.")
        return 0

    phase_3()
    if not health_check('after phase 3'):
        print("[!] STOPPED — phase 3 broke the camera.")
        return 0

    phase_4()
    if not health_check('after phase 4'):
        print("[!] STOPPED — phase 4 broke the camera.")
        return 0

    print("\n[*] All container-fuzz phases completed; PTP service survived.")


if __name__ == '__main__':
    sys.exit(main())
