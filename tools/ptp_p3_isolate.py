#!/usr/bin/env python3
"""Isolate which Phase-3 ptype caused PTP service degradation.

After establishing a valid PTP Init, send ONE malformed op container
with a specific ptype, then close. Then a fresh-session health-check.

If a specific ptype breaks the service → handler-state bug.
If individual ptypes are fine but 13-in-a-row breaks → resource
exhaustion (cumulative).
"""
from __future__ import annotations
import os, socket, struct, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import Camera
from larkfly import types as t
from larkfly import protocol as p

HOST = '192.168.1.1'
BIND = '192.168.1.10'

# Same ptypes as Phase 3 v1
PTYPES = [0, 1, 2, 5, 8, 9, 10, 11, 12, 13, 14, 99, 0xFFFFFFFF]


def fresh_socket(timeout: float = 4.0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((BIND, 0))
    s.settimeout(timeout)
    s.connect((HOST, 15740))
    return s


def container(ptype: int, payload: bytes) -> bytes:
    return struct.pack('<II', 8 + len(payload), ptype) + payload


def health_check(label: str = '') -> tuple[bool, str]:
    try:
        c = Camera(HOST, bind=BIND, timeout=5)
        c.connect()
        info = c.device_info()
        c.close()
        return True, f"OK ({len(info['device_properties_supported'])} props)"
    except Exception as e:
        return False, f"DOWN ({type(e).__name__}: {str(e)[:60]})"


def send_one_post_init(ptype: int) -> str:
    """Connect → InitCmdReq → InitCmdAck → send malformed op container
    with given ptype → close. Return status string."""
    init_payload = p.encode_init_cmd_req(b'\x00'*16, 'localhost')
    op_body = struct.pack('<I', 1) + struct.pack('<H', 0x1001) + struct.pack('<I', 1)

    sock = fresh_socket()
    try:
        # Valid InitCmdReq
        sock.sendall(container(t.PT_INIT_CMD_REQ, init_payload))
        # Read InitCmdAck
        try:
            hdr = sock.recv(8)
            if len(hdr) < 8:
                return f'init-ack short ({len(hdr)}B)'
            length, ack_ptype = struct.unpack('<II', hdr)
            _ = sock.recv(length - 8)
            if ack_ptype != t.PT_INIT_CMD_ACK:
                return f'init failed (got ptype={ack_ptype})'
        except socket.timeout:
            return 'init-ack timeout'

        # Send the malformed op container
        sock.sendall(container(ptype, op_body))

        # Try to read response
        try:
            resp = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                resp += chunk
                if len(resp) > 65536: break
        except socket.timeout:
            return 'recv-timeout'
        if not resp:
            return 'closed-by-peer'
        if len(resp) >= 8:
            length, rt = struct.unpack_from('<II', resp, 0)
            return f'got {len(resp)}B (resp ptype={rt})'
        return f'short-resp ({len(resp)}B)'
    finally:
        try: sock.close()
        except Exception: pass


def main():
    ok, diag = health_check('baseline')
    print(f"[*] Baseline: {diag}")
    if not ok:
        print("Camera unhealthy at start; abort.")
        return 1

    # ─── PHASE A: each ptype individually, with health check between ───
    print("\n" + "="*72)
    print("PHASE A: one ptype at a time + fresh-session health check")
    print("="*72)
    culprit = None
    for ptype in PTYPES:
        name = t.PT_NAMES.get(ptype, f'pt={ptype}')
        print(f"\n  Testing ptype={ptype} ({name})")
        status = send_one_post_init(ptype)
        print(f"    sent malformed op-pkt → {status}")
        time.sleep(0.5)  # give the service a moment
        ok, diag = health_check(f'after ptype={ptype}')
        print(f"    health: {diag}")
        if not ok:
            culprit = (ptype, name)
            print(f"  ★★★ CULPRIT: ptype={ptype} ({name})")
            print(f"  Camera needs power-cycle now.")
            return 0

    print("\n  All single-ptype tests passed individually.")
    print(f"  Service tolerates one malformed packet per session.")

    # ─── PHASE B: cumulative — many of the safest ptype back-to-back ───
    print("\n" + "="*72)
    print("PHASE B: cumulative resource probe — 20 sessions w/ ptype=99 each")
    print("="*72)
    for i in range(20):
        status = send_one_post_init(99)
        if i % 5 == 4:
            ok, diag = health_check(f'after round {i+1}')
            print(f"  round {i+1:>2d}/{20}  status={status}  {diag}")
            if not ok:
                print(f"  ★★★ Cumulative failure after {i+1} rounds — resource exhaustion?")
                return 0
        else:
            print(f"  round {i+1:>2d}/{20}  status={status}")
        time.sleep(0.2)

    print("\n[*] Camera tolerates 20 fuzz sessions in a row.")
    print("    Phase-3 PTP service degradation was likely cumulative across")
    print("    different ptypes — needs investigation of state-machine paths.")


if __name__ == '__main__':
    sys.exit(main())
