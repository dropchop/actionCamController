#!/usr/bin/env python3
"""Factory-mode hunting probes over PTP/IP.

Two experiments in one tool:

  --bool-sweep: For each of the 4 boolean RW properties identified in
                the 0xD7xx sweep (0xD727, 0xD75F, 0xD7FC, 0xD7FF),
                toggle to the opposite value, wait, watch for any
                side-effect (new TCP port, new FTP file, PTP event,
                or a hidden property unlocking). Then restore.

  --magic-session: Try OpenSession with magic session IDs that often
                   unlock vendor-debug surfaces. After each, query
                   property 0xD617 (hidden) to see if it became
                   readable, plus a sample of vendor ops.

Each test is independent and reversible.

Usage:
    python3 tools/ptp_factory_probe.py --bool-sweep
    python3 tools/ptp_factory_probe.py --magic-session
    python3 tools/ptp_factory_probe.py --all
"""
from __future__ import annotations

import argparse
import contextlib
import socket
import struct
import sys
import time

sys.path.insert(0, '.')
from larkfly import Camera
from larkfly.exceptions import PtpError, TransportError

BOOLEAN_RW_PROPS = [0xD727, 0xD75F, 0xD7FC, 0xD7FF]
HIDDEN_PROPS = [0xD617]
VENDOR_OPS_SAMPLE = [0x9601, 0x9614, 0x9805, 0x9602, 0x9801, 0x9812]

MAGIC_SESSIONS = [
    0x00000001,  # baseline (what larkfly normally uses)
    0xDEADBEEF, 0xCAFEBABE, 0xFEEDFACE, 0xC0FFEE00, 0x12345678,
    0xFFFFFFFF, 0x00000000,
    0x01010101, 0x02020202,
    0xA5A5A5A5, 0x5A5A5A5A,
    0x73706361,  # 'spca' little-endian
    0x69636174,  # 'icat'
    0x53554E50,  # 'SUNP'
    0xB0073370,  # 'BOOT' rough encoding
]


def fast_tcp(host: str, port: int, timeout: float = 0.5) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        with contextlib.suppress(OSError):
            s.close()


def tcp_snapshot(host: str) -> dict[int, bool]:
    """Quick check on key ports: which are open."""
    return {p: fast_tcp(host, p) for p in [21, 22, 23, 80, 81, 554, 7878,
                                            8000, 8080, 8554, 8787, 9999,
                                            15740, 23000, 50000]}


def list_ftp(host: str) -> list[str]:
    import ftplib
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, 21, timeout=3)
        ftp.login('wificam', 'wificam')
        lines = []
        ftp.retrlines('LIST /', lines.append)
        ftp.quit()
        return lines
    except Exception:
        return []


def probe_hidden(cam: Camera) -> dict[int, str]:
    """For each hidden property, try GetDevicePropDesc — returns rc/data summary."""
    out = {}
    for code in HIDDEN_PROPS:
        try:
            rc, _, data = cam._raw_op(0x1014, [code])
            out[code] = f'rc=0x{rc:04x} data_len={len(data)}'
        except Exception as e:
            out[code] = f'{type(e).__name__}: {e}'
    return out


def probe_vendor_quick(cam: Camera) -> dict[int, str]:
    """Briefly check vendor ops that we expect to be safe with bare params."""
    out = {}
    try:
        # 0x9601: known polling op
        rc, rp, _ = cam._raw_op(0x9601, [0xD001, 0xFFFFFFFF, 0])
        out[0x9601] = f'rc=0x{rc:04x} rp[0..2]={[hex(x) for x in rp[:3]]}'
    except Exception as e:
        out[0x9601] = f'{type(e).__name__}: {e}'
    return out


def bool_sweep(host: str, bind: str | None) -> dict:
    """Toggle each boolean RW prop and watch for changes."""
    print("=== BOOLEAN RW WRITE-SWEEP ===")
    results = {}

    with Camera(host, bind=bind) as cam:
        print("\n[baseline] reading current values:")
        baseline = {}
        for code in BOOLEAN_RW_PROPS:
            try:
                rc, _, data = cam._raw_op(0x1015, [code])  # GetDevicePropValue
                if rc == 0x2001 and len(data) >= 4:
                    baseline[code] = int.from_bytes(data[:4], 'little')
                    print(f"  0x{code:04x} = {baseline[code]}")
                else:
                    print(f"  0x{code:04x}: rc=0x{rc:04x}")
            except Exception as e:
                print(f"  0x{code:04x}: {e}")
        print(f"\n[snapshot] TCP ports + FTP listing pre-write:")
        tcp_before = tcp_snapshot(host)
        ftp_before = list_ftp(host)
        print(f"  open: {[p for p,v in tcp_before.items() if v]}")
        print(f"  ftp: {len(ftp_before)} entries")
        results['baseline'] = {'values': baseline, 'tcp': tcp_before, 'ftp': ftp_before}

        for code in BOOLEAN_RW_PROPS:
            if code not in baseline:
                continue
            new_val = 0 if baseline[code] == 1 else 1
            print(f"\n[write] 0x{code:04x}: {baseline[code]} -> {new_val}")
            try:
                # SetDevicePropValue: opcode 0x1016 with prop code, data = u32 LE
                tx = new_val.to_bytes(4, 'little')
                rc, _, _ = cam._raw_op(0x1016, [code], tx)
                print(f"  SET rc=0x{rc:04x}")
            except Exception as e:
                print(f"  SET error: {e}")
                continue
            time.sleep(0.5)
            # Read back
            try:
                rc, _, data = cam._raw_op(0x1015, [code])
                rb = int.from_bytes(data[:4], 'little') if data else None
                print(f"  GET back: {rb} (intended {new_val})")
            except Exception as e:
                print(f"  GET error: {e}")
            # Check for side effects
            tcp_after = tcp_snapshot(host)
            new_ports = [p for p in tcp_after if tcp_after[p] and not tcp_before.get(p)]
            ftp_after = list_ftp(host)
            new_ftp = set(ftp_after) - set(ftp_before)
            hidden_status = probe_hidden(cam)
            results[f'0x{code:04x}'] = {
                'wrote': new_val, 'readback': rb,
                'new_ports': new_ports,
                'new_ftp': list(new_ftp),
                'hidden': hidden_status,
            }
            if new_ports:
                print(f"  ** NEW PORTS OPENED: {new_ports} **")
            if new_ftp:
                print(f"  ** NEW FTP FILES: {new_ftp} **")
            for code2, status in hidden_status.items():
                if '0x200a' not in status:
                    print(f"  ** HIDDEN PROP 0x{code2:04x} CHANGED: {status} **")
            # Restore
            print(f"  [restore] write back {baseline[code]}")
            try:
                cam._raw_op(0x1016, [code], baseline[code].to_bytes(4, 'little'))
            except Exception as e:
                print(f"  RESTORE error: {e}")
            time.sleep(0.3)
    return results


def magic_session(host: str, bind: str | None) -> dict:
    """Try OpenSession with magic IDs; check for property/op surface changes."""
    print("=== MAGIC OpenSession SWEEP ===")
    results = {}
    # We can't use the larkfly Camera context manager (it opens a session
    # itself). Manage the connection at a lower level.
    from larkfly.camera import Camera as _Cam
    # Easiest: instantiate Camera with a specific session_id
    for sid in MAGIC_SESSIONS:
        print(f"\n[session 0x{sid:08x}]")
        cam = None
        try:
            cam = _Cam(host, bind=bind, session_id=sid)
            cam.connect()
            # Connect succeeded — try the hidden-prop probe
            hidden = probe_hidden(cam)
            vendor = probe_vendor_quick(cam)
            # Also get the supported-ops list — maybe it changed
            try:
                info = cam.device_info()
                op_count = len(info.get('operations_supported', []))
                prop_count = len(info.get('properties_supported', []))
            except Exception as e:
                op_count = prop_count = -1
            res = {
                'connected': True,
                'ops_count': op_count,
                'props_count': prop_count,
                'hidden': hidden,
                'vendor': vendor,
            }
            print(f"  connected, ops={op_count} props={prop_count}")
            print(f"  hidden: {hidden}")
            print(f"  vendor: {vendor}")
            results[hex(sid)] = res
        except Exception as e:
            results[hex(sid)] = {'connected': False, 'error': str(e)}
            print(f"  connect failed: {type(e).__name__}: {e}")
        finally:
            if cam is not None:
                try: cam.close()
                except Exception: pass
            time.sleep(0.5)  # let camera clean up between sessions
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='192.168.1.1')
    ap.add_argument('--bind', default='192.168.1.10')
    ap.add_argument('--bool-sweep', action='store_true')
    ap.add_argument('--magic-session', action='store_true')
    ap.add_argument('--all', action='store_true')
    args = ap.parse_args()

    if args.all:
        args.bool_sweep = args.magic_session = True
    if not (args.bool_sweep or args.magic_session):
        ap.print_help()
        return 1

    if args.bool_sweep:
        bool_sweep(args.host, args.bind)
    if args.magic_session:
        magic_session(args.host, args.bind)
    return 0


if __name__ == '__main__':
    sys.exit(main())
