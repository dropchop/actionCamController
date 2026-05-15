#!/usr/bin/env python3
"""WiFi-provisioning probe — pushes the camera from AP mode to STATION mode
so it joins a target network (your laptop's AP / router) instead of running
its own.

Status: PARTIAL. We know from APK static analysis that:

  • The SDK exposes ICatchCameraAssistAbstract::simpleConfig(s1, s2, s3, s4,
    s5, int) — five strings plus a mode int, almost certainly
    (SSID, password, ?, ?, ?, encryption_or_mode).
  • The call goes through the established PTP/IP session — `simpleConfig` is
    a member of the post-OpenSession ICatchCameraAssist API, not a
    standalone UDP scanner.
  • libcontrol.so logs include `simpleConfigSend jessid: %s`, `... key: %s`,
    `Fail to sendto ssid or passwd length`.
  • CameraNetworkMode.STATION (= 0) is a real runtime state listed in the
    discovery results — the camera DOES support being a WiFi client.

What we DON'T know without a Wireshark capture of iSmart DV2 doing this
flow once:

  • The exact vendor PTP operation code (16-bit, almost certainly in the
    0xE000-0xEFFF range based on PIMA 15740 vendor allocations and the
    iCatch ICH_CAM_CAP_MOVIE_REC = 0xE604 precedent).
  • The marshal layout of the five strings inside the PTP data phase
    (likely each is a PTP string — u8 len + UTF-16LE chars — concatenated,
    but the order and which fields go where need confirming).

So this script does two useful things even without those answers:

  1. `--list-vendor-ops`     Enumerate the camera's PTP vendor opcodes
                             (0x9000+ in the operations-supported list from
                             GetDeviceInfo). The simpleConfig opcode is in
                             this list. Cross-reference with the iCatch
                             strings in libcontrol.so (apk-analysis/native/)
                             to narrow it down.

  2. `--send-vendor OPCODE`  Send an arbitrary vendor PTP operation with a
                             provided data-phase payload. Once you've
                             confirmed the opcode and layout from a pcap,
                             plug them in here to actually provision.

This is intentionally a sandbox, not a one-click solution. Don't bolt it
into anything automated until the opcode is confirmed against a real
camera.

Run:
  python3 wifi_provision.py 192.168.1.1 --list-vendor-ops
  python3 wifi_provision.py 192.168.1.1 --send-vendor 0xE001 \\
      --string "MyHomeAP" --string "supersecret" --param 4 --dry-run
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
import uuid

# Reuse the framing primitives from the PTP/IP probe.
from ptpip_probe import (
    PT_INIT_CMD_REQ, PT_INIT_CMD_ACK, PT_INIT_FAIL, PT_OP_REQ, PT_OP_RESP,
    PT_START_DATA, PT_DATA, PT_END_DATA, TYPE_NAMES,
    OP_GET_DEVICE_INFO, OP_OPEN_SESSION, OP_CLOSE_SESSION, RC_OK, RC_NAMES,
    PTPIP_PORT, PROTOCOL_VERSION,
    send_packet, recv_packet, recv_exact, connect_tcp,
    encode_ptp_string, decode_ptp_string,
    init_command, init_event, operation, parse_device_info,
)


# ---- candidate iCatch simpleConfig vendor opcodes -----------------------
# These are EDUCATED GUESSES based on the ICH_CAM_CAP_* property codes we
# already extracted from the Java SDK. The 0xE000-0xEFFF range is the PTP
# vendor *operation* range (vs 0xD000-0xDFFF for vendor *properties*). The
# iCatch property `ICH_CAM_CAP_MOVIE_REC = 0xE604` told us their vendor
# operations cluster in 0xE600-0xE6FF. simpleConfig probably lives nearby.
# Confirm against the actual operations-supported list via --list-vendor-ops.
CANDIDATE_SIMPLECONFIG_OPCODES = [0xE600, 0xE610, 0xE620, 0xE630, 0xE640,
                                  0xE650, 0xE660, 0xE700, 0xE800]


def open_session(host: str, port: int, name: str, timeout: float,
                 verbose: bool) -> tuple[socket.socket, socket.socket | None]:
    """Open the PTP/IP command + event channels and call OpenSession."""
    cmd_sock = connect_tcp(host, port, timeout)
    guid = uuid.uuid4().bytes
    conn_num = init_command(cmd_sock, name, guid, verbose)

    evt_sock = None
    try:
        evt_sock = connect_tcp(host, port, timeout)
        init_event(evt_sock, conn_num, verbose)
    except Exception as e:
        print(f"WARN: event channel skipped ({e})", file=sys.stderr)
        if evt_sock:
            evt_sock.close()
            evt_sock = None

    rcode, _, _ = operation(cmd_sock, OP_OPEN_SESSION, txid=0,
                            params=[1], verbose=verbose)
    if rcode != RC_OK:
        raise RuntimeError(f"OpenSession failed: 0x{rcode:04x}")
    return cmd_sock, evt_sock


def cmd_list_vendor_ops(host: str, port: int, name: str, timeout: float,
                        verbose: bool) -> int:
    cmd_sock, evt_sock = open_session(host, port, name, timeout, verbose)
    try:
        rcode, _, data = operation(cmd_sock, OP_GET_DEVICE_INFO,
                                   txid=1, params=[], verbose=verbose)
        if rcode != RC_OK or not data:
            print(f"FAIL: GetDeviceInfo returned 0x{rcode:04x}", file=sys.stderr)
            return 3
        info = parse_device_info(data)

        ops = info['operations_supported']
        vendor_ops = sorted(c for c in ops if c >= 0x9000)
        print()
        print(f"Camera: {info['manufacturer']!r} / {info['model']!r} "
              f"/ firmware {info['device_version']!r}")
        print(f"Vendor extension ID = 0x{info['vendor_extension_id']:08x}")
        print(f"Vendor extension    = {info['vendor_extension_desc']!r}")
        print()
        print(f"Vendor PTP operations ({len(vendor_ops)}):")
        for code in vendor_ops:
            marker = "  <-- CANDIDATE" if code in CANDIDATE_SIMPLECONFIG_OPCODES else ""
            print(f"  0x{code:04x}{marker}")
        if not vendor_ops:
            print("  (none — surprising, simpleConfig may use a different "
                  "transport than PTP/IP)")
        print()
        print("To narrow down simpleConfig: cross-reference these opcodes")
        print("with the native lib strings:")
        print("  grep -E '0x[Ee][0-9A-Fa-f]{3}' apk-analysis/native/libcontrol.strings")
        print("  grep -i simpleconfig apk-analysis/native/libcontrol.strings")
        print()
        print("Or capture iSmart DV2 doing 'Connect to WiFi' in Wireshark and")
        print("watch the 16-bit opcode in the PTP/IP Operation Request packet.")
        return 0
    finally:
        try:
            operation(cmd_sock, OP_CLOSE_SESSION, txid=99, params=[],
                      verbose=verbose)
        except Exception:
            pass
        cmd_sock.close()
        if evt_sock:
            evt_sock.close()


def build_simpleconfig_payload(strings: list[str]) -> bytes:
    """Concatenate PTP-string-encoded values for the data phase.

    GUESS: the layout matches the Java signature simpleConfig(s1..s5, int)
    where the strings are positional. Marshaling format inside the PTP data
    phase is the unknown — could be:
      A) five PTP strings concatenated
      B) a single big-endian length-prefixed blob with internal delimiters
      C) JSON
    This function does (A) because it's the most common iCatch pattern.
    Adjust once a pcap shows the actual layout."""
    return b''.join(encode_ptp_string(s) for s in strings)


def cmd_send_vendor(host: str, port: int, name: str, timeout: float,
                    opcode: int, strings: list[str], params: list[int],
                    dry_run: bool, verbose: bool) -> int:
    payload = build_simpleconfig_payload(strings)
    print(f"Operation: 0x{opcode:04x}")
    print(f"Params:    {params}")
    print(f"Data phase payload ({len(payload)} bytes):")
    for i in range(0, len(payload), 16):
        chunk = payload[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  {i:04x}  {hex_part:<48}  {ascii_part}")
    if dry_run:
        print()
        print("DRY RUN: not connecting to camera.")
        return 0

    cmd_sock, evt_sock = open_session(host, port, name, timeout, verbose)
    try:
        # Send Operation Request with data_phase_info = 2 (data going OUT to camera)
        op_payload = struct.pack('<IHI', 2, opcode, 2)  # txid=2
        for p in params:
            op_payload += struct.pack('<I', p)
        send_packet(cmd_sock, PT_OP_REQ, op_payload, verbose)

        # Send data phase: StartData + EndData
        send_packet(cmd_sock, PT_START_DATA,
                    struct.pack('<IQ', 2, len(payload)), verbose)
        send_packet(cmd_sock, PT_END_DATA,
                    struct.pack('<I', 2) + payload, verbose)

        # Read response
        rcode = 0
        while True:
            ptype, body = recv_packet(cmd_sock, verbose)
            if ptype == PT_OP_RESP:
                rcode = struct.unpack_from('<H', body, 0)[0]
                break
        print()
        print(f"Response code: 0x{rcode:04x} ({RC_NAMES.get(rcode, 'unknown')})")
        if rcode == RC_OK:
            print("SUCCESS — the camera accepted the operation. Watch its")
            print("LEDs / power-cycle behavior to see if it joined STATION mode.")
        elif rcode == 0x2005:
            print("Operation not supported by camera — wrong opcode.")
        elif rcode == 0x2006:
            print("Parameter not supported — opcode may be right but params/data")
            print("layout is wrong. Try a different number of strings or params.")
        return 0 if rcode == RC_OK else 3
    finally:
        try:
            operation(cmd_sock, OP_CLOSE_SESSION, txid=98, params=[],
                      verbose=verbose)
        except Exception:
            pass
        cmd_sock.close()
        if evt_sock:
            evt_sock.close()


def parse_hex_int(s: str) -> int:
    return int(s, 16) if s.lower().startswith('0x') else int(s)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('host', nargs='?', default='192.168.1.1')
    ap.add_argument('--port', type=int, default=PTPIP_PORT)
    ap.add_argument('--name', default='Linux WiFi-Provision Probe')
    ap.add_argument('--timeout', type=float, default=5.0)
    ap.add_argument('--verbose', '-v', action='store_true')

    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--list-vendor-ops', action='store_true',
                      help='enumerate vendor PTP opcodes the camera advertises')
    mode.add_argument('--send-vendor', type=parse_hex_int, metavar='OPCODE',
                      help='send a vendor PTP operation (e.g. 0xE601)')

    ap.add_argument('--string', action='append', default=[], dest='strings',
                    help='string argument to include in data phase '
                         '(repeat in order: --string SSID --string PASSWORD ...)')
    ap.add_argument('--param', action='append', default=[], type=parse_hex_int,
                    dest='params',
                    help='u32 PTP operation parameter (repeat for multiple)')
    ap.add_argument('--dry-run', action='store_true',
                    help='print what would be sent, do not connect')

    args = ap.parse_args()

    if args.list_vendor_ops:
        return cmd_list_vendor_ops(args.host, args.port, args.name,
                                    args.timeout, args.verbose)
    elif args.send_vendor is not None:
        return cmd_send_vendor(args.host, args.port, args.name, args.timeout,
                               args.send_vendor, args.strings, args.params,
                               args.dry_run, args.verbose)
    return 1


if __name__ == '__main__':
    sys.exit(main())
