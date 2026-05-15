#!/usr/bin/env python3
"""Walk a decrypted PTP/IP pcap and reassemble every transaction.

For each PTP operation, captures:
  - direction (phone→cam or cam→phone)
  - opcode + parameters
  - data phase (if any) — full bytes
  - response code + response parameters
  - approximate timestamp

Outputs JSON keyed by transaction ID, and a summary table grouped by opcode.

Useful for figuring out what each vendor opcode does without having to
guess-and-poke the live camera.

Usage:
  python3 mine_pcap.py /tmp/larkfly-capture-decrypted.pcap \\
      [-o probes/data/transactions.json]
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from collections import Counter, defaultdict


PCAP_GLOBAL_HDR = 24
PCAP_REC_HDR = 16
LINKTYPE_ETHERNET = 1


def read_pcap(path):
    """Yield (ts_us, eth_bytes)."""
    with open(path, 'rb') as f:
        gh = f.read(PCAP_GLOBAL_HDR)
        if len(gh) < PCAP_GLOBAL_HDR: return
        magic, _vmaj, _vmin, _tz, _sigfigs, _snaplen, lt = struct.unpack('<IHHIIII', gh)
        if magic != 0xa1b2c3d4:
            raise ValueError("not a libpcap file (or wrong endianness)")
        while True:
            rh = f.read(PCAP_REC_HDR)
            if len(rh) < PCAP_REC_HDR: return
            ts_sec, ts_us, incl, orig = struct.unpack('<IIII', rh)
            data = f.read(incl)
            yield (ts_sec * 1_000_000 + ts_us, data)


def parse_eth_ip_tcp(eth: bytes):
    """Return ((sip, sp, dip, dp), tcp_payload) or None."""
    if len(eth) < 14: return None
    if eth[12:14] != b'\x08\x00': return None
    ip = eth[14:]
    if len(ip) < 20: return None
    ver_ihl = ip[0]
    if (ver_ihl >> 4) != 4: return None
    ihl = (ver_ihl & 0x0f) * 4
    proto = ip[9]
    if proto != 6: return None
    sip = '.'.join(str(b) for b in ip[12:16])
    dip = '.'.join(str(b) for b in ip[16:20])
    tcp = ip[ihl:]
    if len(tcp) < 20: return None
    sp = struct.unpack('>H', tcp[0:2])[0]
    dp = struct.unpack('>H', tcp[2:4])[0]
    seq = struct.unpack('>I', tcp[4:8])[0]
    doff = (tcp[12] >> 4) * 4
    payload = tcp[doff:]
    return (sip, sp, dip, dp, seq), payload


def reassemble_flows(pcap_path, port=15740):
    """Reassemble per-direction streams of TCP payload on the given port.
    Returns dict {(src_ip, src_port, dst_ip, dst_port): {ts: int, data: bytes}}.
    Direction keys are 4-tuples; the data is in TCP-seq order.
    Also returns a list of (ts, key, payload) of each segment in order."""
    flows = defaultdict(list)  # key → list of (seq, ts, payload)
    for ts, eth in read_pcap(pcap_path):
        r = parse_eth_ip_tcp(eth)
        if not r: continue
        (sip, sp, dip, dp, seq), pl = r
        if dp != port and sp != port: continue
        if not pl: continue
        key = (sip, sp, dip, dp)
        flows[key].append((seq, ts, pl))

    streams = {}
    for key, segs in flows.items():
        segs.sort()  # by seq
        # Concatenate by seq, dedup retransmissions
        buf = b''
        last_seq = None
        for seq, ts, pl in segs:
            if last_seq is None or seq >= last_seq:
                buf += pl
                last_seq = seq + len(pl)
        streams[key] = buf
    return streams


def split_ptpip(stream: bytes):
    """Yield (ptype, body, packet_bytes) for each PTP-IP packet in the stream."""
    pos = 0
    while pos + 8 <= len(stream):
        length = struct.unpack_from('<I', stream, pos)[0]
        ptype = struct.unpack_from('<I', stream, pos + 4)[0]
        if length < 8 or length > 5_000_000 or pos + length > len(stream):
            return  # corrupt or truncated
        pkt = stream[pos:pos + length]
        body = pkt[8:]
        yield (ptype, body, pkt)
        pos += length


def parse_op_req(body: bytes):
    if len(body) < 10:
        return None
    dphase = struct.unpack_from('<I', body, 0)[0]
    opcode = struct.unpack_from('<H', body, 4)[0]
    txid = struct.unpack_from('<I', body, 6)[0]
    params = []
    for i in range(10, len(body), 4):
        if i + 4 > len(body): break
        params.append(struct.unpack_from('<I', body, i)[0])
    return {'dphase': dphase, 'opcode': opcode, 'txid': txid, 'params': params}


def parse_op_resp(body: bytes):
    if len(body) < 6:
        return None
    rc = struct.unpack_from('<H', body, 0)[0]
    txid = struct.unpack_from('<I', body, 2)[0]
    params = []
    # iCatch pads response bodies to ~26 bytes with zeros; collect non-trailing
    # params, but the protocol allows up to 5×u32.
    for i in range(6, min(len(body), 26), 4):
        if i + 4 > len(body): break
        params.append(struct.unpack_from('<I', body, i)[0])
    return {'rc': rc, 'txid': txid, 'params': params}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('pcap', nargs='?', default='/tmp/larkfly-capture-decrypted.pcap')
    ap.add_argument('-o', '--output', default='probes/data/transactions.json')
    args = ap.parse_args()

    if not os.path.exists(args.pcap):
        print(f"ERROR: pcap not found: {args.pcap}", file=sys.stderr)
        return 1

    streams = reassemble_flows(args.pcap)
    if not streams:
        print("No PTP/IP TCP flows found in pcap")
        return 1

    # Split each stream into PTP-IP packets, then key them by direction
    # (phone→cam = OpReq / Data outbound; cam→phone = OpResp / Data inbound).
    phone_to_cam = []  # list of (ptype, body)
    cam_to_phone = []
    for key, data in streams.items():
        sip, sp, dip, dp = key
        if dp == 15740:
            target = phone_to_cam
        else:
            target = cam_to_phone
        for pt in split_ptpip(data):
            target.append(pt)

    # Build transactions by walking phone→cam and matching against cam→phone
    # by txid. A transaction is: OpReq (phone→cam) → optional StartData →
    # Data/EndData (either dir, depending on dphase) → OpResp (cam→phone).
    txs = {}  # txid -> dict
    for ptype, body, _ in phone_to_cam:
        if ptype == 6:  # OpReq
            op = parse_op_req(body)
            if op is None: continue
            txs[op['txid']] = {
                'txid': op['txid'],
                'opcode': op['opcode'],
                'opcode_hex': f"0x{op['opcode']:04x}",
                'dphase': op['dphase'],
                'params': [f"0x{p:08x}" for p in op['params']],
                'params_dec': op['params'],
                'data_out_bytes': 0,
                'data_in_bytes': 0,
                'data_in_hex': '',
                'rc': None,
                'response_params': [],
            }

    # Data + responses
    # We need to track which direction has data — without explicit metadata
    # we associate by txid in body[0:4]
    for stream_pkts, direction in [(phone_to_cam, 'out'), (cam_to_phone, 'in')]:
        for ptype, body, _ in stream_pkts:
            if ptype in (9, 10, 12):  # StartData / Data / EndData (iCatch convention)
                if len(body) < 4: continue
                txid = struct.unpack_from('<I', body, 0)[0]
                tx = txs.get(txid)
                if not tx: continue
                if ptype == 9:  # StartData
                    continue
                payload = body[4:]
                if direction == 'in':
                    tx['data_in_bytes'] += len(payload)
                    tx['data_in_hex'] += payload.hex()
                else:
                    tx['data_out_bytes'] += len(payload)

    for ptype, body, _ in cam_to_phone:
        if ptype == 7:  # OpResp
            resp = parse_op_resp(body)
            if resp is None: continue
            tx = txs.get(resp['txid'])
            if not tx: continue
            tx['rc'] = f"0x{resp['rc']:04x}"
            tx['response_params'] = [f"0x{p:08x}" for p in resp['params']]

    # Print summary
    by_op = Counter(t['opcode'] for t in txs.values())
    print(f"Total transactions: {len(txs)}")
    print()
    print(f"By opcode:")
    for op, n in sorted(by_op.items()):
        label = 'standard' if op < 0x9000 else 'VENDOR'
        print(f"  0x{op:04x} ({label}): {n}")

    # Save full data
    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    with open(args.output, 'w') as f:
        # Sort by txid for readability
        sorted_txs = [txs[k] for k in sorted(txs.keys())]
        json.dump(sorted_txs, f, indent=2)
    print(f"\nWrote {args.output} ({len(sorted_txs)} transactions)")

    # Per-opcode summary: show unique param[0] values and what they returned
    print("\n=== Per-opcode param signatures ===")
    for op in sorted(set(t['opcode'] for t in txs.values())):
        calls = [t for t in txs.values() if t['opcode'] == op]
        # Unique param signatures (just first param)
        first_params = Counter(t['params_dec'][0] if t['params_dec'] else None
                                for t in calls)
        # Also show full param sets that are unique
        unique_param_sets = Counter(tuple(t['params_dec']) for t in calls)
        print(f"\n  0x{op:04x}  ({len(calls)} calls)")
        if len(unique_param_sets) <= 15:
            for ps, n in sorted(unique_param_sets.items(), key=lambda x: -x[1])[:15]:
                params_str = ', '.join(f"0x{p:08x}" for p in ps) if ps else '(none)'
                # Show one example's data sizes + rc
                ex = next(t for t in calls if tuple(t['params_dec']) == ps)
                print(f"    params=[{params_str}]  ×{n}  "
                      f"data_in={ex['data_in_bytes']}b  data_out={ex['data_out_bytes']}b  "
                      f"rc={ex['rc']}")
        else:
            top = sorted(first_params.items(), key=lambda x: -x[1])[:8]
            print(f"    {len(unique_param_sets)} unique param sets; first-param top-8:")
            for p, n in top:
                ph = f"0x{p:08x}" if p is not None else 'None'
                print(f"      {ph}: {n}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
