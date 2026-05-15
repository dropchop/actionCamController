#!/usr/bin/env python3
"""Decrypt a WPA2-PSK 802.11 pcap captured in monitor mode, given the SSID
and PSK. Derives PTK from EAPOL M2/M3 nonces (no need for M1) and rewrites
encrypted CCMP data frames as plaintext Ethernet for analysis.

Uses only `cryptography` (already installed) — no scapy / aircrack-ng deps.

Usage:
  python3 decrypt_pcap.py INPUT.pcap [-o OUTPUT.pcap] \\
      --ssid ActionCam_1A80DF --psk 1234567890
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import struct
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

# pcap link layer
LINKTYPE_IEEE802_11_RADIOTAP = 127
LINKTYPE_ETHERNET = 1

# 802.11 frame control bits
FC_TYPE_DATA = 0b10
FC_SUBTYPE_QOS_DATA = 0b1000


def derive_pmk(psk: bytes, ssid: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha1', psk, ssid, 4096, 32)


def prf512(key: bytes, label: bytes, data: bytes) -> bytes:
    """IEEE 802.11i PRF-512 for PTK derivation."""
    out = b''
    counter = 0
    while len(out) < 64:
        out += hmac.new(key, label + b'\x00' + data + bytes([counter]),
                        hashlib.sha1).digest()
        counter += 1
    return out[:64]


def derive_ptk(pmk: bytes, ap_mac: bytes, sta_mac: bytes,
               anonce: bytes, snonce: bytes) -> bytes:
    """PTK = PRF-512(PMK, "Pairwise key expansion",
                     min(macs) || max(macs) || min(nonces) || max(nonces))."""
    b = (min(ap_mac, sta_mac) + max(ap_mac, sta_mac) +
         min(anonce, snonce) + max(anonce, snonce))
    return prf512(pmk, b'Pairwise key expansion', b)


def read_pcap(path: str):
    """Yield (timestamp_us, linktype, raw_bytes) per packet."""
    with open(path, 'rb') as f:
        gh = f.read(24)
        magic, _vmaj, _vmin, _tz, _sigfigs, _snaplen, linktype = struct.unpack('<IHHIIII', gh)
        if magic != 0xa1b2c3d4:
            raise ValueError(f"unexpected pcap magic 0x{magic:08x}")
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            ts_sec, ts_us, incl_len, orig_len = struct.unpack('<IIII', rh)
            data = f.read(incl_len)
            yield (ts_sec * 1_000_000 + ts_us, linktype, data)


class PcapWriter:
    def __init__(self, path: str, linktype: int):
        self.f = open(path, 'wb')
        self.f.write(struct.pack('<IHHIIII',
                                  0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))

    def write(self, ts_us: int, data: bytes):
        self.f.write(struct.pack('<IIII',
                                  ts_us // 1_000_000,
                                  ts_us % 1_000_000,
                                  len(data), len(data)))
        self.f.write(data)

    def close(self):
        self.f.close()


def strip_radiotap(frame: bytes):
    """Return (802.11 frame bytes, has_fcs) after the radiotap header.

    Handles chained 'present' words (radiotap allows multiple 4-byte words
    when bit 31 of a word is set, indicating another word follows). The
    Flags byte position is computed dynamically based on which earlier
    fields are present in present[0]."""
    if len(frame) < 8:
        return b'', False
    rt_len = struct.unpack_from('<H', frame, 2)[0]

    # Walk all chained present-words. Each is 4 bytes; bit 31 set means
    # another follows.
    pos = 4
    presents = []
    while pos + 4 <= rt_len:
        w = struct.unpack_from('<I', frame, pos)[0]
        presents.append(w)
        pos += 4
        if not (w & 0x80000000):
            break

    # Data fields start at `pos`. Process present[0] field-by-field to find
    # where the Flags byte sits.
    first = presents[0] if presents else 0
    has_fcs = False
    if first & (1 << 1):
        off = pos
        if first & (1 << 0):  # TSFT (8 bytes, 8-byte aligned)
            # Align to 8
            off = (off + 7) & ~7
            off += 8
        # Flags (1 byte, 1-byte aligned, so already aligned)
        if off < rt_len:
            has_fcs = bool(frame[off] & 0x10)

    return frame[rt_len:], has_fcs


def parse_dot11(frame: bytes):
    """Return dict with fc, addr1, addr2, addr3, payload_offset, or None."""
    if len(frame) < 24:
        return None
    fc = struct.unpack_from('<H', frame, 0)[0]
    addr1 = frame[4:10]
    addr2 = frame[10:16]
    addr3 = frame[16:22]
    payload = 24
    ftype = (fc >> 2) & 0b11
    fsubtype = (fc >> 4) & 0b1111
    # QoS Data frames have a 2-byte QoS control after addr3 (and possibly addr4 if WDS)
    if ftype == FC_TYPE_DATA and (fsubtype & 0b1000):
        # QoS data: skip 2 bytes
        if len(frame) < 26:
            return None
        payload += 2
    return {
        'fc': fc,
        'ftype': ftype,
        'fsubtype': fsubtype,
        'addr1': addr1, 'addr2': addr2, 'addr3': addr3,
        'protected': bool(fc & 0x4000),
        'to_ds': bool(fc & 0x0100),
        'from_ds': bool(fc & 0x0200),
        'payload_offset': payload,
    }


def parse_eapol(frame: bytes, dot11: dict):
    """Parse an EAPOL key frame. Returns dict with nonce/info or None."""
    off = dot11['payload_offset']
    # LLC (8 bytes: AA AA 03 00 00 00 88 8E)
    if len(frame) < off + 8 or frame[off:off+8] != b'\xaa\xaa\x03\x00\x00\x00\x88\x8e':
        return None
    p = off + 8
    # EAPOL header: version(1), type(1), length(2 BE)
    if frame[p+1] != 3:  # type 3 = EAPOL-Key
        return None
    # Key descriptor
    kp = p + 4
    desc_type = frame[kp]
    if desc_type not in (2, 254):  # 2 = RSN, 254 = vendor
        return None
    key_info = struct.unpack_from('>H', frame, kp + 1)[0]
    key_len = struct.unpack_from('>H', frame, kp + 3)[0]
    replay = struct.unpack_from('>Q', frame, kp + 5)[0]
    nonce = frame[kp + 13: kp + 45]
    return {
        'key_info': key_info,
        'replay': replay,
        'nonce': nonce,
        'ack': bool(key_info & 0x80),     # AP→STA flag
        'mic': bool(key_info & 0x100),
        'install': bool(key_info & 0x40),
        'secure': bool(key_info & 0x200),
    }


def ccmp_decrypt(frame: bytes, dot11: dict, tk: bytes) -> bytes | None:
    """Decrypt one CCMP-protected 802.11 data frame. Returns plaintext payload
    (after CCMP header) or None on failure."""
    off = dot11['payload_offset']
    if len(frame) < off + 8 + 8:  # 8 CCMP header + 8 MIC minimum
        return None

    # CCMP header (8 bytes): PN0 PN1 Reserved KeyID PN2 PN3 PN4 PN5
    ccmp_hdr = frame[off:off+8]
    pn = bytes([ccmp_hdr[7], ccmp_hdr[6], ccmp_hdr[5],
                ccmp_hdr[4], ccmp_hdr[1], ccmp_hdr[0]])  # PN5..PN0

    ciphertext = frame[off+8:]  # includes 8-byte MIC at end

    # QoS TID (priority) for nonce flags — extract before building nonce
    tid = 0
    if dot11['fsubtype'] & 0b1000:
        tid = frame[24] & 0x0f
    # CCMP nonce: flags(1=priority) || A2(6) || PN(6)
    nonce = bytes([tid]) + dot11['addr2'] + pn

    # AAD construction. Spec says mask = 0x078F (clear protected + order),
    # but this Realtek AP empirically uses 0xC78F (keeps both). Verified by
    # decrypting an ARP frame end-to-end. Likely vendor-specific.
    fc_masked = dot11['fc'] & 0xC78F
    aad = struct.pack('<H', fc_masked)
    aad += dot11['addr1'] + dot11['addr2'] + dot11['addr3']
    # SC: keep fragment number (bits 0-3), clear sequence number
    sc = struct.unpack_from('<H', frame, 22)[0]
    aad += struct.pack('<H', sc & 0x000f)
    # QoS Control: keep TID (bits 0-3), zero other bits per spec
    if dot11['fsubtype'] & 0b1000:
        aad += bytes([frame[24] & 0x0f, 0])

    aesccm = AESCCM(tk, tag_length=8)
    try:
        plaintext = aesccm.decrypt(nonce, ciphertext, aad)
        return plaintext
    except Exception:
        return None


def build_eth_frame(dot11: dict, payload: bytes) -> bytes:
    """Build an Ethernet frame from decrypted 802.11 + LLC payload.
    The payload should start with LLC/SNAP (AA AA 03 00 00 00 ETHERTYPE)."""
    if len(payload) < 8 or payload[:6] != b'\xaa\xaa\x03\x00\x00\x00':
        # Not LLC/SNAP — wrap as-is in Ethernet with type 0xFFFF
        ethertype = b'\xff\xff'
        eth_payload = payload
    else:
        ethertype = payload[6:8]
        eth_payload = payload[8:]

    # Pick src/dst based on to/from DS flags
    if dot11['from_ds']:
        dst = dot11['addr1']; src = dot11['addr3']
    elif dot11['to_ds']:
        dst = dot11['addr3']; src = dot11['addr2']
    else:
        dst = dot11['addr1']; src = dot11['addr2']
    return dst + src + ethertype + eth_payload


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('input')
    ap.add_argument('-o', '--output', default=None,
                    help="output pcap (default: <input>-decrypted.pcap)")
    ap.add_argument('--ssid', required=True)
    ap.add_argument('--psk', required=True)
    ap.add_argument('--bssid', default=None,
                    help='AP MAC (auto-detected from EAPOL if not given)')
    args = ap.parse_args()

    out_path = args.output or args.input.replace('.pcap', '-decrypted.pcap')

    pmk = derive_pmk(args.psk.encode(), args.ssid.encode())
    print(f"PMK: {pmk.hex()}")

    # Pass 1: find EAPOL handshake, extract nonces + MACs
    anonce = snonce = ap_mac = sta_mac = None
    for ts, lt, raw in read_pcap(args.input):
        if lt != LINKTYPE_IEEE802_11_RADIOTAP:
            print(f"ERROR: input must be radiotap (got linktype {lt})")
            return 1
        frame, has_fcs = strip_radiotap(raw)
        if has_fcs and len(frame) > 4:
            frame = frame[:-4]
        d = parse_dot11(frame)
        if d is None: continue
        if d['ftype'] != FC_TYPE_DATA: continue
        eapol = parse_eapol(frame, d)
        if eapol is None: continue
        is_m1m3 = eapol['ack'] and not eapol['mic']           # M1
        is_m1m3_alt = eapol['ack'] and eapol['mic']            # M3
        is_m2 = (not eapol['ack']) and eapol['mic'] and not eapol['secure']  # M2
        if eapol['ack']:  # from AP (M1 or M3)
            if ap_mac is None: ap_mac = d['addr2']
            if sta_mac is None: sta_mac = d['addr1']
            if anonce is None or eapol['nonce'] != b'\x00'*32:
                anonce = eapol['nonce']
        else:  # from STA (M2 or M4)
            if ap_mac is None: ap_mac = d['addr1']
            if sta_mac is None: sta_mac = d['addr2']
            if snonce is None or eapol['nonce'] != b'\x00'*32:
                snonce = eapol['nonce']

    if not (anonce and snonce and ap_mac and sta_mac):
        print("ERROR: could not extract nonces + MACs from EAPOL handshake")
        return 2
    print(f"AP  MAC: {ap_mac.hex(':')}")
    print(f"STA MAC: {sta_mac.hex(':')}")
    print(f"ANonce : {anonce.hex()}")
    print(f"SNonce : {snonce.hex()}")

    ptk = derive_ptk(pmk, ap_mac, sta_mac, anonce, snonce)
    tk = ptk[32:48]
    print(f"PTK    : {ptk.hex()}")
    print(f"TK     : {tk.hex()}")
    print()

    # Pass 2: decrypt protected data frames, write Ethernet pcap
    w = PcapWriter(out_path, LINKTYPE_ETHERNET)
    n_total = n_protected = n_decrypted = n_eapol = 0
    for ts, lt, raw in read_pcap(args.input):
        n_total += 1
        frame, has_fcs = strip_radiotap(raw)
        if has_fcs and len(frame) > 4:
            frame = frame[:-4]
        d = parse_dot11(frame)
        if d is None: continue
        if d['ftype'] != FC_TYPE_DATA: continue
        if not d['protected']:
            # Unencrypted data frame (EAPOL, etc.) — still emit as Ethernet
            pay = frame[d['payload_offset']:]
            if pay.startswith(b'\xaa\xaa\x03\x00\x00\x00'):
                w.write(ts, build_eth_frame(d, pay))
                if pay[6:8] == b'\x88\x8e':
                    n_eapol += 1
            continue
        n_protected += 1
        pt = ccmp_decrypt(frame, d, tk)
        if pt is None: continue
        n_decrypted += 1
        w.write(ts, build_eth_frame(d, pt))
    w.close()
    print(f"Frames total            : {n_total}")
    print(f"Data frames protected   : {n_protected}")
    print(f"Successfully decrypted  : {n_decrypted}")
    print(f"EAPOL frames passed thru: {n_eapol}")
    print(f"\nWrote {out_path}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
