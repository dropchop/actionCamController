#!/usr/bin/env python3
"""SendObject magic-filename probe — v2 (uses 4-byte-padded encoder
from PTP quirk #4 fix, so filenames actually land intact).

Tests whether the firmware reads any of a battery of plausible
backdoor / config / autorun filenames at boot. Each file lands at the
SD-card FAT root with its EXACT name, and contains:
  - A unique sentinel ASCII tag (so we can identify it later)
  - A WIFI_MODE=sta + ESSID=PROBE_<name> hook (so if the camera parses
    the file as a WiFi config, the broadcast SSID would change)
  - A shell-script no-op (so if the camera executes it, no harm done)

DELIBERATELY EXCLUDED for safety:
  - SPHOST.BRN — known bootloader trigger; would force FW UPDATE menu
  - *.BRN / *.brn — same family
  - PDCAM_ISP.brn, Parameter.brn, RawC.brn — FRM partition names
These should be tested separately with explicit recovery plan.

INCLUDED candidates:
  - WiFi config: sta.conf, wifi.conf, WIFI.CFG, AP.CFG, STA.CFG
  - Backdoor lead: _BACKDOOR.CONF
  - Yi/Xiaomi/Ambarella autorun: autoexec.sh, autoexec.ash, bootcmd.sh,
    XCServer, script.ini, custom_setting.ini, rcS
  - Linux WiFi: hostapd.conf, wpa_supplicant.conf
  - Factory-namespace following camera's own *.CFG / *.RUN convention:
    SERVICE.CFG, DEBUG.CFG, FACTORY.CFG, DEBUG.RUN, MFG.OVR
  - U-Boot / generic: ENV.bin, upg.bin, update.bin, factory.bin
"""
from __future__ import annotations
import argparse, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import Camera
from larkfly import protocol as p
from larkfly.exceptions import PtpError


CANDIDATES = [
    # WiFi config — different from FTP STOR test because we control file
    # encoding bytes (FAT sector alignment etc.)
    'sta.conf', 'wifi.conf', 'WIFI.CFG', 'AP.CFG', 'STA.CFG',
    # Earlier research lead
    '_BACKDOOR.CONF',
    # Yi / Xiaomi / Ambarella autorun
    'autoexec.sh', 'autoexec.ash', 'bootcmd.sh',
    'XCServer', 'script.ini', 'custom_setting.ini', 'rcS',
    # Linux WiFi standard
    'hostapd.conf', 'wpa_supplicant.conf',
    # Factory namespace matching camera's own convention
    'SERVICE.CFG', 'DEBUG.CFG', 'FACTORY.CFG',
    'DEBUG.RUN', 'MFG.OVR',
    # U-Boot / generic firmware
    'ENV.bin', 'upg.bin', 'update.bin', 'factory.bin',
]


def sentinel_for(filename: str) -> str:
    return ('PROBE_' + filename.replace('.', '_').replace('/', '_').upper())[:32]


def make_payload(filename: str) -> bytes:
    s = sentinel_for(filename)
    return (f"""# SendObject probe v2 — {filename}
# If this file is consumed/renamed/modified after boot, the firmware
# recognized it. Sentinel SSID for AP-config parsers: {s}

WIFI_MODE=sta
ESSID={s}
PASSWORD=testpass12345
ssid={s}
password=testpass12345
mode=sta

[wifi]
mode=sta
essid={s}
password=testpass12345

{{"wifi":{{"mode":"sta","essid":"{s}","password":"testpass12345"}}}}

# shell-form (no actual exec)
WIFI_MODE=sta
ESSID={s}
PASSWORD=testpass12345
""").encode('utf-8')


def build_object_info(filename: str, payload_len: int, storage_id: int) -> bytes:
    out = struct.pack('<I', storage_id)
    out += struct.pack('<H', 0x3000)       # ObjectFormat = Undefined
    out += struct.pack('<H', 0)            # ProtectionStatus
    out += struct.pack('<I', payload_len)  # ObjectCompressedSize
    out += struct.pack('<H', 0) + struct.pack('<I', 0) * 5
    out += struct.pack('<I', 0)            # ParentObject (root)
    out += struct.pack('<H', 0)            # AssociationType
    out += struct.pack('<I', 0)            # AssociationDesc
    out += struct.pack('<I', 0)            # SequenceNumber
    out += p.encode_ptp_string_icatch_objinfo(filename)  # FIX from quirk #4
    out += p.encode_ptp_string('') * 3
    return out


def upload(cam, filename: str, sid: int) -> tuple[int | None, str]:
    """Returns (handle, actual_filename_from_GetObjectInfo) or (None, '')."""
    payload = make_payload(filename)
    info = build_object_info(filename, len(payload), sid)
    try:
        rc, rp, _ = cam._raw_op(0x100C, [sid, 0xFFFFFFFF], tx_data=info)
        if rc != 0x2001:
            return None, f'SendObjectInfo rc=0x{rc:04X}'
        h = rp[2]
        rc, _, _ = cam._raw_op(0x100D, [], tx_data=payload)
        if rc != 0x2001:
            return None, f'SendObject rc=0x{rc:04X} handle={h}'
        # Read back via GetObjectInfo to confirm filename
        rc, _, data = cam._raw_op(0x1008, [h])
        if rc != 0x2001:
            return h, '(GetObjectInfo failed)'
        n = data[52]
        fname = (data[53:53+2*n].decode('utf-16-le', errors='replace').rstrip('\x00')
                 if n else '')
        return h, fname
    except Exception as e:
        return None, repr(e)


def cleanup_via_ptp(cam, handles: list[int]) -> None:
    for h in handles:
        try:
            rc, _, _ = cam._raw_op(0x100B, [h])
            print(f"  delete handle {h}: rc=0x{rc:04X}")
        except Exception as e:
            print(f"  delete handle {h}: {e}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cleanup', action='store_true',
                    help='delete any handles whose filename matches our candidates')
    ap.add_argument('--host', default='192.168.1.1')
    ap.add_argument('--bind', default='192.168.1.10')
    args = ap.parse_args()

    cam = Camera(args.host, bind=args.bind)
    cam.connect()
    sid = cam.storage_ids()[0]
    print(f"[*] Storage ID: 0x{sid:08X}\n")

    if args.cleanup:
        # Enumerate all handles, delete any whose filename matches a candidate
        # (or our sentinel pattern)
        print("=== Cleanup: scanning all handles ===")
        cand_set = set(CANDIDATES)
        for h in sorted(cam.list_objects()):
            rc, _, data = cam._raw_op(0x1008, [h])
            if rc != 0x2001:
                continue
            n = data[52]
            fname = (data[53:53+2*n].decode('utf-16-le', errors='replace').rstrip('\x00')
                     if n else '')
            if fname in cand_set or 'PROBE' in fname.upper():
                rc2, _, _ = cam._raw_op(0x100B, [h])
                print(f"  deleted h={h} fname={fname!r} rc=0x{rc2:04X}")
        cam.close()
        return 0

    print("=== Uploading magic-filename battery (PTP quirk #4 fix applied) ===")
    uploaded = []
    for fname in CANDIDATES:
        h, actual = upload(cam, fname, sid)
        sentinel = sentinel_for(fname)
        if h is None:
            print(f"  ✗ {fname:25s} {actual}")
        else:
            match = '✓ exact' if actual == fname else f'✗ stored as {actual!r}'
            print(f"  {match[:7]} {fname:25s} h={h:3d} sentinel={sentinel}")
            uploaded.append((h, fname))

    print(f"\n[+] {len(uploaded)}/{len(CANDIDATES)} uploaded with exact filenames")

    print("\n=== NEXT STEPS ===")
    print(f"1. (optional) Verify via FTP: curl -s --user wificam:wificam ftp://{args.host}/")
    print("2. POWER-CYCLE the camera.")
    print("3. After boot, scan WiFi:")
    print(f"     nmcli dev wifi list ifname wlx00c0caac3206 --rescan yes | grep -E 'PROBE_|ActionCam'")
    print("   Strongest signal: any 'PROBE_<NAME>' SSID appearing.")
    print("4. After reboot, list SD: curl -s --user wificam:wificam ftp://{args.host}/")
    print("   - Files that GO MISSING were consumed by firmware (= recognized!)")
    print("   - Files RENAMED were processed (= recognized!)")
    print("   - Files unchanged were ignored (= negative)")
    print("5. Property re-check + locked-bool write probe:")
    print("     python3 tools/prop_write_probe.py")
    print()
    print("6. Cleanup before deciding: python3 tools/sendobject_magic_v2.py --cleanup")
    print()
    print("[!] If camera fails to come up on WiFi: AP service got nudged into")
    print("    STA mode trying to join PROBE_*. Recovery = pull SD card, delete")
    print("    .conf files manually, reinsert.")

    cam.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
