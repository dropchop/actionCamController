#!/usr/bin/env python3
"""Phase 1 — SD-card autorun probe.

Uploads a battery of candidate WiFi/autorun config filenames via PTP
SendObject. Each file contains the SAME multi-format payload (key=value,
JSON, INI, shell-script) with a UNIQUE sentinel `ESSID=PROBE_<name>`.

After power-cycling the camera, look for any of these signals:

  1. Camera AP `ActionCam_<MAC>` STOPS broadcasting and a new AP
     `PROBE_<filename>` appears — strongest signal; one of the files
     was parsed AND the firmware can drive AP-config from it.
  2. Camera AP stays as `ActionCam_<MAC>` but a new AP appears — odd
     but informative.
  3. Camera fails to come up on WiFi (AP disappears, no replacement)
     — file was parsed and put the camera into STA mode trying to
     join `PROBE_*` (which doesn't exist). Recovery: remove SD card
     or upload an empty replacement file.
  4. Camera comes up normally, all files still present on SD — the
     firmware didn't recognize any of them. Negative result.
  5. Camera comes up normally, but one of the files is RENAMED or
     CONSUMED — strong signal that filename was recognized and
     processed (even if content wasn't acted on).

Optional --cleanup mode deletes everything we uploaded (run after the
camera is back on WiFi, but BEFORE rebooting if you want to abort).

Reference filenames (provenance):
  sta.conf, wifi.conf       — Yi 4K (proven mechanism in iCatch family)
  hostapd.conf              — Linux hostapd standard
  wpa_supplicant.conf       — Linux wpa_supplicant standard
  ICATCH.CFG                — iCatch vendor namespace
  factory.cfg               — common factory-trigger name
  autoexec.sh / .ash        — Yi / Xiaomi Yi family init scripts
  bootcmd.sh                — Yi family
  XCServer                  — Yi-family service binary substitute
  _BACKDOOR.CONF            — earlier RE lead (D:/HOSTAPD/_BACKDOOR.CONF)
  script.ini                — Ambarella-family config
  custom_setting.ini        — Xiaomi Yi
  rcS                       — sysvinit script convention
  config.txt                — generic fallback
"""
from __future__ import annotations
import os, struct, sys, argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import Camera
from larkfly.exceptions import PtpError


CANDIDATES = [
    'sta.conf',
    'wifi.conf',
    'WIFI.CFG',
    'hostapd.conf',
    'wpa_supplicant.conf',
    'ICATCH.CFG',
    'icatch.cfg',
    'factory.cfg',
    'autoexec.sh',
    'autoexec.ash',
    'bootcmd.sh',
    'XCServer',
    '_BACKDOOR.CONF',
    'config.txt',
    'script.ini',
    'custom_setting.ini',
    'rcS',
]


def encode_ptp_string(s: str) -> bytes:
    """Standard PTP STRING."""
    if not s:
        return b'\x00'
    encoded = (s + '\x00').encode('utf-16-le')
    n = len(s) + 1
    return bytes([n]) + encoded


def encode_ptp_string_icatch_objinfo(s: str) -> bytes:
    """iCatch quirk for ObjectInfo.Filename: 4-byte padding after length.
    Without this, every uploaded filename loses its first 2 chars.
    See docs/findings.md PTP quirk #4."""
    if not s:
        return b'\x00' + b'\x00' * 4
    encoded = (s + '\x00').encode('utf-16-le')
    n = len(s) + 1
    return bytes([n]) + b'\x00' * 4 + encoded


def build_object_info(filename: str, payload_len: int, storage_id: int,
                      object_format: int = 0x3000) -> bytes:
    out = struct.pack('<I', storage_id)
    out += struct.pack('<H', object_format)
    out += struct.pack('<H', 0)         # ProtectionStatus
    out += struct.pack('<I', payload_len)
    out += struct.pack('<H', 0) + struct.pack('<I', 0)*5  # Thumb + Image
    out += struct.pack('<I', 0)         # ParentObject (root)
    out += struct.pack('<H', 0)         # AssociationType
    out += struct.pack('<I', 0)         # AssociationDesc
    out += struct.pack('<I', 0)         # SequenceNumber
    out += encode_ptp_string_icatch_objinfo(filename)  # 4-byte-padded; iCatch quirk
    out += encode_ptp_string('') * 3
    return out


def sentinel_for(filename: str) -> str:
    """Make a per-file SSID sentinel that's <=32 chars and unique."""
    base = filename.replace('.', '_').replace('/', '_').upper()
    # 802.11 SSID is max 32 bytes; "PROBE_" prefix + name should fit
    return ('PROBE_' + base)[:32]


def make_payload(filename: str) -> bytes:
    s = sentinel_for(filename)
    body = f"""# Larkfly A6+ SD-card autorun probe.
# If you see this file on the SD card after a successful reboot,
# the firmware did NOT consume it.

# --- key=value (Yi 4K sta.conf style)
WIFI_MODE=sta
ESSID={s}
PASSWORD=testpass12345
DEVICE_NAME=LarkflyProbe
ssid={s}
password=testpass12345
mode=station

# --- JSON
{{"wifi": {{"mode": "sta", "essid": "{s}", "password": "testpass12345"}}}}

# --- INI sections
[wifi]
mode=sta
essid={s}
password=testpass12345

[ap]
ssid={s}
password=testpass12345

# --- shell-script
export WIFI_MODE=sta
export ESSID={s}
export PASSWORD=testpass12345
WIFI_MODE=sta ESSID={s} PASSWORD=testpass12345
"""
    return body.encode('utf-8')


def upload_one(cam, filename: str, storage_id: int) -> dict:
    """Upload one probe file. Returns {ok, handle, error?}."""
    payload = make_payload(filename)
    info = build_object_info(filename, len(payload), storage_id)
    try:
        rc, rp, _ = cam._raw_op(0x100C, [storage_id, 0xFFFFFFFF], tx_data=info)
        if rc != 0x2001:
            return {'ok': False, 'error': f'SendObjectInfo rc=0x{rc:04X}'}
        handle = rp[2]
        rc, _, _ = cam._raw_op(0x100D, [], tx_data=payload)
        if rc != 0x2001:
            return {'ok': False, 'error': f'SendObject rc=0x{rc:04X}',
                    'handle_assigned': handle}
        return {'ok': True, 'handle': handle, 'bytes': len(payload),
                'sentinel': sentinel_for(filename)}
    except Exception as e:
        return {'ok': False, 'error': repr(e)}


def cleanup_all(cam, handles: list[int]) -> None:
    for h in handles:
        try:
            rc, _, _ = cam._raw_op(0x100B, [h])
            print(f"  delete handle {h}: rc=0x{rc:04X}")
        except Exception as e:
            print(f"  delete handle {h}: {e}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='192.168.1.1')
    ap.add_argument('--bind', default='192.168.1.10')
    ap.add_argument('--cleanup', action='store_true',
                    help='delete all probe files (run BEFORE reboot to abort, '
                         'or AFTER reboot if camera came back on WiFi)')
    args = ap.parse_args()

    cam = Camera(args.host, bind=args.bind)
    cam.connect()
    print(f"[*] Connected to {args.host}")
    storage_ids = cam.storage_ids()
    sid = storage_ids[0] if storage_ids else 0x00010001
    print(f"[*] Storage ID: 0x{sid:08X}")

    pre_handles = set(cam.list_objects())
    print(f"[*] Pre-upload handles on camera: {sorted(pre_handles)}")
    print()

    if args.cleanup:
        # Cleanup mode: delete any handles whose filename matches one of
        # our candidates.
        post_handles = sorted(set(cam.list_objects()) - pre_handles)
        print(f"[*] Cleanup mode (handles to remove): {post_handles}")
        cleanup_all(cam, post_handles)
        cam.close()
        return 0

    # Upload mode.
    print("=== Uploading probe files ===")
    uploaded = []
    for filename in CANDIDATES:
        result = upload_one(cam, filename, sid)
        if result['ok']:
            uploaded.append(result['handle'])
            print(f"  ✓ {filename:25s} handle={result['handle']:3d} bytes={result['bytes']:4d} sentinel={result['sentinel']}")
        else:
            print(f"  ✗ {filename:25s} {result['error']}")

    print()
    print(f"[+] Uploaded {len(uploaded)}/{len(CANDIDATES)} files")
    print(f"    New handles: {uploaded}")
    print()
    print("=== NEXT STEPS ===")
    print("1. Power-cycle the camera.")
    print("2. After it boots, scan WiFi:")
    print("     nmcli dev wifi list ifname wlx00c0caac3206 --rescan yes | grep -E 'ActionCam|PROBE_'")
    print("   Look for:")
    print("     - 'PROBE_<NAME>' SSID = strongest signal (file parsed AND drove AP config)")
    print("     - 'ActionCam_<MAC>' GONE with no replacement = file parsed, camera in STA mode")
    print("     - 'ActionCam_<MAC>' still present + all files intact = no file recognized")
    print("3. Re-connect to the camera AP / network and check via FTP which files survived:")
    print("     curl -s --user wificam:wificam ftp://192.168.1.1/")
    print("   Missing/renamed files = camera consumed them. Surviving files = unrecognized.")
    print("4. Cleanup when done:")
    print(f"     python3 {sys.argv[0]} --cleanup")
    print()
    print("[!] If the camera comes up in STA mode and tries to join 'PROBE_*',")
    print("    it will sit looking for a nonexistent network. Recovery: pull SD")
    print("    card, delete the .conf files manually, reinsert, reboot.")

    cam.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
