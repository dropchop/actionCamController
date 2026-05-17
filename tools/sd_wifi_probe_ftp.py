#!/usr/bin/env python3
"""Phase 1 (re-run via FTP, no PTP-string truncation bug) — WiFi config
file probe.

Step 1: delete the 17 garbage-named files left over from
        tools/sd_autorun_probe.py (PTP SendObject truncated their names).
Step 2: upload sta.conf / wifi.conf / WIFI.CFG (the three highest-
        probability filenames for the WiFi STA mechanism, matching both
        the Yi 4K precedent and the camera's own .CFG file convention).
Step 3: print pre-reboot listing for verification.

Each uploaded file contains a unique sentinel SSID `PROBE_<NAME>` in
multiple format conventions (key=value, JSON, INI, shell). After
power-cycle, observe whether any sentinel appears as the broadcast SSID
(strongest signal), whether the AP disappears (medium signal — file
parsed, camera in STA mode trying to join nonexistent network), or
whether nothing changed (firmware doesn't scan for these filenames).

Run: python3 tools/sd_wifi_probe_ftp.py
Then: power-cycle the camera, scan, and report back.
"""
import ftplib
import sys

CAMERA = '192.168.1.1'
USER = 'wificam'
PASS = 'wificam'

# Cleanup list — the truncated names from sd_autorun_probe.py
GARBAGE = [
    'a.conf', 'fi.conf', 'FI.CFG', 'stapd.conf', 'a_supplicant.conf',
    'ATCH.CFG', 'ctory.cfg', 'toexec.sh', 'toexec.ash', 'otcmd.sh',
    'Server', 'ACKDOOR.CONF', 'nfig.txt', 'ript.ini', 'stom_setting.ini',
    'S',
]

# WiFi config candidate filenames — these are the actual names we want
# the camera to look for on boot.
PROBES = ['sta.conf', 'wifi.conf', 'WIFI.CFG']


def make_payload(filename: str) -> bytes:
    """Multi-format WiFi config payload. Sentinel SSID is unique per file."""
    sentinel = 'PROBE_' + filename.replace('.', '_').upper()
    body = f"""# Larkfly A6+ WiFi STA-mode config probe — {filename}
# If you see this file after the camera boots, it WAS NOT consumed.

# --- key=value (Yi 4K sta.conf convention)
WIFI_MODE=sta
ESSID={sentinel}
PASSWORD=testpass12345
DEVICE_NAME=LarkflyProbe

# --- alternate key names
ssid={sentinel}
password=testpass12345
mode=sta
type=station

# --- INI sections
[wifi]
mode=sta
essid={sentinel}
password=testpass12345
ssid={sentinel}

[ap]
ssid={sentinel}
password=testpass12345

# --- JSON
{{"wifi":{{"mode":"sta","essid":"{sentinel}","password":"testpass12345"}}}}

# --- wpa_supplicant.conf style
network={{
    ssid="{sentinel}"
    psk="testpass12345"
    key_mgmt=WPA-PSK
}}

# --- shell export
export WIFI_MODE=sta
export ESSID={sentinel}
export PASSWORD=testpass12345
"""
    return body.encode('utf-8')


def main():
    ftp = ftplib.FTP()
    ftp.connect(CAMERA, 21, timeout=10)
    ftp.login(USER, PASS)
    print(f"[*] Connected FTP {CAMERA}")

    # Step 1: cleanup garbage from PTP probe
    print("\n=== Step 1: cleanup of truncated-name garbage ===")
    existing = []
    try:
        ftp.retrlines('LIST', existing.append)
    except Exception as e:
        print(f"  LIST failed: {e}")
    existing_names = {line.split()[-1] for line in existing}

    for name in GARBAGE:
        if name in existing_names:
            try:
                ftp.delete(name)
                print(f"  ✓ deleted {name}")
            except ftplib.error_perm as e:
                print(f"  ✗ {name}: {e}")
        else:
            print(f"  - {name} not present (skip)")

    # Step 2: upload WiFi config probes
    print("\n=== Step 2: upload WiFi config probes ===")
    for filename in PROBES:
        payload = make_payload(filename)
        sentinel = 'PROBE_' + filename.replace('.', '_').upper()
        try:
            # Use BytesIO for STOR
            import io
            ftp.storbinary(f'STOR {filename}', io.BytesIO(payload))
            print(f"  ✓ uploaded {filename:15s} ({len(payload)} bytes, sentinel={sentinel})")
        except Exception as e:
            print(f"  ✗ {filename}: {e}")

    # Step 3: print SD root listing
    print("\n=== Step 3: post-upload SD root listing ===")
    lines = []
    ftp.retrlines('LIST', lines.append)
    for line in lines:
        marker = ''
        name = line.split()[-1]
        if name in PROBES:
            marker = '  ← PROBE FILE'
        elif name in [n for n in GARBAGE]:
            marker = '  ← STILL JUNK (delete failed)'
        elif name in ['FACTORY.RUN', 'MFG.CFG', 'CALIB.CFG', 'BURN.CFG',
                       'PROD.CFG', 'MP_MODE.CFG', 'MAC.CFG', 'SERIAL.CFG']:
            marker = '  ← factory-mode flag'
        print(f"  {line}{marker}")

    ftp.quit()

    print("""

=== NEXT STEPS ===

1. POWER-CYCLE the camera (turn it off, wait 5s, turn it back on).

2. Once it boots, scan WiFi:
     nmcli dev wifi list ifname wlx00c0caac3206 --rescan yes | head -10

   Watch for:
     - 'PROBE_STA_CONF', 'PROBE_WIFI_CONF', or 'PROBE_WIFI_CFG' SSID
       → STRONGEST SIGNAL: the file was parsed AND drove AP config.
     - 'ActionCam_<MAC>' GONE with no replacement
       → file parsed, camera in STA mode trying to join PROBE_* (fails).
       Recovery: pull SD card, delete the .conf files manually.
     - 'ActionCam_<MAC>' still present AND all files intact in FTP
       → firmware didn't recognize any of them. Negative result;
       move to V2 (factory mode exit).

3. After reboot, re-connect host to camera AP and check FTP:
     curl -s --user wificam:wificam ftp://192.168.1.1/ | grep -E '\\.conf$|\\.CFG$'

   - If sta.conf/wifi.conf/WIFI.CFG are GONE → camera consumed them.
   - If they're still there → not recognized; safe to delete and try
     other vectors.

4. Cleanup: see end of dev-console-hunt.md for the next experiment.
""")
    return 0


if __name__ == '__main__':
    sys.exit(main())
