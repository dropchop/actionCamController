#!/usr/bin/env python3
"""FTP advanced probe — follow-ups to the path-traversal fuzz.

Three parallel investigations on the camera's now-known-richer FTP
surface:

  A. XMKD everywhere — does mkdir respect the chroot, or can we
     create dirs at /HOSTAPD, /etc, /dev, /sys, /tmp, /root, /system,
     /var, /proc? After XMKD, attempt CWD into it and LIST to see if
     it shows anything. Always XRMD-cleanup after.

  B. Subdirectory write probe — can we STOR into /JPG/, /VIDEO/,
     and the System Volume Information directory? If yes, we can
     plant files where the camera reads from. Critically also test
     whether a STOR'd file in JPG/ shows up in PTP list_objects()
     as a photo handle.

  C. NUL-filename forensics — STOR a file with embedded NUL, then
     test LIST, RETR with several name variants, to see if the FAT
     stores a truncated name while FTP advertises the full one.
     Cleanup is by-handle if the NUL desyncs us.

All operations cleanup-after-themselves where possible. Health
checked between each part.
"""
from __future__ import annotations
import ftplib, io, socket, time

HOST = '192.168.1.1'
USER = 'wificam'
PASS = 'wificam'

SENTINEL = b'FTP_ADVANCED_PROBE_LARKFLY_2026\n'


def fresh_ftp() -> ftplib.FTP:
    ftp = ftplib.FTP()
    ftp.connect(HOST, 21, timeout=10)
    ftp.login(USER, PASS)
    return ftp


def safe_cmd(ftp: ftplib.FTP, cmd: str) -> tuple[str | None, str | None]:
    """Returns (response, error_string)."""
    try:
        return ftp.sendcmd(cmd), None
    except (ftplib.error_perm, ftplib.error_temp, ftplib.error_reply,
            ftplib.error_proto) as e:
        return None, str(e)
    except Exception as e:
        return None, f'{type(e).__name__}: {str(e)[:80]}'


def part_A_xmkd_everywhere():
    print("\n" + "="*72)
    print("PART A: XMKD into system-y paths")
    print("="*72)
    print("(For each: XMKD → if OK, try CWD in + LIST + XRMD cleanup)\n")
    PATHS = [
        # Top-level system dirs
        '/HOSTAPD', '/hostapd', '/etc', '/dev', '/sys', '/tmp',
        '/root', '/system', '/var', '/proc', '/usr', '/bin', '/lib',
        '/mnt', '/run', '/home',
        # iCatch-family specific guesses
        '/factory', '/calib', '/debug', '/log', '/config', '/fw',
        '/firmware', '/update', '/cfg',
        # Path-traversal mkdir
        '../etc',
        '../../etc',
        '../../../etc',
        '../../../../etc',
        '..',
        '/JPG/../newroot_dir',
        '/JPG/../../newroot_dir',
        # Existing-dir overwrites (should fail with EEXIST-style)
        '/JPG',
        '/VIDEO',
    ]
    created = []
    for p in PATHS:
        resp, err = safe_cmd(create_ftp_for_each(), f'XMKD {p}')
        if resp:
            print(f"  ★ XMKD {p!r:42s} → {resp[:60]}")
            created.append(p)
            # Try to LIST it
            ftp2 = fresh_ftp()
            lines = []
            try:
                ftp2.retrlines(f'LIST {p}', lines.append)
                print(f"    LIST {p}: {len(lines)} entries")
                for ln in lines[:5]:
                    print(f"      {ln}")
            except Exception as e:
                print(f"    LIST {p} failed: {type(e).__name__}")
            ftp2.quit()
        else:
            # Suppress the boring 550-perm responses
            if '550' not in (err or '') and 'perm' not in (err or '').lower():
                print(f"  ! XMKD {p!r:42s} → {err[:80]}")

    print("\n  Cleanup XMKD-created dirs:")
    for p in created:
        ftp = fresh_ftp()
        resp, err = safe_cmd(ftp, f'XRMD {p}')
        if resp:
            print(f"    ✓ XRMD {p}")
        else:
            print(f"    ✗ XRMD {p} failed: {err[:80]}")
        ftp.quit()


def create_ftp_for_each():
    """Each XMKD gets a fresh FTP session — paranoid against state corruption."""
    return fresh_ftp()


def part_B_subdir_write_probe():
    print("\n" + "="*72)
    print("PART B: STOR into existing subdirs (JPG, VIDEO, System Volume Information)")
    print("="*72)

    TARGETS = [
        '/JPG/PROBE_B.TXT',
        '/VIDEO/PROBE_B.TXT',
        '/System Volume Information/PROBE_B.TXT',
        'JPG/PROBE_B.TXT',
        'VIDEO/PROBE_B.TXT',
    ]
    for target in TARGETS:
        ftp = fresh_ftp()
        try:
            ftp.storbinary(f'STOR {target}', io.BytesIO(SENTINEL))
            print(f"  ★ STOR {target!r:55s} → accepted")
            # Read back
            try:
                buf = io.BytesIO()
                ftp.retrbinary(f'RETR {target}', buf.write)
                print(f"    RETR back: {len(buf.getvalue())} B, matches sentinel: {buf.getvalue() == SENTINEL}")
            except Exception as e:
                print(f"    RETR failed: {type(e).__name__}")
            # List the parent dir
            parent = '/' + '/'.join(target.lstrip('/').split('/')[:-1])
            try:
                lines = []
                ftp.retrlines(f'LIST {parent}', lines.append)
                matches = [ln for ln in lines if 'PROBE_B' in ln]
                if matches:
                    print(f"    LIST {parent}: file visible ({matches[0]})")
                else:
                    print(f"    LIST {parent}: file NOT visible in listing ({len(lines)} other entries)")
            except Exception as e:
                print(f"    LIST {parent} failed: {type(e).__name__}")
            # Cleanup
            try:
                ftp.delete(target)
                print(f"    ✓ cleaned up")
            except Exception as e:
                print(f"    ✗ cleanup failed: {type(e).__name__}: {e}")
        except ftplib.error_perm as e:
            print(f"  - STOR {target!r:55s} → perm: {e}")
        except Exception as e:
            print(f"  ! STOR {target!r:55s} → {type(e).__name__}: {e}")
        ftp.quit()


def part_C_nul_forensics():
    print("\n" + "="*72)
    print("PART C: NUL-byte filename forensics")
    print("="*72)
    print("(STOR a file with embedded NUL, then test LIST + RETR variants)\n")

    nul_name = 'SENT\x00JUNK.TXT'
    ftp = fresh_ftp()

    # Snapshot LIST before
    pre = []
    ftp.retrlines('LIST', pre.append)
    pre_names = {ln.split()[-1] for ln in pre}

    # Upload the NUL-injected name
    try:
        ftp.storbinary(f'STOR {nul_name}', io.BytesIO(SENTINEL))
        print(f"  STOR {nul_name!r}: accepted")
    except Exception as e:
        print(f"  STOR {nul_name!r}: failed ({e})")
        ftp.quit()
        return

    # LIST and see what shows up
    post = []
    ftp.retrlines('LIST', post.append)
    post_names = {ln.split()[-1] for ln in post}
    new_names = post_names - pre_names
    print(f"\n  LIST diff after STOR — NEW entries: {new_names}")
    for ln in post:
        n = ln.split()[-1]
        if n in new_names:
            print(f"    {ln}")

    # Now try to RETR with various interpretations of the name
    print("\n  Try RETR with several name variants:")
    variants = [
        nul_name,           # original
        'SENT',             # truncated at NUL
        'SENT\x00JUNK.TXT', # explicit NUL
        'SENTJUNK.TXT',     # stripped
        'JUNK.TXT',         # after-NUL portion
        'SENT.TXT',         # ?
    ] + sorted(new_names)
    for v in variants:
        try:
            buf = io.BytesIO()
            ftp.retrbinary(f'RETR {v}', buf.write)
            ok = '★ ok' if buf.getvalue() == SENTINEL else f'differs ({len(buf.getvalue())} B)'
            print(f"    RETR {v!r:30s} → {ok}")
        except ftplib.error_perm as e:
            print(f"    RETR {v!r:30s} → perm: {str(e)[:60]}")
        except Exception as e:
            print(f"    RETR {v!r:30s} → {type(e).__name__}")

    # Cleanup — try every variant we created
    print("\n  Cleanup attempts:")
    cleaned = False
    for v in [nul_name] + sorted(new_names):
        try:
            ftp.delete(v)
            print(f"    ✓ deleted {v!r}")
            cleaned = True
        except Exception as e:
            print(f"    ✗ delete {v!r}: {type(e).__name__}")
    if not cleaned:
        # Final state check — any debris?
        debris = []
        ftp.retrlines('LIST', debris.append)
        debris_names = {ln.split()[-1] for ln in debris} - pre_names
        if debris_names:
            print(f"  !! debris left on FS: {debris_names}")
    ftp.quit()


def main():
    print(f"[*] Connecting to {HOST}")
    ftp = fresh_ftp()
    pre_lines = []
    ftp.retrlines('LIST', pre_lines.append)
    print(f"[*] Pre-fuzz FTP root has {len(pre_lines)} entries")
    ftp.quit()

    part_A_xmkd_everywhere()
    part_B_subdir_write_probe()
    part_C_nul_forensics()

    # Final state check
    print("\n" + "="*72)
    print("FINAL STATE CHECK")
    print("="*72)
    ftp = fresh_ftp()
    post_lines = []
    ftp.retrlines('LIST', post_lines.append)
    print(f"Post-fuzz FTP root has {len(post_lines)} entries (was {len(pre_lines)})")
    if len(post_lines) != len(pre_lines):
        pre_names = {ln.split()[-1] for ln in pre_lines}
        post_names = {ln.split()[-1] for ln in post_lines}
        added = post_names - pre_names
        gone = pre_names - post_names
        if added:
            print(f"  ADDED (debris): {added}")
        if gone:
            print(f"  ! REMOVED: {gone}")
    else:
        print("  ✓ same entry count")
    ftp.quit()


if __name__ == '__main__':
    import sys
    sys.exit(main())
