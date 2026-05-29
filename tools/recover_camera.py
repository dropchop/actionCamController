#!/usr/bin/env python3
"""Interactive multi-camera SD-recovery orchestrator.

Wraps the whole "get footage off a stuck SD card" workflow into one program
you launch over SSH. For each camera it: scans for `ActionCam_*` APs on the
USB WiFi dongle, lets you pick one (or takes --ssid), connects via nmcli,
pins camera traffic to the dongle with a /32 route, detects the dongle's
DHCP IP, checks the camera is reachable, previews the file inventory, asks
for confirmation, then drives tools/ftp_pull.py to mirror the files to
`~/larkfly-recovered/<SSID>/`. Then it loops so you can do the next camera.

  Usage:
    # Interactive — scan, pick from a menu, recover, repeat:
    python3 tools/recover_camera.py

    # Non-interactive single camera:
    python3 tools/recover_camera.py --ssid ActionCam_C762D5 --yes

    # See exactly what it WOULD run, touching nothing:
    python3 tools/recover_camera.py -n --ssid ActionCam_C762D5

  Exit codes (in loop mode, the worst seen across cameras):
    0  ok — every attempted camera fully recovered (or you quit cleanly)
    1  network failure (scan/connect/route/IP-detect/reachability)
    2  partial — a pull finished but >=1 file failed (re-run to resume)
    3  --ptp-verify cross-check mismatch (mirror may be short)
    4  usage error / refused to run as root
    130 interrupted (Ctrl-C)

IMPORTANT: run this as your NORMAL user, NOT with sudo. It runs unprivileged
so recovered files are owned by you, and it `sudo`s only the individual
nmcli commands (you'll be prompted for your password on the terminal).
Running the whole thing as root would make every recovered file root-owned.
"""
from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

FTP_PULL = os.path.join(REPO_ROOT, 'tools', 'ftp_pull.py')

DEFAULT_IFACE = os.environ.get('IFACE', 'wlx00c0caac3206')
DEFAULT_HOST = '192.168.1.1'
DEFAULT_PSK = '1234567890'
DEFAULT_BASE = '~/larkfly-recovered'

CAMERA_IP = '192.168.1.1'
HOME_GW = '192.168.1.254'
CAMERA_ROUTE = '192.168.1.1/32'         # how nmcli stores/reports it
ROUTE_SPEC = '192.168.1.1/32 0.0.0.0'   # how we add it (dest + on-link nh)


# ==========================================================================
# Pure helpers (unit-tested without hardware / sudo)
# ==========================================================================
def _split_terse(line: str) -> list[str]:
    """Split one `nmcli -t` line on unescaped ':' and unescape `\\:` / `\\\\`.

    nmcli terse mode separates fields with ':' and backslash-escapes any
    literal ':' (and '\\') inside a field — BSSIDs come out like
    `00\\:E0\\:4C\\:C7\\:62\\:D5`. This both splits and unescapes in one pass.
    """
    fields: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(line):
        c = line[i]
        if c == '\\' and i + 1 < len(line):
            cur.append(line[i + 1])
            i += 2
            continue
        if c == ':':
            fields.append(''.join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    fields.append(''.join(cur))
    return fields


@dataclass
class Camera:
    ssid: str
    bssid: str = ''
    signal: int = 0
    security: str = ''


def parse_wifi_list(text: str) -> list[Camera]:
    """Parse `nmcli -t -f SSID,BSSID,SIGNAL,SECURITY device wifi list` output
    into ActionCam_* cameras, strongest-signal first, deduped by SSID."""
    by_ssid: dict[str, Camera] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        f = _split_terse(line)
        if len(f) < 4:
            continue
        ssid, bssid, signal, security = f[0], f[1], f[2], f[3]
        if not ssid.startswith('ActionCam'):
            continue
        try:
            sig = int(signal)
        except ValueError:
            sig = 0
        cam = Camera(ssid=ssid, bssid=bssid, signal=sig, security=security)
        prev = by_ssid.get(ssid)
        if prev is None or cam.signal > prev.signal:
            by_ssid[ssid] = cam
    return sorted(by_ssid.values(), key=lambda c: c.signal, reverse=True)


def derive_dest(base: str, ssid: str) -> str:
    """Map an SSID to a per-camera output dir under base. Sanitizes the SSID
    (drops anything but [A-Za-z0-9_-]) so a hostile name can't escape base."""
    safe = re.sub(r'[^A-Za-z0-9_-]', '_', ssid) or 'camera'
    return os.path.join(base, safe)


def parse_dongle_ip(nmcli_g_output: str) -> str:
    """First IPv4 from `nmcli -g IP4.ADDRESS device show <iface>` ('a.b.c.d/NN'
    -> 'a.b.c.d'). Empty string if none (DHCP not ready yet)."""
    for line in nmcli_g_output.splitlines():
        tok = line.strip().split('/')[0]
        if tok:
            return tok
    return ''


def validate_dongle_ip(ip: str) -> bool:
    """True iff ip is a 192.168.1.x address that isn't the camera or home GW."""
    if not re.match(r'^192\.168\.1\.\d{1,3}$', ip):
        return False
    return ip not in (CAMERA_IP, HOME_GW)


def route_present(routes_str: str) -> bool:
    """True if the camera /32 route is already in a profile's ipv4.routes."""
    return CAMERA_ROUTE in routes_str


def build_connect_argv(target: str, psk: str, iface: str) -> list[str]:
    """nmcli args (no sudo) to connect; target is an SSID or a BSSID."""
    return ['nmcli', 'device', 'wifi', 'connect', target,
            'password', psk, 'ifname', iface]


def build_pull_argv(python: str, ftp_pull: str, host: str, bind: str,
                    dest: str, manifest: str, *, sleep: float, retries: int,
                    backoff: float, reconnect_every: int, preview: bool,
                    ptp_verify: bool, verbose: bool,
                    list_mode: bool = False) -> list[str]:
    """argv to invoke tools/ftp_pull.py for a list/preview/real run."""
    if list_mode:
        # Read-only inventory: no dest/manifest needed. --sleep paces the
        # SIZE-probe; ftp_pull --list does its own PTP merge.
        argv = [python, ftp_pull, host, '--bind', bind, '--list',
                '--sleep', str(sleep)]
        if verbose:
            argv.append('-v')
        return argv
    argv = [python, ftp_pull, host, '--bind', bind, '-o', dest,
            '--sleep', str(sleep), '--retries', str(retries),
            '--backoff', str(backoff), '--reconnect-every', str(reconnect_every),
            '--manifest', manifest]
    if preview:
        argv.append('--dry-run')
    if ptp_verify and not preview:
        argv += ['--verify-ptp', '--ptp-bind', bind]
    if verbose:
        argv.append('-v')
    return argv


def map_pull_rc(rc: int) -> tuple[str, int]:
    """Map an ftp_pull exit code to a (message, orchestrator-rc) pair."""
    return {
        0: ("DONE — all files recovered.", 0),
        1: ("FTP unreachable. Power-cycle the camera and retry.", 1),
        2: ("PARTIAL — some files failed. Re-run to resume (see manifest).", 2),
        3: ("PTP cross-check mismatch — mirror may be short (see banner).", 3),
    }.get(rc, (f"ftp_pull error (rc={rc}).", 4))


def prompt_yes_no(question: str, default: bool) -> bool:
    """Prompt y/n. Non-tty stdin returns the default (safe for piping)."""
    if not sys.stdin.isatty():
        return default
    try:
        ans = input(question + ' ').strip().lower()
    except EOFError:
        return default
    if not ans:
        return default
    return ans.startswith('y')


# ==========================================================================
# Orchestrator (impure: subprocess / sockets / sudo)
# ==========================================================================
class Orchestrator:
    def __init__(self, args):
        self.args = args
        self.iface = args.iface
        self.host = args.host
        self.psk = args.psk
        self.base = os.path.abspath(os.path.expanduser(args.base_dir))
        self.dry = args.dry_run
        self.active_profile: Optional[str] = None  # for Ctrl-C cleanup

    # ---- command runners ----
    def _run_sudo(self, argv: list[str], *, capture: bool = False,
                  check: bool = False) -> subprocess.CompletedProcess:
        full = ['sudo'] + argv
        if self.dry:
            print(f"    [dry-run] {' '.join(full)}")
            return subprocess.CompletedProcess(full, 0, '', '')
        # No capture by default so sudo's TTY password prompt reaches the user.
        return subprocess.run(full, text=True,
                              capture_output=capture, check=check)

    def _run_read(self, argv: list[str]) -> subprocess.CompletedProcess:
        """Unprivileged read — never sudo. Always captured for parsing."""
        return subprocess.run(argv, text=True, capture_output=True)

    # ---- scan + select ----
    def scan(self) -> list[Camera]:
        print(f"[*] Scanning for ActionCam_* APs on {self.iface} ...")
        self._run_sudo(['nmcli', 'device', 'wifi', 'rescan', 'ifname',
                        self.iface], check=False)
        time.sleep(self.args.rescan_wait)
        cp = self._run_read(['nmcli', '-t', '-f', 'SSID,BSSID,SIGNAL,SECURITY',
                             'device', 'wifi', 'list', 'ifname', self.iface])
        return parse_wifi_list(cp.stdout)

    def select(self) -> Optional[Camera]:
        if self.args.ssid:
            return Camera(ssid=self.args.ssid, bssid=self.args.bssid or '')
        while True:
            cams = self.scan()
            if not cams:
                print("    No ActionCam_* networks found.")
                if not prompt_yes_no("Re-scan? [Y/n]", default=True):
                    return None
                continue
            print("\n  Cameras found:")
            for i, c in enumerate(cams, 1):
                print(f"    {i}. {c.ssid:24s} signal={c.signal:3d}  {c.bssid}")
            choice = input(
                "  Select camera [1-%d], 'r' rescan, 'q' quit: "
                % len(cams)).strip().lower()
            if choice == 'q':
                return None
            if choice == 'r':
                continue
            if choice.isdigit() and 1 <= int(choice) <= len(cams):
                return cams[int(choice) - 1]
            print("    Invalid selection.")

    # ---- per-camera steps ----
    def connect(self, cam: Camera) -> bool:
        print(f"[1/8] Connecting to {cam.ssid} ...")
        cp = self._run_sudo(build_connect_argv(cam.ssid, self.psk, self.iface),
                            capture=True)
        if cp.returncode == 0:
            self.active_profile = cam.ssid
            return True
        err = (cp.stderr or '').strip()
        print(f"    connect failed: {err}", file=sys.stderr)
        # Stale-scan-cache fallback: try by BSSID if we have one.
        if cam.bssid and 'No network with SSID' in err:
            print(f"    retrying by BSSID {cam.bssid} ...")
            cp2 = self._run_sudo(
                build_connect_argv(cam.bssid, self.psk, self.iface),
                capture=True)
            if cp2.returncode == 0:
                self.active_profile = cam.ssid
                return True
            print(f"    BSSID connect failed: {(cp2.stderr or '').strip()}",
                  file=sys.stderr)
        if 'Not authorized' in err:
            print("    (nmcli needs root over SSH — make sure you can sudo.)",
                  file=sys.stderr)
        return False

    def ensure_route_and_up(self, profile: str) -> bool:
        print("[2/8] Pinning camera route to the dongle ...")
        cp = self._run_read(['nmcli', '-g', 'ipv4.routes', 'connection',
                             'show', profile])
        if route_present(cp.stdout):
            print(f"    {CAMERA_ROUTE} already on profile — keeping it")
        else:
            r = self._run_sudo(['nmcli', 'connection', 'modify', profile,
                                '+ipv4.routes', ROUTE_SPEC], capture=True)
            if r.returncode != 0:
                print(f"    route add failed: {(r.stderr or '').strip()}",
                      file=sys.stderr)
                return False
        up = self._run_sudo(['nmcli', 'connection', 'up', profile,
                            'ifname', self.iface], capture=True)
        if up.returncode != 0:
            print(f"    bring-up failed: {(up.stderr or '').strip()}",
                  file=sys.stderr)
            return False
        return True

    def detect_ip(self) -> Optional[str]:
        print("[3/8] Detecting dongle IP ...")
        for attempt in range(6):
            cp = self._run_read(['nmcli', '-g', 'IP4.ADDRESS', 'device',
                                'show', self.iface])
            ip = parse_dongle_ip(cp.stdout)
            if validate_dongle_ip(ip):
                print(f"    dongle IP = {ip}")
                return ip
            time.sleep(1.0)
        print(f"    could not get a valid 192.168.1.x IP on {self.iface} "
              f"(got {ip!r})", file=sys.stderr)
        return None

    def reachable(self, bind: str) -> bool:
        print(f"[4/8] Checking FTP reachability {self.host}:21 ...")
        try:
            s = socket.create_connection((self.host, 21), timeout=5,
                                         source_address=(bind, 0))
            s.close()
            print("    reachable")
            return True
        except OSError as e:
            print(f"    not reachable: {e}. Power-cycle the camera and retry.",
                  file=sys.stderr)
            return False

    def run_pull(self, bind: str, dest: str, preview: bool = False,
                 list_mode: bool = False) -> int:
        manifest = os.path.join(dest, 'manifest.json')
        argv = build_pull_argv(
            sys.executable, FTP_PULL, self.host, bind, dest, manifest,
            sleep=self.args.sleep, retries=self.args.retries,
            backoff=self.args.backoff,
            reconnect_every=self.args.reconnect_every,
            preview=preview, ptp_verify=self.args.ptp_verify,
            verbose=self.args.verbose, list_mode=list_mode)
        if self.dry:
            print(f"    [dry-run] {' '.join(argv)}")
            return 0
        return subprocess.run(argv).returncode

    def disconnect(self, profile: str) -> None:
        self._run_sudo(['nmcli', 'connection', 'down', profile], capture=True)
        self.active_profile = None

    def _decide_disconnect(self, ssid: str) -> bool:
        if self.args.keep_connected:
            return False
        if self.args.disconnect:
            return True
        return prompt_yes_no(f"Disconnect from {ssid}? [Y/n]", default=True)

    def _confirm_download(self, bind: str, dest: str) -> bool:
        """Ask whether to download. Offers an inline 'list all files' view."""
        if self.args.yes:
            return True
        if not sys.stdin.isatty():
            return False
        while True:
            ans = input(f"Download to {dest}?  "
                        f"[y]es / [l]ist all files / [N]o: ").strip().lower()
            if ans in ('l', 'list'):
                self.run_pull(bind, dest, list_mode=True)
                continue
            if ans.startswith('y'):
                return True
            return False

    def recover_one(self, cam: Camera) -> int:
        print(f"\n=== {cam.ssid} ===")
        dest = derive_dest(self.base, cam.ssid)
        if self.dry:
            # Orchestration dry-run: show the commands, touch nothing.
            self._run_sudo(build_connect_argv(cam.ssid, self.psk, self.iface))
            self._run_sudo(['nmcli', 'connection', 'modify', cam.ssid,
                            '+ipv4.routes', ROUTE_SPEC])
            self._run_sudo(['nmcli', 'connection', 'up', cam.ssid,
                            'ifname', self.iface])
            if self.args.list:
                self.run_pull('192.168.1.10', dest, list_mode=True)
            else:
                self.run_pull('192.168.1.10', dest, preview=True)
                self.run_pull('192.168.1.10', dest, preview=False)
            self._run_sudo(['nmcli', 'connection', 'down', cam.ssid])
            return 0

        try:
            if not self.connect(cam):
                return 1
            if not self.ensure_route_and_up(self.active_profile):
                return 1
            bind = self.detect_ip()
            if bind is None:
                return 1
            if not self.reachable(bind):
                return 1

            # View-only mode: list everything and stop (no download).
            if self.args.list:
                print(f"[5/5] Listing all files on {cam.ssid} ...")
                return 0 if self.run_pull(bind, dest, list_mode=True) == 0 else 1

            print(f"[5/8] Previewing {cam.ssid} -> {dest}")
            prc = self.run_pull(bind, dest, preview=True)
            if prc == 1:
                print("    preview shows FTP unreachable.", file=sys.stderr)
                return 1

            print("[6/8] Confirm")
            if not self._confirm_download(bind, dest):
                print("    skipped by user.")
                return 0

            print("[7/8] Downloading ...")
            rc = self.run_pull(bind, dest, preview=False)
            msg, cam_rc = map_pull_rc(rc)
            print(f"[8/8] {msg}")
            if cam_rc == 0:
                print(f"    saved to {dest}")
            return cam_rc
        finally:
            if self.active_profile and self._decide_disconnect(cam.ssid):
                self.disconnect(self.active_profile)

    def run(self) -> int:
        worst = 0
        while True:
            cam = self.select()
            if cam is None:
                break
            worst = max(worst, self.recover_one(cam))
            if self.args.no_loop or self.args.ssid:
                break
            if not prompt_yes_no("\nRecover another camera? [y/N]",
                                 default=False):
                break
        return worst


# ==========================================================================
# CLI
# ==========================================================================
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--ssid', default=None,
                    help='connect to this SSID (skip the scan menu)')
    ap.add_argument('--bssid', default=None,
                    help='BSSID to use as a fallback if the SSID isn\'t found')
    ap.add_argument('--iface', default=DEFAULT_IFACE,
                    help=f'WiFi dongle interface (default: {DEFAULT_IFACE}; '
                         f'or set $IFACE)')
    ap.add_argument('--host', default=DEFAULT_HOST,
                    help=f'camera AP IP (default: {DEFAULT_HOST})')
    ap.add_argument('--psk', default=DEFAULT_PSK,
                    help='WiFi password (default: the known camera PSK)')
    ap.add_argument('-o', '--base-dir', default=DEFAULT_BASE,
                    help=f'base output dir; files go to <base>/<SSID>/ '
                         f'(default: {DEFAULT_BASE})')
    ap.add_argument('--no-loop', action='store_true',
                    help='do one camera and exit (default: loop)')
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument('--keep-connected', action='store_true',
                     help='never disconnect the AP afterward')
    grp.add_argument('--disconnect', action='store_true',
                     help='always disconnect afterward without asking')
    ap.add_argument('--rescan-wait', type=float, default=4.0,
                    help='seconds to wait after a rescan (default: 4.0)')
    ap.add_argument('--sleep', type=float, default=0.5,
                    help='ftp_pull inter-request pacing (default: 0.5)')
    ap.add_argument('--retries', type=int, default=5,
                    help='ftp_pull per-file retries (default: 5)')
    ap.add_argument('--backoff', type=float, default=2.0,
                    help='ftp_pull retry backoff base (default: 2.0)')
    ap.add_argument('--reconnect-every', type=int, default=50,
                    help='ftp_pull proactive reconnect cadence (default: 50)')
    ap.add_argument('--yes', '-y', action='store_true',
                    help='auto-confirm the download (no prompt)')
    ap.add_argument('--list', action='store_true',
                    help='view mode: after connecting, list ALL files the '
                         'camera exposes (incl. read-only/hidden system files) '
                         'and stop — download nothing')
    ap.add_argument('--ptp-verify', action='store_true',
                    help='cross-check completeness against the PTP index')
    ap.add_argument('-n', '--dry-run', action='store_true',
                    help='print the nmcli commands + pull argv, touch nothing')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='verbose ftp_pull output')
    args = ap.parse_args()

    if os.geteuid() == 0:
        print("Refusing to run as root: run me as your normal user so "
              "recovered files are owned by you. I sudo the individual nmcli "
              "commands myself.", file=sys.stderr)
        return 4

    if args.dry_run and not args.ssid:
        # Can't scan offline (rescan needs sudo); use a placeholder so -n
        # can still show the full command sequence.
        args.ssid = 'ActionCam_EXAMPLE'
        print("[dry-run] no --ssid given; using placeholder "
              f"{args.ssid!r} to illustrate the commands\n")

    orch = Orchestrator(args)
    try:
        return orch.run()
    except KeyboardInterrupt:
        print("\n[interrupted]", file=sys.stderr)
        if orch.active_profile and not args.keep_connected:
            try:
                orch.disconnect(orch.active_profile)
            except Exception:
                pass
        return 130


if __name__ == '__main__':
    sys.exit(main())
