#!/usr/bin/env python3
"""Batch multi-camera SD-recovery — scan a fleet, then pull everything.

A "secondary version" of tools/recover_camera.py for the rig workflow: when
you have several Larkfly cameras powered up at once and want to sweep them all
in one go instead of recovering them one camera at a time.

Flow:
  1. SELECT — scan for `ActionCam_*` APs on the dongle and let you multi-select
     the cameras you know are yours (e.g. `1,3,4` or `all`). Or skip the scan
     and name them with repeated `--ssid`.
  2. SCAN PASS — visit each selected camera in turn (connect → list its files
     in the same inventory format as recover_camera/ftp_pull → disconnect),
     printing "Connecting to … / Scanning … / Disconnecting from …" as it goes.
  3. ONE KEYPRESS — after every camera's inventory is on screen, a single y/N
     confirms the whole batch.
  4. DOWNLOAD PASS — cycle through the cameras again automatically, mirroring
     each one's footage into its own `~/larkfly-recovered/<SSID>/` folder.

Each camera reuses recover_camera's proven bring-up (sudo nmcli connect with
BSSID fallback → /32 camera route → DHCP IP detect+validate → FTP reachability
check) and ftp_pull.py for the read-only listing and the download-only mirror.

  Usage:
    # Interactive — scan, multi-select, review listings, one y to pull all:
    python3 tools/recover_batch.py

    # Name the fleet explicitly and auto-confirm (no menus, no prompt):
    python3 tools/recover_batch.py --ssid ActionCam_C762D5 \
            --ssid ActionCam_1A80DF --yes

    # Just inventory every selected camera, download nothing:
    python3 tools/recover_batch.py --scan-only

    # See the exact nmcli + ftp_pull commands, touch nothing:
    python3 tools/recover_batch.py -n --ssid ActionCam_C762D5

  Exit codes (worst seen across the fleet):
    0  ok — every selected camera fully recovered (or scan-only / clean quit)
    1  network failure on >=1 camera (connect/route/IP/reachability)
    2  partial — a pull finished but >=1 file failed (re-run to resume)
    3  --ptp-verify cross-check mismatch on >=1 camera
    4  usage error / refused to run as root / no cameras selected
    130 interrupted (Ctrl-C)

Like recover_camera.py: run as your NORMAL user, NOT sudo — recovered files
stay owned by you, and only the individual nmcli commands are sudo'd (you'll
be prompted for your password on the terminal).
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from typing import Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, 'tools'))

# Reuse recover_camera's primitives wholesale — same nmcli/route/pull logic,
# same per-camera output convention, same dongle-restore-on-exit behavior.
import recover_camera as rc  # noqa: E402
from recover_camera import (  # noqa: E402
    Camera, Orchestrator, derive_dest, map_pull_rc, prompt_yes_no,
    DEFAULT_IFACE, DEFAULT_HOST, DEFAULT_PSK, DEFAULT_BASE,
)


# ==========================================================================
# Pure helpers (unit-tested without hardware / sudo)
# ==========================================================================
def parse_selection(choice: str, n: int) -> Optional[list[int]]:
    """Parse a multi-select string against `n` 1-based menu options.

    Accepts comma/space-separated indices and `lo-hi` ranges, e.g.
    `1,3,4`, `1 3 4`, `1-3,5`. `all` / `a` / `*` selects everything.
    Returns sorted, de-duplicated 0-based indices; `[]` for an empty string;
    or `None` if anything is out of range or unparseable (so the caller can
    re-prompt rather than silently dropping a camera).
    """
    s = choice.strip().lower()
    if s in ('all', 'a', '*'):
        return list(range(n))
    if not s:
        return []
    out: set[int] = set()
    for part in re.split(r'[,\s]+', s):
        if not part:
            continue
        m = re.match(r'^(\d+)-(\d+)$', part)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo < 1 or hi > n or lo > hi:
                return None
            out.update(range(lo - 1, hi))
            continue
        if part.isdigit() and 1 <= int(part) <= n:
            out.add(int(part) - 1)
            continue
        return None
    return sorted(out)


# ==========================================================================
# Batch orchestrator
# ==========================================================================
class BatchOrchestrator(Orchestrator):
    """Drives the select → scan-pass → download-pass workflow over a fleet."""

    # ---- selection ----
    def select_fleet(self) -> list[Camera]:
        """Build the list of cameras to process this run.

        With `--ssid` (repeatable) we trust the names and skip the scan
        entirely. Otherwise we scan and present a multi-select menu.
        """
        if self.args.ssid:
            return [Camera(ssid=s) for s in self.args.ssid]
        while True:
            cams = self.scan()
            if not cams:
                print("    No ActionCam_* networks found.")
                if not prompt_yes_no("Re-scan? [Y/n]", default=True):
                    return []
                continue
            print("\n  Cameras found:")
            for i, c in enumerate(cams, 1):
                print(f"    {i}. {c.ssid:24s} signal={c.signal:3d}  {c.bssid}")
            choice = input(
                "\n  Select the cameras to recover "
                "(e.g. '1,3,4' or 'all'), 'r' rescan, 'q' quit: ").strip().lower()
            if choice == 'q':
                return []
            if choice == 'r':
                continue
            picks = parse_selection(choice, len(cams))
            if not picks:
                print("    Nothing selected — pick at least one, or 'q'.")
                continue
            chosen = [cams[i] for i in picks]
            print("\n  Selected: " + ", ".join(c.ssid for c in chosen))
            return chosen

    # ---- shared per-camera link bring-up / tear-down ----
    def _bring_up(self, cam: Camera) -> Optional[str]:
        """Connect + route + IP + reachability. Returns the bind IP or None.

        Prints the user-facing 'Connecting to …' line (via connect()'s own
        relabeled message) and leaves self.active_profile set on success."""
        if not self.connect(cam, label=""):
            return None
        if not self.ensure_route_and_up(self.active_profile, label="    "):
            return None
        bind = self.detect_ip(label="    ")
        if bind is None:
            return None
        if not self.reachable(bind, label="    "):
            return None
        return bind

    def _tear_down(self, cam: Camera) -> None:
        if self.active_profile:
            print(f"Disconnecting from {cam.ssid} ...")
            self.disconnect(self.active_profile)

    # ---- passes ----
    def scan_pass(self, fleet: list[Camera]) -> list[Camera]:
        """Visit each camera, print its file inventory. Returns the reachable
        subset (the ones worth attempting a download on)."""
        reachable: list[Camera] = []
        n = len(fleet)
        for i, cam in enumerate(fleet, 1):
            print(f"\n========== SCAN [{i}/{n}]  {cam.ssid} ==========")
            bind = self._bring_up(cam)
            if bind is None:
                print(f"    !! {cam.ssid} unreachable — skipping it this run.")
            else:
                print(f"Scanning {cam.ssid} for files ...")
                self.run_pull(bind, derive_dest(self.base, cam.ssid),
                              list_mode=True)
                reachable.append(cam)
            self._tear_down(cam)
            if i < n:
                print(f"\n>>> Moving on to {fleet[i].ssid} ...")
        return reachable

    def download_pass(self, fleet: list[Camera]) -> int:
        """Cycle through the fleet downloading each camera's footage."""
        worst = 0
        n = len(fleet)
        for i, cam in enumerate(fleet, 1):
            print(f"\n========== PULL [{i}/{n}]  {cam.ssid} ==========")
            dest = derive_dest(self.base, cam.ssid)
            bind = self._bring_up(cam)
            if bind is None:
                print(f"    !! {cam.ssid} unreachable — skipping it this run.")
                worst = max(worst, 1)
                self._tear_down(cam)
                if i < n:
                    print(f"\n>>> Moving on to {fleet[i].ssid} ...")
                continue
            print(f"Downloading {cam.ssid} -> {dest} ...")
            cam_rc = 0
            try:
                msg, cam_rc = map_pull_rc(self.run_pull(bind, dest))
                print(f"    {msg}")
                if cam_rc == 0:
                    print(f"    saved to {dest}")
            finally:
                worst = max(worst, cam_rc)
                self._tear_down(cam)
            if i < n:
                print(f"\n>>> Moving on to {fleet[i].ssid} ...")
        return worst

    # ---- top-level ----
    def run(self) -> int:
        try:
            fleet = self.select_fleet()
            if not fleet:
                print("No cameras selected — nothing to do.")
                return 4

            if self.dry:
                # Show what each camera would do, touch nothing.
                for cam in fleet:
                    self.recover_one(cam)
                return 0

            reachable = self.scan_pass(fleet)
            if self.args.scan_only:
                print(f"\n[scan-only] {len(reachable)}/{len(fleet)} camera(s) "
                      f"reachable. Nothing downloaded.")
                return 0 if len(reachable) == len(fleet) else 1
            if not reachable:
                print("\nNo cameras were reachable — nothing to download.")
                return 1

            print(f"\n{'=' * 50}")
            print(f"Inventoried {len(reachable)} camera(s): "
                  + ", ".join(c.ssid for c in reachable))
            if not self.args.yes and not prompt_yes_no(
                    f"Download ALL footage from these {len(reachable)} "
                    f"camera(s)? [y/N]", default=False):
                print("Skipped — no download.")
                return 0

            return self.download_pass(reachable)
        finally:
            # Undo scan()'s `nmcli device disconnect` so the dongle isn't left
            # stuck disconnected when we end without holding a session.
            self.restore_dongle()


# ==========================================================================
# CLI
# ==========================================================================
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--ssid', action='append', default=None, metavar='SSID',
                    help='camera SSID to include (repeatable); skips the scan '
                         'menu. e.g. --ssid ActionCam_A --ssid ActionCam_B')
    ap.add_argument('--iface', default=DEFAULT_IFACE,
                    help=f'WiFi dongle interface (default: {DEFAULT_IFACE}; '
                         f'or set $IFACE)')
    ap.add_argument('--host', default=DEFAULT_HOST,
                    help=f'camera AP IP (default: {DEFAULT_HOST})')
    ap.add_argument('--psk', default=DEFAULT_PSK,
                    help='WiFi password shared by all cameras (default: the '
                         'known camera PSK)')
    ap.add_argument('-o', '--base-dir', default=DEFAULT_BASE,
                    help=f'base output dir; each camera goes to <base>/<SSID>/ '
                         f'(default: {DEFAULT_BASE})')
    ap.add_argument('--scan-only', action='store_true',
                    help='do the scan pass (connect + list each camera) and '
                         'stop — download nothing')
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
                    help='auto-confirm the batch download (no prompt)')
    ap.add_argument('--ptp-verify', action='store_true',
                    help='cross-check completeness against the PTP index')
    ap.add_argument('-n', '--dry-run', action='store_true',
                    help='print the nmcli + ftp_pull commands, touch nothing')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='verbose ftp_pull output')
    args = ap.parse_args()

    # recover_camera's Orchestrator reads a few attrs the per-camera helper
    # uses; the batch flow doesn't expose them as flags, so pin safe values.
    args.bssid = None
    args.list = False            # batch uses its own scan/download passes
    args.no_loop = False
    args.keep_connected = False  # batch always disconnects between cameras
    args.disconnect = True       # _tear_down disconnects unconditionally

    if os.geteuid() == 0:
        print("Refusing to run as root: run me as your normal user so "
              "recovered files are owned by you. I sudo the individual nmcli "
              "commands myself.", file=sys.stderr)
        return 4

    if args.dry_run and not args.ssid:
        # Can't scan offline (rescan needs sudo); use placeholders so -n can
        # still illustrate the full per-camera command sequence.
        args.ssid = ['ActionCam_EXAMPLE1', 'ActionCam_EXAMPLE2']
        print("[dry-run] no --ssid given; using placeholders "
              f"{args.ssid} to illustrate the commands\n")

    orch = BatchOrchestrator(args)
    try:
        return orch.run()
    except KeyboardInterrupt:
        print("\n[interrupted]", file=sys.stderr)
        if orch.active_profile:
            try:
                orch.disconnect(orch.active_profile)
            except Exception:
                pass
        return 130


if __name__ == '__main__':
    sys.exit(main())
