#!/usr/bin/env python3
"""sync_recovered.py — friendly status + pull for camera-recovery files.

Run this on the *receiving* machine (e.g. your WSL2 instance). It compares a
local "inbound" folder against the matching folder on the **Capture PC** (the
Linux host that ran recover_camera.py) over SSH, prints a color-coded list,
then offers to rsync-pull whatever's new.

  Legend:
    ✓ green    present on BOTH this machine and the Capture PC (synced)
    · neutral  present only here          (local-only)
    ↓ red      present only on Capture PC  (new — not pulled yet)

Colors are chosen to read on light AND dark terminals, and each row carries a
glyph too, so the green/red distinction survives color-blindness or NO_COLOR.

  First run:
    python3 tools/sync_recovered.py            # asks for the Capture PC's
                                               # address + user, saves them,
                                               # then shows the diff. No IP is
                                               # baked into this script.

  Later:
    python3 tools/sync_recovered.py            # uses your saved config
    python3 tools/sync_recovered.py --host 192.168.1.189   # one-off override
    python3 tools/sync_recovered.py --host ts-box --save    # change the saved default
    python3 tools/sync_recovered.py --configure             # re-run the setup wizard
    python3 tools/sync_recovered.py --all -y                # whole base, no prompts
    python3 tools/sync_recovered.py -n                      # preview, transfer nothing

Setting precedence (first non-empty wins):
    --flag  >  $CAPTURE_PC / $CAPTURE_USER  >  saved config  >  built-in default
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from collections import Counter

# --- built-in fallbacks (NO host IP here on purpose — it's user-defined) --
BUILTIN = {
    'host': '',                                   # must come from wizard/flag/env/config
    'user': 'micah',
    'remote_base': '/home/micah/larkfly-recovered',
    'local_base': '~/larkfly-recovered',
}
SETTING_KEYS = ('host', 'user', 'remote_base', 'local_base')

# --- colors (readable on light & dark; gate on TTY + NO_COLOR) ------------
RESET = '\033[0m'
C_GREEN = '\033[38;5;28m'        # #008700 — green that reads on white & black
C_RED = '\033[1;38;5;160m'       # #d70000 bold — red that reads on white & black
C_NEUTRAL = '\033[39m'           # terminal default fg (not hard white: survives light themes)
C_DIM = '\033[2m'

# status -> (glyph, color, label)
STATUS_STYLE = {
    'both':   ('✓', C_GREEN,   'synced'),
    'local':  ('·', C_NEUTRAL, 'local only'),
    'remote': ('↓', C_RED,     'on Capture PC only'),
}


# ==========================================================================
# Pure helpers (unit-tested without ssh / hardware)
# ==========================================================================
def parse_remote_find(text: str) -> dict[str, int]:
    """Parse `find <base> -type f -printf '%P\\t%s\\n'` output into {relpath: size}."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) < 2 or not parts[0]:
            continue
        try:
            out[parts[0]] = int(parts[1])
        except ValueError:
            out[parts[0]] = 0
    return out


def compare(local: dict[str, int], remote: dict[str, int]) -> list[tuple[str, str]]:
    """Return [(relpath, status)] sorted by path. status in both/local/remote."""
    rows: list[tuple[str, str]] = []
    for rel in sorted(set(local) | set(remote)):
        in_l, in_r = rel in local, rel in remote
        status = 'both' if (in_l and in_r) else ('local' if in_l else 'remote')
        rows.append((rel, status))
    return rows


def count_status(rows: list[tuple[str, str]]) -> Counter:
    return Counter(status for _, status in rows)


def resolve_config(cli: dict, env: dict, file_cfg: dict, builtin: dict) -> dict:
    """Merge setting sources by precedence: cli > env > file > builtin.

    A value counts as "present" only if it's truthy (non-None, non-empty), so
    an unset flag/env/key falls through to the next source. Pure — the unit
    tests pin the precedence so nobody silently re-hardcodes a host later.
    """
    out: dict[str, str] = {}
    for key in SETTING_KEYS:
        for src in (cli, env, file_cfg, builtin):
            val = src.get(key)
            if val:
                out[key] = val
                break
        else:
            out[key] = ''
    return out


def colorize(text: str, color: str, *, use_color: bool) -> str:
    return f'{color}{text}{RESET}' if use_color else text


def want_color(stream=None) -> bool:
    """Color iff stdout is a TTY and NO_COLOR isn't set (no-color.org)."""
    stream = stream or sys.stdout
    return stream.isatty() and 'NO_COLOR' not in os.environ


# ==========================================================================
# Config persistence
# ==========================================================================
def config_path() -> str:
    base = os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config')
    return os.path.join(base, 'larkfly-sync', 'config.json')


def load_config(path: str) -> dict:
    try:
        with open(path) as fh:
            data = json.load(fh)
        return {k: data[k] for k in SETTING_KEYS if k in data}
    except (OSError, ValueError):
        return {}


def save_config(path: str, cfg: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    keep = {k: cfg[k] for k in SETTING_KEYS if cfg.get(k)}
    with open(path, 'w') as fh:
        json.dump(keep, fh, indent=2)
        fh.write('\n')


def configure_interactive(current: dict) -> dict:
    """Tiny setup wizard. Returns a config dict; caller decides to save."""
    print("\n  Set up your Capture PC connection")
    print("  (the Linux host that recorded the footage; this is saved for next time)\n")

    def ask(label: str, key: str, example: str) -> str:
        cur = current.get(key) or ''
        hint = cur or example
        ans = input(f"  {label} [{hint}]: ").strip()
        return ans or cur or example

    cfg = dict(current)
    cfg['host'] = ask("Capture PC IP / hostname", 'host', '192.168.1.x')
    cfg['user'] = ask("SSH username", 'user', BUILTIN['user'])
    cfg['remote_base'] = ask("Folder on the Capture PC", 'remote_base',
                             BUILTIN['remote_base'])
    cfg['local_base'] = ask("Inbound folder here", 'local_base',
                            BUILTIN['local_base'])
    return cfg


# ==========================================================================
# SSH / filesystem (impure)
# ==========================================================================
class Remote:
    """Talks to the Capture PC over a multiplexed SSH connection."""

    def __init__(self, host: str, user: str):
        self.host = host
        self.user = user
        self.target = f'{user}@{host}'
        os.makedirs(os.path.expanduser('~/.ssh'), mode=0o700, exist_ok=True)
        cm = os.path.expanduser('~/.ssh/cm-recovered-%r@%h:%p')
        # Shared multiplexing opts so the user authenticates ONCE per run.
        self._mux = ['-o', 'ControlMaster=auto', '-o', f'ControlPath={cm}',
                     '-o', 'ControlPersist=120', '-o', 'ConnectTimeout=10']

    def _ssh(self, remote_cmd: str) -> subprocess.CompletedProcess:
        return subprocess.run(['ssh', *self._mux, self.target, remote_cmd],
                              text=True, capture_output=True)

    def rsync_e(self) -> str:
        """The `-e` transport string so rsync reuses the same muxed connection."""
        return 'ssh ' + ' '.join(shlex.quote(o) for o in self._mux)

    def list_files(self, base: str) -> dict[str, int]:
        cp = self._ssh(f"find {shlex.quote(base)} -type f "
                       f"-printf '%P\\t%s\\n' 2>/dev/null")
        return parse_remote_find(cp.stdout)

    def list_dirs(self, base: str) -> list[str]:
        cp = self._ssh(f"find {shlex.quote(base)} -mindepth 1 -maxdepth 1 "
                       f"-type d -printf '%P\\n' 2>/dev/null")
        return [d for d in cp.stdout.splitlines() if d]

    def reachable(self) -> tuple[bool, str]:
        cp = self._ssh('true')
        return (cp.returncode == 0, (cp.stderr or '').strip())

    def close(self) -> None:
        subprocess.run(['ssh', *self._mux, '-O', 'exit', self.target],
                       text=True, capture_output=True)


def list_local_files(base: str) -> dict[str, int]:
    out: dict[str, int] = {}
    if not os.path.isdir(base):
        return out
    for root, _dirs, files in os.walk(base):
        for name in files:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, base)
            try:
                out[rel] = os.path.getsize(path)
            except OSError:
                out[rel] = 0
    return out


def list_local_dirs(base: str) -> list[str]:
    if not os.path.isdir(base):
        return []
    return [d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))]


# ==========================================================================
# UI
# ==========================================================================
def choose_folder(local_dirs: list[str], remote_dirs: list[str]) -> str | None:
    """Menu over the union of camera subfolders. '' means ALL. None = quit."""
    folders = sorted(set(local_dirs) | set(remote_dirs))
    if not folders:
        return ''  # nothing nested yet — just use the base
    if not sys.stdin.isatty():
        return ''  # non-interactive: default to ALL
    print("\n  Inbound folders on the Capture PC:")
    print("    0. ALL")
    for i, f in enumerate(folders, 1):
        print(f"    {i}. {f}")
    while True:
        choice = input(f"  Choose a folder [0-{len(folders)}], 'q' quit: ").strip().lower()
        if choice == 'q':
            return None
        if choice in ('0', ''):
            return ''
        if choice.isdigit() and 1 <= int(choice) <= len(folders):
            return folders[int(choice) - 1]
        print("    Invalid selection.")


def print_listing(rows: list[tuple[str, str]], *, use_color: bool) -> None:
    if not rows:
        print(f"  {C_DIM if use_color else ''}(no files on either side)"
              f"{RESET if use_color else ''}")
        return
    for rel, status in rows:
        glyph, color, _label = STATUS_STYLE[status]
        print(colorize(f"  {glyph} {rel}", color, use_color=use_color))


def print_legend(use_color: bool) -> None:
    parts = []
    for status in ('both', 'local', 'remote'):
        glyph, color, label = STATUS_STYLE[status]
        parts.append(colorize(f"{glyph} {label}", color, use_color=use_color))
    print("  " + "    ".join(parts))


def prompt_yes_no(question: str, default: bool) -> bool:
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
# Orchestration
# ==========================================================================
def run_sync(remote: Remote, remote_path: str, local_path: str,
             *, dry: bool) -> int:
    os.makedirs(local_path, exist_ok=True)
    argv = ['rsync', '-avP', '-e', remote.rsync_e(),
            f'{remote.target}:{remote_path}/', f'{local_path}/']
    if dry:
        print(f"    [dry-run] {' '.join(shlex.quote(a) for a in argv)}")
        return 0
    return subprocess.run(argv).returncode


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--host', default=None,
                    help='Capture PC address (overrides saved config / $CAPTURE_PC)')
    ap.add_argument('--user', default=None,
                    help=f'SSH user (overrides config / $CAPTURE_USER; '
                         f'built-in default: {BUILTIN["user"]})')
    ap.add_argument('--remote-base', default=None,
                    help=f'source dir on the Capture PC (default: {BUILTIN["remote_base"]})')
    ap.add_argument('--local-base', default=None,
                    help=f'inbound dir here (default: {BUILTIN["local_base"]})')
    ap.add_argument('--configure', action='store_true',
                    help='(re)run the setup wizard, save, and exit')
    ap.add_argument('--save', action='store_true',
                    help='persist the resolved host/user/paths as the new default')
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument('--folder', default=None,
                     help='sync just this camera subfolder (skip the menu)')
    grp.add_argument('--all', action='store_true',
                     help='operate on the whole base (skip the menu)')
    ap.add_argument('--yes', '-y', action='store_true',
                    help='auto-confirm the pull (no prompt)')
    ap.add_argument('-n', '--dry-run', action='store_true',
                    help='show the diff + the rsync command, transfer nothing')
    ap.add_argument('--no-color', action='store_true', help='disable colors')
    args = ap.parse_args()

    cfg_file = config_path()
    cli = {'host': args.host, 'user': args.user,
           'remote_base': args.remote_base, 'local_base': args.local_base}
    env = {'host': os.environ.get('CAPTURE_PC'),
           'user': os.environ.get('CAPTURE_USER')}
    file_cfg = load_config(cfg_file)
    cfg = resolve_config(cli, env, file_cfg, BUILTIN)

    # --- explicit (re)configure ---
    if args.configure:
        cfg = configure_interactive(cfg)
        save_config(cfg_file, cfg)
        print(f"\n  Saved to {cfg_file}")
        return 0

    # --- first-run: no host anywhere -> wizard (or hard error if scripted) ---
    if not cfg['host']:
        if sys.stdin.isatty():
            print("  No Capture PC configured yet.")
            cfg = configure_interactive(cfg)
            save_config(cfg_file, cfg)
            print(f"  Saved to {cfg_file}")
        else:
            print("  No Capture PC configured. Pass --host, set $CAPTURE_PC, "
                  "or run --configure once interactively.", file=sys.stderr)
            return 4
    elif args.save:
        save_config(cfg_file, cfg)
        print(f"  Saved current settings to {cfg_file}")

    use_color = want_color() and not args.no_color
    local_base = os.path.abspath(os.path.expanduser(cfg['local_base']))
    remote_base = cfg['remote_base'].rstrip('/')

    remote = Remote(cfg['host'], cfg['user'])
    try:
        print(f"[*] Capture PC: {remote.target}  (auth once; reused for the run)")
        ok, err = remote.reachable()
        if not ok:
            print(f"    cannot reach Capture PC over SSH: {err}", file=sys.stderr)
            print("    check it's powered, on the network, and sshd is up. "
                  "Wrong address? re-run with --configure.", file=sys.stderr)
            return 1

        if args.all:
            sub = ''
        elif args.folder is not None:
            sub = args.folder
        else:
            sub = choose_folder(list_local_dirs(local_base),
                                remote.list_dirs(remote_base))
            if sub is None:
                print("    quit.")
                return 0

        remote_path = f'{remote_base}/{sub}'.rstrip('/') if sub else remote_base
        local_path = os.path.join(local_base, sub) if sub else local_base
        label = sub or '(all)'

        print(f"\n[*] Comparing {label} ...")
        rows = compare(list_local_files(local_path), remote.list_files(remote_path))
        print_legend(use_color)
        print()
        print_listing(rows, use_color=use_color)

        counts = count_status(rows)
        new_on_pc = counts.get('remote', 0)
        print(f"\n  {counts.get('both', 0)} synced, "
              f"{counts.get('local', 0)} local-only, "
              f"{colorize(str(new_on_pc) + ' new on Capture PC', C_RED, use_color=use_color)}")

        if new_on_pc == 0:
            print("  Everything's in sync ✓")
            return 0

        if not (args.yes or prompt_yes_no(
                f"\n{new_on_pc} new file(s) located on Capture PC. Sync now? [y/N]",
                default=False)):
            print("  skipped.")
            return 0

        print(f"\n[*] Pulling {label} -> {local_path}")
        rc = run_sync(remote, remote_path, local_path, dry=args.dry_run)
        if rc != 0:
            print(f"    rsync exited {rc}.", file=sys.stderr)
            return 2

        if not args.dry_run:
            rows = compare(list_local_files(local_path),
                           remote.list_files(remote_path))
            still = count_status(rows).get('remote', 0)
            if still == 0:
                print("  Done — all of the Capture PC's files are now here ✓")
            else:
                print(f"  Done, but {still} file(s) still missing — re-run to retry.")
        return 0
    except KeyboardInterrupt:
        print("\n[interrupted]", file=sys.stderr)
        return 130
    finally:
        remote.close()


if __name__ == '__main__':
    sys.exit(main())
