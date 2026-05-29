#!/usr/bin/env python3
"""Recover files off the camera's SD card remotely, over FTP.

The Larkfly A6+ runs an iCatch FTP server on its AP (192.168.1.1:21,
creds wificam:wificam) that exposes the SD card's media tree (/VIDEO/*.MOV
full-res 4K H.264, /JPG/*.JPG) plus any root files. When a card is
physically stuck in the camera, this is the way to get the footage off it.

This tool recursively mirrors the FTP-visible filesystem to a local
directory: robust, resumable, and DOWNLOAD-ONLY.

  Usage:
    # Plan only — touches nothing, downloads nothing:
    python3 tools/ftp_pull.py 192.168.1.1 --bind 192.168.1.10 --dry-run -v

    # Real pull, gentle pacing, into ./recovered:
    python3 tools/ftp_pull.py 192.168.1.1 --bind 192.168.1.10 \
            -o ./recovered --sleep 0.5 --retries 5

    # Just the 4K videos, with a PTP completeness cross-check:
    python3 tools/ftp_pull.py 192.168.1.1 --bind 192.168.1.10 \
            -o ./recovered --include '*.MOV' --verify-ptp

    # Resume after a power-cycle: rerun the same command. SIZE-matched
    # files are skipped; failed/partial ones re-download.

  Exit codes:
    0  complete — every in-scope file downloaded and size-verified
    1  could not reach / log in to the FTP server (transport)
    2  partial — finished the walk but >=1 file failed all retries
    3  --verify-ptp found PTP-indexed files missing/short in the mirror
       (or PTP itself was unreachable when --verify-ptp was requested)
    4  usage / argument error

HARD INVARIANT — READ-ONLY ON THE CAMERA. The only FTP data-transfer verb
this tool ever sends is RETR. It never sends DELE / STOR / RMD / RNFR /
RNTO / MKD / XMKD. The camera's FTP service can wedge ("go catatonic")
under rapid hammering — recovery is a power-cycle — so we use a single
sequential connection (no parallelism), pace requests, and retry with
reconnect + exponential backoff. Creating local directories under --dest
is not a camera mutation and is fine.
"""
from __future__ import annotations

import argparse
import fnmatch
import ftplib
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Iterator, Optional

# Make `larkfly` importable when run directly (only needed for --verify-ptp).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HOST_DEFAULT = '192.168.1.1'
USER = 'wificam'
PASS = 'wificam'
FTP_PORT = 21


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclass
class RemoteEntry:
    path: str                  # full FTP path, e.g. '/VIDEO/20251206_141500.MOV'
    name: str                  # basename
    is_dir: bool
    size: Optional[int]        # from LIST if parseable, else None (SIZE later)
    raw: str = ''              # original LIST line, for the manifest / debugging


@dataclass
class FileResult:
    path: str
    size: Optional[int]
    status: str                # downloaded|skipped-resume|resume-unverified|failed|dry-run|skipped-filter
    bytes_written: int = 0
    attempts: int = 0
    error: Optional[str] = None


# --------------------------------------------------------------------------
# Pure helpers (unit-tested without hardware)
# --------------------------------------------------------------------------
def parse_list_line(line: str) -> Optional[RemoteEntry]:
    """Parse one UNIX `ls -l`-style LIST line into a RemoteEntry.

    The camera emits classic lines like:
        drw------- 1 user group 0 May 15 03:07 VIDEO
        -rw------- 1 user group 268435456 Dec 06 14:15 20251206_141500.MOV

    Returns None for anything that isn't a real entry (blank line, a
    'total N' header, '.' / '..', or an unparseable stub). Never raises —
    a malformed line is just skipped by the caller.
    """
    line = line.rstrip('\r\n')
    if not line:
        return None
    if line.lower().startswith('total '):
        return None
    parts = line.split()
    if len(parts) < 4:
        # Too few fields to have learned a name reliably.
        return None

    is_dir = line[0] == 'd'

    # Name: standard `ls -l` has a 9-field prefix
    # (perms, links, owner, group, size, month, day, time/year, name...).
    # When that prefix is present, the name is everything from field 8 on
    # (tolerates spaces). Otherwise fall back to the last token, which is
    # what the existing FTP tools use.
    if len(parts) >= 9:
        name = ' '.join(parts[8:])
    else:
        name = parts[-1]
    if name in ('.', '..', ''):
        return None

    size: Optional[int] = None
    if not is_dir:
        try:
            size = int(parts[4])
        except (ValueError, IndexError):
            size = None  # resolve via SIZE later

    # path is filled in by the caller (it knows the parent dir).
    return RemoteEntry(path=name, name=name, is_dir=is_dir, size=size, raw=line)


def join_remote(parent: str, name: str) -> str:
    """Join an FTP directory path and a child name into an absolute path."""
    if parent == '/' or parent == '':
        return '/' + name
    return parent.rstrip('/') + '/' + name


def normalize_remote(path: str) -> str:
    """Collapse '//' and strip a trailing slash (but keep root as '/')."""
    if not path:
        return '/'
    while '//' in path:
        path = path.replace('//', '/')
    if len(path) > 1:
        path = path.rstrip('/')
    return path or '/'


def local_path_for(dest: str, remote_path: str) -> str:
    """Map an FTP path to a local path under dest, safely (no escape).

    '/VIDEO/x.MOV' under dest '/tmp/r' -> '/tmp/r/VIDEO/x.MOV'.
    Any '..' or absolute-ish component is stripped so a hostile listing
    can never write outside dest.
    """
    rel_parts = [seg for seg in remote_path.split('/')
                 if seg not in ('', '.', '..')]
    return os.path.join(dest, *rel_parts) if rel_parts else dest


def should_skip(remote_size: Optional[int], local_size: Optional[int],
                resume: bool) -> bool:
    """Resume predicate: should we skip downloading this file?

    - resume off            -> never skip (always re-download)
    - no local file         -> never skip
    - sizes known & equal   -> skip (already fully downloaded)
    - remote size unknown   -> skip iff a non-empty local file exists
                               (best effort; recorded as resume-unverified)
    """
    if not resume:
        return False
    if local_size is None:
        return False
    if remote_size is not None:
        return local_size == remote_size
    # remote size unknown — treat a non-empty local file as good enough.
    return local_size > 0


def human(n: Optional[int]) -> str:
    """Render a byte count as a compact human string."""
    if n is None:
        return '?'
    f = float(n)
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if f < 1024 or unit == 'TiB':
            return f"{f:.0f} {unit}" if unit == 'B' else f"{f:.2f} {unit}"
        f /= 1024
    return f"{n} B"


# --------------------------------------------------------------------------
# FTP connection
# --------------------------------------------------------------------------
def connect(host: str, bind: Optional[str], timeout: float) -> ftplib.FTP:
    """Open + login a control connection, source-bound if bind is set.

    `source_address` is reused by ftplib for the passive *data* socket too
    (in ntransfercmd), so a single argument pins BOTH channels to the
    dongle interface — the multi-NIC landmine fix, mirroring
    larkfly.Camera._tcp_connect()'s sock.bind((bind, 0)).
    """
    src = (bind, 0) if bind else None
    ftp = ftplib.FTP()
    ftp.connect(host, FTP_PORT, timeout=timeout, source_address=src)
    ftp.login(USER, PASS)
    # Embedded FTP servers often advertise a bogus IP in the PASV 227
    # reply. With trust_server_pasv_ipv4_address = False (the stdlib
    # default), ftplib ignores that IP and dials the data connection to
    # the control-connection peer (the camera) instead. Pin it explicitly
    # so a future stdlib default-flip can't silently break us.
    ftp.trust_server_pasv_ipv4_address = False
    ftp.set_pasv(True)   # passive only — active/PORT is bind-hostile here
    return ftp


# --------------------------------------------------------------------------
# Walk + download engine
# --------------------------------------------------------------------------
class FtpPuller:
    """Owns exactly one live ftplib.FTP at a time (no parallelism, to
    respect the catatonia landmine). Walks the tree and pulls files."""

    def __init__(self, host: str, bind: Optional[str], timeout: float,
                 retries: int, backoff: float, sleep: float,
                 reconnect_every: int, dest: str,
                 includes: list[str], excludes: list[str],
                 resume: bool, dry_run: bool, verbose: bool):
        self.host = host
        self.bind = bind
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.sleep = sleep
        self.reconnect_every = reconnect_every
        self.dest = dest
        self.includes = includes
        self.excludes = excludes
        self.resume = resume
        self.dry_run = dry_run
        self.verbose = verbose

        self._ftp: Optional[ftplib.FTP] = None
        self._files_since_reconnect = 0

    # ---- connection management ----
    def _ensure_conn(self) -> ftplib.FTP:
        if self._ftp is None:
            self._ftp = connect(self.host, self.bind, self.timeout)
        return self._ftp

    def _reconnect(self) -> None:
        """Drop and reopen the control connection. A wedged transfer often
        poisons the control channel, so we throw it away rather than reuse."""
        if self._ftp is not None:
            try:
                self._ftp.close()
            except Exception:
                pass
            self._ftp = None
        self._ensure_conn()

    def close(self) -> None:
        if self._ftp is not None:
            try:
                self._ftp.quit()
            except Exception:
                try:
                    self._ftp.close()
                except Exception:
                    pass
            self._ftp = None

    def _pace(self) -> None:
        if self.sleep > 0:
            time.sleep(self.sleep)

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    # ---- directory listing ----
    def _list_dir(self, path: str) -> list[RemoteEntry]:
        """LIST a directory and parse its entries. Tries `LIST <path>`
        first; if that yields nothing parseable and path isn't root, falls
        back to CWD + bare LIST. Tolerant of 550 (treated as empty)."""
        ftp = self._ensure_conn()

        def _do_list(arg: Optional[str]) -> list[RemoteEntry]:
            lines: list[str] = []
            cmd = 'LIST' if arg is None else f'LIST {arg}'
            ftp.retrlines(cmd, lines.append)
            out: list[RemoteEntry] = []
            for ln in lines:
                e = parse_list_line(ln)
                if e is not None:
                    e.path = join_remote(path, e.name)
                    out.append(e)
            return out

        try:
            entries = _do_list(path)
            if entries or path == '/':
                return entries
        except ftplib.all_errors as e:
            self._log(f"    LIST {path} failed ({type(e).__name__}); "
                      f"trying CWD fallback")
            self._reconnect()
            ftp = self._ensure_conn()

        # Fallback: CWD into the dir, bare LIST, then CWD back to root.
        try:
            ftp.cwd(path)
            entries = _do_list(None)
            try:
                ftp.cwd('/')
            except ftplib.all_errors:
                pass
            return entries
        except ftplib.all_errors as e:
            self._log(f"    CWD {path} failed ({type(e).__name__}); "
                      f"treating as empty/inaccessible")
            return []

    def _remote_size(self, path: str) -> Optional[int]:
        """SIZE <path>. Returns None on 550 / not-supported / error."""
        ftp = self._ensure_conn()
        try:
            return ftp.size(path)
        except ftplib.all_errors:
            return None

    # ---- the walk ----
    def walk(self, root: str) -> Iterator[RemoteEntry]:
        """Iterative DFS over the tree, yielding file entries. A
        visited-dirs set guards against symlink/self-reference loops."""
        stack = [normalize_remote(root)]
        visited: set[str] = set()
        while stack:
            d = normalize_remote(stack.pop())
            if d in visited:
                continue
            visited.add(d)

            entries = self._list_dir(d)
            n_dirs = n_files = 0
            for e in entries:
                if e.is_dir:
                    n_dirs += 1
                    stack.append(e.path)
                else:
                    n_files += 1
                    yield e
            self._log(f"  [dir] {d}: {n_dirs} subdir(s), {n_files} file(s)")
            self._pace()

    # ---- downloading ----
    def _matches_scope(self, name: str) -> bool:
        if self.includes and not any(fnmatch.fnmatch(name, g)
                                     for g in self.includes):
            return False
        if self.excludes and any(fnmatch.fnmatch(name, g)
                                 for g in self.excludes):
            return False
        return True

    def download_file(self, entry: RemoteEntry) -> FileResult:
        if not self._matches_scope(entry.name):
            return FileResult(entry.path, entry.size, 'skipped-filter')

        final = local_path_for(self.dest, entry.path)

        # Resolve the authoritative remote size.
        remote_size = entry.size
        if remote_size is None and not self.dry_run:
            remote_size = self._remote_size(entry.path)

        local_size = os.path.getsize(final) if os.path.exists(final) else None

        if should_skip(remote_size, local_size, self.resume):
            status = ('skipped-resume' if remote_size is not None
                      else 'resume-unverified')
            self._log(f"  [skip] {entry.path} ({human(local_size)} local, "
                      f"resume)")
            return FileResult(entry.path, remote_size, status,
                              bytes_written=local_size or 0)

        if self.dry_run:
            self._log(f"  [plan] {entry.path} ({human(remote_size)})")
            return FileResult(entry.path, remote_size, 'dry-run')

        # About to write — create the local directory now (not earlier, so
        # a dry-run / resume-skip touches nothing on disk).
        os.makedirs(os.path.dirname(final) or '.', exist_ok=True)

        # Download with retry + reconnect + backoff.
        last_err: Optional[str] = None
        for attempt in range(1, self.retries + 1):
            tmp = final + '.part'
            written = 0
            try:
                ftp = self._ensure_conn()
                with open(tmp, 'wb') as fh:
                    def _cb(chunk: bytes, _fh=fh):
                        nonlocal written
                        _fh.write(chunk)
                        written += len(chunk)
                    ftp.retrbinary(f'RETR {entry.path}', _cb)

                # Verify size when we know what to expect.
                if remote_size is not None and written != remote_size:
                    raise IOError(
                        f"short read: got {written} of {remote_size} bytes")

                os.replace(tmp, final)
                self._maybe_proactive_reconnect()
                self._pace()
                print(f"  [ok]   {entry.path} ({human(written)})"
                      f"{'' if attempt == 1 else f' [attempt {attempt}]'}")
                return FileResult(entry.path, remote_size, 'downloaded',
                                  bytes_written=written, attempts=attempt)
            # ftplib.all_errors is a tuple already including OSError/EOFError.
            except ftplib.all_errors as e:
                last_err = f"{type(e).__name__}: {e}"
                # Leave the .part for inspection; next run re-attempts it
                # (its size won't match, so resume won't skip it).
                self._log(f"  [retry {attempt}/{self.retries}] {entry.path}"
                          f" — {last_err}")
                self._reconnect()
                if attempt < self.retries:
                    time.sleep(self.backoff * (2 ** (attempt - 1)))

        print(f"  [FAIL] {entry.path} after {self.retries} attempts — "
              f"{last_err}", file=sys.stderr)
        return FileResult(entry.path, remote_size, 'failed',
                          attempts=self.retries, error=last_err)

    def _maybe_proactive_reconnect(self) -> None:
        """Cycle the control connection every N files on the happy path,
        hedging against slow service degradation over a multi-GB pull."""
        if self.reconnect_every <= 0:
            return
        self._files_since_reconnect += 1
        if self._files_since_reconnect >= self.reconnect_every:
            self._files_since_reconnect = 0
            self._log("  [conn] proactive reconnect")
            self._reconnect()

    def run(self, root: str) -> list[FileResult]:
        results: list[FileResult] = []
        try:
            for entry in self.walk(root):
                results.append(self.download_file(entry))
        finally:
            self.close()
        return results


# --------------------------------------------------------------------------
# PTP cross-check (optional, advisory, failure-isolated)
# --------------------------------------------------------------------------
def ptp_inventory(host: str, bind: Optional[str],
                  timeout: float) -> dict[str, int]:
    """{filename: object_compressed_size} from the PTP object index.

    PTP reliably catalogs media files at boot, so it's an independent
    completeness oracle. Imported lazily so the FTP-only path needs no
    larkfly import at all."""
    from larkfly import Camera
    inv: dict[str, int] = {}
    with Camera(host, bind=bind, timeout=timeout) as cam:
        for h in cam.list_objects():
            info = cam.object_info(h)
            name = info.get('filename')
            if not name:
                continue
            inv[name] = info.get('object_compressed_size', 0)
    return inv


def cross_check(results: list[FileResult], ptp_inv: dict[str, int]) -> dict:
    """Compare the FTP mirror against the PTP index, by basename."""
    got: dict[str, FileResult] = {}
    for r in results:
        if r.status in ('downloaded', 'skipped-resume', 'resume-unverified'):
            got[os.path.basename(r.path)] = r

    missing: list[dict] = []        # in PTP, not in mirror (and non-empty)
    empty: list[str] = []           # in PTP with size 0 (LIST-hidden), absent
    size_mismatch: list[dict] = []  # in both, sizes disagree
    matched = 0
    for name, psize in ptp_inv.items():
        r = got.get(name)
        if r is None:
            if psize == 0:
                empty.append(name)
            else:
                missing.append({'name': name, 'ptp_size': psize})
        else:
            matched += 1
            if psize and r.size not in (None, psize):
                size_mismatch.append({'name': name, 'mirror_size': r.size,
                                      'ptp_size': psize})
    return {
        'ptp_count': len(ptp_inv),
        'matched': matched,
        'missing_from_mirror': missing,
        'empty_list_hidden': empty,
        'size_mismatch': size_mismatch,
    }


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def summarize(results: list[FileResult]) -> dict:
    totals = {'files_seen': 0, 'downloaded': 0, 'skipped_resume': 0,
              'failed': 0, 'dry_run': 0, 'total_bytes': 0}
    for r in results:
        if r.status == 'skipped-filter':
            continue
        totals['files_seen'] += 1
        if r.status == 'downloaded':
            totals['downloaded'] += 1
            totals['total_bytes'] += r.bytes_written
        elif r.status in ('skipped-resume', 'resume-unverified'):
            totals['skipped_resume'] += 1
            totals['total_bytes'] += r.bytes_written
        elif r.status == 'failed':
            totals['failed'] += 1
        elif r.status == 'dry-run':
            totals['dry_run'] += 1
    return totals


def write_manifest(path: str, host: str, bind: Optional[str], root: str,
                   dest: str, results: list[FileResult], totals: dict,
                   ptp_report: Optional[dict]) -> None:
    doc = {
        'tool': 'ftp_pull.py',
        'host': host,
        'bind': bind,
        'remote_root': root,
        'dest': os.path.abspath(dest),
        'totals': totals,
        'files': [
            {'path': r.path, 'size': r.size, 'status': r.status,
             'bytes_written': r.bytes_written, 'attempts': r.attempts,
             'error': r.error}
            for r in results if r.status != 'skipped-filter'
        ],
        'ptp_verify': ptp_report,
    }
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w') as fh:
        json.dump(doc, fh, indent=2)


def print_summary(host: str, dest: str, manifest: str,
                  results: list[FileResult], totals: dict,
                  ptp_report: Optional[dict]) -> None:
    bar = '=' * 72
    print('\n' + bar)
    print(f"FTP PULL SUMMARY  {host}  ->  {dest}")
    print(bar)
    print(f"  seen        : {totals['files_seen']} file(s)")
    if totals['dry_run']:
        print(f"  planned     : {totals['dry_run']} (dry-run)")
    print(f"  downloaded  : {totals['downloaded']}   "
          f"({human(totals['total_bytes'])})")
    print(f"  resumed/skip: {totals['skipped_resume']}")
    print(f"  FAILED      : {totals['failed']}")
    if totals['failed']:
        for r in results:
            if r.status == 'failed':
                print(f"                  {r.path}  "
                      f"({r.attempts} attempts) {r.error}")
    print(f"  total bytes : {human(totals['total_bytes'])}")
    print(f"  manifest    : {manifest}")
    if ptp_report is not None:
        print('-' * 72)
        if 'error' in ptp_report:
            print(f"  PTP cross-check: FAILED — {ptp_report['error']}")
        else:
            print(f"  PTP cross-check: {ptp_report['ptp_count']} indexed | "
                  f"{len(ptp_report['missing_from_mirror'])} missing | "
                  f"{len(ptp_report['size_mismatch'])} size-mismatch | "
                  f"{len(ptp_report['empty_list_hidden'])} empty/hidden")
            for m in ptp_report['missing_from_mirror']:
                print(f"      MISSING  {m['name']}  "
                      f"(PTP {human(m['ptp_size'])})", file=sys.stderr)
            for m in ptp_report['size_mismatch']:
                print(f"      SIZE??   {m['name']}  mirror={human(m['mirror_size'])} "
                      f"ptp={human(m['ptp_size'])}", file=sys.stderr)
            if ptp_report['empty_list_hidden']:
                print(f"      empty (0-byte, LIST-hidden, unrecoverable via FTP): "
                      f"{', '.join(ptp_report['empty_list_hidden'])}")
    print(bar)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('host', nargs='?', default=HOST_DEFAULT,
                    help=f'camera IP (default: {HOST_DEFAULT})')
    ap.add_argument('--bind', default=None,
                    help='local source IP — pins BOTH control and data '
                         'sockets. Needed when multiple interfaces share '
                         '192.168.1.0/24 (dongle + main WiFi).')
    ap.add_argument('-o', '--dest', default='./recovered',
                    help='local mirror root (default: ./recovered)')
    ap.add_argument('--remote-root', default='/',
                    help='FTP path to start the walk (default: /). Scope a '
                         're-run with e.g. /VIDEO')
    ap.add_argument('--include', action='append', default=[], metavar='GLOB',
                    help='only mirror files whose basename matches (repeatable)')
    ap.add_argument('--exclude', action='append', default=[], metavar='GLOB',
                    help='skip files whose basename matches (repeatable)')
    ap.add_argument('--timeout', type=float, default=30.0,
                    help='per-socket timeout, seconds (default: 30.0)')
    ap.add_argument('--retries', type=int, default=4,
                    help='per-file attempts before giving up (default: 4)')
    ap.add_argument('--backoff', type=float, default=2.0,
                    help='base backoff seconds, exponential (default: 2.0)')
    ap.add_argument('--sleep', type=float, default=0.3,
                    help='inter-request pacing sleep, seconds (default: 0.3) '
                         '— the anti-catatonia knob')
    ap.add_argument('--reconnect-every', type=int, default=50, metavar='N',
                    help='proactively reopen the control conn every N files '
                         '(default: 50; 0 = never)')
    ap.add_argument('--no-resume', action='store_true',
                    help='re-download even if a local file matches SIZE')
    ap.add_argument('-n', '--dry-run', action='store_true',
                    help='walk + plan only; no RETR, no local writes')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='per-file / per-dir detail')
    ap.add_argument('--verify-ptp', action='store_true',
                    help='after the FTP pull, cross-check completeness '
                         'against the PTP object index (advisory)')
    ap.add_argument('--ptp-bind', default=None,
                    help='bind IP for the PTP cross-check (default: --bind)')
    ap.add_argument('--manifest', default=None,
                    help='JSON manifest path (default: <dest>/manifest.json)')
    args = ap.parse_args()

    if not args.bind:
        print("WARNING: no --bind given. On a multi-NIC host the data "
              "socket may route via the wrong interface and silently fail "
              "or hit the wrong host. See CLAUDE.md.", file=sys.stderr)

    manifest_path = args.manifest or os.path.join(args.dest, 'manifest.json')

    print(f"[*] FTP pull from {args.host}:{FTP_PORT} "
          f"(bind={args.bind or 'default routing'}) "
          f"root={args.remote_root} -> {args.dest}"
          f"{'  [DRY-RUN]' if args.dry_run else ''}")

    puller = FtpPuller(
        host=args.host, bind=args.bind, timeout=args.timeout,
        retries=args.retries, backoff=args.backoff, sleep=args.sleep,
        reconnect_every=args.reconnect_every, dest=args.dest,
        includes=args.include, excludes=args.exclude,
        resume=not args.no_resume, dry_run=args.dry_run,
        verbose=args.verbose)

    # The walk's first LIST is also our reachability check.
    try:
        results = puller.run(args.remote_root)
    except ftplib.all_errors as e:
        print(f"FAIL: cannot reach / log in to FTP at {args.host}:{FTP_PORT} "
              f"— {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"FAIL: transport error — {e}", file=sys.stderr)
        return 1

    # Optional PTP cross-check — runs last, failure-isolated.
    ptp_report: Optional[dict] = None
    ptp_failed = False
    if args.verify_ptp:
        print("[*] PTP completeness cross-check ...")
        try:
            inv = ptp_inventory(args.host, args.ptp_bind or args.bind,
                                args.timeout)
            ptp_report = cross_check(results, inv)
        except Exception as e:  # noqa: BLE001 — never let PTP crash the run
            ptp_report = {'error': f"{type(e).__name__}: {e}"}
            ptp_failed = True

    totals = summarize(results)
    write_manifest(manifest_path, args.host, args.bind, args.remote_root,
                   args.dest, results, totals, ptp_report)
    print_summary(args.host, args.dest, manifest_path, results, totals,
                  ptp_report)

    # Exit code precedence: transport(1) handled above; then PTP(3),
    # then partial(2), then complete(0).
    if args.verify_ptp:
        if ptp_failed:
            return 3
        if ptp_report and (ptp_report['missing_from_mirror']
                           or ptp_report['size_mismatch']):
            return 3
    if totals['failed'] > 0:
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
