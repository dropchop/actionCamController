#!/usr/bin/env python3
"""Exhaustive — but camera-friendly — RTSP-port exploration of a Larkfly
A6+ (iCatch V11) camera.

The Larkfly's RTSP server (TCP 554) is fragile: certain DESCRIBE targets
freeze the service hard enough that the camera needs a power-cycle to
recover. This probe is built around that constraint:

- Health-check before every request (fast 1.5 s TCP SYN to :554).
- Stop the moment the camera stops responding; save what we have.
- Resume mode: re-run with --resume to skip labels we already succeeded
  on, so a multi-reset campaign can finish over several power-cycles.
- Sections can be run individually with --only <name> so you can map the
  least-risky surface first.

Sections (run in this order by default):
    info        OPTIONS *, OPTIONS rtsp://host/MJPG, DESCRIBE /MJPG
    session     SETUP + PLAY + GET_PARAMETER + TEARDOWN on /MJPG
    params      16 parameter combinations on /MJPG
    playback    DESCRIBE rtsp://host/VIDEO/<file>.MOV (auto-discovers via FTP)
    paths       38 alternate stream paths (the risky one — runs last)
    verbs       12 RTSP verbs + 2 malformed requests
    concurrency 4 parallel DESCRIBE /MJPG
    media       ffprobe RTSP-TCP stream metadata

Usage:
    # Run everything, crash-safe:
    python3 tools/rtsp_probe.py --host 192.168.1.1 --bind 192.168.1.10

    # After a camera reset, pick up where we left off:
    python3 tools/rtsp_probe.py --resume

    # Only the safe sections (skip path/verb fuzzing):
    python3 tools/rtsp_probe.py --only info,session,params,playback,media
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import ftplib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field

DEFAULT_PORT = 554
DEFAULT_TIMEOUT = 3.0
HEALTH_TIMEOUT = 1.5
PACE_SLEEP = 0.25
UA = "larkfly-rtsp-probe/1.1"

SECTIONS_DEFAULT = ["info", "session", "params", "playback",
                    "paths_options", "paths", "verbs", "concurrency", "media"]


@dataclass
class Exchange:
    label: str
    section: str
    request: str
    status: int | None
    reason: str
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    error: str | None = None


@dataclass
class Report:
    host: str
    bind: str | None
    started_at: str
    finished_at: str | None = None
    sections_run: list[str] = field(default_factory=list)
    exchanges: list[Exchange] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    media_probe: dict | None = None
    concurrency_probe: dict | None = None
    aborted_at: str | None = None
    aborted_reason: str | None = None


def health_check(host: str, port: int, bind: str | None,
                 timeout: float = HEALTH_TIMEOUT) -> bool:
    """Fast TCP SYN test; returns True if the RTSP port answers."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if bind:
        with contextlib.suppress(OSError):
            s.bind((bind, 0))
    try:
        s.connect((host, port))
        return True
    except (OSError, socket.timeout):
        return False
    finally:
        with contextlib.suppress(OSError):
            s.close()


def rtsp_exchange(host: str, port: int, bind: str | None, request: str, *,
                  timeout: float = DEFAULT_TIMEOUT, label: str = "",
                  section: str = "", sock: socket.socket | None = None) -> Exchange:
    """Send one RTSP request and parse the reply. If `sock` is given,
    reuse it (for session-bound SETUP/PLAY/TEARDOWN sequences)."""
    start = time.perf_counter()
    err: str | None = None
    status: int | None = None
    reason = ""
    headers: dict[str, str] = {}
    body = ""
    owns_sock = sock is None
    try:
        if owns_sock:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if bind:
                sock.bind((bind, 0))
            sock.connect((host, port))
        sock.sendall(request.encode("utf-8"))
        buf = b""
        sock.settimeout(timeout)
        while b"\r\n\r\n" not in buf:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) > 1024 * 256:
                break
        head, _, rest = buf.partition(b"\r\n\r\n")
        if head:
            lines = head.decode("latin-1", errors="replace").split("\r\n")
            first = lines[0] if lines else ""
            parts = first.split(" ", 2)
            if len(parts) >= 2:
                with contextlib.suppress(ValueError):
                    status = int(parts[1])
                reason = parts[2] if len(parts) == 3 else ""
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip()] = v.strip()
        content_len = int(headers.get("Content-Length", "0") or "0")
        body_bytes = rest
        while len(body_bytes) < content_len:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            body_bytes += chunk
        body = body_bytes.decode("latin-1", errors="replace")
    except Exception as e:  # noqa: BLE001
        err = f"{type(e).__name__}: {e}"
    finally:
        if owns_sock and sock is not None:
            with contextlib.suppress(OSError):
                sock.close()
    elapsed = (time.perf_counter() - start) * 1000
    return Exchange(label=label, section=section, request=request,
                    status=status, reason=reason, headers=headers, body=body,
                    elapsed_ms=round(elapsed, 1), error=err)


def build(method: str, url: str, cseq: int, extra: dict[str, str] | None = None,
          body: str = "") -> str:
    lines = [f"{method} {url} RTSP/1.0",
             f"CSeq: {cseq}",
             f"User-Agent: {UA}"]
    if extra:
        for k, v in extra.items():
            lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return "\r\n".join(lines) + "\r\n\r\n" + body


# --- Probe sections -----------------------------------------------------------

class Probe:
    def __init__(self, args, report: Report, done_labels: set[str]):
        self.args = args
        self.report = report
        self.done = done_labels
        self.cseq = 1 + max(
            (int(re.search(r"CSeq:\s*(\d+)", e.request).group(1))
             for e in report.exchanges
             if re.search(r"CSeq:\s*(\d+)", e.request)),
            default=0,
        )
        self.host = args.host
        self.port = args.port
        self.bind = args.bind
        self.consecutive_timeouts = 0
        self.aborted = False

    def _next_cseq(self) -> int:
        c = self.cseq
        self.cseq += 1
        return c

    def _save(self) -> None:
        write_outputs(self.report, self.args.json_out, self.args.md_out)

    def _abort(self, reason: str) -> None:
        self.aborted = True
        self.report.aborted_at = datetime.datetime.now().isoformat(timespec="seconds")
        self.report.aborted_reason = reason
        print(f"\n[!!] ABORT: {reason}\n[!!] Camera likely needs a power-cycle.")
        print(f"[!!] Re-run with --resume after reset to continue.")
        self._save()

    def _do(self, label: str, section: str, request: str,
            sock: socket.socket | None = None) -> Exchange | None:
        if self.aborted:
            return None
        if label in self.done:
            print(f"    [skip already-done] {label}")
            return None
        if not health_check(self.host, self.port, self.bind):
            self._abort(f"Health-check failed before {label!r}")
            return None
        ex = rtsp_exchange(self.host, self.port, self.bind, request,
                           timeout=self.args.timeout,
                           label=label, section=section, sock=sock)
        self.report.exchanges.append(ex)
        self.done.add(label)
        # Pretty-print
        status_str = f"{ex.status} {ex.reason}" if ex.status else f"(no reply, {ex.elapsed_ms:.0f}ms)"
        print(f"    {label} -> {status_str}")
        # Save after each request — crash-safe
        self._save()
        # Heuristic: a real camera-wedge produces a true timeout (elapsed
        # near `args.timeout`). A short no-parse response (e.g. binary RTP
        # interleaved data after a PLAY) is something different — don't
        # treat it as a wedge.
        wedge_threshold_ms = self.args.timeout * 800  # 0.8 × timeout in ms
        if ex.status is None and ex.elapsed_ms >= wedge_threshold_ms:
            self.consecutive_timeouts += 1
            if self.consecutive_timeouts >= self.args.max_consecutive_timeouts:
                self._abort(f"{self.consecutive_timeouts} consecutive wedge-timeouts")
        else:
            self.consecutive_timeouts = 0
        time.sleep(PACE_SLEEP)
        return ex

    # -- info -----------------------------------------------------------------
    def section_info(self) -> None:
        print("[info] OPTIONS + known-good DESCRIBE")
        self._do("info:options-mjpg", "info",
                 build("OPTIONS", f"rtsp://{self.host}/MJPG", self._next_cseq()))
        if self.aborted:
            return
        self._do("info:options-star", "info",
                 build("OPTIONS", "*", self._next_cseq()))
        if self.aborted:
            return
        self._do("info:describe-mjpg", "info",
                 build("DESCRIBE", f"rtsp://{self.host}/MJPG", self._next_cseq(),
                       extra={"Accept": "application/sdp"}))

    # -- session: SETUP + control-plane verbs + TEARDOWN ----------------------
    def section_session(self) -> None:
        """Test the RTSP session lifecycle WITHOUT triggering PLAY —
        once the camera starts interleaving RTP frames on the control
        socket, text-mode parsing is no longer reliable. PLAY is verified
        separately in `section_media` via ffprobe."""
        print("[session] SETUP + control-plane verbs + TEARDOWN")
        if not health_check(self.host, self.port, self.bind):
            self._abort("Health-check failed before session setup")
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.args.timeout)
        if self.bind:
            sock.bind((self.bind, 0))
        try:
            sock.connect((self.host, self.port))
        except OSError as e:
            self._abort(f"Cannot connect for session: {e}")
            return
        try:
            ex = self._do(
                "session:setup-track1", "session",
                build("SETUP", f"rtsp://{self.host}/MJPG/track1",
                      self._next_cseq(),
                      extra={"Transport": "RTP/AVP/TCP;unicast;interleaved=0-1"}),
                sock=sock,
            )
            if self.aborted or ex is None or ex.status != 200:
                return
            session_id = ex.headers.get("Session", "").split(";", 1)[0].strip()
            if not session_id:
                self.report.notes.append("SETUP returned 200 but no Session: header")
                return
            self.report.notes.append(f"Session id from SETUP: {session_id}")

            self._do(
                "session:get-parameter-empty", "session",
                build("GET_PARAMETER", f"rtsp://{self.host}/MJPG",
                      self._next_cseq(), extra={"Session": session_id}),
                sock=sock,
            )
            if self.aborted:
                return

            body = "position\nbandwidth\nscale\nclock\n"
            self._do(
                "session:get-parameter-named", "session",
                build("GET_PARAMETER", f"rtsp://{self.host}/MJPG",
                      self._next_cseq(),
                      extra={"Session": session_id,
                             "Content-Type": "text/parameters"},
                      body=body),
                sock=sock,
            )
            if self.aborted:
                return

            # Try SET_PARAMETER for a typically-allowed key
            self._do(
                "session:set-parameter-bandwidth", "session",
                build("SET_PARAMETER", f"rtsp://{self.host}/MJPG",
                      self._next_cseq(),
                      extra={"Session": session_id,
                             "Content-Type": "text/parameters"},
                      body="bandwidth: 5000000\r\n"),
                sock=sock,
            )
            if self.aborted:
                return

            self._do(
                "session:teardown", "session",
                build("TEARDOWN", f"rtsp://{self.host}/MJPG",
                      self._next_cseq(), extra={"Session": session_id}),
                sock=sock,
            )
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    # -- params ---------------------------------------------------------------
    def section_params(self) -> None:
        """DESCRIBE /MJPG with query parameters. Ordered from safest
        (documented webui combo) to riskiest (off-spec values). Each
        request runs with an extended timeout — slow generation is not
        the same as a wedge, but the previous run showed 320x240 does
        in fact wedge the server hard."""
        print("[params] Parameter exploration on /MJPG")
        probes: list[dict] = [
            {},                                                          # bare
            {"W": 720, "H": 400, "Q": 50, "BR": 5_000_000},              # webui default — KNOWN-GOOD
            {"W": 720, "H": 400, "Q": 50, "BR": 5_000_000, "FPS": 30},   # add FPS
            {"W": 720, "H": 400, "Q": 100, "BR": 5_000_000},             # max Q
            {"W": 720, "H": 400, "Q": 1, "BR": 5_000_000},               # min Q
            {"W": 1280, "H": 720, "Q": 50, "BR": 5_000_000},             # 720p
            {"W": 1920, "H": 1080, "Q": 50, "BR": 10_000_000},           # 1080p
            {"W": 640, "H": 480, "Q": 50, "BR": 1_000_000},              # VGA
            {"W": 320, "H": 240, "Q": 50, "BR": 500_000},                # QVGA — known to wedge
            {"W": 1920, "H": 1080, "Q": 100, "BR": 50_000_000},          # max-everything
            {"W": 720, "H": 400, "Q": 50, "BR": 5_000_000, "FORMAT": "H264"},
            {"W": 720, "H": 400, "Q": 50, "BR": 5_000_000, "FORMAT": "MJPEG"},
            {"W": 720, "H": 400, "Q": 50, "BR": 5_000_000, "AUDIO": 1},
            {"W": 720, "H": 400, "Q": 50, "BR": 5_000_000, "GOP": 30},
            {"W": 0, "H": 0, "Q": 50, "BR": 5_000_000},
            {"W": 99999, "H": 99999, "Q": 50, "BR": 5_000_000},
        ]
        # DESCRIBE-with-params is slow on the server — give it room.
        saved_timeout = self.args.timeout
        self.args.timeout = max(saved_timeout, 8.0)
        try:
            for p in probes:
                if self.aborted:
                    break
                qs = "?" + "&".join(f"{k}={v}" for k, v in p.items()) if p else ""
                label = f"params:{','.join(f'{k}={v}' for k, v in p.items()) or 'bare'}"
                url = f"rtsp://{self.host}/MJPG{qs}"
                self._do(label, "params",
                         build("DESCRIBE", url, self._next_cseq(),
                               extra={"Accept": "application/sdp"}))
        finally:
            self.args.timeout = saved_timeout

    # -- playback /VIDEO/<file> -----------------------------------------------
    def section_playback(self) -> None:
        print("[playback] /VIDEO/<file>.MOV via FTP-discovered filename")
        fname = self.args.filename
        if not fname:
            fname = ftp_discover_mov(self.host)
            self.report.notes.append(f"FTP auto-discover .MOV: {fname or 'failed'}")
        if not fname:
            print("    (no file found via FTP — skipping)")
            return
        url = f"rtsp://{self.host}/VIDEO/{fname}"
        self._do(f"playback:{fname}", "playback",
                 build("DESCRIBE", url, self._next_cseq(),
                       extra={"Accept": "application/sdp"}))

    # -- paths via OPTIONS (low-risk pre-check) -------------------------------
    def section_paths_options(self) -> None:
        """Map paths via OPTIONS rather than DESCRIBE. Earlier work showed
        the camera ignores the URI on OPTIONS (Public: header is identical
        for /MJPG and *), so this almost certainly returns 200 OK for any
        path — but it's worth confirming, and any path that returns 404
        or wedges is informative."""
        print("[paths-options] OPTIONS rtsp://host/<path> enumeration")
        wordlist = [
            "H264", "H265", "AVC", "HEVC",
            "MAIN", "SUB", "MAIN0", "SUB0",
            "PREVIEW", "LIVE", "STREAM", "STREAM1",
            "VIDEO", "AUDIO",
            "0", "1", "ch0", "ch1",
            "ICATCH", "CAM", "CAM0",
            "MJPEG", "JPG",
            "nonexistent_dummy_path",
        ]
        for path in wordlist:
            if self.aborted:
                break
            url = f"rtsp://{self.host}/{path}"
            self._do(f"paths-options:/{path}", "paths-options",
                     build("OPTIONS", url, self._next_cseq()))

    # -- paths (the dangerous one) --------------------------------------------
    def section_paths(self) -> None:
        print("[paths] Alternate stream-path enumeration (HIGH-RISK)")
        wordlist = [
            "", "H264", "H265", "AVC", "HEVC",
            "MAIN", "SUB", "MAIN0", "SUB0",
            "PREVIEW", "LIVE", "STREAM", "STREAM1", "stream0",
            "VIDEO", "AUDIO",
            "HQ", "LQ", "MQ",
            "0", "1", "ch0", "ch1", "track1",
            "ICATCH", "CAM", "CAM0", "CAM1",
            "REC", "PROXY", "MEDIA",
            "MJPEG", "JPG", "JPEG",
            "live.sdp", "media.sdp",
        ]
        for path in wordlist:
            if self.aborted:
                break
            url = f"rtsp://{self.host}/{path}" if path else f"rtsp://{self.host}"
            self._do(f"paths:/{path or '(empty)'}", "paths",
                     build("DESCRIBE", url, self._next_cseq(),
                           extra={"Accept": "application/sdp"}))

    # -- verbs ----------------------------------------------------------------
    def section_verbs(self) -> None:
        print("[verbs] Verb fuzzing")
        verbs = ["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "PAUSE", "TEARDOWN",
                 "GET_PARAMETER", "SET_PARAMETER",
                 "ANNOUNCE", "RECORD", "REDIRECT", "REGISTER"]
        for v in verbs:
            if self.aborted:
                break
            self._do(f"verbs:{v}", "verbs",
                     build(v, f"rtsp://{self.host}/MJPG", self._next_cseq(),
                           extra={"Accept": "application/sdp"}))
        for label, raw in [
            ("verbs:garbage-method",
             f"INVALID_METHOD rtsp://{self.host}/MJPG RTSP/1.0\r\nCSeq: {self._next_cseq()}\r\n\r\n"),
            ("verbs:garbage-version",
             f"OPTIONS rtsp://{self.host}/ RTSP/9.9\r\nCSeq: {self._next_cseq()}\r\n\r\n"),
        ]:
            if self.aborted:
                break
            self._do(label, "verbs", raw)

    # -- concurrency ----------------------------------------------------------
    def section_concurrency(self) -> None:
        if "concurrency" in {e.section for e in self.report.exchanges}:
            print("[concurrency] already recorded — skipping")
            return
        print("[concurrency] 4 parallel DESCRIBEs")
        if not health_check(self.host, self.port, self.bind):
            self._abort("Health-check failed before concurrency")
            return
        results: list[Exchange | None] = [None] * 4

        def worker(i: int) -> None:
            req = build("DESCRIBE", f"rtsp://{self.host}/MJPG",
                        100 + i, extra={"Accept": "application/sdp"})
            results[i] = rtsp_exchange(self.host, self.port, self.bind, req,
                                       timeout=self.args.timeout,
                                       label=f"concurrency:worker{i}",
                                       section="concurrency")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        t0 = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wall = (time.perf_counter() - t0) * 1000
        self.report.concurrency_probe = {
            "workers": 4,
            "wall_ms": round(wall, 1),
            "results": [asdict(r) for r in results if r is not None],
        }
        self.report.exchanges.extend(r for r in results if r is not None)
        statuses = [r.status if r else "no-result" for r in results]
        print(f"    wall={wall:.0f}ms statuses={statuses}")
        self._save()

    # -- media (ffprobe) ------------------------------------------------------
    def section_media(self) -> None:
        if "media" in self.report.sections_run:
            print("[media] already recorded — skipping")
            return
        print("[media] ffprobe -rtsp_transport tcp")
        if not health_check(self.host, self.port, self.bind):
            self._abort("Health-check failed before media probe")
            return
        self.report.media_probe = ffprobe_stream(
            f"rtsp://{self.host}/MJPG", self.bind, transport="tcp", duration=4.0
        )
        print(f"    exit={self.report.media_probe.get('returncode')}")
        self._save()


# --- helpers -----------------------------------------------------------------

def ftp_discover_mov(host: str) -> str | None:
    """Pick an arbitrary .MOV from /VIDEO via FTP.  The iCatch FTP
    server doesn't implement NLST cleanly — it answers LIST but returns
    empty on NLST — so we parse the LIST output ourselves."""
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, 21, timeout=4)
        ftp.login("wificam", "wificam")
        ftp.cwd("/VIDEO")
        lines: list[str] = []
        ftp.retrlines("LIST", lines.append)
        ftp.quit()
        for line in lines:
            tok = line.rsplit(None, 1)[-1] if line.split() else ""
            if tok.upper().endswith((".MOV", ".MP4")):
                return tok
    except Exception:
        return None
    return None


def ffprobe_stream(url: str, bind: str | None, transport: str = "tcp",
                   duration: float = 3.0) -> dict:
    if not shutil.which("ffprobe"):
        return {"available": False}
    cmd = ["ffprobe", "-hide_banner", "-v", "error",
           "-rtsp_transport", transport,
           "-stimeout", str(int(duration * 1_000_000)),
           "-print_format", "json", "-show_streams", "-show_format", url]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 4)
        result = {"available": True, "transport": transport,
                  "returncode": proc.returncode,
                  "stderr": proc.stderr.strip()[:2000]}
        if proc.stdout.strip():
            with contextlib.suppress(json.JSONDecodeError):
                result["streams"] = json.loads(proc.stdout)
        return result
    except subprocess.TimeoutExpired:
        return {"available": True, "transport": transport, "error": "timeout"}


def write_outputs(report: Report, json_path: str, md_path: str) -> None:
    os.makedirs(os.path.dirname(json_path) or ".", exist_ok=True)
    payload = {
        "host": report.host, "bind": report.bind,
        "started_at": report.started_at, "finished_at": report.finished_at,
        "aborted_at": report.aborted_at, "aborted_reason": report.aborted_reason,
        "sections_run": report.sections_run, "notes": report.notes,
        "exchanges": [asdict(e) for e in report.exchanges],
        "media_probe": report.media_probe,
        "concurrency_probe": report.concurrency_probe,
    }
    with open(json_path, "w") as f:
        json.dump(payload, f, indent=2)
    os.makedirs(os.path.dirname(md_path) or ".", exist_ok=True)
    write_markdown(report, md_path)


def write_markdown(report: Report, path: str) -> None:
    lines: list[str] = []
    lines.append("# RTSP (TCP 554) — full surface map\n")
    lines.append("Output of `tools/rtsp_probe.py`. The Larkfly RTSP server "
                 "is fragile (some DESCRIBE targets freeze the camera hard "
                 "enough to need a power cycle), so the probe runs with a "
                 "health-check between every request and aborts on the first "
                 "lockup. Re-run with `--resume` after a reset to continue.\n")
    lines.append(f"- Host: `{report.host}`")
    lines.append(f"- Bind: `{report.bind or '(any)'}`")
    lines.append(f"- Run started: {report.started_at}")
    lines.append(f"- Run finished: {report.finished_at or '(in progress / aborted)'}")
    if report.aborted_at:
        lines.append(f"- **Aborted:** {report.aborted_at} — {report.aborted_reason}")
    lines.append("")

    server_hdr = ""
    public_hdr = ""
    for ex in report.exchanges:
        if ex.section == "info" and ex.headers:
            server_hdr = server_hdr or ex.headers.get("Server", "")
            public_hdr = public_hdr or ex.headers.get("Public", "")
    lines.append("## Server identity\n")
    lines.append(f"- `Server:` header — `{server_hdr or '(none — header absent)'}`")
    lines.append(f"- `Public:` header — `{public_hdr or '(only seen on OPTIONS *)'}`\n")

    by_section: dict[str, list[Exchange]] = {}
    for ex in report.exchanges:
        by_section.setdefault(ex.section or "other", []).append(ex)

    titles = {
        "info": "OPTIONS / known-good DESCRIBE",
        "session": "RTSP session — SETUP + GET_PARAMETER + SET_PARAMETER + TEARDOWN",
        "params": "Parameter exploration on /MJPG",
        "playback": "Playback of recorded files — /VIDEO/<file>",
        "paths-options": "Path enumeration via OPTIONS (low-risk)",
        "paths": "Path enumeration via DESCRIBE (wedge-prone)",
        "verbs": "Verb behaviour",
        "concurrency": "Concurrent DESCRIBE",
    }
    for key in ["info", "session", "params", "playback", "paths-options", "paths", "verbs", "concurrency"]:
        if key not in by_section:
            continue
        lines.append(f"## {titles.get(key, key)}\n")
        lines.append("| Label | Status | Reason | Elapsed | Highlight |")
        lines.append("|---|---|---|---|---|")
        for ex in by_section[key]:
            note = ex.error or ""
            if not note and ex.body:
                for body_line in ex.body.splitlines():
                    if body_line.startswith("m=") or body_line.startswith("a=rtpmap") or body_line.startswith("a=fmtp"):
                        note = body_line[:80]
                        break
            lines.append(f"| `{ex.label}` | {ex.status} | {ex.reason} | "
                         f"{ex.elapsed_ms:.0f}ms | {note} |")
        lines.append("")

    lines.append("## Media flow (ffprobe over RTSP-TCP)\n")
    if report.media_probe is None:
        lines.append("Not run yet.\n")
    elif not report.media_probe.get("available"):
        lines.append("ffprobe not on PATH.\n")
    else:
        lines.append("```json")
        lines.append(json.dumps(report.media_probe, indent=2)[:4000])
        lines.append("```\n")

    if report.notes:
        lines.append("## Notes\n")
        for n in report.notes:
            lines.append(f"- {n}")
        lines.append("")

    for ex in report.exchanges:
        if ex.label == "info:describe-mjpg" and ex.body:
            lines.append("## SDP body — `DESCRIBE /MJPG`\n")
            lines.append("```")
            lines.append(ex.body.strip())
            lines.append("```\n")
            break

    with open(path, "w") as f:
        f.write("\n".join(lines))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="192.168.1.1")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--bind", default="192.168.1.10")
    ap.add_argument("--filename", default=None,
                    help="Specific .MOV for playback test (else FTP-discovered)")
    ap.add_argument("--json-out", default="analyses/data/rtsp_probe.json")
    ap.add_argument("--md-out", default="analyses/data/rtsp_probe.md")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--max-consecutive-timeouts", type=int, default=1,
                    help="Abort after this many consecutive no-reply requests")
    ap.add_argument("--only", default=",".join(SECTIONS_DEFAULT),
                    help="Comma-separated list of sections to run")
    ap.add_argument("--resume", action="store_true",
                    help="Load existing JSON and skip already-completed labels")
    args = ap.parse_args()

    report = Report(host=args.host, bind=args.bind,
                    started_at=datetime.datetime.now().isoformat(timespec="seconds"))
    done_labels: set[str] = set()

    if args.resume and os.path.exists(args.json_out):
        with open(args.json_out) as f:
            prev = json.load(f)
        report.started_at = prev.get("started_at", report.started_at)
        report.notes = prev.get("notes", [])
        report.sections_run = prev.get("sections_run", [])
        report.media_probe = prev.get("media_probe")
        report.concurrency_probe = prev.get("concurrency_probe")
        for e in prev.get("exchanges", []):
            ex = Exchange(**e)
            report.exchanges.append(ex)
            if ex.status is not None or ex.error is None:
                # Anything that completed (success OR clean error) we won't redo;
                # only no-reply timeouts get retried.
                if ex.status is not None:
                    done_labels.add(ex.label)
        # Reset abort marker so we can retry
        report.aborted_at = None
        report.aborted_reason = None
        print(f"[resume] Loaded {len(report.exchanges)} prior exchanges; "
              f"{len(done_labels)} labels marked done.")

    print(f"[*] {args.host}:{args.port} bind={args.bind or 'any'} "
          f"timeout={args.timeout}s max-fails={args.max_consecutive_timeouts}")

    sections = [s.strip() for s in args.only.split(",") if s.strip()]
    probe = Probe(args, report, done_labels)

    for section in sections:
        method = getattr(probe, f"section_{section}", None)
        if method is None:
            print(f"[!] Unknown section: {section}")
            continue
        if probe.aborted:
            break
        method()
        if section not in report.sections_run and not probe.aborted:
            report.sections_run.append(section)

    if not probe.aborted:
        report.finished_at = datetime.datetime.now().isoformat(timespec="seconds")
    write_outputs(report, args.json_out, args.md_out)
    print(f"[+] JSON: {args.json_out}")
    print(f"[+] Markdown: {args.md_out}")
    return 1 if probe.aborted else 0


if __name__ == "__main__":
    sys.exit(main())
