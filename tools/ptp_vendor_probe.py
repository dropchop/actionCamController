#!/usr/bin/env python3
"""Exhaustive — but crash-safe — exploration of the camera's PTP/IP
vendor opcode surface.

`DeviceInfo.operations_supported` advertises 8 vendor opcodes in the
`0x9xxx` range. Three (`0x9601` polling, `0x9614` bulk-PropDesc,
`0x9805` global query) were observed in iSmart DV2 captures and have
known shapes. The other five (`0x9602`, `0x9801`, `0x9802`, `0x9803`,
`0x9812`) are advertised but never used by the app — they could be
dead-weight from the iCatch SDK template, or they could be live
endpoints exposing recording, photo capture, logging, or debug.

Prior blind probing crashed the PTP service. This tool therefore:

- Re-confirms the camera is alive via `GetDeviceInfo` between every
  probe.
- Saves after every probe — `analyses/data/ptp_vendor_probe.json`.
- `--resume` skips probes we already captured a non-`None` response
  for; only crashes / timeouts are retried.
- Aborts on the first health-check failure with a clear "power-cycle
  required" message.

Strategy: for each unknown opcode, walk through a small matrix of
parameter shapes (no-params, 1×0, 1×0xFFFFFFFF, 2×0, 5×0xFFFFFFFF) and
observe response code, response params, data length, and data prefix.
Even a `0x2002 Parameter_Not_Supported` reply teaches us how many
parameters the op wants — that's much better data than "blind probe
crashed it".

Usage:
    # Full run — baselines on known ops, then probe all 5 unknowns:
    python3 tools/ptp_vendor_probe.py

    # After a wedge + power-cycle:
    python3 tools/ptp_vendor_probe.py --resume

    # Single targeted shot:
    python3 tools/ptp_vendor_probe.py --op 0x9602 --params 0xD001,0xFFFFFFFF,0
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import json
import os
import socket
import sys
import time
from dataclasses import asdict, dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from larkfly import Camera, types as t
from larkfly.exceptions import LarkflyError, PtpError, TransportError

HEALTH_TIMEOUT = 1.5
PACE_SLEEP = 0.4

# PTP response code names for the common ones we expect to see.
RC_NAMES = {
    0x2000: "Undefined",
    0x2001: "OK",
    0x2002: "General_Error",
    0x2003: "Session_Not_Open",
    0x2005: "Operation_Not_Supported",
    0x2006: "Parameter_Not_Supported",
    0x2007: "Incomplete_Transfer",
    0x2008: "Invalid_StorageID",
    0x2009: "Invalid_ObjectHandle",
    0x200A: "DeviceProp_Not_Supported",
    0x200B: "Invalid_ObjectFormatCode",
    0x200D: "Specification_By_Format_Unsupported",
    0x200E: "No_Valid_ObjectInfo",
    0x200F: "Invalid_Code_Format",
    0x2010: "Unknown_Vendor_Code",
    0x2011: "Capture_Already_Terminated",
    0x2012: "Device_Busy",
    0x2013: "Invalid_ParentObject",
    0x2014: "Invalid_DevicePropFormat",
    0x2015: "Invalid_DevicePropValue",
    0x2016: "Invalid_Parameter",
    0x2017: "Session_Already_Open",
    0x2018: "Transaction_Cancelled",
    0x2019: "Specification_Of_Destination_Unsupported",
    0x201E: "Invalid_TransactionID",
}


def rc_name(rc: int) -> str:
    if rc is None:
        return "(no response — TIMEOUT/CRASH)"
    name = RC_NAMES.get(rc)
    if name:
        return f"0x{rc:04x} {name}"
    if 0xA000 <= rc <= 0xAFFF:
        return f"0x{rc:04x} (Vendor_Error)"
    return f"0x{rc:04x} (unknown)"


@dataclass
class Probe:
    label: str
    opcode: int
    params: list[int]
    rc: int | None
    resp_params: list[int]
    data_len: int
    data_hex: str  # first 256 bytes hex
    elapsed_ms: float
    error: str | None = None


@dataclass
class Report:
    host: str
    bind: str | None
    started_at: str
    finished_at: str | None = None
    probes: list[Probe] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    aborted_at: str | None = None
    aborted_reason: str | None = None


# Known opcodes with documented param shapes from iSmart DV2 pcap RE
BASELINE_PROBES: list[tuple[str, int, list[int]]] = [
    ("baseline:0x9601-poll", 0x9601, [0xD001, 0xFFFFFFFF, 0x00000000]),
    ("baseline:0x9614-bulk-propdesc", 0x9614, []),
    ("baseline:0x9805-global", 0x9805,
     [0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF]),
]

# For each unknown opcode, the matrix of param shapes to try.
# Numbers come from iCatch SDK conventions: bare, 1×0, 1×all-Fs, 3-shape
# (matching 0x9601), 5-shape (matching 0x9805), and a property-style
# shape for 1 prop code.
PARAM_MATRIX: list[tuple[str, list[int]]] = [
    ("no-params", []),
    ("1=0", [0]),
    ("1=allFs", [0xFFFFFFFF]),
    ("1=propcode-D001", [0xD001]),
    ("2=0,0", [0, 0]),
    ("3=9601-shape", [0xD001, 0xFFFFFFFF, 0x00000000]),
    ("5=9805-shape", [0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF]),
]

UNKNOWN_OPCODES = [0x9602, 0x9801, 0x9802, 0x9803, 0x9812]


def tcp_health(host: str, bind: str | None, port: int = 15740,
               timeout: float = HEALTH_TIMEOUT) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if bind:
        with contextlib.suppress(OSError):
            s.bind((bind, 0))
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        with contextlib.suppress(OSError):
            s.close()


def session_health(cam: Camera) -> tuple[bool, str]:
    """Confirm the PTP session is alive by issuing GetDeviceInfo."""
    try:
        cam.device_info()
        return True, "ok"
    except (PtpError, TransportError, LarkflyError, OSError) as e:
        return False, f"{type(e).__name__}: {e}"


def run_probe(cam: Camera, opcode: int, params: list[int],
              timeout: float = 4.0) -> tuple[int | None, list[int], bytes, str | None]:
    """Send the op and return (rc, resp_params, data, error_string)."""
    sock = cam._cmd_sock
    saved = sock.gettimeout() if sock else None
    if sock:
        sock.settimeout(timeout)
    try:
        rc, rp, data = cam._raw_op(opcode, list(params))
        return rc, rp, data, None
    except (PtpError, TransportError, LarkflyError, OSError) as e:
        return None, [], b"", f"{type(e).__name__}: {e}"
    finally:
        if sock:
            with contextlib.suppress(OSError):
                sock.settimeout(saved)


def save(report: Report, json_path: str) -> None:
    os.makedirs(os.path.dirname(json_path) or ".", exist_ok=True)
    payload = {
        "host": report.host, "bind": report.bind,
        "started_at": report.started_at, "finished_at": report.finished_at,
        "aborted_at": report.aborted_at, "aborted_reason": report.aborted_reason,
        "notes": report.notes,
        "probes": [asdict(p) for p in report.probes],
    }
    with open(json_path, "w") as f:
        json.dump(payload, f, indent=2)


def load_resume(json_path: str, report: Report) -> set[str]:
    """Load prior JSON; return the set of labels with a non-None rc
    (i.e. probes that actually got a response and don't need to retry)."""
    if not os.path.exists(json_path):
        return set()
    with open(json_path) as f:
        prev = json.load(f)
    report.started_at = prev.get("started_at", report.started_at)
    report.notes = prev.get("notes", [])
    done = set()
    for p in prev.get("probes", []):
        probe = Probe(**p)
        report.probes.append(probe)
        if probe.rc is not None:
            done.add(probe.label)
    report.aborted_at = None
    report.aborted_reason = None
    return done


def fmt_params(params: list[int]) -> str:
    return "[" + ", ".join(f"0x{p:08x}" for p in params) + "]"


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="192.168.1.1")
    ap.add_argument("--bind", default="192.168.1.10")
    ap.add_argument("--json-out", default="analyses/data/ptp_vendor_probe.json")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--op", default=None,
                    help="Single-shot mode: just probe this opcode (hex)")
    ap.add_argument("--params", default="",
                    help="Comma-separated params for single-shot mode (hex)")
    ap.add_argument("--timeout", type=float, default=4.0,
                    help="Per-op response timeout (seconds)")
    args = ap.parse_args()

    report = Report(host=args.host, bind=args.bind,
                    started_at=datetime.datetime.now().isoformat(timespec="seconds"))
    done_labels: set[str] = set()

    if args.resume:
        done_labels = load_resume(args.json_out, report)
        print(f"[resume] {len(report.probes)} prior probes loaded, "
              f"{len(done_labels)} responded (will skip)")

    print(f"[*] {args.host}:15740 bind={args.bind or 'any'}")
    if not tcp_health(args.host, args.bind):
        print("[!!] PTP port 15740 unreachable — camera off or wedged.")
        return 2

    # Build probe list
    probes_to_run: list[tuple[str, int, list[int]]] = []

    if args.op:
        # Single-shot mode
        opcode = int(args.op, 16) if "x" in args.op.lower() else int(args.op)
        params = []
        for p in args.params.split(",") if args.params else []:
            params.append(int(p.strip(), 16) if "x" in p.lower() else int(p.strip()))
        probes_to_run.append((f"single:{opcode:#06x}={fmt_params(params)}",
                              opcode, params))
    else:
        # Full run: baselines + matrix on unknown opcodes
        probes_to_run.extend(BASELINE_PROBES)
        for op in UNKNOWN_OPCODES:
            for shape_name, params in PARAM_MATRIX:
                probes_to_run.append((f"probe:0x{op:04x}:{shape_name}", op, params))

    print(f"[*] {len(probes_to_run)} probes planned")

    aborted = False
    abort_reason = ""

    try:
        with Camera(args.host, bind=args.bind) as cam:
            ok, why = session_health(cam)
            if not ok:
                print(f"[!!] PTP session unhealthy at start: {why}")
                report.aborted_at = datetime.datetime.now().isoformat(timespec="seconds")
                report.aborted_reason = f"Session unhealthy at start: {why}"
                save(report, args.json_out)
                return 2
            print(f"[*] Baseline session OK — {cam._cmd_sock.getpeername()}")

            for label, opcode, params in probes_to_run:
                if label in done_labels:
                    print(f"  [skip] {label}")
                    continue

                # Pre-probe health: cheap TCP test
                if not tcp_health(args.host, args.bind):
                    aborted = True
                    abort_reason = f"PTP service down before {label}"
                    break

                print(f"  -> {label} op=0x{opcode:04x} params={fmt_params(params)}")
                t0 = time.perf_counter()
                rc, rp, data, err = run_probe(cam, opcode, list(params),
                                              timeout=args.timeout)
                elapsed = (time.perf_counter() - t0) * 1000
                probe = Probe(
                    label=label, opcode=opcode, params=list(params),
                    rc=rc, resp_params=list(rp), data_len=len(data),
                    data_hex=data[:256].hex(),
                    elapsed_ms=round(elapsed, 1), error=err,
                )
                report.probes.append(probe)
                save(report, args.json_out)

                summary = (f"     rc={rc_name(rc)} rp={[hex(x) for x in rp]} "
                           f"data={len(data)}B elapsed={elapsed:.0f}ms")
                if err:
                    summary += f" ERR={err}"
                print(summary)
                if data:
                    print(f"     data[:64]={data[:64].hex()}")

                # Post-probe health: session-level
                ok, why = session_health(cam)
                if not ok:
                    print(f"  [!!] Session health failed after {label}: {why}")
                    # Try to reconnect once
                    print(f"  [..] Attempting reconnect...")
                    try:
                        cam.close()
                    except Exception:
                        pass
                    time.sleep(2)
                    if not tcp_health(args.host, args.bind):
                        aborted = True
                        abort_reason = (f"PTP port dead after {label}; "
                                        f"camera wedged — power-cycle required")
                        break
                    try:
                        cam.connect()
                        ok2, why2 = session_health(cam)
                        if not ok2:
                            aborted = True
                            abort_reason = (f"Reconnect after {label} succeeded but "
                                            f"session check failed: {why2}")
                            break
                        report.notes.append(
                            f"Reconnected successfully after {label} "
                            f"(session health: {why})")
                    except Exception as e:
                        aborted = True
                        abort_reason = f"Reconnect after {label} failed: {e}"
                        break

                time.sleep(PACE_SLEEP)
    except Exception as e:
        aborted = True
        abort_reason = f"Unhandled exception: {type(e).__name__}: {e}"

    if aborted:
        report.aborted_at = datetime.datetime.now().isoformat(timespec="seconds")
        report.aborted_reason = abort_reason
        print(f"\n[!!] ABORT: {abort_reason}")
        print("[!!] Power-cycle the camera and re-run with --resume.")
    else:
        report.finished_at = datetime.datetime.now().isoformat(timespec="seconds")
        print("\n[+] All probes completed.")

    save(report, args.json_out)
    print(f"[+] JSON: {args.json_out}")
    return 1 if aborted else 0


if __name__ == "__main__":
    sys.exit(main())
