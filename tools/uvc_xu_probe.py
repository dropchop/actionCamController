#!/usr/bin/env python3
"""UVC Extension Unit probe for the Larkfly A6+ (iCatch V11) camera.

The camera presents (in UVC mode, VID:PID 2aad:6373) a UVC vendor
extension unit at GUID 63610682-5070-49ab-b8cc-b3855e8d221d, UnitID 3,
on Interface 0 (Video Control). The descriptor declares
`bNumControls = 0` but `bmControls = 0xFFFFFFFF` — i.e. all 32 control
selectors are present but undocumented. The iSmart DV2 app drives them
via out-of-band knowledge (see `Java_..._extensionUnitGet/Set/GetLength`
JNI methods in libcontrol.so).

This probe walks every selector 1..32 and issues:
    UVC_GET_LEN  (returns the control's byte length)
    UVC_GET_INFO (returns capability flags — GET/SET/...)
    UVC_GET_CUR  (returns current value, if GET is supported)
    UVC_GET_MIN/MAX/RES/DEF for numeric controls

Then cross-references the result against `libcontrol.so` strings to
find any plain-text label adjacent to the GUID's selector lookups.

Runs against the live camera via libusb-1.0 (loaded through ctypes) so
no pyusb / no v4l2 UVCIOC_CTRL_MAP setup is needed. The kernel's
uvcvideo driver keeps the streaming interface; control-transfer
ownership is independent.

Usage:
    python3 tools/uvc_xu_probe.py
    python3 tools/uvc_xu_probe.py --json-out analyses/data/uvc_xu_dump.json
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import json
import os
import sys
import time
from ctypes import (POINTER, byref, c_char_p, c_int, c_uint8, c_uint16,
                    c_uint32, c_void_p, cdll, create_string_buffer)

# UVC class-specific request codes (UVC 1.5 spec, Table 4-1)
UVC_RC_UNDEFINED = 0x00
UVC_SET_CUR  = 0x01
UVC_GET_CUR  = 0x81
UVC_GET_MIN  = 0x82
UVC_GET_MAX  = 0x83
UVC_GET_RES  = 0x84
UVC_GET_LEN  = 0x85
UVC_GET_INFO = 0x86
UVC_GET_DEF  = 0x87

# UVC GET_INFO capability flag bits
INFO_SUPPORTS_GET = 0x01
INFO_SUPPORTS_SET = 0x02
INFO_DISABLED     = 0x04
INFO_AUTO_UPDATE  = 0x08
INFO_ASYNCHRONOUS = 0x10

# libusb_control_transfer constants
LIBUSB_REQUEST_TYPE_CLASS = 0x20
LIBUSB_RECIPIENT_INTERFACE = 0x01
LIBUSB_ENDPOINT_IN  = 0x80
LIBUSB_ENDPOINT_OUT = 0x00

GET_IN_REQ_TYPE  = LIBUSB_ENDPOINT_IN  | LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE  # 0xA1
SET_OUT_REQ_TYPE = LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE  # 0x21

# Camera target
DEFAULT_VID = 0x2AAD
DEFAULT_PID = 0x6373
DEFAULT_INTERFACE = 0          # Video Control interface
DEFAULT_UNIT_ID = 3            # iCatch XU UnitID per the descriptor
DEFAULT_GUID = "63610682-5070-49ab-b8cc-b3855e8d221d"


# -- kernel UVC ioctl path (preferred — needs only /dev/video0 ACL) ----------
#
# Compute UVCIOC_CTRL_QUERY = _IOWR('u', 0x21, struct uvc_xu_control_query).
# On x86_64 the struct is { u8 unit; u8 selector; u8 query; u16 size; u8* data }
# with default alignment → 16 bytes (3 bytes of padding before size, 2 before
# the pointer). _IOWR encoding: dir=3<<30, size=16<<16, type=0x75<<8, nr=0x21.
UVCIOC_CTRL_QUERY = (3 << 30) | (16 << 16) | (0x75 << 8) | 0x21  # 0xC0107521

# struct uvc_xu_control_query in ctypes
class UvcXuControlQuery(ctypes.Structure):
    _fields_ = [
        ("unit",     c_uint8),
        ("selector", c_uint8),
        ("query",    c_uint8),
        ("size",     c_uint16),  # natural alignment → 1 byte pad before
        ("data",     POINTER(c_uint8)),  # natural alignment → pad to 8-byte
    ]

import fcntl  # noqa: E402

@contextlib.contextmanager
def video_session(video_dev: str = "/dev/video0"):
    fd = os.open(video_dev, os.O_RDWR)
    try:
        yield fd
    finally:
        os.close(fd)


def xu_control(fd: int, query: int, unit: int, selector: int, interface: int,
               size: int, out_data: bytes | None = None, timeout_ms: int = 1000):
    """One UVC XU control query via kernel UVCIOC_CTRL_QUERY ioctl.
    `interface` is accepted for API symmetry but unused — the kernel
    knows which interface owns the XU. Returns (rc, bytes_received|None)."""
    if query == UVC_SET_CUR:
        if out_data is None or len(out_data) != size:
            raise ValueError("SET_CUR requires out_data == size bytes")
        buf = (c_uint8 * size).from_buffer_copy(out_data)
    else:
        buf = (c_uint8 * size)()
    q = UvcXuControlQuery(
        unit=unit, selector=selector, query=query, size=size,
        data=ctypes.cast(buf, POINTER(c_uint8)),
    )
    try:
        fcntl.ioctl(fd, UVCIOC_CTRL_QUERY, q)
    except OSError as e:
        return -e.errno, None
    if query == UVC_SET_CUR:
        return size, None
    return size, bytes(buf)


def strerror(rc: int) -> str:
    """Convert negative errno to text."""
    if rc >= 0:
        return f"ok ({rc})"
    return f"errno {-rc} ({os.strerror(-rc)})"


def probe_selector(dev, unit: int, selector: int, interface: int) -> dict:
    """Probe one XU selector: GET_LEN, GET_INFO, GET_CUR (+ MIN/MAX/RES/DEF
    if reasonably small numeric)."""
    out = {"selector": selector}

    # 1. GET_LEN — reports byte length
    rc, data = xu_control(dev, UVC_GET_LEN, unit, selector, interface, 2)
    if rc < 0:
        out["len_err"] = strerror(rc)
        return out
    length = int.from_bytes(data, "little")
    out["len"] = length

    # 2. GET_INFO — 1 byte capability flags
    rc, data = xu_control(dev, UVC_GET_INFO, unit, selector, interface, 1)
    if rc < 0:
        out["info_err"] = strerror(rc)
    else:
        flags = data[0]
        out["info"] = flags
        out["info_caps"] = []
        if flags & INFO_SUPPORTS_GET: out["info_caps"].append("GET")
        if flags & INFO_SUPPORTS_SET: out["info_caps"].append("SET")
        if flags & INFO_DISABLED: out["info_caps"].append("DISABLED")
        if flags & INFO_AUTO_UPDATE: out["info_caps"].append("AUTOUPDATE")
        if flags & INFO_ASYNCHRONOUS: out["info_caps"].append("ASYNC")

    if length == 0 or length > 256:
        # length 0 = not implemented; >256 = suspect, skip
        return out

    # 3. GET_CUR if INFO says GET supported (or if INFO failed, try anyway)
    can_get = (out.get("info", 0) & INFO_SUPPORTS_GET) != 0 or "info" not in out
    if can_get:
        rc, data = xu_control(dev, UVC_GET_CUR, unit, selector, interface, length)
        if rc < 0:
            out["cur_err"] = strerror(rc)
        else:
            out["cur_hex"] = data.hex()
            # ASCII view if it looks printable
            try:
                printable = all(32 <= b < 127 or b == 0 for b in data)
                if printable:
                    out["cur_ascii"] = data.rstrip(b"\x00").decode("ascii",
                                                                  errors="replace")
            except Exception:
                pass

    # 4. For numeric-ish controls (length 1/2/4), grab MIN/MAX/RES/DEF too
    if length in (1, 2, 4):
        for query, label in [(UVC_GET_MIN, "min"), (UVC_GET_MAX, "max"),
                             (UVC_GET_RES, "res"), (UVC_GET_DEF, "def")]:
            rc, data = xu_control(dev, query, unit, selector, interface, length)
            if rc >= 0:
                v = int.from_bytes(data, "little")
                out[label] = v

    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vid", type=lambda s: int(s, 16), default=DEFAULT_VID)
    ap.add_argument("--pid", type=lambda s: int(s, 16), default=DEFAULT_PID)
    ap.add_argument("--interface", type=int, default=DEFAULT_INTERFACE)
    ap.add_argument("--unit", type=int, default=DEFAULT_UNIT_ID)
    ap.add_argument("--min-sel", type=int, default=1)
    ap.add_argument("--max-sel", type=int, default=32)
    ap.add_argument("--json-out", default="analyses/data/uvc_xu_dump.json")
    ap.add_argument("--video-dev", default="/dev/video0",
                    help="V4L2 device node for the camera")
    args = ap.parse_args()

    print(f"[*] Target VID:PID = {args.vid:04x}:{args.pid:04x}, "
          f"interface {args.interface}, unit {args.unit}")
    print(f"[*] V4L2 device: {args.video_dev}")
    print(f"[*] XU GUID expected: {DEFAULT_GUID}")
    print(f"[*] Walking selectors {args.min_sel}..{args.max_sel}")
    print()

    results = []
    with video_session(args.video_dev) as fd:
        for sel in range(args.min_sel, args.max_sel + 1):
            r = probe_selector(fd, args.unit, sel, args.interface)
            results.append(r)
            len_str = (f"len={r['len']:>3}" if "len" in r else "len=ERR")
            caps_str = ",".join(r.get("info_caps", [])) or "-"
            cur_str = ""
            if "cur_hex" in r:
                cur_str = f" cur={r['cur_hex'][:64]}"
                if r['cur_hex'] and len(r['cur_hex']) > 64:
                    cur_str += "…"
                if "cur_ascii" in r:
                    cur_str += f" ascii={r['cur_ascii']!r}"
            elif "cur_err" in r:
                cur_str = f" cur-err={r['cur_err']}"
            range_str = ""
            if "min" in r:
                range_str = f" [min={r['min']} max={r['max']} def={r.get('def','?')} res={r.get('res','?')}]"
            err_str = ""
            for k in ("len_err", "info_err"):
                if k in r: err_str += f" {k}={r[k]}"
            print(f"  sel {sel:>2} {len_str} caps={caps_str:<20s}{cur_str}{range_str}{err_str}")

    os.makedirs(os.path.dirname(args.json_out) or ".", exist_ok=True)
    with open(args.json_out, "w") as f:
        json.dump({
            "vid": args.vid, "pid": args.pid, "interface": args.interface,
            "unit": args.unit, "guid": DEFAULT_GUID,
            "selectors": results,
        }, f, indent=2)
    print(f"\n[+] JSON: {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
