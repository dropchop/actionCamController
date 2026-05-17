#!/usr/bin/env python3
"""S1 — USB endpoint-0 vendor control transfer probe.

Two parts:
  1. The specific FRM.exe ISP-mode trigger documented for iCatch V37M
     (sibling SoC, per https://blog.kitor.eu/lenovo-thinksmart-cam-...):
       bmRequestType = 0xC0  (device-to-host, vendor, device-targeted)
       bRequest      = 0xB0
       wValue        = 0x0000
       wIndex        = 0xAA55
       wLength       = 12
     Sent three times in a row, per the original blog. If V11 shares
     the SP-Boot family bootloader, the camera re-enumerates as
     "Icatch(X) KX Series Bulk Camera Device" and accepts the
     SP-Boot command shell over USB.

  2. A wider vendor-request sweep on ep0:
       bmRequestType in {0x40 OUT, 0xC0 IN} × bRequest in 0x00..0xFF
     Any request that returns a non-EPIPE response is a recognized
     vendor handler.

Uses raw USBDEVFS_CONTROL ioctl via /dev/bus/usb/<bus>/<dev>, no pyusb
required.
"""
from __future__ import annotations
import ctypes, fcntl, os, sys, struct, subprocess, re

# struct usbdevfs_ctrltransfer (24 B on 64-bit Linux):
#   u8 bRequestType; u8 bRequest; u16 wValue; u16 wIndex; u16 wLength;
#   u32 timeout; void *data;
class CtrlTransfer(ctypes.Structure):
    _fields_ = [
        ('bRequestType', ctypes.c_uint8),
        ('bRequest',     ctypes.c_uint8),
        ('wValue',       ctypes.c_uint16),
        ('wIndex',       ctypes.c_uint16),
        ('wLength',      ctypes.c_uint16),
        ('timeout',      ctypes.c_uint32),
        ('data',         ctypes.c_void_p),
    ]

# _IOWR('U', 0, ctrltransfer) — direction=3, size=24, type='U'=0x55, nr=0
USBDEVFS_CONTROL = (3 << 30) | (24 << 16) | (0x55 << 8) | 0


def find_camera() -> tuple[int, int] | None:
    out = subprocess.run(['lsusb', '-d', '2aad:6371'],
                         capture_output=True, text=True).stdout
    m = re.match(r'Bus (\d+) Device (\d+)', out)
    if not m:
        # Also try UVC mode
        out = subprocess.run(['lsusb', '-d', '2aad:6373'],
                             capture_output=True, text=True).stdout
        m = re.match(r'Bus (\d+) Device (\d+)', out)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def control(fd, req_type, req, value, index, in_len=0, out_data=None,
            timeout_ms=1000) -> tuple[int, bytes, int]:
    """Returns (n_bytes_returned, data, errno_if_failure)."""
    if out_data is not None:
        buf = (ctypes.c_uint8 * len(out_data)).from_buffer_copy(out_data)
        wlen = len(out_data)
    elif in_len > 0:
        buf = (ctypes.c_uint8 * in_len)()
        wlen = in_len
    else:
        buf = None
        wlen = 0
    ct = CtrlTransfer()
    ct.bRequestType = req_type
    ct.bRequest = req
    ct.wValue = value
    ct.wIndex = index
    ct.wLength = wlen
    ct.timeout = timeout_ms
    ct.data = ctypes.cast(buf, ctypes.c_void_p) if buf else None
    try:
        n = fcntl.ioctl(fd, USBDEVFS_CONTROL, ct)
        out = bytes(buf[:n]) if buf and (req_type & 0x80) and n > 0 else b''
        return n, out, 0
    except OSError as e:
        return -1, b'', e.errno


def main():
    loc = find_camera()
    if not loc:
        print("Camera 2aad:6371 (MSC) or 2aad:6373 (UVC) not found via lsusb.")
        return 2
    bus, dev = loc
    path = f'/dev/bus/usb/{bus:03d}/{dev:03d}'
    print(f"[*] Camera at {path}")

    try:
        fd = os.open(path, os.O_RDWR)
    except PermissionError:
        print("Need sudo for raw USB access.")
        return 2

    try:
        # --- PART 1: the FRM.exe ISP-mode trigger ---
        print("\n=== PART 1: FRM.exe ISP-mode trigger (3 repeats) ===")
        for i in range(3):
            n, data, err = control(fd, 0xC0, 0xB0, 0x0000, 0xAA55, in_len=12)
            if err:
                print(f"  [{i+1}/3] err={os.strerror(err)} (errno={err})")
            else:
                print(f"  [{i+1}/3] n={n} data={data.hex() if data else '(empty)'}")

        # --- PART 2: wider vendor-request sweep ---
        print("\n=== PART 2: bmRequestType={0x40,0xC0} x bRequest=0x00..0xFF sweep ===")
        print("(Only printing requests that did NOT fail with EPIPE=32)")
        hits = []
        for rt in (0xC0, 0x40):
            direction = 'IN' if rt & 0x80 else 'OUT'
            for req in range(0x00, 0x100):
                if rt == 0xC0:
                    n, data, err = control(fd, rt, req, 0, 0, in_len=12, timeout_ms=300)
                else:
                    n, data, err = control(fd, rt, req, 0, 0, out_data=b'\x00'*12, timeout_ms=300)
                if err == 0 or err not in (32, 110):  # 32=EPIPE, 110=ETIMEDOUT
                    desc = f"n={n}" if err == 0 else f"errno={err} ({os.strerror(err)})"
                    hit = f"  ★ {direction} bRequest=0x{req:02X}  {desc}  data={data.hex() if data else '-'}"
                    print(hit)
                    hits.append(hit)

        # --- PART 3: try the FRM.exe trigger with various wIndex / wValue ---
        print("\n=== PART 3: variations on the FRM.exe trigger ===")
        for wValue, wIndex, label in [
            (0x0000, 0xAA55, 'original'),
            (0xAA55, 0x0000, 'swapped'),
            (0x55AA, 0x0000, 'byteswap value'),
            (0x0000, 0x55AA, 'byteswap index'),
            (0xAA55, 0xAA55, 'AA55 in both'),
            (0x0001, 0xAA55, 'value=1'),
            (0x0000, 0xCAFE, 'index=CAFE'),
        ]:
            n, data, err = control(fd, 0xC0, 0xB0, wValue, wIndex, in_len=12)
            if err:
                print(f"  {label:25s} wValue=0x{wValue:04X} wIndex=0x{wIndex:04X}  errno={err} ({os.strerror(err)})")
            else:
                print(f"  {label:25s} wValue=0x{wValue:04X} wIndex=0x{wIndex:04X}  n={n} data={data.hex()}")

        # --- PART 4: also a quick MSC re-enumerate check ---
        print("\n=== After all probes, what does lsusb see? ===")
        out = subprocess.run(['lsusb'], capture_output=True, text=True).stdout
        for line in out.splitlines():
            if '2aad' in line.lower() or 'sport' in line.lower() or 'icatch' in line.lower():
                print(f"  {line}")

        if not hits:
            print("\n[!] No vendor handlers responded.")
        else:
            print(f"\n[+] {len(hits)} vendor-handler hits.")
    finally:
        os.close(fd)


if __name__ == '__main__':
    sys.exit(main())
