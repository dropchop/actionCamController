#!/usr/bin/env python3
"""Live test: does PTP InitiateCapture (0x100E) actually produce a photo?

Background: the larkfly constant OP_INITIATE_CAPTURE was historically
defined as 0x100C (SendObjectInfo), so take_photo() created empty object
stubs and no JPG appeared — the project recorded "photo capture is a dead
end". The captured iSmart DV2 session takes a photo with
InitiateCapture(0, 0) — analyses/data/transactions.json txid 352. The
constant is now 0x100E.

First live re-test (mode 3, no preview): InitiateCapture(0x100E) returned
rc=0x2001 OK but produced no event, no PTP object, no JPG. iSmart DV2,
however, always holds an RTSP preview open. This script re-tests with a
live RTSP preview running during the capture, and can sweep camera modes.

Usage:
    python3 tools/photo_capture_test.py [--host H] [--bind IP]
                                        [--modes 3,4,5,6] [--no-preview]
"""
import argparse
import ftplib
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from larkfly import Camera, types as t          # noqa: E402
from larkfly.exceptions import PtpError, LarkflyError  # noqa: E402


def ftp_jpg_names(host):
    """Sorted entries in /JPG, or an error string."""
    try:
        f = ftplib.FTP(encoding='latin-1')
        f.connect(host, 21, timeout=8)
        f.login('wificam', 'wificam')
        lines = []
        f.cwd('/JPG')
        f.retrlines('LIST', lines.append)
        try:
            f.quit()
        except Exception:
            pass
        # last token of each LIST line is the filename
        return sorted(ln.split()[-1] for ln in lines if ln.split())
    except Exception as e:
        return f"(FTP error: {e})"


class Preview:
    """Background RTSP preview reader — keeps the camera's liveview
    pipeline active, the way the iSmart DV2 app does."""

    def __init__(self, host):
        self.url = f"rtsp://{host}/MJPG?W=720&H=400&Q=50&BR=5000000"
        self.cap = None
        self.frames = 0
        self._run = True
        self._thr = None

    def start(self):
        import cv2
        self.cap = cv2.VideoCapture(self.url, cv2.CAP_FFMPEG)
        self._thr = threading.Thread(target=self._loop, daemon=True)
        self._thr.start()
        # give it a moment to connect + pull frames
        for _ in range(40):
            if self.frames > 2:
                break
            time.sleep(0.25)
        return self.frames > 2

    def _loop(self):
        while self._run and self.cap is not None:
            ok, _ = self.cap.read()
            if ok:
                self.frames += 1
            else:
                time.sleep(0.05)

    def stop(self):
        self._run = False
        if self.cap is not None:
            try:
                self.cap.release()
            except Exception:
                pass


def attempt(cam, host, mode, jpg_baseline):
    """Set a mode, fire InitiateCapture, report. Returns list of new JPGs."""
    print(f"\n--- mode {mode} ---")
    try:
        cam.set_mode(mode)
        time.sleep(2.0)
        readback = cam.get_mode()
        print(f"  set D604={mode}, readback={readback}")
    except (PtpError, LarkflyError) as e:
        print(f"  mode set/read failed: {e}")
        readback = None

    while cam.poll_event(timeout=0.3) is not None:
        pass

    rc, rp, _ = cam._raw_op(t.OP_INITIATE_CAPTURE, [0, 0])
    print(f"  InitiateCapture(0x100E,[0,0]) -> rc=0x{rc:04X} "
          f"resp={[hex(x) for x in rp]}")

    events = []
    deadline = time.monotonic() + 6.0
    while time.monotonic() < deadline:
        ev = cam.poll_event(timeout=0.5)
        if ev:
            events.append(ev)
            print(f"  event: {ev}")
    if not events:
        print("  (no events)")

    time.sleep(1.5)
    after = ftp_jpg_names(host)
    new = ([x for x in after if x not in jpg_baseline]
           if isinstance(after, list) and isinstance(jpg_baseline, list)
           else [])
    print(f"  /JPG new files: {new or '(none)'}")
    return new


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='192.168.1.1')
    ap.add_argument('--bind', default='192.168.1.10')
    ap.add_argument('--modes', default='3',
                    help='comma-separated D604 modes to try (e.g. 3,4,5,6)')
    ap.add_argument('--no-preview', action='store_true',
                    help='do not hold an RTSP preview open')
    args = ap.parse_args()
    modes = [int(x) for x in args.modes.split(',') if x.strip()]

    print(f"== photo_capture_test  host={args.host} modes={modes} "
          f"preview={not args.no_preview} ==\n")

    jpg_baseline = ftp_jpg_names(args.host)
    print(f"/JPG baseline: {jpg_baseline}")

    preview = None
    if not args.no_preview:
        preview = Preview(args.host)
        ok = preview.start()
        print(f"RTSP preview: {'streaming, %d frames' % preview.frames if ok else 'FAILED to start'}")

    found = None
    try:
        with Camera(args.host, bind=args.bind) as cam:
            print(f"PTP connected. mode now = {cam.get_mode()}")
            for m in modes:
                new = attempt(cam, args.host, m, jpg_baseline)
                if new:
                    found = (m, new)
                    break
    finally:
        if preview is not None:
            print(f"\nRTSP preview pulled {preview.frames} frames total.")
            preview.stop()

    print("\n" + "=" * 62)
    if found:
        print(f"RESULT: PHOTO PRODUCED in mode {found[0]} — new JPG: {found[1]}")
        print("InitiateCapture(0x100E) works in this configuration.")
    else:
        print("RESULT: no JPG produced in any mode tried.")
        print("InitiateCapture(0x100E) is accepted (rc=OK) but does not")
        print("capture a still in these conditions — investigate further.")
    print("=" * 62)


if __name__ == '__main__':
    main()
