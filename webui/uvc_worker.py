"""UVC camera worker — for Larkfly cameras plugged in over USB.

When the Larkfly is connected via a data-carrying USB cable (and any
required "PC mode" / "Webcam" menu setting is selected), it presents
as a UVC class device. We get:

- 1920×1080 @ 30 fps MJPEG (or H.264) preview
- Standard UVC controls (auto-exposure, focus, white balance)
- A vendor extension unit (GUID 63610682-...-221d) with up to 32
  vendor-specific control bits — likely how the iCatch SDK reaches
  photo/record over USB, but we don't have those decoded yet

What this worker does:
- Owns the /dev/videoN device exclusively while it's running
- Pulls MJPEG-encoded frames in a background thread
- Exposes the most recent frame as JPEG bytes for the Flask preview
- Supports host-side video recording (saves a .mp4 to ~/larkfly_recordings/)
- Take-photo just grabs and saves the current frame (no camera-side
  high-res capture yet)

This complements LarkflyWorker (WiFi PTP-IP) in the same Flask app;
both expose the same .take_photo() / .start_recording() / .get_jpeg()
interface so the UI doesn't care which path a slot uses.
"""
from __future__ import annotations

import os
import threading
import time
from datetime import datetime
from typing import Optional

import cv2


PREVIEW_JPEG_QUALITY = 70
PREVIEW_MAX_WIDTH = 1280
DEFAULT_RECORD_DIR = os.path.expanduser("~/larkfly_recordings")


class UvcWorker:
    """Same interface as LarkflyWorker but backed by V4L2/UVC."""

    STARTING     = 'starting'
    RUNNING      = 'running'
    RECONNECTING = 'reconnecting'
    DEAD         = 'dead'

    def __init__(self, slot: int, dev_path: str,
                 name: Optional[str] = None,
                 width: int = 1920, height: int = 1080, fps: int = 30,
                 record_dir: Optional[str] = None):
        self.slot = slot
        self.dev_path = dev_path
        self.name = name or f"usb{slot}"
        self.req_width = width
        self.req_height = height
        self.req_fps = fps
        self.record_dir = record_dir or DEFAULT_RECORD_DIR
        os.makedirs(self.record_dir, exist_ok=True)

        self.state = self.STARTING
        self.error: Optional[str] = None
        self.actual_size = (0, 0)
        self.fps_actual = 0.0
        self.last_frame_jpeg: Optional[bytes] = None
        self.last_frame_ts: float = 0.0
        self._latest_bgr = None  # latest decoded frame (numpy array) for record/photo

        self._frame_lock = threading.Lock()
        self._stop = threading.Event()
        self._recording = False
        self._record_writer: Optional[cv2.VideoWriter] = None
        self._record_path: Optional[str] = None
        self._record_lock = threading.Lock()
        self._cap: Optional[cv2.VideoCapture] = None

        self._thread = threading.Thread(target=self._run, daemon=True,
                                         name=f"UvcWorker-{slot}")

    # ---- lifecycle ------------------------------------------------
    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._recording:
            self.stop_recording()
        if self._thread.is_alive():
            self._thread.join(timeout=3.0)
        if self._cap:
            try: self._cap.release()
            except Exception: pass

    # ---- control surface (matches LarkflyWorker) ------------------
    def take_photo(self) -> Optional[str]:
        """Snapshot the latest frame to disk and return the file path."""
        with self._frame_lock:
            frame = self._latest_bgr
        if frame is None:
            return None
        ts = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]
        out = os.path.join(self.record_dir, f"{self.name}_{ts}.jpg")
        cv2.imwrite(out, frame, [cv2.IMWRITE_JPEG_QUALITY, 92])
        return out

    def start_recording(self):
        """Start host-side video recording to a .mp4 file."""
        with self._record_lock:
            if self._recording:
                return
            if self.actual_size == (0, 0):
                raise RuntimeError("no frames yet — can't size the recording")
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            out = os.path.join(self.record_dir, f"{self.name}_{ts}.mp4")
            # mp4v: pretty universal, plays in browsers and VLC
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            writer = cv2.VideoWriter(out, fourcc,
                                      self.fps_actual or self.req_fps,
                                      self.actual_size)
            if not writer.isOpened():
                raise RuntimeError(f"could not open VideoWriter for {out}")
            self._record_writer = writer
            self._record_path = out
            self._recording = True

    def stop_recording(self) -> Optional[str]:
        with self._record_lock:
            if not self._recording:
                return None
            self._recording = False
            try:
                if self._record_writer:
                    self._record_writer.release()
            except Exception:
                pass
            out = self._record_path
            self._record_writer = None
            self._record_path = None
            return out

    def is_recording(self) -> bool:
        return self._recording

    def get_status(self) -> dict:
        return {
            'slot': self.slot,
            'host': self.dev_path,
            'name': self.name,
            'kind': 'usb-uvc',
            'state': self.state,
            'error': self.error,
            'model': 'Sport Cam (UVC)',
            'firmware': '',
            'mode': 0,
            'mode_name': 'UVC',
            'recording': self._recording,
            'fps_actual': round(self.fps_actual, 1),
            'has_preview': self.last_frame_jpeg is not None,
            'last_frame_age_s': round(time.time() - self.last_frame_ts, 2)
                                if self.last_frame_ts else None,
            'requested_size': f"{self.req_width}x{self.req_height}@{self.req_fps}",
            'actual_size': f"{self.actual_size[0]}x{self.actual_size[1]}",
        }

    def get_jpeg(self) -> Optional[bytes]:
        with self._frame_lock:
            return self.last_frame_jpeg

    # ---- background loop -----------------------------------------
    def _run(self):
        retry = 0
        while not self._stop.is_set():
            try:
                self._open_capture()
                self._stream_loop()
                retry = 0
            except (RuntimeError, cv2.error) as e:
                self.error = str(e)
                self.state = self.RECONNECTING
                retry += 1
                if retry >= 5:
                    self.state = self.DEAD
                    return
                self._stop.wait(2.0 * retry)

    def _open_capture(self):
        if self._cap:
            try: self._cap.release()
            except Exception: pass
            self._cap = None
        self.state = self.STARTING
        cap = cv2.VideoCapture(self.dev_path, cv2.CAP_V4L2)
        if not cap.isOpened():
            raise RuntimeError(f"failed to open {self.dev_path}")
        # Force MJPEG + 1080p
        cap.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc('M', 'J', 'P', 'G'))
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, self.req_width)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self.req_height)
        cap.set(cv2.CAP_PROP_FPS, self.req_fps)
        # Tiny buffer = lowest preview latency
        cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        self._cap = cap
        w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        self.actual_size = (w, h)

    def _stream_loop(self):
        self.state = self.RUNNING
        self.error = None
        t_window = time.time()
        n_window = 0
        while not self._stop.is_set():
            ok, frame = self._cap.read()
            if not ok:
                raise RuntimeError("V4L2 read failed (device removed or busy)")
            # Save full frame for record/photo
            with self._frame_lock:
                self._latest_bgr = frame
            # Write to disk if recording
            if self._recording and self._record_writer:
                try:
                    self._record_writer.write(frame)
                except Exception as e:
                    self.error = f"record write failed: {e}"
            # Build preview JPEG
            h, w = frame.shape[:2]
            preview = frame
            if w > PREVIEW_MAX_WIDTH:
                scale = PREVIEW_MAX_WIDTH / w
                preview = cv2.resize(frame, (int(w * scale), int(h * scale)))
            ok, jpeg = cv2.imencode('.jpg', preview,
                                     [cv2.IMWRITE_JPEG_QUALITY, PREVIEW_JPEG_QUALITY])
            if ok:
                with self._frame_lock:
                    self.last_frame_jpeg = jpeg.tobytes()
                    self.last_frame_ts = time.time()
            # FPS metering
            n_window += 1
            now = time.time()
            if now - t_window >= 1.0:
                self.fps_actual = n_window / (now - t_window)
                n_window = 0
                t_window = now
