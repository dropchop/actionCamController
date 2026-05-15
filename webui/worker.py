"""Per-camera worker: owns a Camera (PTP control) + an RTSP frame grabber
(OpenCV VideoCapture). Runs a background thread that keeps the latest
JPEG-encoded preview frame available for the Flask MJPEG endpoint.

Mirrors the design of the parent ClaudesWorld/webcam/app.py CameraWorker
state machine but targets PTP-IP + RTSP instead of V4L2.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Optional

import cv2

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from larkfly import Camera, PtpError, TransportError, types as t


# Larkfly RTSP preview URL. Resolution 720x400 @ 5 Mbps is the low-rate
# preview format the camera advertises; the camera uses MJPEG (not H264)
# for this stream so latency is low and OpenCV decodes it directly.
RTSP_URL_TMPL = "rtsp://{host}/MJPG?W=720&H=400&Q=50&BR=5000000"

PREVIEW_JPEG_QUALITY = 70
PREVIEW_MAX_WIDTH = 1280
DEFAULT_RTSP_RECONNECT_DELAY = 2.0


class LarkflyWorker:
    """Background-managed connection to one camera.

    State machine:
        starting     → connect to camera + open RTSP   → running
        starting     → connect fails                   → dead
        running      → camera or RTSP error            → reconnecting
        reconnecting → recovery succeeds               → running
        reconnecting → too many retries                → dead
    """

    STARTING     = 'starting'
    RUNNING      = 'running'
    RECONNECTING = 'reconnecting'
    DEAD         = 'dead'

    def __init__(self, slot: int, host: str,
                 bind: Optional[str] = None,
                 name: Optional[str] = None,
                 max_retries: int = 5):
        self.slot = slot
        self.host = host
        self.bind = bind
        self.name = name or f"cam{slot}"
        self.max_retries = max_retries

        self.state = self.STARTING
        self.error: Optional[str] = None
        self.model = ''
        self.fw = ''
        self.last_frame_jpeg: Optional[bytes] = None
        self.last_frame_ts: float = 0.0
        self.fps_actual = 0.0
        self.mode: int = 0  # current D604 value

        self._frame_lock = threading.Lock()
        self._stop = threading.Event()
        self._cmd_lock = threading.Lock()   # serialize PTP commands
        self._camera: Optional[Camera] = None
        self._thread = threading.Thread(target=self._run, daemon=True,
                                         name=f"LarkflyWorker-{slot}")

    # ---- lifecycle -----------------------------------------------
    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=3.0)
        try:
            if self._camera:
                self._camera.close()
        except Exception:
            pass

    # ---- PTP control API (called from Flask handlers) ------------
    def take_photo(self) -> Optional[int]:
        with self._cmd_lock:
            if not self._camera:
                raise RuntimeError(f"slot {self.slot}: not connected")
            return self._camera.take_photo()

    def start_recording(self):
        with self._cmd_lock:
            if not self._camera:
                raise RuntimeError(f"slot {self.slot}: not connected")
            self._camera.start_recording()
            self.mode = t.MODE_VIDEO_ON

    def stop_recording(self):
        with self._cmd_lock:
            if not self._camera:
                raise RuntimeError(f"slot {self.slot}: not connected")
            self._camera.stop_recording()
            self.mode = t.MODE_VIDEO_OFF

    def is_recording(self) -> bool:
        return self.mode == t.MODE_VIDEO_ON

    def get_status(self) -> dict:
        return {
            'slot': self.slot,
            'host': self.host,
            'name': self.name,
            'state': self.state,
            'error': self.error,
            'model': self.model,
            'firmware': self.fw,
            'mode': self.mode,
            'mode_name': t.MODE_NAMES.get(self.mode, '?'),
            'recording': self.is_recording(),
            'fps_actual': round(self.fps_actual, 1),
            'has_preview': self.last_frame_jpeg is not None,
            'last_frame_age_s': round(time.time() - self.last_frame_ts, 2)
                                if self.last_frame_ts else None,
        }

    def get_jpeg(self) -> Optional[bytes]:
        with self._frame_lock:
            return self.last_frame_jpeg

    # ---- background loop ----------------------------------------
    def _run(self):
        retry = 0
        while not self._stop.is_set():
            try:
                self._connect_ptp()
                self._stream_rtsp()  # blocks until error or stop
                retry = 0
            except (TransportError, PtpError, RuntimeError, cv2.error) as e:
                self.error = str(e)
                self.state = self.RECONNECTING
                retry += 1
                if retry >= self.max_retries:
                    self.state = self.DEAD
                    return
                # backoff
                self._stop.wait(min(DEFAULT_RTSP_RECONNECT_DELAY * retry, 30))

    def _connect_ptp(self):
        if self._camera:
            try: self._camera.close()
            except Exception: pass
            self._camera = None
        self.state = self.STARTING
        cam = Camera(self.host, bind=self.bind)
        cam.connect()
        self._camera = cam
        try:
            info = cam.device_info()
            self.model = info.get('model') or 'V11'  # camera leaves model empty
            self.fw = cam.get_prop_value(0x501F)  # FwVersion
            self.mode = cam.get_mode()
        except Exception as e:
            self.error = f"DeviceInfo failed: {e}"

    def _stream_rtsp(self):
        """Open the RTSP MJPEG preview and pump frames into last_frame_jpeg."""
        url = RTSP_URL_TMPL.format(host=self.host)
        cap = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
        if not cap.isOpened():
            raise RuntimeError(f"RTSP open failed: {url}")
        try:
            self.state = self.RUNNING
            self.error = None
            t_last = time.time()
            t_window = time.time()
            n_window = 0
            while not self._stop.is_set():
                ok, frame = cap.read()
                if not ok:
                    raise RuntimeError("RTSP read returned not-ok (camera disconnect?)")
                # Downscale if needed
                h, w = frame.shape[:2]
                if w > PREVIEW_MAX_WIDTH:
                    scale = PREVIEW_MAX_WIDTH / w
                    frame = cv2.resize(frame, (int(w * scale), int(h * scale)))
                ok, jpeg = cv2.imencode('.jpg', frame,
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
        finally:
            try: cap.release()
            except Exception: pass
