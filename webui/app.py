#!/usr/bin/env python3
"""Multi-camera Larkfly A6+ controller — Flask web UI.

Architecture mirrors the parent ClaudesWorld/webcam/app.py: each slot owns
a LarkflyWorker thread; the Flask server serves MJPEG preview streams per
slot and a small JSON API for control.

Usage:
    python3 webui/app.py                          # auto-detect 1 camera at 192.168.1.1
    python3 webui/app.py --camera 192.168.1.1     # specify cameras explicitly
    python3 webui/app.py --camera 192.168.50.11 --camera 192.168.50.12

When using multiple cameras on the same subnet from a single host, set
`--bind <local-ip>` if the cameras share IPs (e.g., all default to
192.168.1.1 and you're routing each one through a different USB WiFi
dongle); pass `--bind` once for the single source IP that should be
used for outgoing PTP-IP connections.
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import time
from datetime import datetime
from typing import Optional

from flask import Flask, Response, jsonify, render_template, request

# Make `larkfly` importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from webui.worker import LarkflyWorker

app = Flask(__name__,
            template_folder=os.path.join(os.path.dirname(__file__), 'templates'))

# Populated by main()
WORKERS: list[LarkflyWorker] = []
_workers_lock = threading.Lock()

# Burst-record state — when set, all currently-running workers are
# recording for a fixed duration and a timer will stop them.
_burst_lock = threading.Lock()
_burst_active = False
_burst_started_at = 0.0
_burst_duration = 0


# ──────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html', n_slots=len(WORKERS))


@app.route('/video_feed/<int:slot>')
def video_feed(slot):
    """MJPEG-over-HTTP multipart stream for the given slot."""
    if slot < 0 or slot >= len(WORKERS):
        return '', 404
    return Response(_mjpeg_generator(slot),
                    mimetype='multipart/x-mixed-replace; boundary=frame')


def _mjpeg_generator(slot: int):
    """Yield multipart MJPEG frames at up to ~15 FPS."""
    boundary = b'--frame\r\n'
    last_jpeg = None
    while True:
        worker = WORKERS[slot] if slot < len(WORKERS) else None
        if worker is None:
            time.sleep(0.5)
            continue
        jpeg = worker.get_jpeg()
        if jpeg is None or jpeg is last_jpeg:
            time.sleep(0.05)
            continue
        last_jpeg = jpeg
        yield (boundary
               + b'Content-Type: image/jpeg\r\n'
               + f'Content-Length: {len(jpeg)}\r\n\r\n'.encode()
               + jpeg
               + b'\r\n')
        time.sleep(1 / 15)  # cap at 15 FPS to keep the browser sane


@app.route('/api/status')
def api_status():
    """Aggregate status of every slot."""
    statuses = []
    for w in WORKERS:
        try:
            statuses.append(w.get_status())
        except Exception as e:
            statuses.append({'slot': w.slot, 'state': 'error', 'error': str(e)})
    return jsonify({
        'slots': statuses,
        'burst': {
            'active': _burst_active,
            'started_at': _burst_started_at,
            'duration_s': _burst_duration,
            'elapsed_s': time.time() - _burst_started_at if _burst_active else 0,
        },
    })


@app.route('/api/capture', methods=['POST'])
def api_capture():
    """Trigger InitiateCapture on all RUNNING workers concurrently."""
    results = []
    threads = []
    out = {}
    def go(w):
        try:
            h = w.take_photo()
            out[w.slot] = {'ok': True, 'handle': h}
        except Exception as e:
            out[w.slot] = {'ok': False, 'error': str(e)}
    for w in WORKERS:
        if w.state == w.RUNNING:
            tr = threading.Thread(target=go, args=(w,))
            tr.start()
            threads.append(tr)
    for tr in threads: tr.join(timeout=10)
    return jsonify({'results': out})


@app.route('/api/record/start', methods=['POST'])
def api_record_start():
    """Start recording on all RUNNING workers concurrently."""
    out = {}
    threads = []
    def go(w):
        try:
            w.start_recording()
            out[w.slot] = {'ok': True}
        except Exception as e:
            out[w.slot] = {'ok': False, 'error': str(e)}
    for w in WORKERS:
        if w.state == w.RUNNING:
            tr = threading.Thread(target=go, args=(w,))
            tr.start()
            threads.append(tr)
    for tr in threads: tr.join(timeout=10)
    return jsonify({'results': out})


@app.route('/api/record/stop', methods=['POST'])
def api_record_stop():
    out = {}
    threads = []
    def go(w):
        try:
            w.stop_recording()
            out[w.slot] = {'ok': True}
        except Exception as e:
            out[w.slot] = {'ok': False, 'error': str(e)}
    for w in WORKERS:
        if w.state == w.RUNNING:
            tr = threading.Thread(target=go, args=(w,))
            tr.start()
            threads.append(tr)
    for tr in threads: tr.join(timeout=10)
    return jsonify({'results': out})


@app.route('/api/burst', methods=['POST'])
def api_burst():
    """Start synchronized recording, auto-stop after `duration` seconds.

    Body: {"duration": 5}
    """
    global _burst_active, _burst_started_at, _burst_duration
    try:
        duration = int(request.get_json(silent=True).get('duration', 3))
    except Exception:
        duration = 3
    duration = max(1, min(60, duration))

    with _burst_lock:
        if _burst_active:
            return jsonify({'error': 'burst already active'}), 409
        _burst_active = True
        _burst_started_at = time.time()
        _burst_duration = duration

    # Start all in parallel
    out = {}
    threads = []
    def go_start(w):
        try:
            w.start_recording()
            out[w.slot] = {'started': True}
        except Exception as e:
            out[w.slot] = {'started': False, 'error': str(e)}
    for w in WORKERS:
        if w.state == w.RUNNING:
            tr = threading.Thread(target=go_start, args=(w,))
            tr.start()
            threads.append(tr)
    for tr in threads: tr.join(timeout=5)

    # Schedule stop
    def stop_after():
        global _burst_active
        time.sleep(duration)
        threads = []
        def go_stop(w):
            try: w.stop_recording()
            except Exception: pass
        for w in WORKERS:
            if w.state == w.RUNNING:
                tr = threading.Thread(target=go_stop, args=(w,))
                tr.start()
                threads.append(tr)
        for tr in threads: tr.join(timeout=5)
        with _burst_lock:
            _burst_active = False
    threading.Thread(target=stop_after, daemon=True).start()

    return jsonify({'started': True, 'duration': duration, 'cameras': out})


# ──────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--camera', action='append', default=[],
                    help="camera IP (repeat for multiple). Default: 192.168.1.1")
    ap.add_argument('--bind', default='192.168.1.10',
                    help="local source IP for PTP-IP socket binding. Default: "
                         "192.168.1.10")
    ap.add_argument('--port', type=int, default=5000,
                    help="HTTP port (default 5000)")
    ap.add_argument('--host', default='127.0.0.1',
                    help="HTTP bind address (default 127.0.0.1)")
    args = ap.parse_args()

    cameras = args.camera or ['192.168.1.1']
    for i, host in enumerate(cameras):
        w = LarkflyWorker(slot=i, host=host, bind=args.bind, name=f"cam{i}")
        WORKERS.append(w)
        w.start()
        print(f"[slot {i}] starting worker for {host}")

    print(f"\nUI: http://{args.host}:{args.port}/")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == '__main__':
    main()
