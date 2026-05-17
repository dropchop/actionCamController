# RTSP (TCP 554) — full surface map

Output of `tools/rtsp_probe.py`. The Larkfly RTSP server is fragile (some DESCRIBE targets freeze the camera hard enough to need a power cycle), so the probe runs with a health-check between every request and aborts on the first lockup. Re-run with `--resume` after a reset to continue.

- Host: `192.168.1.1`
- Bind: `192.168.1.10`
- Run started: 2026-05-15T16:00:53
- Run finished: 2026-05-16T20:01:45

## Server identity

- `Server:` header — `(none — header absent)`
- `Public:` header — `OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, GET_PARAMETER, SET_PARAMETER`

## OPTIONS / known-good DESCRIBE

| Label | Status | Reason | Elapsed | Highlight |
|---|---|---|---|---|
| `info:options-mjpg` | 200 | OK | 48ms |  |
| `info:options-star` | 200 | OK | 48ms |  |
| `info:describe-mjpg` | 200 | OK | 446ms | m=video 0 RTP/AVP 96 |

## RTSP session — SETUP + GET_PARAMETER + SET_PARAMETER + TEARDOWN

| Label | Status | Reason | Elapsed | Highlight |
|---|---|---|---|---|
| `session:setup-track1` | 200 | OK | 44ms |  |
| `session:get-parameter-empty` | 200 | OK | 37ms |  |
| `session:get-parameter-named` | 200 | OK | 36ms |  |
| `session:set-parameter-bandwidth` | 200 | OK | 35ms |  |
| `session:teardown` | 200 | OK | 110ms |  |

## Parameter exploration on /MJPG

| Label | Status | Reason | Elapsed | Highlight |
|---|---|---|---|---|
| `params:bare` | 200 | OK | 454ms | m=video 0 RTP/AVP 96 |
| `params:W=320,H=240,Q=50,BR=500000` | None |  | 3006ms |  |
| `params:W=720,H=400,Q=50,BR=5000000` | 200 | OK | 1450ms | m=video 0 RTP/AVP 96 |
| `params:W=720,H=400,Q=50,BR=5000000,FPS=30` | None |  | 8010ms |  |

## Playback of recorded files — /VIDEO/<file>

| Label | Status | Reason | Elapsed | Highlight |
|---|---|---|---|---|
| `playback:20260515_035416.MOV` | 200 | OK | 289ms | m=video 0 RTP/AVP 26 |

## Path enumeration via OPTIONS (low-risk)

| Label | Status | Reason | Elapsed | Highlight |
|---|---|---|---|---|
| `paths-options:/H264` | 200 | OK | 57ms |  |
| `paths-options:/H265` | 200 | OK | 54ms |  |
| `paths-options:/AVC` | 200 | OK | 50ms |  |
| `paths-options:/HEVC` | 200 | OK | 54ms |  |
| `paths-options:/MAIN` | 200 | OK | 53ms |  |
| `paths-options:/SUB` | 200 | OK | 51ms |  |
| `paths-options:/MAIN0` | 200 | OK | 52ms |  |
| `paths-options:/SUB0` | 200 | OK | 53ms |  |
| `paths-options:/PREVIEW` | 200 | OK | 52ms |  |
| `paths-options:/LIVE` | 200 | OK | 53ms |  |
| `paths-options:/STREAM` | 200 | OK | 51ms |  |
| `paths-options:/STREAM1` | 200 | OK | 54ms |  |
| `paths-options:/VIDEO` | 200 | OK | 53ms |  |
| `paths-options:/AUDIO` | 200 | OK | 50ms |  |
| `paths-options:/0` | 200 | OK | 52ms |  |
| `paths-options:/1` | 200 | OK | 53ms |  |
| `paths-options:/ch0` | 200 | OK | 55ms |  |
| `paths-options:/ch1` | 200 | OK | 52ms |  |
| `paths-options:/ICATCH` | 200 | OK | 51ms |  |
| `paths-options:/CAM` | 200 | OK | 54ms |  |
| `paths-options:/CAM0` | 200 | OK | 53ms |  |
| `paths-options:/MJPEG` | 200 | OK | 50ms |  |
| `paths-options:/JPG` | 200 | OK | 53ms |  |
| `paths-options:/nonexistent_dummy_path` | 200 | OK | 53ms |  |

## Verb behaviour

| Label | Status | Reason | Elapsed | Highlight |
|---|---|---|---|---|
| `verbs:OPTIONS` | 200 | OK | 60ms |  |
| `verbs:DESCRIBE` | 200 | OK | 65ms | m=video 0 RTP/AVP 96 |
| `verbs:SETUP` | 200 | OK | 80ms |  |
| `verbs:PLAY` | 454 | Session Not Found | 48ms |  |
| `verbs:PAUSE` | 454 | Session Not Found | 48ms |  |
| `verbs:TEARDOWN` | 454 | Session Not Found | 56ms |  |
| `verbs:GET_PARAMETER` | 454 | Session Not Found | 58ms |  |
| `verbs:SET_PARAMETER` | 454 | Session Not Found | 56ms |  |
| `verbs:ANNOUNCE` | 405 | Method Not Allowed | 58ms |  |
| `verbs:RECORD` | 405 | Method Not Allowed | 60ms |  |
| `verbs:REDIRECT` | 405 | Method Not Allowed | 58ms |  |
| `verbs:REGISTER` | 405 | Method Not Allowed | 57ms |  |
| `verbs:garbage-method` | 405 | Method Not Allowed | 63ms |  |
| `verbs:garbage-version` | 200 | OK | 57ms |  |

## Concurrent DESCRIBE

| Label | Status | Reason | Elapsed | Highlight |
|---|---|---|---|---|
| `concurrency:worker0` | 200 | OK | 510ms | m=video 0 RTP/AVP 96 |
| `concurrency:worker1` | 200 | OK | 2101ms | m=video 0 RTP/AVP 96 |
| `concurrency:worker2` | 200 | OK | 1076ms | m=video 0 RTP/AVP 96 |
| `concurrency:worker3` | 200 | OK | 1092ms | m=video 0 RTP/AVP 96 |

## Media flow (ffprobe over RTSP-TCP)

```json
{
  "available": true,
  "transport": "tcp",
  "returncode": 0,
  "stderr": "",
  "streams": {
    "streams": [
      {
        "index": 0,
        "codec_name": "h264",
        "codec_long_name": "H.264 / AVC / MPEG-4 AVC / MPEG-4 part 10",
        "profile": "High",
        "codec_type": "video",
        "codec_tag_string": "[0][0][0][0]",
        "codec_tag": "0x0000",
        "width": 640,
        "height": 360,
        "coded_width": 640,
        "coded_height": 360,
        "closed_captions": 0,
        "has_b_frames": 0,
        "pix_fmt": "yuv420p",
        "level": 40,
        "chroma_location": "left",
        "field_order": "progressive",
        "refs": 1,
        "is_avc": "false",
        "nal_length_size": "0",
        "r_frame_rate": "30/1",
        "avg_frame_rate": "30/1",
        "time_base": "1/90000",
        "start_pts": 18960,
        "start_time": "0.210667",
        "bits_per_raw_sample": "8",
        "disposition": {
          "default": 0,
          "dub": 0,
          "original": 0,
          "comment": 0,
          "lyrics": 0,
          "karaoke": 0,
          "forced": 0,
          "hearing_impaired": 0,
          "visual_impaired": 0,
          "clean_effects": 0,
          "attached_pic": 0,
          "timed_thumbnails": 0
        }
      }
    ],
    "format": {
      "filename": "rtsp://192.168.1.1/MJPG",
      "nb_streams": 1,
      "nb_programs": 0,
      "format_name": "rtsp",
      "format_long_name": "RTSP input",
      "start_time": "0.210667",
      "probe_score": 100,
      "tags": {
        "title": "H.264 Video. Streamed by iCatchTek.",
        "comment": "H264"
      }
    }
  }
}
```

## Notes

- Session id from SETUP: 0D3DAC52
- FTP auto-discover .MOV: failed
- FTP auto-discover .MOV: 20260515_035416.MOV

## SDP body — `DESCRIBE /MJPG`

```
v=0
o=- 274607610 1 IN IP4 192.168.1.1
s=H.264 Video. Streamed by iCatchTek.
i=H264
t=0 0
a=tool:iCatchTek
a=type:broadcast
a=control:*
a=range:npt=0-
a=x-qt-text-nam:H.264 Video. Streamed by iCatchTek.
a=x-qt-text-inf:H264
m=video 0 RTP/AVP 96
c=IN IP4 0.0.0.0
b=AS:98304
a=rtpmap:96 H264/90000
a=fmtp:96 packetization-mode=1;profile-level-id=640028;sprop-parameter-sets=Z2QAKKy0BQF/ywgAAH0AAB1MBCA=,aO44sA==
a=framerate:30.0
a=control:track1
```
