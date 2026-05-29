# RTSP — full TCP-554 surface map

What the Larkfly A6+ (iCatch V39A-family SoC; `V11` is the ODM model
code, firmware build 20251206) exposes on its
RTSP port. Mapped exhaustively in May 2026 via `tools/rtsp_probe.py`
against a real device; 55 request/response pairs captured at
`analyses/data/rtsp_probe.json`, with an auto-generated table at
`analyses/data/rtsp_probe.md`.

## TL;DR

- Server identifies as **iCatchTek** in SDP `a=tool:` and stream titles;
  no `Server:` header on responses. Date header is `2012/1/1` (firmware
  clock never gets set — fine, but worth knowing for log correlation).
- **Both RTSP paths are app-side preview transcodes**, not the camera's
  real content. They exist for the iSmart DV2 app — a live viewfinder
  and a gallery playback stream, both downscaled and re-encoded to
  something a phone can decode cheaply:
  - `rtsp://<host>/MJPG` → **H.264 High @ Level 4.0, 640x360 @ 30 fps,
    no audio**. The app's live viewfinder. No audio because a
    framing-preview doesn't need it.
  - `rtsp://<host>/VIDEO/<name>.MOV` → **Motion JPEG +
    L16/48000/2 audio**. The app's playback path — the camera transcodes
    on the fly when you tap a file in the gallery.
  - **The actual SD-card recording** behind those preview streams is
    **3840x2160 H.264 High @ Level 5.2, 60 fps, with AAC-LC 48 kHz
    stereo**, in a QuickTime container branded `qt  icat`. Get it via
    FTP — see "On-disk recording format" below.
- Public verbs (from `OPTIONS`): `OPTIONS, DESCRIBE, SETUP, TEARDOWN,
  PLAY, PAUSE, GET_PARAMETER, SET_PARAMETER`. No `ANNOUNCE`/`RECORD`
  (so RTSP cannot drive recording — that is mode-toggle on property
  `0xD604`; see `findings.md`).
- **Crash-on-bad-URL is a real bug.** Any DESCRIBE for a non-existent
  stream path (e.g. `/H264`) or a `/MJPG?…` URL with an unrecognized
  query key (e.g. `…&FPS=30`) freezes the RTSP service hard enough
  that the camera needs a power-cycle. The probe is built around this
  constraint (per-request health check, resume mode).
- **Query parameters on `/MJPG` are ignored.** SDP body is byte-equal
  for `/MJPG`, `/MJPG?`, and `/MJPG?W=720&H=400&Q=50&BR=5000000`; the
  served stream is always 640x360 H.264. The webui's
  `?W=720&H=400&Q=50&BR=5000000` URL is harmless decoration.

## Server identity

| Field          | Value                                                                                       |
| -------------- | ------------------------------------------------------------------------------------------- |
| `Server:`      | not sent                                                                                    |
| `Date:`        | `2012/1/1` (unset RTC)                                                                      |
| `Public:`      | `OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, GET_PARAMETER, SET_PARAMETER`             |
| SDP tool       | `iCatchTek`                                                                                 |
| Stream title   | `H.264 Video. Streamed by iCatchTek.` / `Motion JPEG. Streamed by iCatchTek.`               |
| SDP timestamp  | `t=0 0` (no NPT bounds on live; `npt=0-<dur>` on file playback — exposes file duration)     |
| Build date     | `2013.11.26` — returned as the body of every `GET_PARAMETER`, regardless of body content    |

## Verb behaviour

| Verb              | Result                                  | Notes                                                                      |
| ----------------- | --------------------------------------- | -------------------------------------------------------------------------- |
| `OPTIONS`         | 200 OK, identical for any URI           | Server does not parse the URI for OPTIONS — even `OPTIONS *` works         |
| `DESCRIBE`        | 200 OK for `/MJPG`, `/VIDEO/<file>.MOV` | See "Wedge triggers" — wrong URI here can crash the service                |
| `SETUP`           | 200 OK; allocates a session             | Defaults to `RTP/AVP;client_port=0-1;server_port=6972-6973` if Transport omitted |
| `PLAY`            | 200 OK with a session; otherwise 454    |                                                                            |
| `PAUSE`           | 454 Session Not Found without session   |                                                                            |
| `TEARDOWN`        | 200 OK with session, 454 without        | ~110 ms (RTP allocator teardown)                                           |
| `GET_PARAMETER`   | 200 OK with session, 454 without        | Body is **always** `2013.11.26` regardless of request body                 |
| `SET_PARAMETER`   | 200 OK with session                     | No verifiable effect — `bandwidth: 5000000` accepted but stream unchanged  |
| `ANNOUNCE`        | 405 Method Not Allowed                  | Proper `Allow:` enumeration in response                                    |
| `RECORD`          | 405 Method Not Allowed                  | Confirms no server-side recording trigger via RTSP                         |
| `REDIRECT`        | 405 Method Not Allowed                  |                                                                            |
| `REGISTER`        | 405 Method Not Allowed                  |                                                                            |
| unknown verb      | 405 Method Not Allowed                  | e.g. `INVALID_METHOD`                                                      |
| `RTSP/9.9` version| 200 OK                                  | Server does not validate the RTSP version in the request line              |

## Codec & transport — what the two paths actually serve

### `/MJPG` (live preview — misnamed)

| Property               | Value                                                                  |
| ---------------------- | ---------------------------------------------------------------------- |
| Codec                  | H.264 High profile, Level 4.0 (`profile-level-id=640028`)              |
| Resolution             | **640x360** (confirmed via ffprobe; from SPS in `sprop-parameter-sets`) |
| Pixel format           | yuv420p, progressive, no B-frames                                       |
| Frame rate             | 30 fps                                                                  |
| Bandwidth attribute    | `b=AS:98304` (~98 Mbit/s ceiling — the real stream is well under)      |
| Audio                  | none — single video track                                              |
| Tracks                 | `track1` only                                                          |
| RTP payload type       | 96 (dynamic), `rtpmap:96 H264/90000`                                   |

### `/VIDEO/<name>.MOV` (transcoded gallery playback)

| Property               | Value                                                                  |
| ---------------------- | ---------------------------------------------------------------------- |
| Video codec            | **Motion JPEG** (RTP payload type 26, RFC 2435)                        |
| Audio codec            | **L16 / 48000 Hz / 2-channel** (RTP payload type 97)                   |
| Video bandwidth        | `b=AS:12288` (~12 Mbit/s)                                              |
| Audio bandwidth        | `b=AS:1500` (~1.5 Mbit/s)                                              |
| Tracks                 | `track1` (video), `track2` (audio)                                     |
| NPT range              | exposes file duration: `a=range:npt=0-2.25`                            |
| Curiosity              | SDP has a typo: `a=frmerate:30.0` (missing `a`) — iCatch firmware bug  |

What this stream is **not**: the file as stored on the SD card. The
real file is H.264 + AAC (see next section). The camera transcodes to
MJPEG + L16 on the fly when you DESCRIBE/PLAY this URL, presumably
because old iSmart DV2 versions decode MJPEG cheaply on phones. This
means `/VIDEO/*.MOV` over RTSP is **lossy** relative to the SD-card
original.

### On-disk recording format (FTP-only, the real file)

The .MOV files behind `/VIDEO/` look completely different when pulled
down via FTP and probed locally:

| Property        | Value                                                              |
| --------------- | ------------------------------------------------------------------ |
| Container       | QuickTime (`major_brand: qt  `, `compatible_brands: qt  icat`)     |
| Video codec     | H.264 High @ Level 5.2 (`is_avc=true`, `nal_length_size=4`)        |
| Resolution      | **3840 × 2160** (4K)                                               |
| Frame rate      | 60 fps                                                             |
| Pixel format    | yuv420p, BT.709 color (`color_space=bt709`)                        |
| Video bit rate  | ~1.85 Mbit/s (highly compressed for 4K60)                          |
| Audio codec     | AAC-LC, 48 kHz, stereo, ~129 kbit/s                                |
| Container brand | `qt  icat` — iCatch's QuickTime variant identifier                 |

The `creation_time` tag is set correctly (`2026-05-15T10:57:28Z` in
the sample), so unlike the RTSP `Date:` header the on-disk timestamps
*are* trustworthy.

So there are three different things to keep straight:

| Layer                | Codec / size              | Audio                   |
| -------------------- | ------------------------- | ----------------------- |
| Sensor → SD card     | H.264 4K60                | AAC-LC 48 kHz stereo    |
| `rtsp://…/VIDEO/<f>` | MJPEG (transcoded)        | L16 PCM 48 kHz stereo   |
| `rtsp://…/MJPG`      | H.264 640x360 @ 30 fps    | (none)                  |

### Default transport ports

When SETUP is sent without a `Transport:` header, the server picks
defaults and reports them back:

```
Transport: RTP/AVP;unicast;destination=192.168.1.10;source=192.168.1.1;
           client_port=0-1;server_port=6972-6973
```

So the **server uses UDP 6972 (RTP) / 6973 (RTCP)** by default. When
the probe asked for `RTP/AVP/TCP;interleaved=0-1`, the server agreed —
both UDP and TCP-interleaved transports work.

## Wedge triggers (do not do these)

The RTSP service has two URL-parser fragilities. Hitting either takes
the service down hard — TCP 554 stops `LISTEN`-ing, the camera does
not self-recover within 60 s, and the device needs a power-cycle. The
WiFi stack continues to answer ARP normally, which is what makes this
look at first like a sleep timeout rather than a crash.

| Trigger                                              | Survives request? | Recovery       |
| ---------------------------------------------------- | ----------------- | -------------- |
| `DESCRIBE rtsp://host/<nonexistent path>` (e.g. `/H264`) | No                | Power-cycle    |
| `DESCRIBE rtsp://host/MJPG?…&FPS=30` (unknown key)    | No                | Power-cycle    |
| `DESCRIBE rtsp://host/MJPG?<allowed keys only>`       | Yes               | —              |
| `OPTIONS rtsp://host/<anything>`                      | Yes (always 200)  | —              |
| `DESCRIBE rtsp://host/VIDEO/<file>.MOV` (real file)   | Yes               | —              |

The allowed query keys for `/MJPG` appear to be `W`, `H`, `Q`, `BR`
and they don't actually change the stream — the server accepts them
without crashing and returns the same SDP. Any *other* key looks
like it goes through a different code path that dereferences
something it shouldn't.

The DESCRIBE-on-bad-path crash matches the same pattern: a code path
that tries to bind the URI to a stream object and dies if there isn't
one (instead of returning 404 cleanly the way the root path `/` does
— `/` returns `404 Stream Not Found` and is fine).

## Concurrency

4 simultaneous DESCRIBE requests on `/MJPG` all returned 200 OK within
2.1 s wall-clock. The server serialises them rather than fanning out
— individual response times were 510 ms, 1076 ms, 1092 ms, 2101 ms —
but it does not lose, error, or refuse any of them. Multi-client
preview is supported.

We did not test simultaneous PLAY sessions (multiple active media
streams) — only the control-channel handling.

## Session lifecycle

```
client                                   camera
  │                                        │
  │── SETUP /MJPG/track1 ─────────────────▶│
  │     Transport: RTP/AVP/TCP;            │
  │       interleaved=0-1                  │
  │◀────────────── 200 OK ─────────────────│
  │                Session: 0D3DAC52       │
  │                Transport: ...;         │
  │                  interleaved=0-1       │
  │                                        │
  │── GET_PARAMETER  (with Session) ──────▶│
  │◀─── 200 OK, body "2013.11.26" ─────────│   (always; body content ignored)
  │                                        │
  │── SET_PARAMETER  (any key) ───────────▶│
  │◀─── 200 OK ────────────────────────────│   (no observable effect)
  │                                        │
  │── PLAY (with Session) ────────────────▶│
  │◀─── 200 OK ────────────────────────────│   (interleaved RTP starts)
  │                                        │
  │── TEARDOWN ───────────────────────────▶│
  │◀─── 200 OK (~110 ms) ──────────────────│
```

Session IDs are 8 hex chars (`[0-9A-F]{8}`), so 32 bits of state.
The probe captured `0D3DAC52` and `0AE349ED` — looks random rather
than sequential.

## Implications for this project

- **`webui/worker.py` could be simplified.** The query-string
  template `RTSP_URL_TMPL = "rtsp://{host}/MJPG?W=720&H=400&Q=50&BR=5000000"`
  doesn't do anything the server respects — but it stays harmless
  because all four keys are on the allow-list. Removing the query
  string would not change the stream and would slightly reduce the
  blast radius of an accidental URL edit (any unrecognized key crashes
  the camera).
- **The preview is 640x360**, not 720x400. The webui's
  `PREVIEW_MAX_WIDTH` and per-camera resolution dropdowns should
  not advertise dimensions the server doesn't honour.
- **For "real" recorded video, use FTP.** RTSP playback of
  `/VIDEO/<file>.MOV` is a lossy transcode (4K60 H.264 → 640x-ish
  MJPEG, AAC → L16). If a gallery feature wants full quality, it
  should `RETR` the file over FTP and play that directly. The on-disk
  file is a clean QuickTime/H.264/AAC container that any player
  handles natively.
- **The RTSP `/VIDEO/` path is still useful for instant in-browser
  previews of recordings** — it skips the FTP download and starts
  playing immediately. Just don't archive what it produces.
- **Be careful with stream-path probing in any future tools.** A
  single DESCRIBE for an unknown path bricks the RTSP service.
  `tools/rtsp_probe.py` is the only tool that should issue
  speculative DESCRIBEs.

## Reproducing

```bash
# Camera at 192.168.1.1 on the dongle, host at 192.168.1.10.
python3 tools/rtsp_probe.py --host 192.168.1.1 --bind 192.168.1.10 \
    --only info,session,params,playback,media,concurrency,paths_options,verbs

# If a section wedges the camera, power-cycle and resume:
python3 tools/rtsp_probe.py --resume \
    --host 192.168.1.1 --bind 192.168.1.10 \
    --only <whatever-was-running>

# Raw data: analyses/data/rtsp_probe.json (every request + response)
# Auto-tabulated:  analyses/data/rtsp_probe.md
```

The `paths` section (DESCRIBE over a path wordlist) is not run by
default — every unknown path is a wedge, and we already proved that
behaviour in the first capture (`docs/archive/` for the original
investigation log).
