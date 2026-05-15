# actionCamController

Linux controller for **Larkfly A6+** action cameras (iCatch chipset), replacing the iSmart DV2 Android app.

## Status

**Protocol confirmed end-to-end.** PTP/IP on TCP 15740 works against a
real Larkfly A6+ once three quirks are handled: (1) iCatch uses a
non-spec wire format for the initiator name (no length prefix), (2) the
camera whitelists the initiator name (`"localhost"` or empty only),
(3) PTP-IP packet types 11/12 are Cancel/EndData per spec (libgphoto2
convention), not the reverse. See `docs/findings.md`'s "Breakthrough"
section for the full reverse-engineered wire format and the camera's
complete `DeviceInfo` (28 ops, 9 events, 56 properties; 8 vendor ops
in 0x9xxx range, of which only `0x9601` and `0x9805` are used by
iSmart DV2 in a normal session).

- `docs/protocol.md` — original (now partly superseded) hypothesis
- `docs/findings.md` — APK static-analysis results + live investigation log
- `probes/ptpip_probe.py` — works at the framing layer; ready to use once
  PTP/IP is unlocked. Use `--bind 192.168.1.10` when running.
- `probes/wifi_provision.py` — sandbox; can't be tested until PTP/IP opens
- `apk-analysis/` — APK and decompile artifacts (gitignored)

## Camera basics

- WiFi hotspot (default password `1234567890`); client receives `192.168.1.10`, camera is `192.168.1.1`
- RTSP live stream on port 554, FTP on port 21 (`wificam` / `wificam`)
- Control protocol: candidate is JSON-over-TCP on port 7878 — pending APK confirmation

## Prior art

- [Rollei AC 420 reverse engineering](https://github.com/clerie/rollei-AC-420)
- [iCatch V50 Playground](https://github.com/Linouth/iCatch-V50-Playground)
