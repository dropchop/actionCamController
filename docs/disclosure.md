# Security disclosure — pre-auth DoS in the iCatch PTP/IP service

**Status:** Drafted 2026-05-20. **Not yet sent.** See "Disclosure plan"
below for recommended recipients; the project owner should send it and
record dates in the timeline table.

## Summary

The Larkfly A6+ action camera (iCatch V39A-family SoC, firmware build
`20251206`) exposes a PTP/IP control service on TCP port 15740. A single
malformed packet, sent after the normal — unauthenticated — PTP/IP
handshake, permanently disables that service until the camera is
power-cycled. The attack is remote, needs no credentials, and takes the
camera's primary control surface offline for every client, including
the official iSmart DV2 app.

## Affected

- **Confirmed:** Larkfly A6+ / model `V11`, firmware `20251206`. The
  same white-label hardware also ships as **VIRAN V11** and
  **CERASTES V11**.
- **Likely:** any camera running the stock iCatch PTP/IP service from
  the same SDK generation (the iCatch V37/V39 family, possibly adjacent
  iCatch chipsets). Not independently verified on other units.

## Type

Improper handling of an unexpected PTP/IP packet type in the
post-initialisation dispatcher (CWE-20 Improper Input Validation; the
persistent lock-out points to CWE-667 Improper Locking or CWE-400
Uncontrolled Resource Consumption — a leaked session lock / connection
slot). Pre-authentication remote denial of service.

## Reproduction

Prerequisite: be associated to the camera's WiFi AP (default WPA2-PSK
`1234567890` — i.e. any device that can see the camera).

1. TCP-connect to `192.168.1.1:15740`.
2. Send a valid PTP/IP `InitCmdReq` (packet type 1): a 16-byte GUID,
   the initiator name `localhost` as raw UTF-16LE + NUL, then a u32
   protocol version.
3. Receive the normal `InitCmdAck`.
4. Send one more PTP/IP container with:
   - `length = 14` (u32 LE)
   - `packet type = 0` (u32 LE) — or `1`, or `2`
   - 6 arbitrary payload bytes
5. The camera does not reply, and the PTP/IP service is now dead.
6. Every subsequent `InitCmdReq`, from any client, returns
   `InitFail reason=3` regardless of the (otherwise valid) initiator
   name.
7. Recovery requires a physical power-cycle of the camera.

Confirmed deterministic on a freshly-booted camera for packet types
**0, 1 and 2**, each tested in isolation with a power-cycle between
tests. Reproduced by `tools/ptp_container_fuzz.py` (phase 3) and
`tools/ptp_p3_full_isolate.py`. The misleading `InitFail reason=3`
("initiator name not allowed") is almost certainly not the real
failure mode — it is the closest available PIMA error code being
returned for internal-state corruption.

## Impact

- **Remote** — any host on the camera's WiFi AP.
- **Pre-authentication** — PTP/IP `InitCmdReq` is itself unauthenticated.
- **Single packet**, after a one-round-trip handshake.
- **Persistent** — the control surface stays down until power-cycle; no
  timeout-based recovery observed within at least 60 s.
- Denies camera control to every client, including the vendor's own app.

This is a denial of service only. No memory disclosure or code
execution has been found; whether the underlying dispatcher fault is
exploitable beyond DoS is unknown and not claimed.

## Suggested remediation (vendor)

Validate the PTP/IP packet-type field in the post-init dispatcher and
reject or ignore unknown types without disturbing session state, rather
than falling through a default branch that leaks a lock or connection
slot.

## Mitigation (users)

Treat the camera's WiFi AP as a trusted-only network; do not expose it
to untrusted devices. No firmware fix is available.

## Disclosure plan

This camera is a white-label product; Larkfly is a reseller and is
unlikely to operate a security contact. The PTP/IP service originates
from **iCatch Technology Inc.** (the SoC/SDK vendor). Recommended
recipients, in order:

1. **iCatch Technology Inc.** — via the contact channel on
   `icatchtek.com`. They own the affected code.
2. **CERT/CC** (CERT Coordination Center) coordinated-disclosure
   submission — appropriate when there is no vendor PSIRT; CERT/CC will
   attempt vendor contact and can coordinate a CVE.
3. Optionally request a CVE ID from MITRE if no CNA covers the product.

Suggested embargo: 90 days from first vendor contact (standard
coordinated-disclosure practice).

| Date | Action |
| --- | --- |
| 2026-05-20 | Advisory drafted (this document). |
| _TBD_ | Sent to iCatch Technology / CERT/CC — fill in when sent. |

## Reporter

Project: `actionCamController` (github.com/dropchop/actionCamController).
The project owner should add a preferred disclosure contact here before
sending (kept out of the repo until then, per the project's "scrub
personal info" policy).
