# Project retrospective — actionCamController / larkfly

A review of the Larkfly A6+ (iCatch V11) reverse-engineering project: the
`larkfly` library, the `webui` controller, the `tools/` + `analyses/`
investigation infrastructure, and the `docs/` log trail. Compiled
2026-05-20 from the repo state on branch `claude/zen-brattain-b972d8`
and the full doc/commit history. Revised 2026-05-20 after web
verification — see "Camera identity" below, which the first pass missed.

---

## What went well

- **The hard RE was done properly.** The four off-spec PTP/IP wire
  quirks (no-length-prefix initiator name, `"localhost"` whitelist,
  packet-type-12 = EndData, the `SendObjectInfo.Filename` 4-byte
  alignment header) are genuinely non-obvious, each is characterized
  with captured wire bytes, and each is covered by a unit test. This is
  the core deliverable and it is solid.

- **WPA2 pcap decryption from scratch.** `tools/decrypt_pcap.py` derives
  PMK→PTK and AES-CCM-decrypts monitor-mode captures with pure stdlib +
  `cryptography`, including recovering the PTK without EAPOL M1 and
  brute-forcing the Realtek `0xC78F` AAD-FC mask quirk. That is real
  signal-processing work, not glue code.

- **Crash-safe tooling discipline.** The camera wedges on several RTSP
  and PTP vendor inputs. Instead of fighting that, the probes
  (`ptp_vendor_probe.py`, `rtsp_probe.py`, `ptp_p3_full_isolate.py`)
  health-check between requests and checkpoint to JSON so a run resumes
  across power-cycles. Correct engineering for a hostile target.

- **Safety culture.** `CLAUDE.md`'s "Landmines" section, always
  `DeleteObject` after `SendObject`, never selecting "Yes" on the
  `SPHOST.BRN` FW-UPDATE menu, mirroring factory files before editing,
  documented power-cycle recovery — the brick risk was understood and
  managed throughout.

- **Documentation architecture.** The split is genuinely good:
  `findings.md` = current truth, `archive/` = chronological story,
  `untried-vectors.md` = forward inventory, per-surface files
  (`ports.md`, `rtsp.md`, `ptp-vendor.md`). Dead ends are recorded so
  they aren't re-walked. Most RE projects don't document this well.

- **Methodical breadth.** All 56 properties enumerated, all 8 vendor
  opcodes swept, all 65,535 TCP ports scanned, MSC/UVC/Bluetooth all
  checked. The "is there a dev console" question was answered honestly:
  no, not on the wire.

- **A real find.** The pre-auth PTP/IP DoS (`bf80f8c`) is a legitimate
  CVE-class bug — remote, unauthenticated, single packet, persistent
  until power-cycle — with a clean minimal reproducer.

- **The library is clean.** Pure-stdlib core, typed (`py.typed`), 23
  passing tests, sensible package layout, optional-extras split in
  `pyproject.toml`. `Camera.connect()`'s auto-recovery from the
  cross-disconnect `DeviceBusy` session-state quirk is a nice touch.

---

## What can be improved

- **Doc rot — stale counts contradict each other.**
  - `README.md:10` still says "three undocumented quirks"; there are
    four (the 4th, `findings.md` quirk #4, landed in `583daf5`).
    `docs/archive/investigation-log.md:816` also says "three" — that
    one is archived so it's acceptable, the README is not.
  - `docs/ports.md:122-124` says `operations_supported` "enumerates 23
    vendor codes ... the other 22 are unexplored." Every other doc
    (`findings.md:67`, `ptp-vendor.md:3`) correctly says **8** vendor
    opcodes. `ports.md` was written before the vendor sweep and never
    reconciled.

- **`docs/dev-console-hunt.md` Status table has copy-paste cruft.**
  Step `1.3` appears three times, `1.4` twice, `1.1c` twice — some rows
  marked done, duplicates marked pending. The table is unreliable as a
  progress tracker.

- **No CI, no constant validation.** The 23 tests exercise the codec
  but nothing checks opcode constants against the PTP spec. A
  three-line test (`assertEqual(OP_INITIATE_CAPTURE, 0x100E)`, etc.)
  would have caught the bug in the next section. For a public repo,
  a minimal GitHub Actions workflow running `unittest` is cheap.

- **A codec bug — found, and not the one the docs claimed.**
  `findings.md` and `dev-console-hunt.md` had described a `larkfly`
  "`PropDesc.current_value` STRING bleed bug." Re-examined 2026-05-20:
  that bug is **not real** — `parse_prop_desc` decodes all 56 captured
  descriptors correctly. A *different*, genuine bug was found instead:
  `encode_ptp_string` derived the PTP `NumChars` count from Python code
  points, so non-BMP strings went out malformed. Both the false claim
  and the real bug are now corrected — the encoder is fixed in
  `larkfly/protocol.py`.

- **Test coverage stops at the codec.** `camera.py` (383 lines —
  session recovery, the capture paths, event polling) has no tests.
  Hardware dependence makes full coverage hard, but the session-state
  recovery logic is pure enough to test with a socket fake.

- **README oversells multi-camera.** README and `architecture.md`
  present a 4-camera controller, but multi-camera was only ever
  verified with **one** camera (one WiFi *or* one USB). "4 × 1080p
  MJPEG fits the 480 Mb/s bus with margin" is asserted, never measured.
  The headline goal is half-finished; the README reads as if it isn't.

---

## What was messed up

- **Mislabeled PTP opcode constants — `larkfly/types.py:49,54,55`.**
  Against standard PIMA 15740 (which the docs themselves use to name
  the `DeviceInfo` operations list):

  | `types.py` constant | Defined as | `0x...` actually is | Correct value |
  |---|---|---|---|
  | `OP_INITIATE_CAPTURE` | `0x100C` | SendObjectInfo | **`0x100E`** |
  | `OP_INITIATE_OPEN_CAPTURE` | `0x100D` | SendObject | `0x101C` |
  | `OP_TERMINATE_OPEN_CAPTURE` | `0x101B` | GetPartialObject | `0x1018` |

  Only `OP_GET_PARTIAL_OBJECT = 0x101B` is right. The investigation log
  itself names these correctly in the `DeviceInfo` dump
  (`investigation-log.md:583-584`: "SendObjectInfo, SendObject,
  InitiateCapture ... GetPartialObject") — so the camera enumeration
  was decoded right, then the library constants were filled in wrong.

- **A fabricated comment papering over the collision.**
  `types.py:56-60` claims `0x101B` is "ALSO ... the same opcode reused
  ... in iCatch context the camera advertises it as supported and uses
  it for both" `TerminateOpenCapture` and `GetPartialObject`. That is
  not true — they are distinct opcodes (`0x1018` vs `0x101B`). When two
  constants collided, the fix was a rationalizing comment instead of
  correcting the value. The same misread propagated into `CLAUDE.md`
  and `findings.md:127` ("the camera advertises `InitiateOpenCapture
  (0x101B)`" — it advertises GetPartialObject; real InitiateOpenCapture
  `0x101C` is *not* in the supported list at all).

- **Consequence: the "photo capture is a dead end" conclusion is
  unsound.** `Camera.take_photo()` (`camera.py:323`) sends
  `OP_INITIATE_CAPTURE`, which is `0x100C` = **SendObjectInfo**. So
  every "InitiateCapture returns OK + a new handle but no JPG appears"
  observation (`findings.md`, `README.md`, `investigation-log.md:791`)
  was SendObjectInfo creating an empty object stub awaiting a data
  phase — which is *exactly* what the log saw ("handles with
  `format=0x3000 Undefined`, tiny sizes 5–21 bytes"). The real
  `InitiateCapture` (`0x100E`) was never sent.

  **What the captured data does and doesn't show.**
  `analyses/data/transactions.json` records the iSmart DV2 session
  *sending* `InitiateCapture (0x100E)` with params `[0, 0]` at txid
  352 — so a photo capture WAS attempted in the session. (The
  op-frequency table mislabelled this transaction as "GetPartialObject",
  and `investigation-log.md:800` wrongly concluded the session "didn't
  include a photo capture"; `investigation-log.md:636` lists it as a
  "snapshot".) But that capture is **request-side only** — responses
  were reassembled for just 7 of 574 transactions, none past txid 12 —
  so it does NOT show whether the app's `InitiateCapture` succeeded.

  Live test 2026-05-20 (`tools/photo_capture_test.py`): with the
  opcode corrected, `InitiateCapture(0x100E, [0,0])` returns `rc=OK`
  but produces no JPG / event / object in modes 3-6, with or without a
  live RTSP preview. **The opcode fix was necessary but does not
  resolve photo capture** — that remains open. (An earlier draft of
  this review overstated this as "the proof was in the repo's data the
  whole time" and implied the opcode fix alone would close the photo
  bug. Corrected here: the data shows an *attempt*, not a success, and
  the live test disproves the implication.)

  Video recording was unaffected only by luck: `start_recording()`
  uses the `0xD604` property toggle, which works regardless. But the
  parallel conclusion "`InitiateOpenCapture` is a no-op for video"
  (`investigation-log.md:757`) rests on sending `0x100D` = SendObject —
  also the wrong opcode.

- **The "camera advertises InitiateOpenCapture" premise is false.**
  `findings.md:127` and `CLAUDE.md` frame the recording design around
  "the camera advertises `InitiateOpenCapture` ... but doesn't use it
  for video." The camera's `DeviceInfo` advertises `0x101B` =
  **GetPartialObject** (the project's own decode at
  `investigation-log.md:584` says exactly that). `InitiateOpenCapture`
  (`0x101C`) and `TerminateOpenCapture` (`0x1018`) are **not in the
  supported list at all**. The 0xD604-toggle design is right; its
  stated rationale is built on a misread opcode.

- **The DoS retraction was a self-inflicted error.** Commits
  `bf80f8c` → `c295453` ("Retract overreach: only ptype=0 confirmed")
  → `83a737e` ("confirm ptypes 1+2 also trigger") are a claim, a
  retraction, and a re-confirmation of the original claim.
  `dev-console-hunt.md` states the retraction "was based on a test
  where the camera hadn't been rebooted between sends" — it skipped
  the project's own central, repeatedly-stated rule (power-cycle
  between DoS tests, because the bug is persistent-until-power-cycle).
  A known protocol was ignored, producing a wrong retraction and three
  commits of churn over one finding.

- **Camera identity — "V11" is not an iCatch product code.**
  `findings.md:13`, `README.md:3` and `CLAUDE.md` all state the camera's
  `ProductName` property (`0x501E` = `'V11'`) is the "iCatch internal
  product code." Web verification (2026-05-20) shows that is wrong:
  - iCatch Technology's own catalog (icatchtek.com) lists **no V11
    SoC**. The consumer-imaging line is V9 / V33 / V35 / V57 / V77; the
    V37/V39 part ships as packages V37A / V37M / V39A / V39M.
  - "V11" is a **generic white-label action-camera model number** —
    the same hardware sells as the **VIRAN V11** and **CERASTES V11**
    ("4K/5K WiFi anti-shake action camera, 48 MP"). "Larkfly A6+" is
    another rebrand of that ODM platform. `0x501E` carries the **ODM
    model code**, set by the firmware build — not an iCatch name.
  - The VIRAN V11 spec sheet names the SoC as **iCatch V39A ("V39AX")**
    with an IMX386 sensor, 48 MP photo / 4K60 video — matching this
    camera's `findings.md` specs. USB PIDs `2aad:6371/6373` sit in
    iCatch's `0x63xx` band beside the SPCA635x / V37-V39 family.
  - **The project already knew this.** `dev-console-hunt.md` §4 ("Our
    V11 is likely an iCatch V39 (SPCA63xx) ... V11 does not exist in
    iCatch's catalog") reached the right answer — but the correction
    was never carried into `findings.md` / `README.md` / `CLAUDE.md`.
    The repo now asserts both "V11 is the iCatch code" and "V11 is not
    an iCatch code" in different files.
  - `0x501F` `FwVersion` = `'20251206'` is the same kind of field — an
    ODM-populated property string. As a `YYYYMMDD` build date
    (2025-12-06) it's a fair read (iCatch firmware is date-coded), but
    it is a build stamp, not a semantic version, and not iCatch-canonical.

---

## What was missed

- **The opcode bug itself.** It survived from `72bf2f3` (library
  added) through every subsequent session, the `findings.md` rewrite,
  and the `CLAUDE.md` authoring — propagated into comments and three
  docs without anyone cross-checking `types.py` against the spec or
  against the project's own correctly-decoded `DeviceInfo` list.

- **Photo capture was abandoned before the real op was tried.**
  `findings.md` declares photo-via-PTP "a dead end" and falls back to
  the physical shutter button. Given the above, the cheapest next
  experiment in the whole project is: fix `OP_INITIATE_CAPTURE` to
  `0x100E` and call it once. That was never done.

- **Responsible disclosure of the DoS.** `dev-console-hunt.md`
  lists "disclose to Larkfly / iCatch upstream" as follow-up #3, and
  notes the bug "almost certainly affects all V11-family cameras." No
  evidence in the repo that any disclosure was attempted. A CVE-class
  pre-auth DoS affecting a product family warrants at least a
  documented disclosure attempt (vendor contact, or CERT/CC if no
  PSIRT).

- **Unresolved contradiction: two different SimpleConfig AES keys.**
  `findings.md:177` gives the default AES-128 key as
  `b"echo1234echo1234"` (from `libcontrol.so` RE).
  `untried-vectors.md:289` gives it as
  `21 7E 1A 16 28 DE D2 A7 AB E7 85 88 09 CA 40 3C` (from the APK).
  Both can't be "the" key for the same feature. (An earlier draft of
  this review called the APK value "conspicuously close to" the
  FIPS-197 AES test vector `2b7e151628aed2a6abf7158809cf4f3c` — that
  was wrong: only 8 of 16 bytes match, i.e. no meaningful resemblance.
  The two keys simply disagree.) The contradiction is unresolved and
  cannot be settled offline: `apk-analysis/` is gitignored and not
  extracted. Resolving it needs the APK re-extracted, then reading
  `ICatchCameraAssistImpl.java` to see whether that key actually feeds
  the SmartConfig path.

- **Storage size — resolved 2026-05-20.** `findings.md:16`'s "62.5 GB
  SD" was correct. Live `StorageInfo` probe: `max_capacity=67092086784`
  (62.5 GB), `free_space_bytes=66817359872`, `storage_type=4`
  (removable RAM = SD card). The earlier `dev-console-hunt.md` entry
  ("~261 MB total ... internal G: partition") was wrong — that probe
  ran while the SD card was absent or not yet mounted. `dev-console-hunt.md`
  corrected 2026-05-20.

- **This report's first pass missed the V11 misidentification.** It
  accepted the docs' "iCatch internal product code" framing at face
  value and only caught it on web-verification follow-up. The lesson
  is the project's, but the miss was the review's too: a claim that
  one repo doc already contradicts another should have been caught by
  reading alone.

- **`0x9805` decoding left unfinished.** Acknowledged as a TODO
  (`ptp-vendor.md`), so this is a known gap rather than a true miss —
  but it's the one decode that would let `webui` replace its
  property-by-property polling with a single round-trip.

---

## Recommended immediate actions

1. ~~**Fix `larkfly/types.py:49,54,55`** to `0x100E`, `0x101C`, `0x1018`;
   delete the false comment at `:56-60`. Add a test asserting each
   opcode constant against its spec value.~~ **Done 2026-05-21:** the
   three constants are corrected and the false comment removed;
   `tests/test_protocol.py::TestOpcodeConstants` now asserts all 19
   standard opcode constants against PIMA 15740, checks for value
   collisions, and pins `OP_INITIATE_CAPTURE != 0x100C`. 26 tests pass.
2. ~~Live-test the real photo trigger.~~ **Done 2026-05-20 — did not
   close the bug.** `InitiateCapture(0x100E,[0,0])` returns `rc=OK` but
   captures nothing (modes 3-6, ± RTSP preview). Photo capture over PTP
   is still open; next leads in the chat thread (other modes, a fresh
   iSmart DV2 capture with full response reassembly, the UVC/SCSI
   capture paths).
3. Reconcile `README.md:10` ("three"→"four" quirks) and rewrite or
   delete the stale `ports.md:122-124` "23 vendor codes" claim.
4. ~~Fix the `PropDesc` STRING-bleed parser bug.~~ **Done 2026-05-20:**
   the bleed bug is a misdiagnosis (not real — verified vs all 56
   descriptors). The genuine codec bug — `encode_ptp_string`'s
   `NumChars` miscount on non-BMP strings — is fixed in
   `larkfly/protocol.py`.
5. Make a disclosure decision on the pre-auth DoS and record it.
6. De-duplicate the `dev-console-hunt.md` Status table.
7. Correct the camera identity in `findings.md:13`, `README.md:3` and
   `CLAUDE.md`: `V11` is the ODM/white-label model code (shared with
   VIRAN V11 / CERASTES V11), the SoC is **iCatch V39A**, and "iCatch
   product code" is wrong. Carry over the conclusion `dev-console-hunt.md`
   §4 already reached.
