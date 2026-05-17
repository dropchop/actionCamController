# Docs

| File | What it is |
| --- | --- |
| [`findings.md`](findings.md) | **Read this first.** Concise current-state reference: protocol, opcodes, recording paradigm, multi-camera situation. |
| [`architecture.md`](architecture.md) | Multi-camera design tradeoffs — USB UVC vs WiFi PTP/IP vs STATION mode. |
| [`rtsp.md`](rtsp.md) | TCP-554 RTSP surface map: codec/transport, public verbs, wedge triggers, why `/MJPG` actually serves H.264. |
| [`ports.md`](ports.md) | Exhaustive network surface — every TCP/UDP port we tested. Verdict: no dev console reachable over the network. |
| [`ptp-vendor.md`](ptp-vendor.md) | Per-opcode behaviour of all 8 PTP/IP vendor ops (`0x9601-0x9812`), including the parameter-shape matrix and wedge triggers. |
| [`dev-console-hunt.md`](dev-console-hunt.md) | Running log of the "find a dev console" investigation: hidden properties, PTP write-access, the SPHOST.BRN bootloader trigger. **Updated with overnight RE — includes the full SCSI command table and verify-handshake spec.** |
| [`untried-vectors.md`](untried-vectors.md) | **Forward-looking inventory.** Attack vectors that remain untried (or are partially explored), each with concrete test commands, references, and risk assessment. Compiled from two deep-RE agents + live verification 2026-05-17. |
| [`archive/`](archive/) | Stale-but-preserved earlier docs: the chronological investigation log + the original (now-disproven) protocol hypothesis. |

## Where to look for specific things

- **Wire format quirks** that break naïve PTP/IP clients → `findings.md` § "How the PTP/IP protocol works on this camera"
- **Full property catalog** (all 56 properties, with descriptors and current values) → `../analyses/data/properties.json`
- **Raw RTSP probe data** (55 captured request/response pairs) → `../analyses/data/rtsp_probe.json` + `../analyses/data/rtsp_probe.md`
- **The chronological RE story**, including dead ends → `archive/investigation-log.md`
- **Why simpleConfig is hard** → `findings.md` § "Multi-camera / STATION-mode situation"
