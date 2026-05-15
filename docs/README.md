# Docs

| File | What it is |
| --- | --- |
| [`findings.md`](findings.md) | **Read this first.** Concise current-state reference: protocol, opcodes, recording paradigm, multi-camera situation. |
| [`architecture.md`](architecture.md) | Multi-camera design tradeoffs — USB UVC vs WiFi PTP/IP vs STATION mode. |
| [`archive/`](archive/) | Stale-but-preserved earlier docs: the chronological investigation log + the original (now-disproven) protocol hypothesis. |

## Where to look for specific things

- **Wire format quirks** that break naïve PTP/IP clients → `findings.md` § "How the PTP/IP protocol works on this camera"
- **Full property catalog** (all 56 properties, with descriptors and current values) → `../analyses/data/properties.json`
- **The chronological RE story**, including dead ends → `archive/investigation-log.md`
- **Why simpleConfig is hard** → `findings.md` § "Multi-camera / STATION-mode situation"
