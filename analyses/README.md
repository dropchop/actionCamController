# Analyses

One-shot scripts that produced a finding and captured its output. Kept
in the repo for reproducibility — re-running them either reconfirms the
finding (if the camera state matches) or surfaces something that's
changed.

| Script | What it did | Output | Status |
| --- | --- | --- | --- |
| `enumerate_props.py` | Calls `GetDevicePropDesc` + `GetDevicePropValue` on every supported property; writes a JSON catalog. | `data/properties.json` (all 56 properties) | Re-runnable on demand. |
| `mine_pcap.py` | Walks a decrypted PTP/IP pcap, reassembles every transaction, summarizes opcode usage frequency + first-occurrence param signatures. | `data/transactions.json` (574 transactions from the iSmart DV2 session) — **request-side only**: response codes/data were reassembled for just ~7 of the 574, so it shows which ops the app *sent*, not their outcomes. Not authoritative for "the app did/didn't do X". | Needs an input pcap. |
| `decode_9614.py` | Parses the 233-byte response from vendor opcode `0x9614` (a bulk PropDesc dump) into individual records. Cross-references against the catalog from `enumerate_props.py`. | Console output; saves raw response bytes to `data/op_9614_response.bin`. | Runnable offline against the saved bytes; also `--live` against the camera. |

## Reproducing

```bash
# Property catalog (read-only against a connected camera)
python3 analyses/enumerate_props.py 192.168.1.1 --bind 192.168.1.10

# Mine an existing decrypted pcap (no camera needed)
python3 analyses/mine_pcap.py /path/to/decrypted.pcap

# Decode the saved 0x9614 response (no camera needed)
python3 analyses/decode_9614.py
# …or fetch a fresh response from the live camera and decode it:
python3 analyses/decode_9614.py --live
```

## Adding new analyses

When something becomes a "one-shot": move it here, save its output to
`data/`, and add a row to the table above with a 1-sentence summary of
what it proved. If it grows into a tool you'll use repeatedly, promote
it to `tools/` instead.
