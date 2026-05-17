# Network surface — every reachable port

Definitive port-surface map of the Larkfly A6+ on its AP IP
`192.168.1.1`, as of May 2026. The earlier scan in
`docs/archive/investigation-log.md` checked ~30 ports; this is the
exhaustive sweep + UDP service probes + FTP chroot walk that the
"is there a hidden dev console?" question deserves.

## TL;DR — there is no dev console on the network

- **TCP**: 3 ports open out of all 65 535 — `21` (FTP), `554` (RTSP),
  `15740` (PTP-IP). No SSH, no telnet, no HTTP/HTTPS, no SNMP, no
  TR-069, no Realtek 9999, no Ambarella 7878.
- **UDP**: no replies from any of 15 well-known service probes (DNS,
  TFTP, NTP, SNMP, mDNS, SSDP unicast & multicast, CoAP, syslog, …).
  DHCP and the camera's AP-side networking obviously work, but the
  camera exposes nothing else to discovery on UDP.
- **FTP** is `iCatch FTP Server` and is **chroot'd** to two
  directories — `/VIDEO` and `/JPG`. No `/etc`, `/tmp`, `/var`, `/sys`,
  `/proc`, `/dev`, or any other system path is reachable. `HELP` and
  `STAT` are not implemented. There is no escape hatch.
- **The only "dev console-shaped" surface left on the network is PTP/IP
  vendor opcodes** (0x9xxx range). One has been decoded
  (`analyses/decode_9614.py`); the rest are unexplored and could in
  principle expose logging or shell-style functionality. Not pursued
  yet because vendor-op probing has historically hung the camera's PTP
  service (see "Things that hang the PTP service" in `findings.md`).

If there really is a serial / UART console it's on the PCB, not on
the radio. That would mean opening the case.

## TCP — all 65 535 ports

| Port    | Service     | Auth                  | Documented in                   |
| ------- | ----------- | --------------------- | ------------------------------- |
| 21      | FTP         | `wificam` / `wificam` | This file, `findings.md`        |
| 554     | RTSP        | none                  | `docs/rtsp.md`                  |
| 15740   | PTP-IP      | iCatch handshake      | `findings.md`, `larkfly/`       |

Scan method: parallel `connect()` on all 65 535 ports with 0.5 s
timeout, source-bound to the USB dongle's `192.168.1.10`. Camera RSTs
closed ports immediately, so a scan completes in ~10 s and would
catch anything actually `LISTEN`ing. **Three ports — no surprises.**

Ports that were specifically hoped to find a dev surface and weren't
there: 22, 23, 80, 81, 88, 443, 880, 1080, 2000-2002, 2222, 3000,
3389, 4000-4999 (incl. 4444), 5000, 5900, 6970-6975, 7547, 7777, 8000,
8001, 8008, 8080-8090, 8443, 8554, 8787, 8888, 9000, 9090, 9100, 9999,
10000, 19999, 23456, 41794. Everything in the IANA dynamic range
(49152-65535) was also closed.

## UDP — well-known service probes

Nothing on the camera answered any of the following protocol-correct
probes. (Empty datagrams to UDP ports prove little; these are real
service-level queries that would elicit a reply if the service were
running.)

| Port  | Probe                                                  | Reply |
| ----- | ------------------------------------------------------ | ----- |
| 53    | DNS A query for `camera.local`                         | none  |
| 67    | DHCP DISCOVER (unicast — won't reach a normal DHCP server, listed for completeness) | none  |
| 69    | TFTP RRQ                                               | none  |
| 123   | NTP client request                                     | none  |
| 137   | NetBIOS name query                                     | none  |
| 161   | SNMP v2c GetRequest for `sysDescr.0`                   | none  |
| 514   | syslog test message                                    | none  |
| 1900  | SSDP M-SEARCH (`ssdp:all`) — both unicast and multicast | none  |
| 5000  | UPnP probe                                             | none  |
| 5353  | mDNS query for `_services._dns-sd._udp.local`          | none  |
| 5683  | CoAP GET `/.well-known/core`                           | none  |
| 6970  | iCatch speculative                                     | none  |
| 6972  | RTP server default (from RTSP SETUP)                   | none — only allocated *during* an active RTSP session |
| 7547  | TR-069 CWMP                                            | none  |
| 8089  | Splunk / MQTT poke                                     | none  |

The camera does run a DHCP server — that's how the dongle gets
`192.168.1.10`. But it only answers to proper broadcast DHCPDISCOVER
from a client without an IP yet, not to arbitrary probes from a
configured client.

## FTP — chrooted, no system access

```
> 220 Welcomd to iCatch FTP Server          ← typo intentional in firmware
> USER wificam
> 331 ...
> PASS wificam
> 230 User logged in, proceed.
> SYST
> 215 UNIX TYPE: L8
> HELP
> 500 Syntax error, command unrecognized.
> STAT
> 500 Syntax error, command unrecognized.
> PWD
> 257 "/"
> LIST /
drw------- 1 user group 0 May 15 03:07 VIDEO
drw------- 1 user group 0 May 15 03:07 JPG
```

Confirmed inaccessible (`550` from `CWD`): `/etc`, `/tmp`, `/var`,
`/sys`, `/proc`, `/dev`, `/mnt`, `/data`, `/SD`, `/SD0`, `/SDCARD`,
`/SETTING`, `/SETTINGS`, `/CONFIG`, `/LOG`, `/LOGS`, `/SYSTEM`,
`/FIRMWARE`, `/FW`, `/HOME`.

The two visible directories are the camera-roll mount points: `.MOV`
files in `/VIDEO`, `.JPG` files in `/JPG`. The 4K-original recordings
are here (see `docs/rtsp.md` for the codec details). No log files, no
config files, no scripts.

The iCatch SDK's FTP server is open-source-adjacent (libsdk includes
fix-paths in `libreliant.so` — see `analyses/decode_9614.py` for an
example of what's reachable through PTP vendor ops), and from the
strings extracted in earlier RE work, the FTP root is hardwired to
the SD card mount, with no read/write access outside it.

## What's left if you want a dev console

1. **PTP vendor opcodes (0x9xxx range)** — `DeviceInfo.operations_supported`
   enumerates 23 vendor codes; we have decoded one
   (`0x9614`, decompressed via `analyses/decode_9614.py`). The other
   22 are unexplored and *could* expose firmware state, logs, or
   debug commands. Risky: vendor-op probing has wedged the PTP
   service in earlier sessions; recovery may need a power-cycle. If
   pursued, do it the way `tools/rtsp_probe.py` does — one op per
   request, health-check between, resume from JSON.
2. **A physical serial / UART header on the PCB**. Requires opening
   the case. Out of scope for the network-facing project.

There is no third option on the wire.

## Reproducing

```bash
# Full TCP sweep (~10 s)
python3 -c "
import socket, concurrent.futures as cf
def p(port):
    s = socket.socket(); s.settimeout(0.5)
    try: s.bind(('192.168.1.10', 0))
    except OSError: pass
    try: s.connect(('192.168.1.1', port)); return port
    except OSError: return None
    finally: s.close()
with cf.ThreadPoolExecutor(400) as ex:
    print(sorted(p for p in ex.map(p, range(1, 65536)) if p))
"

# UDP service probes — copy from this doc's table or use the inline
# script in commit history (search 'UDP service probes to').

# FTP walk
python3 -c "
import ftplib; f = ftplib.FTP(); f.connect('192.168.1.1', 21)
f.login('wificam', 'wificam'); print(f.getwelcome())
f.retrlines('LIST')
"
```
