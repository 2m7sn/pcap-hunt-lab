# PCAP Hunt Lab

Generate realistic packet captures with attacks hidden inside normal office
traffic, then hunt those attacks with a Zeek-style analyser. Pure Python 3.13,
standard library only. Nothing is ever sent on the network — the generator
writes libpcap files, the analyser reads them.

Built as a SOC / network-security portfolio project: it shows packet-level
protocol knowledge (correct Ethernet/IP/TCP/UDP checksums and handshakes),
flow reconstruction into conn/dns/http/tls logs, and seven detections mapped to
MITRE ATT&CK v20.

## Problem

Detection content is hard to demo without a lab full of real attack traffic,
and real malware captures are messy to share. This builds a reproducible,
seeded dataset — every attack carries ground truth — so detectors can be scored
with real precision/recall, and the same analyser runs on real captures from
Wireshark.

## Quickstart

```bash
pip install -e ".[dev]"

python -m pcaphunt.cli generate pcaps              # easy set + ground-truth.json
python -m pcaphunt.cli generate pcaps-hard --hard  # evasive attacks + benign look-alikes
python -m pcaphunt.cli hunt pcaps/c2_beacon.pcap -o out   # logs + alerts + HTML report
python -m pcaphunt.cli eval pcaps                  # precision/recall per detector
python -m pcaphunt.cli eval pcaps-hard
python heldout/gen_r2.py pcaps-heldout --skip-big   # reviewer's held-out set, prints pass/fail
pytest -q
```

`hunt` writes Zeek-style `*.conn.log / *.dns.log / *.http.log / *.tls.log`
(TSV), an `*.alerts.json`, and a self-contained `*.report.html`. Pass
`--config pcaps-hard/allowlist.toml` to allow-list known destinations and
`--sensitivity low|default|high` to move the scan/bruteforce/exfil floors.
Generation is deterministic for a given `--seed` (tested).

## Scenarios

Normal baseline in every capture: DNS lookups, HTTPS with SNI, plain HTTP,
NTP, SMB between hosts, DHCP. All hosts use RFC 1918 (10.0.0.0/24) internally
and RFC 5737 (203.0.113/198.51.100/192.0.2) externally; domains are `.example`.

**Easy set** (`pcaps/`, 3 attack-free + 7 one-attack captures):

| scenario | attack | detector | ATT&CK |
|---|---|---|---|
| `syn_scan` | 125-port SYN scan in ~1 s | scan | T1046 |
| `ssh_brute` | 40 short SSH sessions | bruteforce | T1110 |
| `c2_beacon` | HTTPS every 30 s ±3 s to one host | beacon | T1071.001 |
| `dns_tunnel` | 80 long base36 labels, TXT | dns_tunnel | T1071.004 |
| `exfil` | 6 MB HTTPS upload to a new host | exfil | T1048 |
| `arp_spoof` | gateway IP claimed by a second MAC within seconds | arp_spoof | T1557.002 |
| `cleartext_creds` | HTTP Basic credentials in clear | cleartext_creds | T1552.001 |

**Hard set = development set** (`pcaps-hard/`, 4 evasive attacks + 4 benign
look-alikes). It was used for tuning, so its 8/8 is a regression result, not
a measurement:

| scenario | what it is | should fire |
|---|---|---|
| `slow_scan_30ports` | 30 ports, one SYN every ~20 s | scan |
| `horizontal_scan_60hosts` | 60 hosts, port 445, unanswered | scan |
| `beacon_40pct_jitter` | 30 s beacon with ±40 % jitter | beacon |
| `slow_ssh_brute` | 40 attempts, each session ~5 s | bruteforce |
| `benign_periodic` | update poll /60 s, health check /60 s, NTP /64 s | nothing |
| `cdn_long_labels` | 40 lookups of 32-hex CDN labels | nothing |
| `backup_upload_3mb` | 3 MB upload to the backup host (allow-listed) | nothing |
| `arp_failover` | gateway MAC changes once, 300 s apart | nothing |

## Results (synthetic pcaps)

Scores from `pcaphunt eval`, seed 1337, default sensitivity. tp/fp/fn count
(detector, entity) matches against ground truth per capture.

| detector | easy tp/fp/fn | easy P / R | dev (hard) tp/fp/fn | dev P / R |
|---|---|---|---|---|
| scan | 1/0/0 | 1.00 / 1.00 | 2/0/0 | 1.00 / 1.00 |
| bruteforce | 1/0/0 | 1.00 / 1.00 | 1/0/0 | 1.00 / 1.00 |
| beacon | 1/0/0 | 1.00 / 1.00 | 1/0/0 | 1.00 / 1.00 |
| dns_tunnel | 1/0/0 | 1.00 / 1.00 | 0/0/0 | quiet (CDN labels) |
| arp_spoof | 1/0/0 | 1.00 / 1.00 | 0/0/0 | quiet (failover) |
| cleartext_creds | 1/0/0 | 1.00 / 1.00 | 0/0/0 | n/a |
| exfil | 1/0/0 | 1.00 / 1.00 | 0/0/0 | quiet (backup allow-listed) |

Easy captures are ~4,000–14,600 frames / 436–839 flows; dev captures
~6,100–10,500 frames / 645–733 flows. All three normal captures and all four
benign look-alikes produce zero alerts. Both sets were used to tune the
detectors — treat the numbers as a regression test, not a benchmark.

### Held-out round 2 (`heldout/gen_r2.py`, 13 variants, seed 4242)

A reviewer wrote this set without showing it to the author. **Scored BEFORE
any change: reviewer 5/13; author's reproduction 4/13** (the difference is a
baseline-web beacon FP that landed in `cdn_base64ish_labels`).

| variant | expected | before fix (default) | result |
|---|---|---|---|
| slow_scan_30min (40 ports / 1800 s) | scan | nothing | miss |
| horizontal_15hosts (3389, 2 min) | scan | nothing | miss |
| ssh_brute_10_over_20min | bruteforce | nothing | miss |
| beacon_70pct_jitter | beacon | nothing | miss |
| beacon_sleep_5min (300 s ±5 %) | beacon | beacon | pass |
| dns_tunnel_base32_txt_slow | dns_tunnel | dns_tunnel | pass |
| dns_tunnel_hex_over_A | dns_tunnel | nothing | miss |
| exfil_1p5mb_new_dst | exfil | nothing | miss |
| zoom_udp_long (10 min UDP media) | nothing | exfil | FP |
| cdn_base64ish_labels | nothing | beacon + dns_tunnel | FP |
| printer_arp_announce | nothing | nothing | pass |
| windows_update_50mb | nothing | nothing | pass |
| nightly_backup_500mb_unlisted | nothing | exfil | FP |

Fixes made after seeing it (general rules, not matches on the variants):
exfil is TCP-only on upload-capable services (ssl/http/ssh/ftp) so UDP media
is skipped; beacon requires regularity ≥ 0.85 under 15 connections, and above
15 accepts regularity ≥ 0.5 when the per-check-in size (orig+resp bytes) has
CV < 0.3; DNS tunnelling exempts a base domain whose long-label queries are
≥ 90 % A/AAAA *and* resolved to ≤ 2 distinct addresses (cache keys, not
payload) — which also catches hex-over-A; and a `--sensitivity low|default|high`
flag that scales the scan/bruteforce/exfil floors and window (default floor:
20 probe targets, 15 SSH sessions, 2 MB upload, 600 s window; high halves the
counts and doubles the window).

**After fix — after the author saw these variants; no longer held-out:**

| variant | default | high |
|---|---|---|
| slow_scan_30min | miss | pass |
| horizontal_15hosts | miss | pass |
| ssh_brute_10_over_20min | miss | pass |
| beacon_70pct_jitter | pass | pass |
| beacon_sleep_5min | pass | pass |
| dns_tunnel_base32_txt_slow | pass | pass |
| dns_tunnel_hex_over_A | pass | pass |
| exfil_1p5mb_new_dst | miss | pass |
| zoom_udp_long | pass | pass |
| cdn_base64ish_labels | pass | pass |
| printer_arp_announce | pass | pass |
| windows_update_50mb | pass | pass |
| nightly_backup_500mb_unlisted | FP (by design) | FP (by design) |
| **score** | **8/13** | **12/13** |

What still fails, and why it is left that way: the four default-sensitivity
misses are all sub-threshold — 40 probes spread over 1800 s, 15 hosts, 10
logins over 1200 s, a 1.5 MB upload. Fixed thresholds are evaded by anything
slower or smaller than the floor, by design; lowering the floor is what
`--sensitivity high` does, at the cost of more alerts on real traffic. The
500 MB backup "FP" is the documented rule: any upload > 2 MB to an unlisted
host alerts, nightly backups included; the allow-list is mandatory in
production (`--config` with `allow_dst`/`allow_sni`).

### Real captures

`python scripts/fetch_real_pcap.py [url]` pulls one small benign sample from
the Wireshark SampleCaptures (default `dns.cap`, ~4 KB). The wiki is mirrored
at <https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures>. Downloaded
files are git-ignored; no malware captures.

- `dns.cap`: 38 frames / 8 flows / 0 alerts; recovered 38 DNS records
  including a real SPF TXT answer (`v=spf1 ptr ?all`).
- `tcp-ecn-sample.pcap` (~119 KB): 479 frames / 1 flow / **1 alert** —
  `cleartext_creds` on an HTTP Basic `Authorization` header to `/show-tech`
  on `1.1.12.1`. A genuine cleartext-credential finding in a 20-year-old
  public sample; the report shows the username only, never the password.

No ground truth is claimed for real captures — they show the parser handles
third-party pcaps, not only its own bytes.

## Open a scenario in Wireshark

| scenario | Wireshark display filter |
|---|---|
| syn_scan / slow scan | `tcp.flags.syn==1 && tcp.flags.ack==0 && ip.dst==10.0.0.5` |
| horizontal scan | `tcp.dstport==445 && tcp.flags.syn==1 && tcp.flags.ack==0` |
| ssh_brute | `tcp.port==22 && tcp.flags.syn==1` |
| c2_beacon | `tls.handshake.extensions_server_name == "sync.example"` |
| dns_tunnel | `dns.qry.name contains ".tun.example"` |
| exfil | `ip.dst==192.0.2.200 && tcp.len>0` |
| arp_spoof | `arp.opcode==2 && arp.src.proto_ipv4==10.0.0.1` |
| cleartext_creds | `http.authorization` |

## Limits

- Writes/reads classic **pcap** only (little/big-endian), Ethernet link type.
  pcapng is rejected with a hint to run `editcap -F pcap`.
- No IPv6, no TCP reassembly across segments, no TLS decryption (SNI only from
  the ClientHello), no IP-fragment reassembly.
- Thresholds are tuned to these two sets; real traffic needs re-tuning and a
  baseline-learning period. The 600 s window equals the capture length here,
  so "windowed" is only exercised at one scale.
- `tshark` was not installed in the build environment; checksums were verified
  in the test suite and independently by a reviewer with scapy and dpkt
  (0 bad checksums).

## Roadmap

- pcapng read support
- Suricata rule export for each detection
- Zeek script equivalents of the detectors
- IPv6 and basic TCP stream reassembly

## License

MIT — Abdulmohsen Alharbi.
