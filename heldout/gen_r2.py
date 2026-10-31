"""Held-out stress set, round 2 (reviewer-written, never seen by the detectors).

Usage:  python heldout/gen_r2.py <outdir> [--seed N] [--skip-big]
Writes <outdir>/*.pcap + ground-truth.json (same shape as pcaphunt.generate.build_set),
then prints variant -> expected -> got.  --skip-big drops the 50 MB / 500 MB flows.
Lives inside the repo (heldout/); $PCAPHUNT_REPO overrides the repo path.
"""
import base64
import json
import os
import random
import sys
import time
import zlib

REPO = os.environ.get("PCAPHUNT_REPO") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.abspath(REPO))

from pcaphunt import packets as P                                   # noqa: E402
from pcaphunt.generate import (WS, FILESRV, EXT, GW_MAC, Host, Conn, _mac,  # noqa: E402
                               dns_lookup, https_session, http_session, normal_baseline)

BASE = 1_700_000_000.0


def _syn_probe(out, rnd, atk, tgt, port, t, answer):
    sp = rnd.randint(40000, 60000)
    out.append((t, P.ether(tgt.mac, atk.mac, P.ETH_IP, P.ipv4(atk.ip, tgt.ip, P.PROTO_TCP,
                P.tcp(atk.ip, tgt.ip, sp, port, rnd.getrandbits(32), 0, P.SYN)))))
    if answer:
        out.append((t + .0005, P.ether(atk.mac, tgt.mac, P.ETH_IP, P.ipv4(tgt.ip, atk.ip, P.PROTO_TCP,
                    P.tcp(tgt.ip, atk.ip, port, sp, 0, 1, P.RST | P.ACK)))))


# ---- attacks (truth dict) --------------------------------------------------

def slow_scan_30min(out, rnd, start):
    """40 ports on the file server, one SYN every ~45 s -> spans 1800 s (> 600 s window)."""
    t = start
    for p in rnd.sample(range(1, 1024), 40):
        t += rnd.uniform(40, 50)
        _syn_probe(out, rnd, WS[0], FILESRV, p, t, answer=True)
    return {"detector": "scan", "entity": WS[0].ip, "technique": "T1046"}


def horizontal_15hosts(out, rnd, start):
    """15 hosts, port 3389, unanswered, inside 2 minutes."""
    t = start
    for i in range(200, 215):
        t += rnd.uniform(4, 10)
        _syn_probe(out, rnd, WS[0], Host("10.0.0.%d" % i, _mac(i)), 3389, t, answer=False)
    return {"detector": "scan", "entity": WS[0].ip, "technique": "T1046"}


def ssh_brute_10_over_20min(out, rnd, start):
    """10 failed SSH logins spread over 1200 s."""
    t = start
    for _ in range(10):
        t += rnd.uniform(100, 140)
        c = Conn(out, rnd, WS[1], FILESRV, rnd.randint(40000, 60000), 22, t)
        c.handshake()
        c.send(b"SSH-2.0-OpenSSH_9.6\r\n")
        c.send(b"SSH-2.0-OpenSSH_9.3\r\n", from_client=False)
        c.send(P.ssh_packet(rnd.randbytes(280)))
        c.send(P.ssh_packet(rnd.randbytes(280)), from_client=False)
        c.send(P.ssh_packet(rnd.randbytes(48)))
        c.send(P.ssh_packet(bytes([51]) + rnd.randbytes(12)), from_client=False)
        c.close()
    return {"detector": "bruteforce", "entity": WS[1].ip, "technique": "T1110"}


def beacon_70pct_jitter(out, rnd, start):
    """30 s beacon, +/-70 % jitter, 10 minutes."""
    c2 = Host("192.0.2.91", GW_MAC, False)
    EXT["telemetry.example"] = c2
    t = start
    while t < start + 580:
        https_session(out, rnd, WS[2], "telemetry.example", t, nbytes=400)
        t += 30 * rnd.uniform(0.3, 1.7)
    return {"detector": "beacon", "entity": "%s->%s" % (WS[2].ip, c2.ip), "technique": "T1071.001"}


def beacon_sleep_5min(out, rnd, start):
    """Long-sleep beacon: every 300 s +/-5 %, 10 check-ins over ~50 min."""
    c2 = Host("192.0.2.92", GW_MAC, False)
    EXT["status.example"] = c2
    t = start
    for _ in range(10):
        https_session(out, rnd, WS[2], "status.example", t, nbytes=300)
        t += 300 * rnd.uniform(0.95, 1.05)
    return {"detector": "beacon", "entity": "%s->%s" % (WS[2].ip, c2.ip), "technique": "T1071.001"}


def dns_tunnel_base32_txt_slow(out, rnd, rnd_start):
    """Base32 labels (RFC 4648, upper-case) over TXT, 25 queries in 10 min (~1 per 24 s)."""
    t = rnd_start
    for _ in range(25):
        t += rnd.uniform(18, 30)
        lab = base32(rnd.randbytes(30)).rstrip("=")           # 48 chars
        dns_lookup(out, rnd, WS[3], "%s.t.example" % lab, t, qtype=16, txt=rnd.randbytes(60).hex().encode())
    return {"detector": "dns_tunnel", "entity": WS[3].ip, "technique": "T1071.004"}


def base32(b):
    return base64.b32encode(b).decode()


def dns_tunnel_hex_over_A(out, rnd, start):
    """Hex-encoded payload in A-record lookups (the trade-off the README admits)."""
    t = start
    for _ in range(60):
        t += rnd.uniform(0.1, 0.5)
        lab = rnd.randbytes(26).hex()                          # 52 hex chars
        dns_lookup(out, rnd, WS[3], "%s.x.example" % lab, t, qtype=1, rdata_ip="192.0.2.%d" % rnd.randint(1, 254))
    return {"detector": "dns_tunnel", "entity": WS[3].ip, "technique": "T1071.004"}


def exfil_1p5mb_new_dst(out, rnd, start):
    """1.5 MB HTTPS upload to a never-seen host."""
    sink = Host("192.0.2.150", GW_MAC, False)
    EXT["drop.example"] = sink
    dns_lookup(out, rnd, WS[4], "drop.example", start, rdata_ip=sink.ip)
    https_session(out, rnd, WS[4], "drop.example", start + 0.05, nbytes=1_500_000, up_ratio=0.97)
    return {"detector": "exfil", "entity": "%s->%s" % (WS[4].ip, sink.ip), "technique": "T1048"}


# ---- benign (nothing should fire) -----------------------------------------

def zoom_udp_long(out, rnd, start):
    """One 10-minute bidirectional UDP media flow to an external host (Zoom/Teams-like)."""
    srv = Host("203.0.113.200", GW_MAC, False)
    ws = WS[1]
    sp = rnd.randint(49152, 65535)
    t = start
    while t < start + 600:
        t += 0.05
        up = rnd.randbytes(rnd.randint(120, 900))
        out.append((t, P.ether(GW_MAC, ws.mac, P.ETH_IP, P.ipv4(ws.ip, srv.ip, P.PROTO_UDP, P.udp(ws.ip, srv.ip, sp, 8801, up)))))
        dn = rnd.randbytes(rnd.randint(300, 1200))
        out.append((t + 0.01, P.ether(ws.mac, GW_MAC, P.ETH_IP, P.ipv4(srv.ip, ws.ip, P.PROTO_UDP, P.udp(srv.ip, ws.ip, 8801, sp, dn), ttl=110))))
    return None


def windows_update_50mb(out, rnd, start):
    """50 MB plain-HTTP download from update.example.com (mostly resp bytes)."""
    srv = EXT["update.example.com"]
    c = Conn(out, rnd, WS[0], srv, rnd.randint(49152, 65535), 80, start)
    c.handshake()
    c.send(P.http_request("GET", "update.example.com", "/d/msdownload/update/kb5055555.cab"))
    hdr = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 50000000\r\n\r\n"
    c.send(hdr, from_client=False)
    sent = 0
    while sent < 50_000_000:
        n = min(1400, 50_000_000 - sent)
        c._s2c(P.PSH | P.ACK, rnd.randbytes(n))
        if sent % (1400 * 4) == 0:
            c._c2s(P.ACK)
        sent += n
    c.close()
    return None


def cdn_base64ish_labels(out, rnd, start):
    """40 A lookups of 40-char mixed base64url-ish labels under one CDN zone (not hex)."""
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789-"
    t = start
    for _ in range(40):
        t += rnd.uniform(0.5, 5)
        lab = "".join(rnd.choice(alpha) for _ in range(40))
        dns_lookup(out, rnd, WS[2], "%s.edge.cdn.example" % lab, t, rdata_ip="203.0.113.10")
    return None


def printer_arp_announce(out, rnd, start):
    """Printer boots: 3 gratuitous ARP replies for its own IP, one MAC, then a probe from a workstation."""
    pr = Host("10.0.0.50", _mac(50))
    t = start
    for _ in range(3):
        out.append((t, P.ether(P.BCAST, pr.mac, P.ETH_ARP, P.arp(2, pr.mac, pr.ip, P.BCAST, pr.ip))))
        t += 1.0
    out.append((t + 5, P.ether(P.BCAST, WS[0].mac, P.ETH_ARP, P.arp(1, WS[0].mac, WS[0].ip, "00:00:00:00:00:00", pr.ip))))
    out.append((t + 5.001, P.ether(WS[0].mac, pr.mac, P.ETH_ARP, P.arp(2, pr.mac, pr.ip, WS[0].mac, WS[0].ip))))
    return None


def nightly_backup_500mb_unlisted(out, rnd, start):
    """500 MB upload to a backup host that is NOT in any allowlist (legit nightly job)."""
    bk = Host("198.51.100.210", GW_MAC, False)
    EXT["nas-backup.example.com"] = bk
    dns_lookup(out, rnd, WS[3], "nas-backup.example.com", start, rdata_ip=bk.ip)
    https_session(out, rnd, WS[3], "nas-backup.example.com", start + 1, nbytes=500_000_000, up_ratio=0.99)
    return None


VARIANTS = {
    "slow_scan_30min": slow_scan_30min,
    "horizontal_15hosts": horizontal_15hosts,
    "ssh_brute_10_over_20min": ssh_brute_10_over_20min,
    "beacon_70pct_jitter": beacon_70pct_jitter,
    "beacon_sleep_5min": beacon_sleep_5min,
    "dns_tunnel_base32_txt_slow": dns_tunnel_base32_txt_slow,
    "dns_tunnel_hex_over_A": dns_tunnel_hex_over_A,
    "exfil_1p5mb_new_dst": exfil_1p5mb_new_dst,
    "zoom_udp_long": zoom_udp_long,
    "cdn_base64ish_labels": cdn_base64ish_labels,
    "printer_arp_announce": printer_arp_announce,
    "windows_update_50mb": windows_update_50mb,
    "nightly_backup_500mb_unlisted": nightly_backup_500mb_unlisted,
}
BIG = {"windows_update_50mb", "nightly_backup_500mb_unlisted"}


def build(outdir, seed=4242, skip_big=False):
    os.makedirs(outdir, exist_ok=True)
    manifest = []
    for name, fn in VARIANTS.items():
        if skip_big and name in BIG:
            continue
        rnd = random.Random(seed + zlib.crc32(name.encode()) % 1000)
        out = []
        normal_baseline(out, rnd, BASE, duration=600.0)
        truth = fn(out, rnd, BASE + rnd.uniform(30, 120))
        if truth:
            truth["scenario"] = name
        P.write_pcap(os.path.join(outdir, name + ".pcap"), out)
        manifest.append({"pcap": name + ".pcap", "truth": [truth] if truth else []})
        print("wrote", name, len(out), "frames", flush=True)
    json.dump(manifest, open(os.path.join(outdir, "ground-truth.json"), "w"), indent=2)
    return manifest


def score(outdir, manifest):
    from pcaphunt.analyze import Capture
    from pcaphunt import detectors as D
    rows = []
    for item in manifest:
        t0 = time.time()
        cap = Capture(os.path.join(outdir, item["pcap"]))
        alerts = D.run_all(cap)
        exp = sorted("%s@%s" % (t["detector"], t["entity"]) for t in item["truth"]) or ["nothing"]
        got = sorted("%s@%s" % (a["detector"], a["entity"]) for a in alerts) or ["nothing"]
        ok = exp == got
        rows.append((item["pcap"][:-5], ", ".join(exp), ", ".join(got), "PASS" if ok else "FAIL", cap.frames, round(time.time() - t0, 1)))
    print("\n%-30s | %-34s | %-34s | %s" % ("variant", "expected", "got", "result"))
    for r in rows:
        print("%-30s | %-34s | %-34s | %s  (%d frames, %.1fs)" % r)
    n = sum(1 for r in rows if r[3] == "PASS")
    print("\n%d/%d pass" % (n, len(rows)))
    return rows


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    seed = int(sys.argv[sys.argv.index("--seed") + 1]) if "--seed" in sys.argv else 4242
    outdir = args[0] if args else "pcaps-heldout"
    m = build(outdir, seed=seed, skip_big="--skip-big" in sys.argv)
    score(outdir, m)
