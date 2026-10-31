"""Generate synthetic pcaps: normal traffic plus seeded attacks, each with ground truth.

Addresses: RFC 1918 internal (10.0.0.0/24), RFC 5737 external (203.0.113/198.51.100/192.0.2).
Domains: *.example / *.example.com. Nothing is sent; files only.
"""
import json
import os
import random
import zlib

from . import packets as P

GW_MAC = "02:00:00:00:00:01"
GW_IP = "10.0.0.1"          # gateway + DNS resolver
DNS_IP = "10.0.0.1"


def _mac(i: int) -> str:
    return "02:00:00:00:%02x:%02x" % ((i >> 8) & 0xFF, i & 0xFF)


class Host:
    def __init__(self, ip, mac, internal=True):
        self.ip, self.mac, self.internal = ip, mac, internal


def _lan(i):
    return Host("10.0.0.%d" % i, _mac(i))


WS = [_lan(i) for i in (10, 11, 12, 13, 14)]      # workstations
FILESRV = _lan(5)
EXT = {  # external services (TEST-NET ranges)
    "cdn.example.com": Host("203.0.113.10", GW_MAC, False),
    "www.example.com": Host("203.0.113.20", GW_MAC, False),
    "api.example.com": Host("203.0.113.30", GW_MAC, False),
    "mail.example.com": Host("198.51.100.25", GW_MAC, False),
    "update.example.com": Host("198.51.100.80", GW_MAC, False),
}
NTP_SRV = Host("203.0.113.123", GW_MAC, False)


class Conn:
    """A coherent TCP connection. Appends (ts, frame) to `out`; advances `t`."""

    def __init__(self, out, rnd, client: Host, server: Host, sport, dport, t):
        self.out, self.rnd, self.c, self.s = out, rnd, client, server
        self.sport, self.dport, self.t = sport, dport, t
        self.cseq = rnd.getrandbits(32)
        self.sseq = rnd.getrandbits(32)
        self.ident = rnd.getrandbits(16)

    def _gap(self, lo=0.0005, hi=0.004):
        self.t += self.rnd.uniform(lo, hi)
        return self.t

    def _c2s(self, flags, payload=b""):
        self.ident = (self.ident + 1) & 0xFFFF
        seg = P.tcp(self.c.ip, self.s.ip, self.sport, self.dport, self.cseq, self.sseq, flags, payload)
        frame = P.ether(self.s.mac, self.c.mac, P.ETH_IP, P.ipv4(self.c.ip, self.s.ip, P.PROTO_TCP, seg, ident=self.ident))
        self.out.append((self._gap(), frame))
        self.cseq += len(payload) + (1 if flags & (P.SYN | P.FIN) else 0)

    def _s2c(self, flags, payload=b""):
        seg = P.tcp(self.s.ip, self.c.ip, self.dport, self.sport, self.sseq, self.cseq, flags, payload)
        frame = P.ether(self.c.mac, self.s.mac, P.ETH_IP, P.ipv4(self.s.ip, self.c.ip, P.PROTO_TCP, seg,
                        ttl=(64 if self.s.internal else 118), ident=self.rnd.getrandbits(16)))
        self.out.append((self._gap(), frame))
        self.sseq += len(payload) + (1 if flags & (P.SYN | P.FIN) else 0)

    def handshake(self):
        self._c2s(P.SYN)
        self._s2c(P.SYN | P.ACK)
        self._c2s(P.ACK)

    def send(self, payload, from_client=True):
        (self._c2s if from_client else self._s2c)(P.PSH | P.ACK, payload)
        (self._s2c if from_client else self._c2s)(P.ACK)

    def close(self):
        self._c2s(P.FIN | P.ACK)
        self._s2c(P.FIN | P.ACK)
        self._c2s(P.ACK)


# --- building blocks ------------------------------------------------------

def dns_lookup(out, rnd, client, name, t, qtype=1, rdata_ip="203.0.113.10", txt=None):
    txid = rnd.getrandbits(16)
    sport = rnd.randint(49152, 65535)
    q = P.dns_query(txid, name, qtype)
    out.append((t, P.ether(GW_MAC, client.mac, P.ETH_IP,
                P.ipv4(client.ip, DNS_IP, P.PROTO_UDP, P.udp(client.ip, DNS_IP, sport, 53, q)))))
    if qtype == 16 and txt is not None:
        rdata = [P.dns_txt(txt)]
    else:
        rdata = [P.ip(rdata_ip)]
    r = P.dns_response(txid, name, qtype, rdata)
    out.append((t + rnd.uniform(0.002, 0.03), P.ether(client.mac, GW_MAC, P.ETH_IP,
                P.ipv4(DNS_IP, client.ip, P.PROTO_UDP, P.udp(DNS_IP, client.ip, 53, sport, r), ttl=63))))


def https_session(out, rnd, client, host_name, t, nbytes=None, up_ratio=0.3):
    srv = EXT[host_name]
    c = Conn(out, rnd, client, srv, rnd.randint(49152, 65535), 443, t)
    c.handshake()
    c.send(P.tls_client_hello(host_name, rnd))
    c.send(P.tls_server_hello(rnd), from_client=False)
    nbytes = nbytes if nbytes is not None else rnd.randint(1500, 9000)
    sent = 0
    while sent < nbytes:
        n = min(1400, nbytes - sent)
        c.send(P.tls_app_data(n, rnd), from_client=rnd.random() < up_ratio)
        sent += n
    c.close()
    return c.t


def http_session(out, rnd, client, host_name, path, t, extra=(), resp_body=None):
    srv = EXT[host_name]
    c = Conn(out, rnd, client, srv, rnd.randint(49152, 65535), 80, t)
    c.handshake()
    c.send(P.http_request("GET", host_name, path, extra))
    body = resp_body if resp_body is not None else rnd.randbytes(rnd.randint(400, 3000))
    c.send(P.http_response(200, "OK", body), from_client=False)
    c.close()
    return c.t


def ntp_sync(out, rnd, client, t):
    req = P.ntp(3, t)
    out.append((t, P.ether(GW_MAC, client.mac, P.ETH_IP,
                P.ipv4(client.ip, NTP_SRV.ip, P.PROTO_UDP, P.udp(client.ip, NTP_SRV.ip, 123, 123, req)))))
    out.append((t + rnd.uniform(0.005, 0.04), P.ether(client.mac, GW_MAC, P.ETH_IP,
                P.ipv4(NTP_SRV.ip, client.ip, P.PROTO_UDP, P.udp(NTP_SRV.ip, client.ip, 123, 123, P.ntp(4, t)), ttl=55))))


def smb_session(out, rnd, client, t):
    c = Conn(out, rnd, client, FILESRV, rnd.randint(49152, 65535), 445, t)
    c.handshake()
    c.send(P.smb2_negotiate_request())
    c.send(P.smb2_negotiate_response(), from_client=False)
    c.close()
    return c.t


def dhcp_renew(out, rnd, client, t):
    xid = rnd.getrandbits(32)
    disc = P.dhcp(1, xid, client.mac, 3, ciaddr=client.ip, options=bytes([54, 4]) + P.ip(GW_IP))
    out.append((t, P.ether(P.BCAST, client.mac, P.ETH_IP,
                P.ipv4("0.0.0.0", "255.255.255.255", P.PROTO_UDP, P.udp("0.0.0.0", "255.255.255.255", 68, 67, disc)))))
    ack = P.dhcp(2, xid, client.mac, 5, yiaddr=client.ip, options=bytes([54, 4]) + P.ip(GW_IP) + bytes([51, 4]) + b"\x00\x01\x51\x80")
    out.append((t + rnd.uniform(0.01, 0.05), P.ether(client.mac, GW_MAC, P.ETH_IP,
                P.ipv4(GW_IP, client.ip, P.PROTO_UDP, P.udp(GW_IP, client.ip, 67, 68, ack)))))


# --- normal baseline ------------------------------------------------------

NORMAL_SITES = list(EXT)


def normal_baseline(out, rnd, start, duration=600.0):
    """Spread typical office traffic over `duration` seconds from `start`."""
    t = start
    for ws in WS:
        dhcp_renew(out, rnd, ws, start + rnd.uniform(0, 5))
    while t < start + duration:
        ws = rnd.choice(WS)
        t += rnd.expovariate(1 / 1.2)
        kind = rnd.random()
        if kind < 0.45:
            name = rnd.choice(NORMAL_SITES)
            dns_lookup(out, rnd, ws, name, t, rdata_ip=EXT[name].ip)
            https_session(out, rnd, ws, name, t + rnd.uniform(0.01, 0.05))
        elif kind < 0.6:
            dns_lookup(out, rnd, ws, rnd.choice(NORMAL_SITES), t)
        elif kind < 0.75:
            http_session(out, rnd, ws, "update.example.com", "/v/%d.bin" % rnd.randint(1, 99), t)
        elif kind < 0.85:
            smb_session(out, rnd, ws, t)
        elif kind < 0.95:
            ntp_sync(out, rnd, ws, t)
        else:
            dhcp_renew(out, rnd, ws, t)
    return out


# --- attacks (each returns a ground-truth dict) ---------------------------

def attack_syn_scan(out, rnd, start):
    attacker, target = WS[0], FILESRV
    t = start
    ports = sorted(rnd.sample(range(1, 1024), 120) + [22, 80, 443, 445, 3389])
    for p in ports:
        t += rnd.uniform(0.001, 0.01)
        sport = rnd.randint(40000, 60000)
        seg = P.tcp(attacker.ip, target.ip, sport, p, rnd.getrandbits(32), 0, P.SYN, window=1024)
        out.append((t, P.ether(target.mac, attacker.mac, P.ETH_IP, P.ipv4(attacker.ip, target.ip, P.PROTO_TCP, seg))))
        open_port = p in (22, 80, 443, 445)
        flags = (P.SYN | P.ACK) if open_port else (P.RST | P.ACK)
        rseg = P.tcp(target.ip, attacker.ip, p, sport, rnd.getrandbits(32), (rnd.getrandbits(32)) if open_port else 1, flags)
        out.append((t + 0.0005, P.ether(attacker.mac, target.mac, P.ETH_IP, P.ipv4(target.ip, attacker.ip, P.PROTO_TCP, rseg))))
    return {"scenario": "syn_scan", "detector": "scan", "entity": attacker.ip,
            "technique": "T1046", "ports": len(ports), "target": target.ip}


def attack_ssh_brute(out, rnd, start):
    attacker, target = WS[1], FILESRV
    t = start
    for i in range(40):
        t += rnd.uniform(0.2, 0.6)
        c = Conn(out, rnd, attacker, target, rnd.randint(40000, 60000), 22, t)
        c.handshake()
        c.send(b"SSH-2.0-OpenSSH_9.6\r\n")
        c.send(b"SSH-2.0-OpenSSH_9.3\r\n", from_client=False)
        c.send(P.ssh_packet(rnd.randbytes(280)))                    # key exchange
        c.send(P.ssh_packet(rnd.randbytes(280)), from_client=False)
        c.send(P.ssh_packet(rnd.randbytes(48)))                     # auth attempt
        c.send(P.ssh_packet(bytes([51]) + rnd.randbytes(12)), from_client=False)  # SSH_MSG_USERAUTH_FAILURE
        c.close()
    return {"scenario": "ssh_brute", "detector": "bruteforce", "entity": attacker.ip,
            "technique": "T1110", "attempts": 40, "target": target.ip}


def attack_c2_beacon(out, rnd, start):
    victim = WS[2]
    c2 = Host("192.0.2.66", GW_MAC, False)
    EXT["sync.example"] = c2
    interval, t = 30.0, start
    n = 0
    while t < start + 600:
        dns_lookup(out, rnd, victim, "sync.example", t, rdata_ip=c2.ip)
        cc = Conn(out, rnd, victim, c2, rnd.randint(49152, 65535), 443, t + 0.02)
        cc.handshake()
        cc.send(P.tls_client_hello("sync.example", rnd))
        cc.send(P.tls_server_hello(rnd), from_client=False)
        cc.send(P.tls_app_data(rnd.randint(180, 260), rnd))
        cc.send(P.tls_app_data(rnd.randint(180, 260), rnd), from_client=False)
        cc.close()
        n += 1
        t += interval + rnd.uniform(-3, 3)      # periodic with jitter
    return {"scenario": "c2_beacon", "detector": "beacon", "entity": "%s->%s" % (victim.ip, c2.ip),
            "technique": "T1071.001", "interval": interval, "beacons": n, "dst": c2.ip}


def attack_dns_tunnel(out, rnd, start):
    victim = WS[3]
    t = start
    n = 0
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
    for _ in range(80):
        t += rnd.uniform(0.05, 0.3)
        label = "".join(rnd.choice(alpha) for _ in range(rnd.randint(45, 60)))
        name = "%s.tun.example" % label
        dns_lookup(out, rnd, victim, name, t, qtype=16, txt=rnd.randbytes(rnd.randint(40, 120)).hex().encode())
        n += 1
    return {"scenario": "dns_tunnel", "detector": "dns_tunnel", "entity": victim.ip,
            "technique": "T1071.004", "queries": n, "domain": "tun.example"}


def attack_exfil(out, rnd, start):
    victim = WS[4]
    sink = Host("192.0.2.200", GW_MAC, False)
    EXT["files.example"] = sink
    dns_lookup(out, rnd, victim, "files.example", start, rdata_ip=sink.ip)
    https_session(out, rnd, victim, "files.example", start + 0.05, nbytes=6_000_000, up_ratio=0.97)
    return {"scenario": "exfil", "detector": "exfil", "entity": "%s->%s" % (victim.ip, sink.ip),
            "technique": "T1048", "bytes": 6_000_000, "dst": sink.ip}


def attack_arp_spoof(out, rnd, start):
    attacker_mac = _mac(66)
    t = start
    n = 0
    # legitimate gateway presence first (real IP->MAC), so the spoof creates a conflict
    for ws in WS[:3]:
        out.append((t, P.ether(ws.mac, GW_MAC, P.ETH_ARP, P.arp(2, GW_MAC, GW_IP, ws.mac, ws.ip))))
        t += 0.2
    for _ in range(30):
        t += rnd.uniform(0.5, 1.5)
        # attacker claims to be the gateway
        a = P.arp(2, attacker_mac, GW_IP, WS[0].mac, WS[0].ip)
        out.append((t, P.ether(WS[0].mac, attacker_mac, P.ETH_ARP, a)))
        n += 1
    return {"scenario": "arp_spoof", "detector": "arp_spoof", "entity": GW_IP,
            "technique": "T1557.002", "gratuitous": n, "spoofed_mac": attacker_mac}


def attack_cleartext_creds(out, rnd, start):
    victim = WS[0]
    web = EXT["www.example.com"]
    # HTTP Basic auth header carries base64(user:pass)
    import base64
    cred = base64.b64encode(b"admin:Summer2026!").decode()
    c = Conn(out, rnd, victim, web, rnd.randint(49152, 65535), 80, start)
    c.handshake()
    c.send(P.http_request("GET", "www.example.com", "/admin/", ("Authorization: Basic " + cred,)))
    c.send(P.http_response(200, "OK", b"<html>ok</html>"), from_client=False)
    c.close()
    return {"scenario": "cleartext_creds", "detector": "cleartext_creds", "entity": victim.ip,
            "technique": "T1552.001", "proto": "http-basic", "dst": web.ip}


ATTACKS = {
    "syn_scan": attack_syn_scan, "ssh_brute": attack_ssh_brute, "c2_beacon": attack_c2_beacon,
    "dns_tunnel": attack_dns_tunnel, "exfil": attack_exfil, "arp_spoof": attack_arp_spoof,
    "cleartext_creds": attack_cleartext_creds,
}


# --- hard variants: evasive attacks + benign look-alikes -------------------
# Each returns a truth dict, or None when the variant is benign (nothing should fire).

def hard_slow_scan(out, rnd, start):
    """30 ports (below the old fixed threshold), one SYN every ~20 s."""
    atk, tgt = WS[0], FILESRV
    t = start
    for p in rnd.sample(range(1, 1024), 30):
        t += rnd.uniform(15, 25)
        sp = rnd.randint(40000, 60000)
        out.append((t, P.ether(tgt.mac, atk.mac, P.ETH_IP, P.ipv4(atk.ip, tgt.ip, P.PROTO_TCP,
                    P.tcp(atk.ip, tgt.ip, sp, p, rnd.getrandbits(32), 0, P.SYN)))))
        out.append((t + .0005, P.ether(atk.mac, tgt.mac, P.ETH_IP, P.ipv4(tgt.ip, atk.ip, P.PROTO_TCP,
                    P.tcp(tgt.ip, atk.ip, p, sp, 0, 1, P.RST | P.ACK)))))
    return {"scenario": "slow_scan_30ports", "detector": "scan", "entity": atk.ip, "technique": "T1046"}


def hard_horizontal_scan(out, rnd, start):
    """60 hosts, port 445 each, unanswered."""
    atk = WS[0]
    t = start
    for i in range(100, 160):
        tgt = Host("10.0.0.%d" % i, _mac(i))
        t += rnd.uniform(0.5, 2)
        sp = rnd.randint(40000, 60000)
        out.append((t, P.ether(tgt.mac, atk.mac, P.ETH_IP, P.ipv4(atk.ip, tgt.ip, P.PROTO_TCP,
                    P.tcp(atk.ip, tgt.ip, sp, 445, rnd.getrandbits(32), 0, P.SYN)))))
    return {"scenario": "horizontal_scan_60hosts", "detector": "scan", "entity": atk.ip, "technique": "T1046"}


def hard_jitter_beacon(out, rnd, start):
    """Beacon with +/-40% jitter."""
    victim = WS[2]
    c2 = Host("192.0.2.77", GW_MAC, False)
    EXT["cdn-sync.example"] = c2
    t = start
    while t < start + 580:
        https_session(out, rnd, victim, "cdn-sync.example", t, nbytes=400)
        t += 30 * rnd.uniform(0.6, 1.4)
    return {"scenario": "beacon_40pct_jitter", "detector": "beacon",
            "entity": "%s->%s" % (victim.ip, c2.ip), "technique": "T1071.001"}


def hard_benign_periodic(out, rnd, start):
    """Legit periodic traffic: update poll /60s, health-check /60s, NTP /64s."""
    t = start
    while t < start + 580:
        http_session(out, rnd, WS[1], "update.example.com", "/cab/wuredir.cab", t)
        t += 60 + rnd.uniform(-0.5, 0.5)
    t = start + 2
    while t < start + 580:
        https_session(out, rnd, WS[4], "api.example.com", t, nbytes=300)
        t += 60
    t = start - 2
    while t < start + 580:
        ntp_sync(out, rnd, WS[3], t)
        t += 64
    return None


def hard_cdn_dns(out, rnd, start):
    """CDN-style 32-hex labels, 40 lookups, A records."""
    hexa = "abcdef0123456789"
    t = start
    for _ in range(40):
        t += rnd.uniform(0.5, 5)
        lab = "".join(rnd.choice(hexa) for _ in range(32))
        dns_lookup(out, rnd, WS[0], "%s.cloudfront.example" % lab, t, rdata_ip="203.0.113.10")
    return None


def hard_backup(out, rnd, start):
    """Legit 3 MB backup upload to a known backup host (allow-listed in allowlist.toml)."""
    bk = Host("198.51.100.200", GW_MAC, False)
    EXT["backup.example.com"] = bk
    dns_lookup(out, rnd, WS[3], "backup.example.com", start, rdata_ip=bk.ip)
    https_session(out, rnd, WS[3], "backup.example.com", start + 1, nbytes=3_000_000, up_ratio=0.98)
    return None


def hard_slow_brute(out, rnd, start):
    """40 SSH attempts but each session ~5 s long."""
    atk, tgt = WS[1], FILESRV
    t = start
    for _ in range(40):
        t += rnd.uniform(1, 3)
        c = Conn(out, rnd, atk, tgt, rnd.randint(40000, 60000), 22, t)
        c.handshake()
        c.send(b"SSH-2.0-OpenSSH_9.6\r\n")
        c.send(b"SSH-2.0-OpenSSH_9.3\r\n", from_client=False)
        c.t += 4.5
        c.send(P.ssh_packet(rnd.randbytes(48)))
        c.send(P.ssh_packet(bytes([51]) + rnd.randbytes(12)), from_client=False)
        c.close()
    return {"scenario": "slow_ssh_brute", "detector": "bruteforce", "entity": atk.ip, "technique": "T1110"}


def hard_arp_failover(out, rnd, start):
    """Gateway changes MAC once (HA failover), 300 s apart, then stable."""
    out.append((start, P.ether(WS[0].mac, GW_MAC, P.ETH_ARP, P.arp(2, GW_MAC, GW_IP, WS[0].mac, WS[0].ip))))
    new = _mac(2)
    out.append((start + 300, P.ether(P.BCAST, new, P.ETH_ARP, P.arp(2, new, GW_IP, P.BCAST, GW_IP))))
    return None


HARD = {
    "slow_scan_30ports": hard_slow_scan, "horizontal_scan_60hosts": hard_horizontal_scan,
    "beacon_40pct_jitter": hard_jitter_beacon, "benign_periodic": hard_benign_periodic,
    "cdn_long_labels": hard_cdn_dns, "backup_upload_3mb": hard_backup,
    "slow_ssh_brute": hard_slow_brute, "arp_failover": hard_arp_failover,
}

HARD_ALLOWLIST = """# Known-good destinations for the hard set. Loaded by `pcaphunt eval`/`hunt --config`.
[exfil]
allow_dst = ["198.51.100.200"]        # backup.example.com
allow_sni = ["backup.example.com"]

[dns_tunnel]
allow_domains = []
"""


def build_set(outdir, seed=1337, hard=False):
    """Write a synthetic set + ground-truth.json. Deterministic for a given seed."""
    os.makedirs(outdir, exist_ok=True)
    manifest = []
    base_ts = 1_700_000_000.0
    variants = HARD if hard else ATTACKS
    n_normal = 0 if hard else 3
    for i in range(n_normal):
        rnd = random.Random(seed + i)
        out = []
        normal_baseline(out, rnd, base_ts, duration=400.0)
        path = os.path.join(outdir, "normal_%d.pcap" % (i + 1))
        P.write_pcap(path, out)
        manifest.append({"pcap": os.path.basename(path), "truth": []})
    for name, fn in variants.items():
        rnd = random.Random(seed + zlib.crc32(name.encode()) % 1000)   # stable across runs
        out = []
        normal_baseline(out, rnd, base_ts, duration=600.0)
        truth = fn(out, rnd, base_ts + rnd.uniform(30, 120))
        path = os.path.join(outdir, "%s.pcap" % name)
        P.write_pcap(path, out)
        manifest.append({"pcap": os.path.basename(path), "truth": [truth] if truth else []})
    with open(os.path.join(outdir, "ground-truth.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    if hard:
        with open(os.path.join(outdir, "allowlist.toml"), "w") as f:
            f.write(HARD_ALLOWLIST)
    return manifest


if __name__ == "__main__":
    import sys
    d = sys.argv[1] if len(sys.argv) > 1 else "pcaps"
    m = build_set(d, hard="--hard" in sys.argv)
    print("wrote %d pcaps to %s" % (len(m), d))
