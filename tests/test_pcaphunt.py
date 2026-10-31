"""checksums valid, pcap round-trips, generation deterministic, each detector fires on its
scenario (easy + hard) and stays quiet on normal and benign look-alikes."""
import hashlib
import os
import struct

import pytest

from pcaphunt import packets as P
from pcaphunt.analyze import Capture, _iter_records
from pcaphunt import detectors as D
from pcaphunt.generate import build_set


@pytest.fixture(scope="session")
def pcap_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("pcaps")
    build_set(str(d))
    return str(d)


@pytest.fixture(scope="session")
def hard_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("hard")
    build_set(str(d), hard=True)
    return str(d)


def _walk(path):
    yield from _iter_records(open(path, "rb").read())


def _sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def test_checksums_valid(pcap_dir):
    checked_ip = checked_l4 = 0
    for _ts, _lt, frame in _walk(pcap_dir + "/c2_beacon.pcap"):
        if struct.unpack("!H", frame[12:14])[0] != 0x0800:
            continue
        pkt = frame[14:]
        ihl = (pkt[0] & 0x0F) * 4
        assert P.checksum(pkt[:ihl]) == 0          # IPv4 header checksum closes to 0
        checked_ip += 1
        total = struct.unpack("!H", pkt[2:4])[0]
        proto = pkt[9]
        l4 = pkt[ihl:total]
        if proto in (6, 17):
            pseudo = pkt[12:16] + pkt[16:20] + struct.pack("!BBH", 0, proto, len(l4))
            if proto == 17 and l4[6:8] == b"\x00\x00":
                continue
            assert P.checksum(pseudo + l4) == 0    # TCP/UDP checksum closes to 0
            checked_l4 += 1
    assert checked_ip > 100 and checked_l4 > 100


def test_pcap_round_trip(tmp_path):
    frames = [
        (1.5, P.ether("02:00:00:00:00:02", "02:00:00:00:00:01", P.ETH_IP,
                      P.ipv4("10.0.0.10", "10.0.0.5", P.PROTO_TCP,
                             P.tcp("10.0.0.10", "10.0.0.5", 44000, 445, 1, 0, P.SYN)))),
        (1.6, P.ether("02:00:00:00:00:01", "02:00:00:00:00:02", P.ETH_IP,
                      P.ipv4("10.0.0.5", "10.0.0.10", P.PROTO_TCP,
                             P.tcp("10.0.0.5", "10.0.0.10", 445, 44000, 10, 2, P.SYN | P.ACK)))),
    ]
    path = str(tmp_path / "rt.pcap")
    P.write_pcap(path, frames)
    read = list(_walk(path))
    assert len(read) == 2
    assert read[0][0] == pytest.approx(1.5, abs=1e-6)
    assert struct.unpack("!H", read[1][2][12:14])[0] == 0x0800


def test_generation_is_deterministic(pcap_dir, tmp_path):
    """Two build_set runs with the same seed must be byte-identical (R1)."""
    again = str(tmp_path / "again")
    build_set(again)
    for name in os.listdir(pcap_dir):
        if name.endswith(".pcap"):
            assert _sha(os.path.join(pcap_dir, name)) == _sha(os.path.join(again, name)), name


def test_tls_alpn_list_length():
    import random
    ch = P.tls_client_hello("a.example", random.Random(1))
    i = ch.find(b"\x00\x10\x00")                      # ALPN extension type 16
    ext_len, list_len = struct.unpack("!HH", ch[i + 2:i + 6])
    assert list_len == 12 and ext_len == list_len + 2  # 1+2 "h2" + 1+8 "http/1.1"


def test_dns_lookup_is_one_flow(pcap_dir):
    cap = Capture(pcap_dir + "/normal_1.pcap")
    for f in cap.flows.values():
        if f.service == "dns":
            assert f.orig_pkts >= 1 and f.resp_pkts >= 1   # reply came back on the query's port


def test_frames_count_includes_arp(pcap_dir):
    cap = Capture(pcap_dir + "/arp_spoof.pcap")
    assert cap.frames == len(cap.packets) + len(cap.arp)


def test_dns_name_round_trip():
    cap_name, _ = Capture.__new__(Capture)._dns_name(P.dns_name("a.tun.example"), 0)
    assert cap_name == "a.tun.example"


EASY = {
    "syn_scan": "scan", "ssh_brute": "bruteforce", "c2_beacon": "beacon",
    "dns_tunnel": "dns_tunnel", "exfil": "exfil", "arp_spoof": "arp_spoof",
    "cleartext_creds": "cleartext_creds",
}
HARD_FIRES = {"slow_scan_30ports": "scan", "horizontal_scan_60hosts": "scan",
              "beacon_40pct_jitter": "beacon", "slow_ssh_brute": "bruteforce"}
HARD_QUIET = ["benign_periodic", "cdn_long_labels", "backup_upload_3mb", "arp_failover"]


@pytest.mark.parametrize("scenario,detector", EASY.items())
def test_detector_fires_on_easy_scenario(pcap_dir, scenario, detector):
    cap = Capture("%s/%s.pcap" % (pcap_dir, scenario))
    fired = {a["detector"] for a in D.run_all(cap)}
    assert fired == {detector}, "%s: expected only %s, got %s" % (scenario, detector, fired)


@pytest.mark.parametrize("n", [1, 2, 3])
def test_quiet_on_normal(pcap_dir, n):
    cap = Capture("%s/normal_%d.pcap" % (pcap_dir, n))
    assert D.run_all(cap) == [], "no detector may fire on normal traffic"


@pytest.mark.parametrize("scenario,detector", HARD_FIRES.items())
def test_detector_fires_on_hard_scenario(hard_dir, scenario, detector):
    cfg = D.load_config(hard_dir + "/allowlist.toml")
    cap = Capture("%s/%s.pcap" % (hard_dir, scenario))
    fired = {a["detector"] for a in D.run_all(cap, cfg)}
    assert fired == {detector}, "%s: expected only %s, got %s" % (scenario, detector, fired)


@pytest.mark.parametrize("scenario", HARD_QUIET)
def test_quiet_on_benign_lookalike(hard_dir, scenario):
    cfg = D.load_config(hard_dir + "/allowlist.toml")
    cap = Capture("%s/%s.pcap" % (hard_dir, scenario))
    assert D.run_all(cap, cfg) == [], scenario


def test_backup_fires_without_allowlist(hard_dir):
    """Documented behaviour: a 3 MB upload to an unlisted host IS flagged; the allowlist is the fix."""
    cap = Capture(hard_dir + "/backup_upload_3mb.pcap")
    assert {a["detector"] for a in D.run_all(cap)} == {"exfil"}


# --- round-2 rules: (a) exfil TCP-only, (b) beacon size consistency, (c) DNS answer pattern, (d) sensitivity

def _cap(tmp_path, frames, name="t.pcap"):
    p = str(tmp_path / name)
    P.write_pcap(p, frames)
    return Capture(p)


def test_exfil_ignores_udp_media(tmp_path):
    import random
    from pcaphunt import generate as G
    rnd, out, ws = random.Random(3), [], G.WS[1]
    srv = G.Host("203.0.113.200", G.GW_MAC, False)
    t = 1_700_000_000.0
    for _ in range(3000):                                     # ~3 MB up over UDP 8801
        t += 0.05
        out.append((t, P.ether(G.GW_MAC, ws.mac, P.ETH_IP, P.ipv4(ws.ip, srv.ip, P.PROTO_UDP,
                    P.udp(ws.ip, srv.ip, 50000, 8801, rnd.randbytes(1000))))))
    cap = _cap(tmp_path, out)
    assert sum(f.orig_bytes for f in cap.flows.values()) >= 2_000_000
    assert D.exfil(cap) == []


def test_beacon_jittered_needs_constant_size(tmp_path):
    import random
    from pcaphunt import generate as G
    c2 = G.Host("192.0.2.91", G.GW_MAC, False)
    G.EXT["jit.example"] = c2
    for nbytes, expect in ((400, 1), (None, 0)):            # constant 400 B vs random 1.5–9 KB
        rnd, out, t = random.Random(5), [], 1_700_000_000.0
        for _ in range(20):
            G.https_session(out, rnd, G.WS[2], "jit.example", t, nbytes=nbytes)
            t += 30 * rnd.uniform(0.3, 1.7)                   # +/-70 % jitter
        cap = _cap(tmp_path, out, "b%s.pcap" % nbytes)
        assert len(D.beacon(cap)) == expect, "nbytes=%s" % nbytes


def test_dns_cdn_exempt_by_answer_pattern(tmp_path):
    import random
    from pcaphunt import generate as G
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789-"
    rnd, out, t = random.Random(7), [], 1_700_000_000.0
    for _ in range(40):                                       # base64ish labels, ONE A answer -> CDN
        t += 1
        G.dns_lookup(out, rnd, G.WS[2], "%s.edge.cdn.example" % "".join(rnd.choice(alpha) for _ in range(40)),
                     t, rdata_ip="203.0.113.10")
    assert D.dns_tunnel(_cap(tmp_path, out, "cdn.pcap")) == []
    out = []
    for _ in range(60):                                       # hex labels over A, varied answers -> tunnel
        t += 0.3
        G.dns_lookup(out, rnd, G.WS[3], "%s.x.example" % rnd.randbytes(26).hex(), t,
                     rdata_ip="192.0.2.%d" % rnd.randint(1, 254))
    assert len(D.dns_tunnel(_cap(tmp_path, out, "hexa.pcap"))) == 1


def test_sensitivity_scales_scan_floor(tmp_path):
    import random
    from pcaphunt import generate as G
    rnd, out, t = random.Random(9), [], 1_700_000_000.0
    for i in range(200, 215):                                 # 15-host sweep: under default floor (20), over high (10)
        t += 5
        tgt = G.Host("10.0.0.%d" % i, G._mac(i))
        out.append((t, P.ether(tgt.mac, G.WS[0].mac, P.ETH_IP, P.ipv4(G.WS[0].ip, tgt.ip, P.PROTO_TCP,
                    P.tcp(G.WS[0].ip, tgt.ip, 40000 + i, 3389, 1, 0, P.SYN)))))
    cap = _cap(tmp_path, out)
    assert D.scan(cap) == [] and len(D.scan(cap, sens="high")) == 1


def test_every_alert_has_technique(pcap_dir):
    cap = Capture(pcap_dir + "/syn_scan.pcap")
    for a in D.run_all(cap):
        assert a["technique"].startswith("T") and a["evidence"]
