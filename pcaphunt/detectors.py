"""Detectors over a parsed Capture. Each returns alerts with evidence + ATT&CK v20 id.

`cfg`  — optional dict from a TOML allow-list (see load_config()).
`sens` — "low" | "default" | "high": scales the count/byte thresholds and the
         sliding window for scan, bruteforce and exfil. Default floor: 20 probe
         targets, 15 SSH sessions, 2 MB upload, all within 600 s. Anything
         slower or smaller than the active floor evades by design.
"""
import base64
import math
import statistics

WINDOW = 600.0
SENSITIVITY = {"low": 2.0, "default": 1.0, "high": 0.5}   # multiplier on thresholds; divisor on window


def load_config(path):
    import tomllib
    with open(path, "rb") as f:
        return tomllib.load(f)


def _k(sens):
    return SENSITIVITY[sens]


def _internal(ip: str) -> bool:
    o = ip.split(".")
    if len(o) != 4:
        return False
    a, b = int(o[0]), int(o[1])
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in [s.count(x) for x in set(s)])


def _cv(values):
    m = statistics.mean(values)
    return (statistics.pstdev(values) / m) if m else 1.0


def _alert(detector, entity, technique, summary, evidence, severity="medium"):
    return {"detector": detector, "entity": entity, "technique": technique,
            "severity": severity, "summary": summary, "evidence": evidence}


def _windows(events, window):
    """events: sorted list of (ts, payload). Yields the slice inside each trailing window."""
    j = 0
    for i, (ts, _) in enumerate(events):
        while events[j][0] < ts - window:
            j += 1
        yield events[j:i + 1]


# -- scan: windowed fan-out of empty SYN probes across ports OR hosts ------
def scan(cap, min_targets=20, cfg=None, sens="default"):
    min_targets = max(5, round(min_targets * _k(sens)))
    window = WINDOW / _k(sens)
    out = []
    probes = {}
    for f in cap.flows.values():
        # a probe is a SYN-initiated TCP flow that never carried payload in either direction
        if f.proto == "tcp" and f.syn and f.orig_bytes + f.resp_bytes == 0:
            probes.setdefault(f.orig_h, []).append((f.ts, (f.resp_h, f.resp_p)))
    for src, ev in probes.items():
        ev.sort()
        best = None
        for win in _windows(ev, window):
            by_host, by_port = {}, {}
            for _, (h, p) in win:
                by_host.setdefault(h, set()).add(p)
                by_port.setdefault(p, set()).add(h)
            host, ports = max(by_host.items(), key=lambda kv: len(kv[1]))
            port, hosts = max(by_port.items(), key=lambda kv: len(kv[1]))
            if len(ports) >= min_targets and (best is None or len(ports) > best[1]):
                best = ("vertical", len(ports), host, win[0][0], win[-1][0])
            if len(hosts) >= min_targets and (best is None or len(hosts) > best[1]):
                best = ("horizontal", len(hosts), port, win[0][0], win[-1][0])
        if best:
            kind, n, target, t0, t1 = best
            what = "%d ports on %s" % (n, target) if kind == "vertical" else "%d hosts on port %s" % (n, target)
            out.append(_alert("scan", src, "T1046", "%s probed %s in %.0f s" % (src, what, t1 - t0),
                              {"kind": kind, "distinct_targets": n, "target": str(target),
                               "window_s": round(t1 - t0, 1), "probes_total": len(ev),
                               "threshold": min_targets, "sensitivity": sens}, "high"))
    return out


# -- brute force: many low-byte SSH sessions to one host per window -------
def bruteforce(cap, min_attempts=15, max_orig_bytes=4000, cfg=None, sens="default"):
    min_attempts = max(4, round(min_attempts * _k(sens)))
    window = WINDOW / _k(sens)
    out = []
    pairs = {}
    for f in cap.flows.values():
        if f.service == "ssh" and f.synack and f.orig_bytes <= max_orig_bytes:
            pairs.setdefault((f.orig_h, f.resp_h), []).append((f.ts, f.orig_bytes))
    for (src, dst), ev in pairs.items():
        ev.sort()
        peak = max(_windows(ev, window), key=len)
        if len(peak) >= min_attempts:
            out.append(_alert("bruteforce", src, "T1110",
                       "%s opened %d low-byte SSH sessions to %s within %.0f s" % (src, len(peak), dst, window),
                       {"dst": dst, "attempts_in_window": len(peak), "attempts_total": len(ev),
                        "median_orig_bytes": int(statistics.median(b for _, b in peak)),
                        "threshold": min_attempts, "sensitivity": sens}, "high"))
    return out


# -- beaconing: regular timing, or looser timing + constant payload size ---
def beacon(cap, min_conns=8, lo=5.0, hi=600.0, cfg=None, sens="default"):
    """n < 15: regularity >= 0.85. n >= 15: regularity >= 0.7, or regularity >= 0.5
    with check-in size CV < 0.3 (orig+resp bytes per connection: jittered beacons
    keep a constant check-in size; human browsing does not)."""
    out = []
    series = {}
    for f in cap.flows.values():
        if f.service in ("ssl", "http") and not _internal(f.resp_h):
            series.setdefault((f.orig_h, f.resp_h), []).append((f.ts, f.orig_bytes + f.resp_bytes))
    for (src, dst), ev in series.items():
        n = len(ev)
        if n < min_conns:
            continue
        ev.sort()
        gaps = [b[0] - a[0] for a, b in zip(ev, ev[1:])]
        mean = statistics.mean(gaps)
        if not (lo <= mean <= hi):
            continue
        regularity = max(0.0, 1 - _cv(gaps))
        bytes_cv = _cv([b for _, b in ev])
        if n < 15:
            hit = regularity >= 0.85
        else:
            hit = regularity >= 0.7 or (regularity >= 0.5 and bytes_cv < 0.3)
        if hit:
            out.append(_alert("beacon", "%s->%s" % (src, dst), "T1071.001",
                       "%s beaconed to %s every ~%.0fs (regularity %.2f, size CV %.2f)" %
                       (src, dst, mean, regularity, bytes_cv),
                       {"dst": dst, "connections": n, "mean_interval_s": round(mean, 1),
                        "regularity": round(regularity, 3), "checkin_bytes_cv": round(bytes_cv, 3)}, "high"))
    return out


# -- DNS tunnelling --------------------------------------------------------
def dns_tunnel(cap, min_unique=20, min_label=28, min_entropy=3.3, cfg=None, sens="default"):
    """Many unique long high-entropy subdomains under one base domain.
    CDN exemption by answer pattern: if >= 90 % of the queries are A/AAAA and the
    base domain resolved to <= 2 distinct A addresses, the labels are cache keys,
    not payload. A tunnel needs varied answers (or TXT/NULL) to carry data back."""
    allow = set((cfg or {}).get("dns_tunnel", {}).get("allow_domains", []))
    out = []
    by_src, a_answers = {}, {}
    for q in cap.dns:
        labels = q["query"].lower().split(".")
        base = ".".join(labels[-2:]) if len(labels) >= 2 else q["query"]
        if q["resp"]:
            a_answers.setdefault((q["dst"], base), set()).update(q["a"])
            continue
        if not q["query"] or base in allow:
            continue
        longest = max(labels, key=len)
        ent = _entropy(longest)
        if len(longest) < min_label or ent < min_entropy:
            continue
        by_src.setdefault((q["src"], base), []).append((".".join(labels[:-2]), len(longest), ent, q["qtype"]))
    for (src, base), hits in by_src.items():
        uniq = {h[0] for h in hits}
        if len(uniq) < min_unique:
            continue
        a_frac = sum(1 for h in hits if h[3] in (1, 28)) / len(hits)
        distinct_a = len(a_answers.get((src, base), set()))
        if a_frac >= 0.9 and distinct_a <= 2:
            continue   # CDN-style: many keys, one or two addresses
        out.append(_alert("dns_tunnel", src, "T1071.004",
                   "%s sent %d unique long high-entropy subdomains under %s" % (src, len(uniq), base),
                   {"domain": base, "unique_subdomains": len(uniq), "queries": len(hits),
                    "avg_label_len": round(sum(h[1] for h in hits) / len(hits), 1),
                    "avg_entropy": round(sum(h[2] for h in hits) / len(hits), 2),
                    "txt_queries": sum(1 for h in hits if h[3] == 16),
                    "distinct_a_answers": distinct_a}, "high"))
    return out


# -- ARP spoofing: MAC flapping or conflicting claims in a short window ----
def arp_spoof(cap, conflict_window=60.0, min_flaps=2, cfg=None, sens="default"):
    out = []
    claims = {}
    for ts, ip, mac, op in cap.arp:
        if op == 2:
            claims.setdefault(ip, []).append((ts, mac))
    for ip, ev in claims.items():
        ev.sort()
        changes = [(ev[i][0] - ev[i - 1][0], ev[i - 1][1], ev[i][1])
                   for i in range(1, len(ev)) if ev[i][1] != ev[i - 1][1]]
        if not changes:
            continue
        fast = [c for c in changes if c[0] <= conflict_window]
        if len(changes) >= min_flaps or fast:
            macs = sorted({m for _, m in ev})
            out.append(_alert("arp_spoof", ip, "T1557.002",
                       "%s claimed by %d MACs (%d changes, %d within %.0f s)" %
                       (ip, len(macs), len(changes), len(fast), conflict_window),
                       {"macs": macs, "mac_changes": len(changes), "fast_changes": len(fast),
                        "replies": len(ev)}, "high"))
    return out


# -- cleartext credentials: HTTP Basic -------------------------------------
def cleartext_creds(cap, cfg=None, sens="default"):
    out = []
    for h in cap.http:
        if h["auth"].lower().startswith("basic "):
            try:
                user = base64.b64decode(h["auth"].split(" ", 1)[1]).split(b":", 1)[0].decode("latin1")
            except Exception:
                user = "?"
            out.append(_alert("cleartext_creds", h["src"], "T1552.001",
                       "HTTP Basic credentials sent in clear by %s" % h["src"],
                       {"dst": h["dst"], "host": h["host"], "uri": h["uri"], "username": user}, "high"))
    return out


# -- large outbound transfer on an upload-capable TCP service -------------
UPLOAD_SERVICES = {"ssl", "http", "ssh", "ftp"}


def exfil(cap, min_bytes=2_000_000, min_ratio=20.0, cfg=None, sens="default"):
    """TCP only, on services that carry uploads; UDP media (Zoom/Teams/VoIP) is skipped.
    Any upload over the floor to an unlisted host alerts — nightly backups included —
    so the allow-list is mandatory in production."""
    min_bytes = int(min_bytes * _k(sens))
    ex = (cfg or {}).get("exfil", {})
    allow_dst, allow_sni = set(ex.get("allow_dst", [])), set(ex.get("allow_sni", []))
    sni_by_uid = {t["uid"]: t["sni"] for t in cap.tls}
    out = []
    ext_flows = [f for f in cap.flows.values()
                 if f.proto == "tcp" and f.service in UPLOAD_SERVICES
                 and _internal(f.orig_h) and not _internal(f.resp_h)]
    for f in ext_flows:
        if f.orig_bytes < min_bytes or f.resp_h in allow_dst or sni_by_uid.get(f.uid, "") in allow_sni:
            continue
        others = [g.orig_bytes for g in ext_flows if g.orig_h == f.orig_h and g is not f]
        baseline = statistics.median(others) if others else 0
        ratio = f.orig_bytes / baseline if baseline else float("inf")
        if ratio < min_ratio:
            continue
        novel = not any(g.resp_h == f.resp_h and g.ts < f.ts for g in ext_flows if g is not f)
        out.append(_alert("exfil", "%s->%s" % (f.orig_h, f.resp_h), "T1048",
                   "%s sent %.1f MB to %s (%.0fx its median upload%s)" %
                   (f.orig_h, f.orig_bytes / 1e6, f.resp_h, min(ratio, 9999), ", first contact" if novel else ""),
                   {"dst": f.resp_h, "resp_p": f.resp_p, "orig_bytes": f.orig_bytes,
                    "host_median_orig_bytes": int(baseline), "sni": sni_by_uid.get(f.uid, ""),
                    "first_contact_with_dst": novel, "service": f.service,
                    "threshold_bytes": min_bytes, "sensitivity": sens}, "high"))
    return out


ALL = [scan, bruteforce, beacon, dns_tunnel, arp_spoof, cleartext_creds, exfil]


def run_all(cap, cfg=None, sens="default"):
    alerts = []
    for fn in ALL:
        alerts.extend(fn(cap, cfg=cfg, sens=sens))
    return alerts
