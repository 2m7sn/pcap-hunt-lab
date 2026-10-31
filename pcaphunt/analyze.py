"""Read a pcap, rebuild flows, emit Zeek-style logs (conn/dns/http/tls). pcap only."""
import socket
import struct
from dataclasses import dataclass, field


class PcapError(Exception):
    pass


def _iter_records(data: bytes):
    if len(data) < 24:
        raise PcapError("file too short")
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic[:4] == b"\x0a\x0d\x0d\x0a":
        raise PcapError("pcapng not supported (roadmap); convert with `editcap -F pcap`")
    else:
        raise PcapError("not a libpcap file")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_usec, caplen, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        frame = data[off:off + caplen]
        off += caplen
        if len(frame) < caplen:
            break
        yield ts_sec + ts_usec / 1e6, linktype, frame


@dataclass
class Flow:
    uid: str
    proto: str
    orig_h: str = ""
    orig_p: int = 0
    resp_h: str = ""
    resp_p: int = 0
    ts: float = 0.0
    last: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    orig_pkts: int = 0
    resp_pkts: int = 0
    history: str = ""
    service: str = ""
    syn: bool = False
    synack: bool = False
    rst: bool = False
    fin: int = 0

    @property
    def duration(self):
        return round(self.last - self.ts, 6)

    @property
    def state(self):
        if self.syn and self.synack and self.fin >= 1:
            return "SF"
        if self.syn and self.rst:
            return "REJ"
        if self.syn and not self.synack:
            return "S0"
        if self.syn and self.synack:
            return "S1"
        return "OTH"


class Capture:
    """Parsed capture: packets, flows, and per-protocol logs."""

    def __init__(self, path: str):
        with open(path, "rb") as f:
            data = f.read()
        self.path = path
        self.packets = []          # dicts: ts, src, dst, proto, sport, dport, flags, length
        self.flows = {}            # key -> Flow
        self.dns, self.http, self.tls = [], [], []
        self.arp = []              # (ts, sender_ip, sender_mac, opcode)
        self.frames = 0            # every link-layer frame, incl. ARP and non-IP
        self.first_ts = self.last_ts = None
        self._uid = 0
        for ts, linktype, frame in _iter_records(data):
            if linktype != 1:
                raise PcapError("link-layer type %d not supported (Ethernet only)" % linktype)
            self._eth(ts, frame)

    # -- layers ------------------------------------------------------------
    def _eth(self, ts, frame):
        if len(frame) < 14:
            return
        self.frames += 1
        self.first_ts = ts if self.first_ts is None else self.first_ts
        self.last_ts = ts
        etype = struct.unpack("!H", frame[12:14])[0]
        dst_mac, src_mac = frame[:6].hex(":"), frame[6:12].hex(":")
        pay = frame[14:]
        if etype == 0x0806 and len(pay) >= 28:
            op = struct.unpack("!H", pay[6:8])[0]
            s_mac = pay[8:14].hex(":")
            s_ip = socket.inet_ntoa(pay[14:18])
            self.arp.append((ts, s_ip, s_mac, op))
        elif etype == 0x0800:
            self._ipv4(ts, pay, src_mac, dst_mac)

    def _ipv4(self, ts, pkt, src_mac, dst_mac):
        if len(pkt) < 20:
            return
        ihl = (pkt[0] & 0x0F) * 4
        proto = pkt[9]
        src, dst = socket.inet_ntoa(pkt[12:16]), socket.inet_ntoa(pkt[16:20])
        total = struct.unpack("!H", pkt[2:4])[0]
        l4 = pkt[ihl:total] if total >= ihl else pkt[ihl:]
        if proto == 6:
            self._tcp(ts, src, dst, l4, src_mac)
        elif proto == 17:
            self._udp(ts, src, dst, l4)

    def _flow(self, proto, a, ap, b, bp, is_orig_src):
        key = tuple(sorted([(a, ap), (b, bp)])) + (proto,)
        f = self.flows.get(key)
        if f is None:
            self._uid += 1
            f = Flow(uid="C%d" % self._uid, proto=proto)
            if is_orig_src:
                f.orig_h, f.orig_p, f.resp_h, f.resp_p = a, ap, b, bp
            else:
                f.orig_h, f.orig_p, f.resp_h, f.resp_p = b, bp, a, ap
            self.flows[key] = f
        return f

    def _tcp(self, ts, src, dst, seg, src_mac):
        if len(seg) < 20:
            return
        sport, dport = struct.unpack("!HH", seg[:4])
        off = (seg[12] >> 4) * 4
        flags = seg[13]
        payload = seg[off:]
        # establish flow orientation on SYN (no ACK)
        is_syn = flags & 0x02 and not flags & 0x10
        f = self._flow("tcp", src, sport, dst, dport, is_orig_src=is_syn or sport > dport)
        orig = (src == f.orig_h and sport == f.orig_p)
        if f.ts == 0.0:
            f.ts = ts
        f.last = ts
        if orig:
            f.orig_pkts += 1
            f.orig_bytes += len(payload)
        else:
            f.resp_pkts += 1
            f.resp_bytes += len(payload)
        if flags & 0x02 and not flags & 0x10:
            f.syn = True
        if flags & 0x02 and flags & 0x10:
            f.synack = True
        if flags & 0x04:
            f.rst = True
        if flags & 0x01:
            f.fin += 1
        svc_port = min(f.orig_p, f.resp_p)
        f.service = {21: "ftp", 22: "ssh", 80: "http", 443: "ssl", 445: "smb", 53: "dns",
                     8080: "http", 8443: "ssl"}.get(svc_port, f.service)
        self.packets.append({"ts": ts, "src": src, "dst": dst, "proto": "tcp", "sport": sport,
                             "dport": dport, "flags": flags, "length": len(payload), "src_mac": src_mac})
        if payload:
            self._appl_tcp(ts, src, dst, sport, dport, payload, f)

    def _udp(self, ts, src, dst, seg):
        if len(seg) < 8:
            return
        sport, dport = struct.unpack("!HH", seg[:4])
        payload = seg[8:struct.unpack("!H", seg[4:6])[0]] if len(seg) >= 8 else seg[8:]
        f = self._flow("udp", src, sport, dst, dport, is_orig_src=dport < sport)
        if f.ts == 0.0:
            f.ts = ts
        f.last = ts
        if src == f.orig_h and sport == f.orig_p:
            f.orig_pkts += 1
            f.orig_bytes += len(payload)
        else:
            f.resp_pkts += 1
            f.resp_bytes += len(payload)
        f.service = {53: "dns", 123: "ntp", 67: "dhcp", 68: "dhcp"}.get(min(sport, dport), f.service)
        self.packets.append({"ts": ts, "src": src, "dst": dst, "proto": "udp", "sport": sport,
                             "dport": dport, "flags": 0, "length": len(payload), "src_mac": ""})
        if (sport == 53 or dport == 53) and payload:
            self._dns(ts, src, dst, payload)

    # -- application parsing ----------------------------------------------
    def _dns(self, ts, src, dst, data):
        if len(data) < 12:
            return
        txid, flags, qd, an = struct.unpack("!HHHH", data[:8])
        is_resp = bool(flags & 0x8000)
        name, off = self._dns_name(data, 12)
        if off + 4 > len(data):
            return
        qtype = struct.unpack("!H", data[off:off + 2])[0]
        txt, ips = (self._answers(data, off + 4, an) if is_resp and an else (None, []))
        self.dns.append({"ts": ts, "src": src, "dst": dst, "query": name, "qtype": qtype,
                         "resp": is_resp, "rcode": flags & 0x0F, "answers": an, "txt": txt, "a": ips})

    def _dns_name(self, data, off, depth=0):
        labels = []
        while off < len(data) and depth < 20:
            ln = data[off]
            if ln == 0:
                off += 1
                break
            if ln & 0xC0 == 0xC0:
                ptr = struct.unpack("!H", data[off:off + 2])[0] & 0x3FFF
                sub, _ = self._dns_name(data, ptr, depth + 1)
                labels.append(sub)
                off += 2
                break
            labels.append(data[off + 1:off + 1 + ln].decode("latin1"))
            off += 1 + ln
        return ".".join(x for x in labels if x), off

    def _answers(self, data, off, count):
        """Walk answer RRs: first TXT string and all A-record IPs."""
        txt, ips = None, []
        try:
            for _ in range(count):
                _, p = self._dns_name(data, off)
                rtype, rlen = struct.unpack("!H", data[p:p + 2])[0], struct.unpack("!H", data[p + 8:p + 10])[0]
                rdata = data[p + 10:p + 10 + rlen]
                if rtype == 1 and rlen == 4:
                    ips.append(socket.inet_ntoa(rdata))
                elif rtype == 16 and txt is None and rdata:
                    txt = rdata[1:1 + rdata[0]].decode("latin1")
                off = p + 10 + rlen
        except Exception:
            pass
        return txt, ips

    def _appl_tcp(self, ts, src, dst, sport, dport, payload, flow):
        if dport == 80 and payload[:3] in (b"GET", b"POS", b"PUT", b"HEA", b"DEL"):
            self._http_req(ts, src, dst, payload, flow)
        elif dport == 443 and payload[0] == 0x16:
            self._tls(ts, src, dst, payload, flow)

    def _http_req(self, ts, src, dst, data, flow):
        try:
            head = data.split(b"\r\n\r\n", 1)[0].decode("latin1")
        except Exception:
            return
        lines = head.split("\r\n")
        method, uri = (lines[0].split(" ") + ["", ""])[:2]
        host = auth = ""
        for ln in lines[1:]:
            low = ln.lower()
            if low.startswith("host:"):
                host = ln[5:].strip()
            elif low.startswith("authorization:"):
                auth = ln.split(":", 1)[1].strip()
        self.http.append({"ts": ts, "uid": flow.uid, "src": src, "dst": dst, "method": method,
                          "host": host, "uri": uri, "auth": auth})

    def _tls(self, ts, src, dst, data, flow):
        if len(data) < 6 or data[5] != 0x01:  # handshake type 1 = ClientHello
            return
        sni = self._tls_sni(data)
        self.tls.append({"ts": ts, "uid": flow.uid, "src": src, "dst": dst, "sni": sni})

    @staticmethod
    def _tls_sni(d):
        try:
            p = 5 + 4 + 2 + 32            # record+hs hdr, version, random
            p += 1 + d[p]                 # session id
            p += 2 + struct.unpack("!H", d[p:p + 2])[0]   # cipher suites
            p += 1 + d[p]                 # compression
            ext_end = p + 2 + struct.unpack("!H", d[p:p + 2])[0]
            p += 2
            while p + 4 <= ext_end:
                etype, elen = struct.unpack("!HH", d[p:p + 4])
                if etype == 0:
                    n = struct.unpack("!H", d[p + 7:p + 9])[0]
                    return d[p + 9:p + 9 + n].decode("latin1")
                p += 4 + elen
        except Exception:
            pass
        return ""

    # -- Zeek-style TSV export --------------------------------------------
    def conn_log(self):
        rows = []
        for f in self.flows.values():
            rows.append({"ts": round(f.ts, 6), "uid": f.uid, "id.orig_h": f.orig_h, "id.orig_p": f.orig_p,
                         "id.resp_h": f.resp_h, "id.resp_p": f.resp_p, "proto": f.proto, "service": f.service,
                         "duration": f.duration, "orig_bytes": f.orig_bytes, "resp_bytes": f.resp_bytes,
                         "orig_pkts": f.orig_pkts, "resp_pkts": f.resp_pkts, "conn_state": f.state})
        return sorted(rows, key=lambda r: r["ts"])


def write_tsv(rows, path):
    if not rows:
        open(path, "w").write("")
        return
    cols = list(rows[0].keys())
    with open(path, "w", encoding="utf-8") as f:
        f.write("#fields\t" + "\t".join(cols) + "\n")
        for r in rows:
            f.write("\t".join(str(r[c]) for c in cols) + "\n")
