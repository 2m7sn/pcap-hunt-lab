"""Raw packet builders (bytes in, bytes out) and a libpcap writer. Stdlib only."""
import random
import struct

ETH_IP, ETH_ARP = 0x0800, 0x0806
PROTO_TCP, PROTO_UDP = 6, 17
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
BCAST = "ff:ff:ff:ff:ff:ff"


def mac(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", ""))


def ip(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ether(dst: str, src: str, ethertype: int, payload: bytes) -> bytes:
    frame = mac(dst) + mac(src) + struct.pack("!H", ethertype) + payload
    return frame + b"\0" * max(0, 60 - len(frame))  # pad to min frame size (no FCS)


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl=64, ident=0) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, ttl, proto, 0, ip(src), ip(dst))
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + payload


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    return ip(src) + ip(dst) + struct.pack("!BBH", 0, proto, length)


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b"", window=64240) -> bytes:
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, window, 0, 0) + payload
    csum = checksum(_pseudo(src, dst, PROTO_TCP, len(seg)) + seg)
    return seg[:16] + struct.pack("!H", csum) + seg[18:]


def udp(src, dst, sport, dport, payload: bytes) -> bytes:
    length = 8 + len(payload)
    seg = struct.pack("!HHHH", sport, dport, length, 0) + payload
    csum = checksum(_pseudo(src, dst, PROTO_UDP, length) + seg) or 0xFFFF
    return seg[:6] + struct.pack("!H", csum) + seg[8:]


def arp(op: int, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    return struct.pack("!HHBBH", 1, ETH_IP, 6, 4, op) + mac(sha) + ip(spa) + mac(tha) + ip(tpa)


# --- application payloads -------------------------------------------------

def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(x)]) + x.encode() for x in name.rstrip(".").split(".")) + b"\0"


def dns_query(txid: int, name: str, qtype=1) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(txid: int, name: str, qtype: int, rdata: list, ttl=300, rcode=0) -> bytes:
    hdr = struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, len(rdata), 0, 0)
    answers = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, ttl, len(r)) + r for r in rdata)
    return hdr + dns_name(name) + struct.pack("!HH", qtype, 1) + answers


def dns_txt(text: bytes) -> bytes:
    return bytes([len(text)]) + text


def _ext(kind: int, body: bytes) -> bytes:
    return struct.pack("!HH", kind, len(body)) + body


def _handshake(kind: int, body: bytes, rec_version=0x0301) -> bytes:
    hs = bytes([kind]) + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", 0x16, rec_version, len(hs)) + hs


def tls_client_hello(sni: str, rnd: random.Random) -> bytes:
    ciphers = struct.pack("!6H", 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC030)
    name = sni.encode()
    exts = (
        _ext(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)
        + _ext(10, struct.pack("!H3H", 6, 0x001D, 0x0017, 0x0018))
        + _ext(16, struct.pack("!HB", 12, 2) + b"h2" + struct.pack("!B", 8) + b"http/1.1")  # list len = 3 + 9
        + _ext(43, struct.pack("!B2H", 4, 0x0304, 0x0303))
    )
    body = (struct.pack("!H", 0x0303) + rnd.randbytes(32) + b"\x20" + rnd.randbytes(32)
            + struct.pack("!H", len(ciphers)) + ciphers + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    return _handshake(1, body)


def tls_server_hello(rnd: random.Random) -> bytes:
    exts = _ext(43, struct.pack("!H", 0x0304))
    body = (struct.pack("!H", 0x0303) + rnd.randbytes(32) + b"\x20" + rnd.randbytes(32)
            + struct.pack("!H", 0x1301) + b"\x00" + struct.pack("!H", len(exts)) + exts)
    return _handshake(2, body, 0x0303)


def tls_app_data(n: int, rnd: random.Random) -> bytes:
    return struct.pack("!BHH", 0x17, 0x0303, n) + rnd.randbytes(n)


def http_request(method: str, host: str, path: str, extra_headers=(), body=b"") -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/128.0",
             "Accept: text/html,*/*;q=0.8", "Connection: keep-alive", *extra_headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http_response(status: int, reason: str, body: bytes, ctype="text/html; charset=utf-8", extra_headers=()) -> bytes:
    lines = [f"HTTP/1.1 {status} {reason}", "Server: nginx/1.24.0", f"Content-Type: {ctype}", f"Content-Length: {len(body)}",
             "Connection: keep-alive", *extra_headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def ssh_packet(payload: bytes) -> bytes:
    pad = 8 - (5 + len(payload)) % 8
    pad += 8 if pad < 4 else 0
    return struct.pack("!IB", 1 + len(payload) + pad, pad) + payload + b"\0" * pad


def ntp(mode: int, ts: float) -> bytes:
    secs = int(ts) + 2208988800
    frac = int((ts - int(ts)) * 2**32)
    return bytes([0x20 | mode, 3, 10, 0xEC]) + b"\0" * 36 + struct.pack("!II", secs, frac)


def dhcp(op: int, xid: int, chaddr: str, msg_type: int, ciaddr="0.0.0.0", yiaddr="0.0.0.0", options=b"") -> bytes:
    fixed = struct.pack("!BBBBIHH4s4s4s4s", op, 1, 6, 0, xid, 0, 0x8000 if op == 1 else 0,
                        ip(ciaddr), ip(yiaddr), ip("0.0.0.0"), ip("0.0.0.0"))
    return fixed + mac(chaddr) + b"\0" * 10 + b"\0" * 192 + b"\x63\x82\x53\x63" + bytes([53, 1, msg_type]) + options + b"\xff"


def smb2_negotiate_request() -> bytes:
    hdr = b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) + b"\0" * 16
    body = struct.pack("<HHHHI", 36, 2, 1, 0, 0) + b"\0" * 16 + struct.pack("<IHH", 0, 0, 0) + struct.pack("<HH", 0x0202, 0x0210)
    payload = hdr + body
    return struct.pack("!I", len(payload)) + payload


def smb2_negotiate_response() -> bytes:
    hdr = b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0) + b"\0" * 16
    body = struct.pack("<HHHH", 65, 1, 0x0210, 0) + b"\0" * 16 + struct.pack("<IIII", 0x2F, 0x800000, 0x800000, 0x800000)
    body += b"\0" * 16 + struct.pack("<HHI", 0, 0, 0)
    payload = hdr + body
    return struct.pack("!I", len(payload)) + payload


# --- pcap file ------------------------------------------------------------

class PcapWriter:
    def __init__(self, path: str):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def write(self, ts: float, frame: bytes):
        sec, usec = int(ts), int(round((ts - int(ts)) * 1_000_000))
        if usec == 1_000_000:
            sec, usec = sec + 1, 0
        self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)

    def close(self):
        self.f.close()


def write_pcap(path: str, packets):
    w = PcapWriter(path)
    for ts, frame in sorted(packets, key=lambda p: p[0]):
        w.write(ts, frame)
    w.close()
