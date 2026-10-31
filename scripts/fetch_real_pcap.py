"""Fetch one small, legal public pcap for a real-world smoke test.

Default: the Wireshark SampleCaptures DNS sample (small, benign). Respect each
source's terms. Do NOT commit downloaded pcaps (see .gitignore); do NOT fetch
malware captures with this — only benign protocol samples.

Usage:  python scripts/fetch_real_pcap.py [url] [out_dir]
"""
import os
import sys
import urllib.request

# Benign protocol sample from the Wireshark wiki SampleCaptures (gzipped pcap).
DEFAULT = "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap"


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "real"
    os.makedirs(out_dir, exist_ok=True)
    name = url.rsplit("/", 1)[-1] or "sample.pcap"
    dest = os.path.join(out_dir, name)
    req = urllib.request.Request(url, headers={"User-Agent": "pcaphunt/0.1 (+github.com/2m7sn)"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read()
    if len(data) > 5_000_000:
        sys.exit("refusing: file larger than 5 MB (%d bytes)" % len(data))
    with open(dest, "wb") as f:
        f.write(data)
    print("saved %d bytes -> %s" % (len(data), dest))
    print("now run:  python -m pcaphunt.cli hunt %s -o out_real" % dest)


if __name__ == "__main__":
    main()
