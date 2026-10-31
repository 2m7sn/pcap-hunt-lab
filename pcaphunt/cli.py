"""Command line: generate | hunt | eval."""
import argparse
import json
import os

from .analyze import Capture, write_tsv
from . import detectors as D
from .evaluate import evaluate
from .generate import build_set
from .report import build_report


def _hunt(pcap, outdir, make_report=True, cfg=None, sens="default"):
    cap = Capture(pcap)
    alerts = D.run_all(cap, cfg, sens)
    os.makedirs(outdir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(pcap))[0]
    write_tsv(cap.conn_log(), os.path.join(outdir, stem + ".conn.log"))
    write_tsv(cap.dns, os.path.join(outdir, stem + ".dns.log"))
    write_tsv(cap.http, os.path.join(outdir, stem + ".http.log"))
    write_tsv(cap.tls, os.path.join(outdir, stem + ".tls.log"))
    json.dump(alerts, open(os.path.join(outdir, stem + ".alerts.json"), "w"), indent=2)
    if make_report:
        build_report(cap, alerts, os.path.join(outdir, stem + ".report.html"))
    return cap, alerts


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pcaphunt", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="write a synthetic pcap set + ground truth")
    g.add_argument("outdir", nargs="?", default="pcaps")
    g.add_argument("--seed", type=int, default=1337)
    g.add_argument("--hard", action="store_true", help="evasive attacks + benign look-alikes")
    h = sub.add_parser("hunt", help="analyse a pcap: logs, alerts, HTML report")
    h.add_argument("pcap")
    h.add_argument("-o", "--outdir", default="out")
    h.add_argument("--config", help="TOML allowlist (see pcaps-hard/allowlist.toml)")
    h.add_argument("--no-report", action="store_true")
    e = sub.add_parser("eval", help="precision/recall per detector on a generated set")
    e.add_argument("pcap_dir", nargs="?", default="pcaps")
    for p in (h, e):
        p.add_argument("--sensitivity", choices=sorted(D.SENSITIVITY), default="default",
                       help="low/default/high scales scan, bruteforce and exfil thresholds and window")
    args = ap.parse_args(argv)

    if args.cmd == "generate":
        m = build_set(args.outdir, seed=args.seed, hard=args.hard)
        print("wrote %d pcaps + ground-truth.json to %s/" % (len(m), args.outdir))
    elif args.cmd == "hunt":
        cfg = D.load_config(args.config) if args.config else None
        cap, alerts = _hunt(args.pcap, args.outdir, make_report=not args.no_report, cfg=cfg, sens=args.sensitivity)
        print("%s: %d frames, %d flows, %d alerts -> %s/" %
              (os.path.basename(args.pcap), cap.frames, len(cap.flows), len(alerts), args.outdir))
        for a in alerts:
            print("  [%s] %s  %s" % (a["technique"], a["detector"], a["summary"]))
    elif args.cmd == "eval":
        rows = evaluate(args.pcap_dir, sens=args.sensitivity)
        print("%-16s %4s %4s %4s  %5s %5s" % ("detector", "tp", "fp", "fn", "prec", "rec"))
        for r in rows:
            print("%-16s %4d %4d %4d  %5.2f %5.2f" %
                  (r["detector"], r["tp"], r["fp"], r["fn"], r["precision"], r["recall"]))


if __name__ == "__main__":
    main()
