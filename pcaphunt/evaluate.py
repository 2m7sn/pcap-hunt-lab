"""Per-detector precision/recall against ground truth on a generated set.

If the set directory holds an allowlist.toml it is passed to the detectors."""
import json
import os

from .analyze import Capture
from . import detectors as D

DETECTORS = [fn.__name__ for fn in D.ALL]


def evaluate(pcap_dir, sens="default"):
    manifest = json.load(open(os.path.join(pcap_dir, "ground-truth.json")))
    cfg_path = os.path.join(pcap_dir, "allowlist.toml")
    cfg = D.load_config(cfg_path) if os.path.exists(cfg_path) else None
    stats = {d: {"tp": 0, "fp": 0, "fn": 0} for d in DETECTORS}
    for item in manifest:
        cap = Capture(os.path.join(pcap_dir, item["pcap"]))
        alerts = D.run_all(cap, cfg, sens)
        for d in DETECTORS:
            truth = {t["entity"] for t in item["truth"] if t["detector"] == d}
            found = {a["entity"] for a in alerts if a["detector"] == d}
            stats[d]["tp"] += len(truth & found)
            stats[d]["fp"] += len(found - truth)
            stats[d]["fn"] += len(truth - found)
    rows = []
    for d in DETECTORS:
        s = stats[d]
        prec = s["tp"] / (s["tp"] + s["fp"]) if (s["tp"] + s["fp"]) else 1.0
        rec = s["tp"] / (s["tp"] + s["fn"]) if (s["tp"] + s["fn"]) else 1.0
        rows.append({"detector": d, **s, "precision": round(prec, 3), "recall": round(rec, 3)})
    return rows


if __name__ == "__main__":
    import sys
    for r in evaluate(sys.argv[1] if len(sys.argv) > 1 else "pcaps"):
        print("%-16s tp=%d fp=%d fn=%d  P=%.2f R=%.2f" %
              (r["detector"], r["tp"], r["fp"], r["fn"], r["precision"], r["recall"]))
