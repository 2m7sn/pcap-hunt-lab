"""Static HTML hunt report: top talkers, alerts with evidence, beacon timing SVG.
Plain network-engineer style: dense tables, no tiles/pills/gradients/emoji."""
import html
import json
import os

ACCENT = "#a68af9"
BG = "#262626"


def _esc(x):
    return html.escape(str(x))


def _top_talkers(cap, n=12):
    tx = {}
    for p in cap.packets:
        tx[p["src"]] = tx.get(p["src"], [0, 0])
        tx[p["src"]][0] += 1
        tx[p["src"]][1] += p["length"]
    rows = sorted(tx.items(), key=lambda kv: kv[1][1], reverse=True)[:n]
    return rows


def _beacon_svg(cap, alerts):
    pairs = [a["entity"] for a in alerts if a["detector"] == "beacon"]
    if not pairs:
        return ""
    import pcaphunt.detectors as D
    series = {}
    for f in cap.flows.values():
        if f.service in ("ssl", "http") and not D._internal(f.resp_h):
            series.setdefault("%s->%s" % (f.orig_h, f.resp_h), []).append(f.ts)
    svgs = []
    W, H, pad = 680, 54, 8
    for ent in pairs:
        ts = sorted(series.get(ent, []))
        if len(ts) < 2:
            continue
        t0, t1 = ts[0], ts[-1]
        span = (t1 - t0) or 1
        ticks = "".join(
            '<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="%s" stroke-width="2"/>'
            % (pad + (t - t0) / span * (W - 2 * pad), pad, pad + (t - t0) / span * (W - 2 * pad), H - pad, ACCENT)
            for t in ts)
        svgs.append(
            '<figure><figcaption>%s &mdash; %d connections over %.0f s</figcaption>'
            '<svg viewBox="0 0 %d %d" width="100%%" role="img" aria-label="beacon timing for %s">'
            '<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#555" stroke-width="1"/>%s</svg></figure>'
            % (_esc(ent), len(ts), span, W, H, _esc(ent), pad, H // 2, W - pad, H // 2, ticks))
    return "\n".join(svgs)


def _flows_table(cap, n=25):
    rows = sorted(cap.conn_log(), key=lambda r: r["orig_bytes"] + r["resp_bytes"], reverse=True)[:n]
    body = "".join(
        "<tr><td>%s</td><td>%s:%d</td><td>%s:%d</td><td>%s</td><td>%s</td><td class=num>%d</td>"
        "<td class=num>%d</td><td>%s</td></tr>"
        % (_esc(r["uid"]), _esc(r["id.orig_h"]), r["id.orig_p"], _esc(r["id.resp_h"]), r["id.resp_p"],
           _esc(r["proto"]), _esc(r["service"] or "-"), r["orig_bytes"], r["resp_bytes"], _esc(r["conn_state"]))
        for r in rows)
    return body


def build_report(cap, alerts, out_path, title="PCAP Hunt Lab report"):
    talkers = _top_talkers(cap)
    span = (cap.last_ts - cap.first_ts) if cap.first_ts else 0
    alert_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=ev>%s</td></tr>"
        % (_esc(a["detector"]), _esc(a["entity"]), _esc(a["technique"]), _esc(a["summary"]),
           _esc(json.dumps(a["evidence"])))
        for a in alerts)
    talker_rows = "".join(
        "<tr><td>%s</td><td class=num>%d</td><td class=num>%d</td></tr>" % (_esc(ip), v[0], v[1])
        for ip, v in talkers)
    doc = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:{bg}; color:#d6d6d6; margin:0;
    font:14px/1.5 ui-monospace,"Cascadia Code",Menlo,Consolas,monospace; }}
  main {{ max-width:860px; margin:0 auto; padding:20px 16px 60px; }}
  h1 {{ font-size:18px; margin:0 0 2px; color:#f0f0f0; }}
  h2 {{ font-size:14px; margin:28px 0 8px; color:#f0f0f0;
    border-bottom:1px solid #3a3a3a; padding-bottom:4px; }}
  p.meta {{ color:#8f8f8f; margin:0 0 4px; }}
  table {{ border-collapse:collapse; width:100%; font-size:13px; }}
  .tw {{ overflow-x:auto; }}
  th,td {{ text-align:left; padding:4px 8px; border-bottom:1px solid #333; vertical-align:top; }}
  td {{ word-break:break-word; }}
  th {{ color:#9f9f9f; font-weight:600; white-space:nowrap; }}
  td.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  td.ev {{ color:#9f9f9f; font-size:12px; }}
  tr td:first-child {{ color:{accent}; }}
  figure {{ margin:10px 0; }}
  figcaption {{ color:#8f8f8f; font-size:12px; margin-bottom:2px; }}
  a {{ color:{accent}; }}
  @media (max-width:420px) {{ main {{ padding:16px 12px; }} table {{ font-size:12px; }} th,td {{ padding:4px 5px; }} }}
</style></head><body><main>
<h1>{title}</h1>
<p class="meta">source: {src} &middot; {npkts} packets &middot; {nflows} flows &middot; {span:.0f}s window</p>
<p class="meta">{nalerts} alerts across {ndet} detectors</p>

<h2>Alerts</h2>
<div class="tw"><table><thead><tr><th>detector</th><th>entity</th><th>att&amp;ck</th><th>finding</th><th>evidence</th></tr></thead>
<tbody>{alerts}</tbody></table></div>

<h2>Beacon timing</h2>
{svg}

<h2>Top talkers (by bytes sent)</h2>
<div class="tw"><table><thead><tr><th>host</th><th>packets</th><th>bytes</th></tr></thead><tbody>{talkers}</tbody></table></div>

<h2>Largest flows</h2>
<div class="tw"><table><thead><tr><th>uid</th><th>orig</th><th>resp</th><th>proto</th><th>service</th>
<th>orig_bytes</th><th>resp_bytes</th><th>state</th></tr></thead><tbody>{flows}</tbody></table></div>
</main></body></html>
""".format(
        title=_esc(title), bg=BG, accent=ACCENT, src=_esc(os.path.basename(cap.path)),
        npkts=cap.frames, nflows=len(cap.flows), span=span, nalerts=len(alerts),
        ndet=len({a["detector"] for a in alerts}),
        alerts=alert_rows or "<tr><td colspan=5>none</td></tr>",
        svg=_beacon_svg(cap, alerts) or "<p class=meta>no beaconing detected</p>",
        talkers=talker_rows, flows=_flows_table(cap))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path
