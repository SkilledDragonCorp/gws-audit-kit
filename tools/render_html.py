"""Render findings.json as a self-contained visual report (report.html).

Usage: python -I render_html.py <snapshot_dir> [--previous <snapshot_dir>]

The page has no external scripts, fonts or images, so it works offline and sends nothing anywhere.
It contains the same sensitive details as gap-report.md: keep it with the snapshot.
"""
import argparse
import collections
import html
import json
import os
import sys

SEVERITIES = ("critical", "high", "medium", "low", "info")
LABELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}

CSS = """
:root { --bg:#f7f7f5; --card:#fff; --text:#1d1d1b; --muted:#6b6b66; --line:#e3e2dd;
  --critical:#b42318; --high:#d9480f; --medium:#c47f00; --low:#3b7d3b; --info:#3b6ea5; --pass:#2f7d4f; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#161615; --card:#1f1f1d; --text:#ecebe6; --muted:#a3a29b; --line:#33332f;
    --critical:#f97066; --high:#fd8a4b; --medium:#f5b83d; --low:#7cc47c; --info:#7fb0e8; --pass:#6fcf97; }
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
main { max-width:980px; margin:0 auto; padding:32px 16px 64px; }
h1 { font-size:26px; margin:0 0 4px; } h2 { font-size:18px; margin:36px 0 12px; }
.meta { color:var(--muted); margin:0 0 24px; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:12px; }
.tile { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px; }
.tile .n { font-size:30px; font-weight:700; } .tile .l { color:var(--muted); font-size:13px; }
.tile .d { font-size:12px; color:var(--muted); }
.bar { display:flex; height:14px; border-radius:7px; overflow:hidden; background:var(--line); margin:16px 0 6px; }
.bar span { display:block; height:100%; }
.legend { display:flex; flex-wrap:wrap; gap:14px; font-size:13px; color:var(--muted); }
.dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:5px; vertical-align:baseline; }
table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:10px; overflow:hidden; }
th, td { text-align:left; padding:8px 12px; border-bottom:1px solid var(--line); font-size:14px; }
th { color:var(--muted); font-weight:600; }
.cat-bar { display:flex; height:10px; min-width:120px; border-radius:5px; overflow:hidden; background:var(--line); }
.card { background:var(--card); border:1px solid var(--line); border-left:5px solid var(--sev); border-radius:10px; padding:14px 16px; margin:10px 0; }
.card h3 { margin:0 0 6px; font-size:16px; }
.pill { display:inline-block; font-size:12px; font-weight:600; color:#fff; background:var(--sev); border-radius:999px; padding:1px 9px; margin-right:6px; }
.tag { font-size:12px; color:var(--muted); }
.new { font-size:12px; font-weight:700; color:var(--critical); margin-left:6px; }
.card p { margin:6px 0; } .fix { font-weight:600; }
.note { color:var(--muted); font-size:13px; }
details { margin-top:6px; } summary { cursor:pointer; color:var(--muted); font-size:13px; }
details ul { margin:6px 0 0; padding-left:20px; font-size:13px; word-break:break-word; }
ul.plain { padding-left:20px; }
footer { margin-top:40px; color:var(--muted); font-size:12px; }
"""


def esc(value):
    return html.escape(str(value if value is not None else ""))


def load(folder):
    path = os.path.join(folder, "findings.json")
    if not os.path.exists(path):
        sys.exit(f"{path} not found: run analyze.py first")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def severity_bar(counts, total):
    parts = []
    for s in SEVERITIES:
        n = counts.get(s, 0)
        if n:
            parts.append(f'<span style="width:{100 * n / total:.2f}%;background:var(--{s})" title="{LABELS[s]}: {n}"></span>')
    return '<div class="bar">' + "".join(parts) + "</div>"


def render(cur, prev=None):
    findings = cur["findings"]
    counts = collections.Counter(f["severity"] for f in findings)
    total = max(len(findings), 1)
    prev_counts = collections.Counter(f["severity"] for f in prev["findings"]) if prev else None
    prev_ids = {f["id"] for f in prev["findings"]} if prev else set()
    resolved = [f for f in prev["findings"] if f["id"] not in {x["id"] for x in findings}] if prev else []

    out = ["<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
           "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
           f"<title>Workspace audit {esc(cur['snapshot_date'])}</title><style>{CSS}</style></head><body><main>",
           "<h1>Google Workspace security audit</h1>",
           f"<p class=\"meta\">Snapshot {esc(cur['snapshot_date'])} · {esc(cur.get('edition', 'unknown'))} edition"
           + (f" · compared with {esc(prev['snapshot_date'])}" if prev else "") + "</p>"]

    out.append('<div class="tiles">')
    for s in SEVERITIES:
        delta = ""
        if prev_counts is not None:
            d = counts.get(s, 0) - prev_counts.get(s, 0)
            delta = f'<div class="d">{"+" if d > 0 else ""}{d} since last</div>' if d else '<div class="d">no change</div>'
        out.append(f'<div class="tile" style="border-top:4px solid var(--{s})"><div class="n">{counts.get(s, 0)}</div>'
                   f'<div class="l">{LABELS[s]}</div>{delta}</div>')
    out.append(f'<div class="tile" style="border-top:4px solid var(--pass)"><div class="n">{len(cur["passed"])}</div>'
               '<div class="l">Already good</div></div></div>')
    out.append(severity_bar(counts, total))
    out.append('<div class="legend">' + "".join(
        f'<span><span class="dot" style="background:var(--{s})"></span>{LABELS[s]}</span>' for s in SEVERITIES) + "</div>")

    by_cat = collections.defaultdict(collections.Counter)
    for f in findings:
        by_cat[f["category"]][f["severity"]] += 1
    for p in cur["passed"]:
        by_cat[p["category"]]["pass"] += 1
    out.append("<h2>By area</h2><table><tr><th>Area</th><th>Open</th><th>Good</th><th></th></tr>")
    for cat in sorted(by_cat, key=lambda c: (-sum(v for k, v in by_cat[c].items() if k != "pass"), c)):
        c = by_cat[cat]
        open_n = sum(v for k, v in c.items() if k != "pass")
        width = open_n + c["pass"] or 1
        segs = "".join(f'<span style="width:{100 * c[s] / width:.2f}%;background:var(--{s})"></span>'
                       for s in SEVERITIES if c[s])
        segs += f'<span style="width:{100 * c["pass"] / width:.2f}%;background:var(--pass)"></span>' if c["pass"] else ""
        out.append(f"<tr><td>{esc(cat)}</td><td>{open_n}</td><td>{c['pass']}</td>"
                   f'<td><div class="cat-bar">{segs}</div></td></tr>')
    out.append("</table>")

    if prev:
        new = [f for f in findings if f["id"] not in prev_ids]
        out.append("<h2>Since last time</h2><ul class=\"plain\">")
        out.append(f"<li><strong>{len(new)}</strong> new finding(s)"
                   + (": " + ", ".join(esc(f["title"]) for f in new) if new else "") + "</li>")
        out.append(f"<li><strong>{len(resolved)}</strong> resolved"
                   + (": " + ", ".join(esc(f["title"]) for f in resolved) if resolved else "") + "</li></ul>")

    out.append("<h2>Findings</h2>")
    for i, f in enumerate(findings, 1):
        s = f["severity"]
        badge = '<span class="new">NEW</span>' if prev and f["id"] not in prev_ids else ""
        out.append(f'<div class="card" style="--sev:var(--{s})"><h3>{i}. {esc(f["title"])}{badge}</h3>'
                   f'<span class="pill">{LABELS[s]}</span><span class="tag">{esc(f["category"])}</span>'
                   f'<p>{esc(f["detail"])}</p><p class="fix">Fix: {esc(f["recommendation"])}</p>')
        if f.get("edition_note"):
            out.append(f'<p class="note">Edition note: {esc(f["edition_note"])}</p>')
        if f.get("evidence"):
            more = f["evidence_total"] - len(f["evidence"])
            out.append(f'<details><summary>Evidence ({f["evidence_total"]})</summary><ul>'
                       + "".join(f"<li>{esc(e)}</li>" for e in f["evidence"])
                       + (f"<li>… and {more} more (see gap-report.md / CSVs)</li>" if more > 0 else "")
                       + "</ul></details>")
        if f.get("reference"):
            out.append(f'<p class="note">{esc(f["reference"])}</p>')
        out.append("</div>")

    if cur["passed"]:
        out.append("<h2>Already good</h2><ul class=\"plain\">"
                   + "".join(f"<li>{esc(p['title'])}</li>" for p in cur["passed"]) + "</ul>")
    if cur.get("not_checked"):
        out.append("<h2>Not checked (input missing)</h2><ul class=\"plain\">"
                   + "".join(f"<li>{esc(n)}</li>" for n in cur["not_checked"]) + "</ul>")
    out.append("<footer>Generated locally by gws-audit-kit. Contains sensitive tenant details: "
               "keep it with the snapshot and don't upload it.</footer></main></body></html>")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("snapshot_dir")
    parser.add_argument("--previous", help="earlier snapshot folder, to show changes")
    args = parser.parse_args()
    page = render(load(args.snapshot_dir), load(args.previous) if args.previous else None)
    path = os.path.join(args.snapshot_dir, "report.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(page)
    print(path)


if __name__ == "__main__":
    main()
