"""Report renderers: console (ANSI), JSON, CSV, self-contained HTML."""
import csv
import io
import json
from dataclasses import asdict
from xml.sax.saxutils import escape as esc

from ..checks.base import Status
from ..utils.helpers import BOLD, CYAN, GREY, YELLOW, colorize

_STYLE = {Status.PASS: "\033[92m", Status.FAIL: "\033[91m", Status.WARN: "\033[93m",
          Status.ERROR: "\033[91m", Status.SKIP: "\033[90m"}


def to_console(rep):
    W, out = 78, []
    bar = "═" * W
    out.append(colorize(bar, CYAN))
    out.append(colorize(" ESHF — Endpoint Security Hardening Framework", BOLD))
    out.append(f" Baseline : {rep.baseline_name}")
    out.append(f" Host     : {rep.target}")
    out.append(f" Date     : {rep.timestamp}    Checks: {len(rep.results)}    "
               f"Duration: {rep.duration:.2f}s")
    out.append(colorize(bar, CYAN))

    last_cat = None
    for r in sorted(rep.results, key=lambda x: (x.category, x.check_id)):
        if r.category != last_cat:
            out.append("")
            out.append(colorize(f" {r.category.upper()}", CYAN))
            last_cat = r.category
        out.append(f" {colorize(f'{r.status.value:<5}', _STYLE[r.status])} "
                   f"{r.check_id}  {r.title}")
        if r.message:
            out.append(colorize(f"        ↳ {r.message[:110]}", GREY))

    s = rep.summary
    out += ["", colorize("─" * W, CYAN),
            f" PASS {s['passed']} | FAIL {s['failed']} | WARN {s['warnings']} | "
            f"ERROR {s['errors']} | SKIP {s['skipped']}",
            colorize(f" Score    : {s['score']}/100   Grade: {s['grade']}",
                     BOLD if s["score"] >= 80 else YELLOW)]
    fails = [r for r in rep.results if r.status == Status.FAIL and r.remediation]
    if fails:
        out.append(colorize(" Suggested fixes:", BOLD))
        out += [colorize(f"  - {r.check_id}: {r.remediation[:100]}", GREY) for r in fails]
    out.append(colorize(bar, CYAN))
    return "\n".join(out)


def to_json(rep):
    payload = {
        "framework": "ESHF",
        "baseline": rep.baseline_name,
        "target": rep.target,
        "timestamp": rep.timestamp,
        "duration_seconds": round(rep.duration, 2),
        "summary": rep.summary,
        "results": [],
    }
    for r in rep.results:
        d = asdict(r)
        d["status"] = r.status.value
        payload["results"].append(d)
    return json.dumps(payload, indent=2)


def to_csv(rep):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["check_id", "title", "category", "severity", "status",
                "actual", "message", "remediation"])
    for r in rep.results:
        w.writerow([r.check_id, r.title, r.category, r.severity,
                    r.status.value, r.actual, r.message, r.remediation])
    return buf.getvalue()


def to_html(rep):
    color = {"PASS": "#15803d", "FAIL": "#b91c1c", "WARN": "#b45309",
             "ERROR": "#7e22ce", "SKIP": "#6b7280"}
    rows = []
    for r in sorted(rep.results, key=lambda x: (x.category, x.check_id)):
        rows.append(
            f"<tr><td>{esc(r.check_id)}</td><td>{esc(r.title)}</td>"
            f"<td>{esc(r.category)}</td><td>{esc(r.severity)}</td>"
            f"<td style='color:{color[r.status.value]};font-weight:700'>{r.status.value}</td>"
            f"<td>{esc(r.message or r.actual)}</td></tr>")
    s = rep.summary
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>ESHF Report</title>
<style>
 body{{font-family:system-ui,sans-serif;margin:2rem;color:#111}}
 table{{border-collapse:collapse;width:100%;font-size:.9rem}}
 th,td{{border:1px solid #e5e7eb;padding:.45rem .6rem;text-align:left;vertical-align:top}}
 th{{background:#f3f4f6}}
 .meta{{color:#6b7280;font-size:.9rem}}
 .score{{font-size:1.3rem;font-weight:700;margin:1rem 0}}
</style></head><body>
<h1>ESHF Compliance Report</h1>
<p class="meta">Baseline: {esc(rep.baseline_name)} &nbsp;|&nbsp; Host: {esc(rep.target)} &nbsp;|&nbsp; {esc(rep.timestamp)}</p>
<p class="score">Score: {s['score']}/100 (grade {s['grade']}) — {s['passed']} passed, {s['failed']} failed, {s['warnings']} warnings, {s['errors']} errors, {s['skipped']} skipped</p>
<table><tr><th>ID</th><th>Check</th><th>Category</th><th>Severity</th><th>Status</th><th>Detail</th></tr>
{''.join(rows)}
</table></body></html>"""


def write(rep, fmt, path):
    renderers = {"json": to_json, "csv": to_csv, "html": to_html}
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(renderers[fmt](rep))
