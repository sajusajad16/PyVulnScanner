"""
utils/reporter.py
-----------------
Generates JSON and self-contained HTML scan reports.
"""

import json
import os
from datetime import datetime


REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")


def save_json_report(scan_result: dict, filename: str = None) -> str:
    """Save a scan result as a JSON file. Returns the file path."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    if not filename:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{scan_result.get('type','scan')}_{ts}.json"
    path = os.path.join(REPORTS_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(scan_result, f, indent=2, default=str)
    return path


def save_html_report(scan_result: dict, filename: str = None) -> str:
    """Generate a self-contained HTML report. Returns the file path."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    if not filename:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{scan_result.get('type','scan')}_{ts}.html"
    path = os.path.join(REPORTS_DIR, filename)

    score   = scan_result.get("risk_score", 0)
    verdict = scan_result.get("verdict",    "Unknown")
    color_map = {"Safe": "#22c55e", "Suspicious": "#f97316", "Phishing": "#ef4444"}
    color = color_map.get(verdict, "#6b7280")

    issues_html = "".join(
        f"<li>{iss}</li>" for iss in scan_result.get("issues", ["No issues found"])
    )

    features_rows = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>"
        for k, v in scan_result.get("features", {}).items()
        if not isinstance(v, list)
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PhishGuard Scan Report</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 2rem; }}
  .card {{ background: #1e293b; border-radius: 12px; padding: 2rem; margin-bottom: 1.5rem; }}
  h1 {{ color: {color}; font-size: 2rem; margin: 0 0 0.5rem; }}
  .score {{ font-size: 4rem; font-weight: 800; color: {color}; }}
  .badge {{ display: inline-block; background: {color}; color: #fff; border-radius: 99px;
            padding: 0.3rem 1.2rem; font-weight: 700; font-size: 1.1rem; }}
  ul {{ padding-left: 1.5rem; line-height: 2; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ background: #334155; padding: 0.5rem 1rem; text-align: left; }}
  td {{ padding: 0.4rem 1rem; border-bottom: 1px solid #334155; }}
  .meta {{ color: #94a3b8; font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="card">
  <p class="meta">PhishGuard AI — Scan Report</p>
  <h1>🛡 {verdict}</h1>
  <div class="score">{score:.0f}<span style="font-size:1.5rem;color:#94a3b8">/100</span></div>
  <br>
  <span class="badge">{verdict}</span>
  <p class="meta">Scanned: {scan_result.get('scanned_at','N/A')} UTC | Type: {scan_result.get('type','N/A').upper()}</p>
  {'<p><b>Target:</b> <code>' + str(scan_result.get("target","")) + '</code></p>' if scan_result.get("target") else ""}
</div>

<div class="card">
  <h2>⚠️ Detected Issues</h2>
  <ul>{issues_html}</ul>
</div>

<div class="card">
  <h2>📊 Feature Details</h2>
  <table>
    <tr><th>Feature</th><th>Value</th></tr>
    {features_rows}
  </table>
</div>

<div class="card">
  <h2>📋 Raw JSON</h2>
  <pre style="background:#0f172a;padding:1rem;border-radius:8px;overflow:auto;font-size:0.8rem;">
{json.dumps(scan_result, indent=2, default=str)}
  </pre>
</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
