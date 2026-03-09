# output.py
"""Fonctions d'export des résultats de scan."""

import csv
import html as html_lib
import json
from datetime import datetime
from pathlib import Path
from typing import Dict


def write_output(results: Dict[int, dict], output_path: Path, target: str, scan_type: str) -> None:
    """Écrit les résultats dans le format correspondant à l'extension du fichier."""
    ext = output_path.suffix.lower()
    if ext == ".json":
        _write_json(results, output_path)
    elif ext == ".csv":
        _write_csv(results, output_path)
    elif ext == ".html":
        _write_html(results, output_path, target, scan_type)
    else:
        _write_txt(results, output_path)


def _write_txt(results: Dict[int, dict], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        for port, info in sorted(results.items()):
            f.write(f"{port:5d}: {info['status']}  {info['service']}  {info['banner']}\n")


def _write_json(results: Dict[int, dict], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump({str(p): info for p, info in results.items()}, f, indent=2)


def _write_csv(results: Dict[int, dict], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["port", "status", "service", "banner"])
        writer.writeheader()
        for port, info in sorted(results.items()):
            writer.writerow({"port": port, **info})


def _write_html(results: Dict[int, dict], path: Path, target: str, scan_type: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = {"open": 0, "closed": 0, "filtered": 0}
    for info in results.values():
        counts[info["status"]] = counts.get(info["status"], 0) + 1

    color_map = {"open": "#2ecc71", "closed": "#e74c3c", "filtered": "#95a5a6"}

    safe_target = html_lib.escape(target)
    safe_scan_type = html_lib.escape(scan_type)

    rows = ""
    for port, info in sorted(results.items()):
        color = color_map.get(info["status"], "#fff")
        rows += (
            f"<tr style='background:{color}22'>"
            f"<td>{port}</td>"
            f"<td>{html_lib.escape(info['service'])}</td>"
            f"<td style='color:{color};font-weight:bold'>{html_lib.escape(info['status'])}</td>"
            f"<td>{html_lib.escape(info['banner']) if info['banner'] else '—'}</td>"
            f"</tr>\n"
        )

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><title>Scan — {safe_target}</title>
<style>
  body {{ font-family: monospace; background: #1a1a2e; color: #eee; padding: 2rem; }}
  h1 {{ color: #00d4ff; }}
  .meta {{ color: #aaa; margin-bottom: 1rem; }}
  .stats {{ margin-bottom: 1rem; }}
  .stat-open {{ color: #2ecc71; }} .stat-closed {{ color: #e74c3c; }} .stat-filtered {{ color: #95a5a6; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th {{ background: #16213e; padding: 8px 12px; text-align: left; }}
  td {{ padding: 6px 12px; border-bottom: 1px solid #333; }}
</style>
</head>
<body>
<h1>Rapport de scan</h1>
<div class="meta">Cible : <strong>{safe_target}</strong> | Type : {safe_scan_type} | Date : {now}</div>
<div class="stats">
  <span class="stat-open">open: {counts['open']}</span> &nbsp;
  <span class="stat-closed">closed: {counts['closed']}</span> &nbsp;
  <span class="stat-filtered">filtered: {counts['filtered']}</span>
</div>
<table>
<tr><th>Port</th><th>Service</th><th>Statut</th><th>Banner</th></tr>
{rows}
</table>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")
