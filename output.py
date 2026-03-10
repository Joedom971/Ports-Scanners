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
    # Aiguille vers la fonction d'écriture selon l'extension du fichier
    if ext == ".json":
        _write_json(results, output_path)
    elif ext == ".csv":
        _write_csv(results, output_path)
    elif ext == ".html":
        _write_html(results, output_path, target, scan_type)
    else:
        # Par défaut : texte brut (.txt ou extension inconnue)
        _write_txt(results, output_path)


def _write_txt(results: Dict[int, dict], path: Path) -> None:
    """Écrit les résultats en texte brut, un port par ligne."""
    with path.open("w", encoding="utf-8") as f:
        # sorted() trie les ports par ordre croissant
        for port, info in sorted(results.items()):
            version_str = f"  [{info['version']}]" if info.get("version") else ""
            f.write(f"{port:5d}: {info['status']}  {info['service']}  {info['banner']}{version_str}\n")


def _write_json(results: Dict[int, dict], path: Path) -> None:
    """Écrit les résultats en JSON structuré."""
    with path.open("w", encoding="utf-8") as f:
        # Les clés JSON doivent être des chaînes → conversion str(p)
        json.dump({str(p): info for p, info in results.items()}, f, indent=2)


def _write_csv(results: Dict[int, dict], path: Path) -> None:
    """Écrit les résultats en CSV (compatible Excel/tableur)."""
    with path.open("w", encoding="utf-8", newline="") as f:
        # DictWriter génère automatiquement les en-têtes et les lignes
        writer = csv.DictWriter(f, fieldnames=["port", "status", "service", "banner", "version"])
        writer.writeheader()
        for port, info in sorted(results.items()):
            writer.writerow({"port": port, "status": info["status"], "service": info["service"],
                             "banner": info["banner"], "version": info.get("version", "")})


def _write_html(results: Dict[int, dict], path: Path, target: str, scan_type: str) -> None:
    """Génère un rapport HTML coloré avec tableau et statistiques."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Comptage des ports par statut pour les statistiques
    counts = {"open": 0, "closed": 0, "filtered": 0}
    for info in results.values():
        counts[info["status"]] = counts.get(info["status"], 0) + 1

    # Couleurs associées à chaque statut (vert = ouvert, rouge = fermé, gris = filtré)
    color_map = {"open": "#2ecc71", "closed": "#e74c3c", "filtered": "#95a5a6"}

    # html_lib.escape() protège contre les injections HTML en échappant <, >, &, "
    safe_target = html_lib.escape(target)
    safe_scan_type = html_lib.escape(scan_type)

    # Construction des lignes du tableau HTML
    rows = ""
    for port, info in sorted(results.items()):
        color = color_map.get(info["status"], "#fff")
        # La couleur est appliquée en fond transparent (22 = opacité 13% en hexadécimal)
        rows += (
            f"<tr style='background:{color}22'>"
            f"<td>{port}</td>"
            f"<td>{html_lib.escape(info['service'])}</td>"
            f"<td style='color:{color};font-weight:bold'>{html_lib.escape(info['status'])}</td>"
            f"<td>{html_lib.escape(info['banner']) if info['banner'] else '—'}</td>"
            f"<td>{html_lib.escape(info.get('version', '')) or '—'}</td>"
            f"</tr>\n"
        )

    # Template HTML complet avec CSS intégré (pas de dépendance externe)
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
<tr><th>Port</th><th>Service</th><th>Statut</th><th>Banner</th><th>Version</th></tr>
{rows}
</table>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")
