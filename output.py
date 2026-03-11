"""Fonctions d'export des résultats de scan."""

import csv
import html as html_lib
import json
import xml.etree.ElementTree as ET
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
    elif ext == ".xml":
        _write_xml(results, output_path, target, scan_type)
    elif ext == ".html":
        _write_html(results, output_path, target, scan_type)
    else:
        _write_txt(results, output_path)


def _write_txt(results: Dict[int, dict], path: Path) -> None:
    """Écrit les résultats en texte brut, un port par ligne."""
    with path.open("w", encoding="utf-8") as f:
        for port, info in sorted(results.items()):
            version_str = f"  [{info['version']}]" if info.get("version") else ""
            fw_str = f" ({info['firewall']})" if info.get("firewall") else ""
            vuln_str = f"  [!] {len(info.get('vulns', []))} CVE(s)" if info.get("vulns") else ""
            
            f.write(f"{port:5d}: {info['status']}{fw_str}  {info['service']}  {info['banner']}{version_str}{vuln_str}\n")
            # Ajout du détail des vulnérabilités
            for vuln in info.get("vulns", []):
                f.write(f"       -> {vuln['id']} (CVSS: {vuln['cvss']}): {vuln['description']}\n")


def _write_json(results: Dict[int, dict], path: Path) -> None:
    """Écrit les résultats en JSON structuré."""
    with path.open("w", encoding="utf-8") as f:
        json.dump({str(p): info for p, info in results.items()}, f, indent=2)


def _write_csv(results: Dict[int, dict], path: Path) -> None:
    """Écrit les résultats en CSV (compatible Excel/tableur)."""
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["port", "status", "service", "banner", "os", "version", "firewall", "vulns"])
        writer.writeheader()
        for port, info in sorted(results.items()):
            # Formate les vulns sous forme de liste de CVE séparées par des virgules
            vulns_str = ", ".join([v["id"] for v in info.get("vulns", [])])
            
            writer.writerow({
                "port": port,
                "status": info["status"],
                "service": info["service"],
                "banner": info["banner"],
                "os": info.get("os", ""),
                "version": info.get("version", ""),
                "firewall": info.get("firewall", ""),
                "vulns": vulns_str,
            })


def _write_xml(results: Dict[int, dict], path: Path, target: str, scan_type: str) -> None:
    """Génère un rapport XML compatible avec le format Nmap/Metasploit."""
    root = ET.Element("nmaprun", scanner="port-scanner", target=target, type=scan_type)
    host_elem = ET.SubElement(root, "host")
    ET.SubElement(host_elem, "address", addr=target, addrtype="ipv4")
    ports_elem = ET.SubElement(host_elem, "ports")

    for port, info in sorted(results.items()):
        port_elem = ET.SubElement(ports_elem, "port", protocol="tcp", portid=str(port))
        ET.SubElement(port_elem, "state", state=info.get("status", "unknown"))

        svc_attrs: dict = {"name": info.get("service", "")}
        if info.get("version"):
            svc_attrs["version"] = info["version"]
        if info.get("banner"):
            svc_attrs["banner"] = info["banner"]
        ET.SubElement(port_elem, "service", **svc_attrs)

        if info.get("firewall"):
            ET.SubElement(port_elem, "firewall", type=info["firewall"])
            
        # Ajout des vulnérabilités dans le XML
        vulns = info.get("vulns", [])
        if vulns:
            vulns_elem = ET.SubElement(port_elem, "vulnerabilities")
            for vuln in vulns:
                ET.SubElement(vulns_elem, "cve", id=vuln["id"], cvss=str(vuln["cvss"]))

    ET.indent(root, space="  ")
    tree = ET.ElementTree(root)
    tree.write(str(path), encoding="utf-8", xml_declaration=True)


def _write_html(results: Dict[int, dict], path: Path, target: str, scan_type: str) -> None:
    """Génère un rapport HTML coloré avec tableau et statistiques."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    counts = {"open": 0, "closed": 0, "filtered": 0}
    vuln_count = 0
    for info in results.values():
        counts[info["status"]] = counts.get(info["status"], 0) + 1
        vuln_count += len(info.get("vulns", []))

    color_map = {"open": "#2ecc71", "closed": "#e74c3c", "filtered": "#95a5a6"}
    safe_target = html_lib.escape(target)
    safe_scan_type = html_lib.escape(scan_type)

    rows = ""
    for port, info in sorted(results.items()):
        color = color_map.get(info["status"], "#fff")
        
        # Formatage des vulnérabilités avec des badges HTML
        vulns_html = "—"
        vulns_list = info.get("vulns", [])
        if vulns_list:
            badges = []
            for v in vulns_list:
                # Ajoute un tooltip (title) avec la description de la CVE
                safe_desc = html_lib.escape(v["description"])
                badges.append(f"<span class='cve-badge' title='{safe_desc}'>{v['id']} ({v['cvss']})</span>")
            vulns_html = "<br>".join(badges)

        rows += (
            f"<tr style='background:{color}22'>"
            f"<td>{port}</td>"
            f"<td>{html_lib.escape(info['service'])}</td>"
            f"<td style='color:{color};font-weight:bold'>{html_lib.escape(info['status'])}</td>"
            f"<td>{html_lib.escape(info['banner']) if info['banner'] else '—'}</td>"
            f"<td>{html_lib.escape(info.get('version', '')) or '—'}</td>"
            f"<td>{html_lib.escape(info.get('firewall', '')) or '—'}</td>"
            f"<td>{vulns_html}</td>"
            f"</tr>\n"
        )

    # Style CSS mis à jour pour inclure les badges CVE
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><title>Scan — {safe_target}</title>
<style>
  body {{ font-family: monospace; background: #1a1a2e; color: #eee; padding: 2rem; }}
  h1 {{ color: #00d4ff; }}
  .meta {{ color: #aaa; margin-bottom: 1rem; }}
  .stats {{ margin-bottom: 1rem; }}
  .stat-open {{ color: #2ecc71; }} .stat-closed {{ color: #e74c3c; }} .stat-filtered {{ color: #95a5a6; }}
  .stat-vuln {{ color: #ff4757; font-weight: bold; margin-left: 15px; border: 1px solid #ff4757; padding: 2px 6px; border-radius: 4px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th {{ background: #16213e; padding: 8px 12px; text-align: left; }}
  td {{ padding: 6px 12px; border-bottom: 1px solid #333; vertical-align: top; }}
  .cve-badge {{ display: inline-block; background: #ff4757; color: white; padding: 2px 6px; margin: 2px 0; border-radius: 3px; font-size: 0.85em; cursor: help; }}
</style>
</head>
<body>
<h1>Rapport de scan</h1>
<div class="meta">Cible : <strong>{safe_target}</strong> | Type : {safe_scan_type} | Date : {now}</div>
<div class="stats">
  <span class="stat-open">open: {counts['open']}</span> &nbsp;
  <span class="stat-closed">closed: {counts['closed']}</span> &nbsp;
  <span class="stat-filtered">filtered: {counts['filtered']}</span>
  {f'<span class="stat-vuln">⚠ {vuln_count} CVE(s) détectée(s)</span>' if vuln_count > 0 else ''}
</div>
<table>
<tr><th>Port</th><th>Service</th><th>Statut</th><th>Banner</th><th>Version</th><th>Firewall</th><th>Vulnérabilités</th></tr>
{rows}
</table>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")