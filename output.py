# output.py
"""Scan result export functions."""

import csv
import html as html_lib
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict


def write_output(results: Dict[int, dict], output_path: Path, target: str, scan_type: str) -> None:
    """Writes results in the format matching the file extension."""
    ext = output_path.suffix.lower()
    # Route to the appropriate write function based on the file extension
    if ext == ".json":
        _write_json(results, output_path)
    elif ext == ".csv":
        _write_csv(results, output_path)
    elif ext == ".xml":
        _write_xml(results, output_path, target, scan_type)
    elif ext == ".html":
        _write_html(results, output_path, target, scan_type)
    else:
        # Default: plain text (.txt or unknown extension)
        _write_txt(results, output_path)


def _write_txt(results: Dict[int, dict], path: Path) -> None:
    """Writes results as plain text, one port per line."""
    with path.open("w", encoding="utf-8") as f:
        # sorted() sorts ports in ascending order
        for port, info in sorted(results.items()):
            version_str = f"  [{info['version']}]" if info.get("version") else ""
            fw_str = f" ({info['firewall']})" if info.get("firewall") else ""
            vuln_str = f"  [!] {len(info.get('vulns', []))} CVE(s)" if info.get("vulns") else ""
            f.write(f"{port:5d}: {info['status']}{fw_str}  {info['service']}  {info['banner']}{version_str}{vuln_str}\n")
            for vuln in info.get("vulns", []):
                f.write(f"       -> {vuln['id']} (CVSS: {vuln['cvss']}): {vuln['description']}\n")


def _write_json(results: Dict[int, dict], path: Path) -> None:
    """Writes results as structured JSON."""
    with path.open("w", encoding="utf-8") as f:
        # JSON keys must be strings → convert with str(p)
        json.dump({str(p): info for p, info in results.items()}, f, indent=2)


def _write_csv(results: Dict[int, dict], path: Path) -> None:
    """Writes results as CSV (Excel/spreadsheet compatible)."""
    with path.open("w", encoding="utf-8", newline="") as f:
        # DictWriter automatically generates headers and rows
        writer = csv.DictWriter(f, fieldnames=["port", "status", "service", "banner", "os", "version", "firewall", "vulns"])
        writer.writeheader()
        for port, info in sorted(results.items()):
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
    """Generates an XML report compatible with the Nmap/Metasploit format.

    Structure:
      <nmaprun scanner="port-scanner" target="..." type="...">
        <host>
          <address addr="..." addrtype="ipv4"/>
          <ports>
            <port protocol="tcp" portid="22">
              <state state="open"/>
              <service name="ssh" version="..." banner="..."/>
              <firewall type="..."/>  <!-- only if present -->
            </port>
          </ports>
        </host>
      </nmaprun>
    """
    root = ET.Element("nmaprun", scanner="port-scanner", target=target, type=scan_type)
    host_elem = ET.SubElement(root, "host")
    ET.SubElement(host_elem, "address", addr=target, addrtype="ipv4")
    ports_elem = ET.SubElement(host_elem, "ports")

    for port, info in sorted(results.items()):
        port_elem = ET.SubElement(ports_elem, "port", protocol="tcp", portid=str(port))
        ET.SubElement(port_elem, "state", state=info.get("status", "unknown"))

        # Service attributes: name is mandatory, version and banner are optional
        svc_attrs: dict = {"name": info.get("service", "")}
        if info.get("version"):
            svc_attrs["version"] = info["version"]
        if info.get("banner"):
            svc_attrs["banner"] = info["banner"]
        ET.SubElement(port_elem, "service", **svc_attrs)

        # Firewall element only if a filtering type was detected
        if info.get("firewall"):
            ET.SubElement(port_elem, "firewall", type=info["firewall"])

        # Vulnerability elements
        vulns = info.get("vulns", [])
        if vulns:
            vulns_elem = ET.SubElement(port_elem, "vulnerabilities")
            for vuln in vulns:
                ET.SubElement(vulns_elem, "cve", id=vuln["id"], cvss=str(vuln["cvss"]))

    # ET.indent() adds human-readable indentation (Python 3.9+)
    ET.indent(root, space="  ")
    tree = ET.ElementTree(root)
    tree.write(str(path), encoding="utf-8", xml_declaration=True)


def _write_html(results: Dict[int, dict], path: Path, target: str, scan_type: str) -> None:
    """Generates a coloured HTML report with a table and statistics."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Count ports by status for the statistics section
    counts = {"open": 0, "closed": 0, "filtered": 0}
    vuln_count = 0
    for info in results.values():
        counts[info["status"]] = counts.get(info["status"], 0) + 1
        vuln_count += len(info.get("vulns", []))

    # Colours associated with each status (green = open, red = closed, grey = filtered)
    color_map = {"open": "#2ecc71", "closed": "#e74c3c", "filtered": "#95a5a6"}

    # html_lib.escape() protects against HTML injection by escaping <, >, &, "
    safe_target = html_lib.escape(target)
    safe_scan_type = html_lib.escape(scan_type)

    # Build the HTML table rows
    rows = ""
    for port, info in sorted(results.items()):
        color = color_map.get(info["status"], "#fff")
        # Build vulnerability badges for this port
        vulns_html = "—"
        vulns_list = info.get("vulns", [])
        if vulns_list:
            badges = []
            for v in vulns_list:
                safe_desc = html_lib.escape(v["description"])
                badges.append(f"<span class='cve-badge' title='{safe_desc}'>{v['id']} ({v['cvss']})</span>")
            vulns_html = "<br>".join(badges)

        # The colour is applied as a transparent background (22 = 13% opacity in hexadecimal)
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

    # Full HTML template with embedded CSS (no external dependency)
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
  {f'<span class="stat-vuln">⚠ {vuln_count} CVE(s) detected</span>' if vuln_count > 0 else ''}
</div>
<table>
<tr><th>Port</th><th>Service</th><th>Statut</th><th>Banner</th><th>Version</th><th>Firewall</th><th>Vulnerabilities</th></tr>
{rows}
</table>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")


# --- FEATURE  : STATISTIK GENERATOR ---
def print_summary(all_results: Dict[str, Dict[int, dict]], elapsed: float) -> None:
    """Prints an analytical scan summary to the console.

    Calculates and displays:
      - the total number of (host, port) pairs scanned
      - the open / closed / filtered breakdown (all variants combined)
      - the firewall-silent and firewall-active detail if available
      - the percentage of open ports
      - the execution time

    Args:
        all_results: host -> port -> info dictionary (supports single and multi-host scans).
        elapsed: scan duration in seconds (time.time() end - time.time() start).
    """
    # Flatten all port info dicts across all hosts into a single list.
    # This correctly counts every (host, port) pair without overwriting duplicates.
    all_infos = []
    for host_results in all_results.values():
        for info in host_results.values():
            all_infos.append(info)

    # Count ports by status
    open_count = 0
    for info in all_infos:
        if info["status"] == "open":
            open_count += 1

    closed_count = 0
    for info in all_infos:
        if info["status"] == "closed":
            closed_count += 1

    # Count filtered ports — status is always "filtered" from the scanner.
    # The firewall type detail (silent/active) is stored in info["firewall"], not info["status"].
    filtered_count = 0
    for info in all_infos:
        if info["status"] == "filtered":
            filtered_count += 1

    # Filtering type detail (the "firewall" field is only populated with --firewall-detect)
    firewall_silent = 0
    firewall_active = 0
    for info in all_infos:
        firewall = info.get("firewall", "")  # "" if --firewall-detect not enabled
        if firewall == "filtered-silent":
            firewall_silent += 1
        elif firewall == "filtered-active":
            firewall_active += 1

    total = len(all_infos)  # total number of (host, port) pairs scanned

    # Percentage of open ports — guard against division by zero
    pourcentage = (open_count / total * 100) if total > 0 else 0.0

    print("\n--- Résumé du Scan ---")
    print(f"  Ports scannés   : {total}")
    print(f"  Ports ouverts   : {open_count}")
    print(f"  Ports fermés    : {closed_count}")
    print(f"  Ports filtrés   : {filtered_count}", end="")
    # Display the silent/active detail only if firewall data is available
    if firewall_silent or firewall_active:
        print(f"  (silent: {firewall_silent}, active: {firewall_active})", end="")
    print()
    print(f"  Taux d'ouverts  : {pourcentage:.2f}%")
    print(f"  Temps d'exécut. : {elapsed:.2f} secondes")
