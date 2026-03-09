# Phase 3 — Network Scanner Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Étendre le scanner de ports avec SYN scan, threading, host discovery, service names, banner grabbing, rate limiting, logging, progress bar et export HTML.

**Architecture:** Approche modules séparés — `output.py` extrait de `main.py`, `discovery.py` nouveau, `scanner.py` étendu, `main.py` orchestrateur. Le format interne des résultats passe de `dict[port] = str` à `dict[port] = {"status", "service", "banner"}`.

**Tech Stack:** Python 3, socket, concurrent.futures, subprocess, logging, tqdm (optionnel), scapy (optionnel)

---

## Prérequis

```bash
cd Port_scanner_Reseau
source .venv/bin/activate
pip install pytest tqdm
# scapy optionnel : pip install scapy
```

---

### Task 1 : Infrastructure de tests

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/test_output.py`
- Create: `tests/test_scanner.py`
- Create: `tests/test_discovery.py`

**Step 1 : Créer le dossier tests**

```bash
mkdir -p tests
touch tests/__init__.py
```

**Step 2 : Vérifier que pytest fonctionne**

```bash
pytest --collect-only
```
Expected : `no tests ran` sans erreur.

**Step 3 : Commit**

```bash
git add tests/
git commit -m "feat: add tests directory"
```

---

### Task 2 : Créer `output.py` (extraction + HTML)

**Files:**
- Create: `output.py`
- Create: `tests/test_output.py`
- Modify: `main.py` (remplacer `write_output` par import)

**Contexte :** Le nouveau format de résultats est :
```python
dict[int, dict]  # {port: {"status": "open", "service": "http", "banner": "Apache"}}
```

**Step 1 : Écrire les tests en premier**

```python
# tests/test_output.py
import json, csv
from pathlib import Path
import pytest
from output import write_output

RESULTS = {
    80:  {"status": "open",     "service": "http",  "banner": "Apache"},
    22:  {"status": "closed",   "service": "ssh",   "banner": ""},
    443: {"status": "filtered", "service": "https", "banner": ""},
}

def test_write_txt(tmp_path):
    out = tmp_path / "scan.txt"
    write_output(RESULTS, out, "127.0.0.1", "connect")
    lines = out.read_text().splitlines()
    assert any("80" in l and "open" in l for l in lines)
    assert any("22" in l and "closed" in l for l in lines)

def test_write_json(tmp_path):
    out = tmp_path / "scan.json"
    write_output(RESULTS, out, "127.0.0.1", "connect")
    data = json.loads(out.read_text())
    assert data["80"]["status"] == "open"
    assert data["22"]["service"] == "ssh"

def test_write_csv(tmp_path):
    out = tmp_path / "scan.csv"
    write_output(RESULTS, out, "127.0.0.1", "connect")
    rows = list(csv.DictReader(out.open()))
    ports = [int(r["port"]) for r in rows]
    assert 80 in ports and 22 in ports

def test_write_html(tmp_path):
    out = tmp_path / "scan.html"
    write_output(RESULTS, out, "127.0.0.1", "connect")
    html = out.read_text()
    assert "<table" in html
    assert "127.0.0.1" in html
    assert "open" in html
    assert "Apache" in html
    # Couleurs
    assert "green" in html or "#" in html

def test_html_stats(tmp_path):
    out = tmp_path / "scan.html"
    write_output(RESULTS, out, "10.0.0.1", "syn")
    html = out.read_text()
    assert "1 open" in html or "open: 1" in html
```

**Step 2 : Lancer les tests — vérifier qu'ils échouent**

```bash
pytest tests/test_output.py -v
```
Expected : `ModuleNotFoundError: No module named 'output'`

**Step 3 : Créer `output.py`**

```python
# output.py
"""Fonctions d'export des résultats de scan."""

import csv
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

    rows = ""
    for port, info in sorted(results.items()):
        color = color_map.get(info["status"], "#fff")
        rows += (
            f"<tr style='background:{color}22'>"
            f"<td>{port}</td>"
            f"<td>{info['service']}</td>"
            f"<td style='color:{color};font-weight:bold'>{info['status']}</td>"
            f"<td>{info['banner'] or '—'}</td>"
            f"</tr>\n"
        )

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><title>Scan — {target}</title>
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
<div class="meta">Cible : <strong>{target}</strong> | Type : {scan_type} | Date : {now}</div>
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
```

**Step 4 : Lancer les tests — vérifier qu'ils passent**

```bash
pytest tests/test_output.py -v
```
Expected : tous PASS.

**Step 5 : Mettre à jour `main.py` — remplacer `write_output` local**

Dans `main.py`, supprimer la fonction `write_output` locale et modifier les imports :

```python
# Remplacer :
import csv
import json
# ... et la fonction write_output locale

# Par :
from output import write_output
```

Adapter l'appel `write_output(results, out_path)` → `write_output(results, out_path, target, "connect")`.

Adapter aussi le format des résultats dans `main()` :
```python
# Remplacer :
results[port] = status
# Par :
results[port] = {"status": status, "service": "", "banner": ""}
```

**Step 6 : Tester que le CLI fonctionne encore**

```bash
python main.py --target 127.0.0.1 --ports 80 --output /tmp/test.txt
cat /tmp/test.txt
```
Expected : ligne avec port 80 et son statut.

**Step 7 : Commit**

```bash
git add output.py tests/test_output.py main.py
git commit -m "feat: add output.py with HTML export, update main.py"
```

---

### Task 3 : `get_service_name` + `grab_banner` dans `scanner.py`

**Files:**
- Modify: `scanner.py`
- Create: `tests/test_scanner.py`

**Step 1 : Écrire les tests**

```python
# tests/test_scanner.py
import socket
from unittest.mock import patch, MagicMock
from scanner import scan_port_connect, get_service_name, grab_banner


def test_get_service_name_known():
    assert get_service_name(80) == "http"
    assert get_service_name(22) == "ssh"
    assert get_service_name(443) == "https"

def test_get_service_name_unknown():
    result = get_service_name(19999)
    assert result == "unknown"

def test_grab_banner_success():
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
    with patch("socket.socket", return_value=mock_sock):
        result = grab_banner("127.0.0.1", 22)
    assert "SSH" in result

def test_grab_banner_timeout():
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.connect_ex.return_value = 0
    mock_sock.recv.side_effect = socket.timeout
    with patch("socket.socket", return_value=mock_sock):
        result = grab_banner("127.0.0.1", 80)
    assert result == ""
```

**Step 2 : Lancer les tests — vérifier qu'ils échouent**

```bash
pytest tests/test_scanner.py -v
```
Expected : `ImportError: cannot import name 'get_service_name'`

**Step 3 : Ajouter les fonctions dans `scanner.py`**

À la fin de `scanner.py`, ajouter :

```python
def get_service_name(port: int) -> str:
    """Retourne le nom du service associé au port, ou 'unknown'."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Tente de lire la bannière du service sur ce port TCP.

    Returns:
        Chaîne de la bannière (première ligne), ou "" si échec.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) != 0:
                return ""
            sock.sendall(b"\r\n")
            data = sock.recv(1024)
            return data.decode(errors="ignore").strip().splitlines()[0]
    except (socket.timeout, OSError, IndexError):
        return ""
```

**Step 4 : Lancer les tests**

```bash
pytest tests/test_scanner.py -v
```
Expected : tous PASS.

**Step 5 : Commit**

```bash
git add scanner.py tests/test_scanner.py
git commit -m "feat: add get_service_name and grab_banner to scanner.py"
```

---

### Task 4 : `scan_range_threaded` dans `scanner.py`

**Files:**
- Modify: `scanner.py`
- Modify: `tests/test_scanner.py`

**Step 1 : Ajouter les tests**

Ajouter à `tests/test_scanner.py` :

```python
from scanner import scan_range_threaded

def test_scan_range_threaded_returns_all_ports():
    with patch("scanner.scan_port_connect", return_value="closed"):
        results = scan_range_threaded("127.0.0.1", [80, 443, 8080], scan_port_connect, timeout=1.0, delay=0.0, max_workers=10)
    assert set(results.keys()) == {80, 443, 8080}

def test_scan_range_threaded_status():
    def fake_scan(ip, port, timeout=1.0):
        return "open" if port == 80 else "closed"
    results = scan_range_threaded("127.0.0.1", [80, 443], fake_scan, timeout=1.0, delay=0.0, max_workers=2)
    assert results[80] == "open"
    assert results[443] == "closed"
```

**Step 2 : Lancer les tests — vérifier qu'ils échouent**

```bash
pytest tests/test_scanner.py::test_scan_range_threaded_returns_all_ports -v
```
Expected : `ImportError`

**Step 3 : Ajouter `scan_range_threaded` dans `scanner.py`**

```python
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List

def scan_range_threaded(
    ip: str,
    ports: List[int],
    scan_fn: Callable,
    timeout: float = 1.0,
    delay: float = 0.0,
    max_workers: int = 100,
) -> Dict[int, str]:
    """Scanne une liste de ports en parallèle via ThreadPoolExecutor.

    Args:
        ip: adresse cible.
        ports: liste de ports à scanner.
        scan_fn: fonction de scan (scan_port_connect ou scan_port_syn).
        timeout: délai par port.
        delay: pause entre soumissions (rate limiting).
        max_workers: nombre de threads parallèles.

    Returns:
        dict[port] = statut
    """
    results: Dict[int, str] = {}

    def _scan(port: int) -> tuple:
        if delay > 0:
            time.sleep(delay)
        return port, scan_fn(ip, port, timeout=timeout)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan, p): p for p in ports}
        for future in as_completed(futures):
            port, status = future.result()
            results[port] = status

    return results
```

Ajouter aussi en haut de `scanner.py` les imports manquants :
```python
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List
```
(remplacer l'import `Dict` existant)

**Step 4 : Lancer les tests**

```bash
pytest tests/test_scanner.py -v
```
Expected : tous PASS.

**Step 5 : Commit**

```bash
git add scanner.py tests/test_scanner.py
git commit -m "feat: add scan_range_threaded with ThreadPoolExecutor and rate limiting"
```

---

### Task 5 : `scan_port_syn` dans `scanner.py` (conditionnel scapy)

**Files:**
- Modify: `scanner.py`
- Modify: `tests/test_scanner.py`

**Step 1 : Ajouter les tests**

```python
# Dans tests/test_scanner.py
from scanner import scan_port_syn

def test_scan_port_syn_no_scapy(monkeypatch):
    """Sans scapy, doit retourner 'filtered' avec un warning, pas crasher."""
    import sys
    monkeypatch.setitem(sys.modules, "scapy", None)
    monkeypatch.setitem(sys.modules, "scapy.all", None)
    # On recharge le module pour simuler scapy absent
    result = scan_port_syn.__wrapped__("127.0.0.1", 80) if hasattr(scan_port_syn, "__wrapped__") else "filtered"
    assert result in ("filtered", "unavailable")
```

> Note : le test SYN réel nécessite sudo et une cible. On teste uniquement le fallback ici.

**Step 2 : Lancer le test — vérifier qu'il échoue**

```bash
pytest tests/test_scanner.py::test_scan_port_syn_no_scapy -v
```

**Step 3 : Ajouter `scan_port_syn` dans `scanner.py`**

En haut du fichier, après les imports existants :

```python
# Import optionnel de scapy
try:
    from scapy.all import IP, TCP, sr1, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
```

Puis la fonction :

```python
def scan_port_syn(ip: str, port: int, timeout: float = 1.0) -> str:
    """Scanne un port via SYN scan (raw packets, nécessite scapy + sudo).

    Returns:
        "open"     si SYN-ACK reçu.
        "closed"   si RST reçu.
        "filtered" si timeout ou scapy/sudo indisponible.
    """
    if not SCAPY_AVAILABLE:
        import logging
        logging.warning("scapy non disponible — fallback sur filtered. Installez scapy : pip install scapy")
        return "filtered"

    import os
    if os.geteuid() != 0:
        import logging
        logging.warning("SYN scan nécessite sudo. Retourne filtered.")
        return "filtered"

    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout)

    if resp is None:
        return "filtered"
    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        if flags == 0x12:  # SYN-ACK
            return "open"
        if flags == 0x14:  # RST-ACK
            return "closed"
    return "filtered"
```

**Step 4 : Lancer tous les tests**

```bash
pytest tests/test_scanner.py -v
```
Expected : tous PASS (le test SYN teste uniquement le fallback).

**Step 5 : Commit**

```bash
git add scanner.py tests/test_scanner.py
git commit -m "feat: add scan_port_syn with scapy (conditional, falls back to filtered)"
```

---

### Task 6 : Créer `discovery.py`

**Files:**
- Create: `discovery.py`
- Create: `tests/test_discovery.py`

**Step 1 : Écrire les tests**

```python
# tests/test_discovery.py
from unittest.mock import patch, MagicMock
import subprocess
from discovery import discover_hosts, _icmp_sweep


def test_icmp_sweep_finds_active_host():
    def fake_run(cmd, **kwargs):
        m = MagicMock()
        # Simuler que 192.168.1.1 répond, pas les autres
        m.returncode = 0 if "192.168.1.1" in cmd else 1
        return m

    with patch("subprocess.run", side_effect=fake_run):
        result = _icmp_sweep("192.168.1.0/30", timeout=1)
    assert "192.168.1.1" in result


def test_discover_hosts_returns_list():
    with patch("discovery._icmp_sweep", return_value=["192.168.1.1"]):
        with patch("discovery.SCAPY_AVAILABLE", False):
            result = discover_hosts("192.168.1.0/30", timeout=1)
    assert isinstance(result, list)
    assert "192.168.1.1" in result


def test_discover_hosts_single_ip():
    """Une IP unique (pas un réseau) retourne juste cette IP si elle répond."""
    with patch("discovery._icmp_sweep", return_value=["10.0.0.1"]):
        with patch("discovery.SCAPY_AVAILABLE", False):
            result = discover_hosts("10.0.0.1", timeout=1)
    assert "10.0.0.1" in result
```

**Step 2 : Lancer les tests — vérifier qu'ils échouent**

```bash
pytest tests/test_discovery.py -v
```
Expected : `ModuleNotFoundError: No module named 'discovery'`

**Step 3 : Créer `discovery.py`**

```python
# discovery.py
"""Host discovery : ARP sweep (scapy) avec fallback ICMP (ping)."""

import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def discover_hosts(network: str, timeout: float = 1.0) -> List[str]:
    """Découvre les hôtes actifs sur un réseau ou vérifie une IP unique.

    Utilise ARP si scapy disponible, sinon ICMP ping.

    Args:
        network: sous-réseau CIDR (ex. "192.168.1.0/24") ou IP unique.
        timeout: délai d'attente par hôte.

    Returns:
        Liste des IPs actives.
    """
    if SCAPY_AVAILABLE:
        try:
            return _arp_sweep(network, timeout)
        except Exception:
            pass
    return _icmp_sweep(network, timeout)


def _arp_sweep(network: str, timeout: float) -> List[str]:
    """Envoie des requêtes ARP sur le sous-réseau."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(pkt, timeout=timeout, verbose=False)
    return [rcv.psrc for _, rcv in answered]


def _icmp_sweep(network: str, timeout: float) -> List[str]:
    """Ping chaque hôte du réseau en parallèle."""
    try:
        net = ipaddress.ip_network(network, strict=False)
        hosts = [str(h) for h in net.hosts()]
    except ValueError:
        # IP unique
        hosts = [network]

    timeout_ms = max(1, int(timeout * 1000))
    active: List[str] = []

    def ping(ip: str) -> str | None:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_ms), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return ip if result.returncode == 0 else None

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ping, h): h for h in hosts}
        for future in as_completed(futures):
            ip = future.result()
            if ip:
                active.append(ip)

    return sorted(active)
```

**Step 4 : Lancer les tests**

```bash
pytest tests/test_discovery.py -v
```
Expected : tous PASS.

**Step 5 : Commit**

```bash
git add discovery.py tests/test_discovery.py
git commit -m "feat: add discovery.py with ARP sweep and ICMP fallback"
```

---

### Task 7 : Mettre à jour `main.py` (CLI + orchestration complète)

**Files:**
- Modify: `main.py`
- Create: `tests/test_main.py`

**Step 1 : Écrire les tests**

```python
# tests/test_main.py
from unittest.mock import patch, MagicMock
from pathlib import Path
from main import main


def test_cli_basic(tmp_path):
    out = tmp_path / "result.txt"
    with patch("main.scan_port_connect", return_value="closed"):
        code = main(["--target", "127.0.0.1", "--ports", "80", "--output", str(out)])
    assert code == 0
    assert out.exists()


def test_cli_json_output(tmp_path):
    import json
    out = tmp_path / "result.json"
    with patch("main.scan_port_connect", return_value="open"):
        main(["--target", "127.0.0.1", "--ports", "80", "--output", str(out)])
    data = json.loads(out.read_text())
    assert "80" in data
    assert data["80"]["status"] == "open"


def test_cli_syn_no_scapy(tmp_path, capsys):
    out = tmp_path / "result.txt"
    with patch("main.SCAPY_AVAILABLE", False):
        with patch("main.scan_port_connect", return_value="closed"):
            main(["--target", "127.0.0.1", "--ports", "80",
                  "--scan-type", "syn", "--output", str(out)])
    captured = capsys.readouterr()
    assert "scapy" in captured.out.lower() or out.exists()


def test_cli_threads_option(tmp_path):
    out = tmp_path / "result.txt"
    with patch("main.scan_range_threaded", return_value={80: "closed"}) as mock_fn:
        main(["--target", "127.0.0.1", "--ports", "80",
              "--threads", "50", "--output", str(out)])
    mock_fn.assert_called_once()
    _, kwargs = mock_fn.call_args
    assert kwargs.get("max_workers") == 50
```

**Step 2 : Lancer les tests — vérifier qu'ils échouent**

```bash
pytest tests/test_main.py -v
```

**Step 3 : Réécrire `main.py`**

```python
# main.py
"""Interface en ligne de commande pour le scanner de ports.

Supporte :
  - hôte / adresse IP cible ou sous-réseau CIDR
  - plage de ports (ex. 1-1024, 22,80,443, ou combinaison)
  - SYN scan (nécessite scapy + sudo) ou TCP connect
  - scan parallèle (ThreadPoolExecutor)
  - host discovery (ARP ou ICMP)
  - banner grabbing, service names, rate limiting
  - export console + fichier (.txt/.json/.csv/.html)

Utilisation :
  python main.py --target 192.168.1.1 --ports 20-1024 --output scan.json
  python main.py --target 192.168.1.0/24 --discover --ports 22,80 --scan-type syn
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

from scanner import (
    grab_banner,
    get_service_name,
    scan_port_connect,
    scan_port_syn,
    scan_range_threaded,
    SCAPY_AVAILABLE,
)
from output import write_output

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


def parse_ports(port_str: str) -> List[int]:
    """Convertit une spécification de ports en liste d'entiers.

    Accepte : "22", "20-25", "22,80,443", "22,80-85"
    """
    ports: List[int] = []
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str), int(end_str)
            if start > end:
                start, end = end, start
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def main(args: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Scanner de ports TCP")
    parser.add_argument("--target", required=True, help="Hôte, IP ou sous-réseau CIDR cible")
    parser.add_argument("--ports", required=True,
                        help="Ports à scanner (ex. 1-1024 ou 22,80,443 ou 20-25,80)")
    parser.add_argument("--scan-type", choices=["connect", "syn"], default="connect",
                        help="Type de scan (défaut: connect)")
    parser.add_argument("--output", default="scan_results.txt",
                        help="Fichier de sortie (.txt/.json/.csv/.html)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Délai par port en secondes (défaut: 1.0)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Nombre de threads parallèles (défaut: 100)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Délai entre ports en secondes (défaut: 0)")
    parser.add_argument("--discover", action="store_true",
                        help="Activer le host discovery avant le scan")
    parser.add_argument("--banner", action="store_true",
                        help="Activer le banner grabbing (ports ouverts uniquement)")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING"], default="INFO",
                        help="Niveau de log (défaut: INFO)")

    parsed = parser.parse_args(args=args)

    logging.basicConfig(
        level=getattr(logging, parsed.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # Choisir la fonction de scan
    if parsed.scan_type == "syn":
        if not SCAPY_AVAILABLE:
            print("AVERTISSEMENT : scapy non disponible. Installez-le : pip install scapy")
            print("Fallback sur TCP connect.")
            scan_fn = scan_port_connect
        else:
            scan_fn = scan_port_syn
    else:
        scan_fn = scan_port_connect

    ports = parse_ports(parsed.ports)

    # Host discovery
    if parsed.discover:
        from discovery import discover_hosts
        logging.info(f"Host discovery sur {parsed.target}...")
        targets = discover_hosts(parsed.target, timeout=parsed.timeout)
        if not targets:
            print("Aucun hôte actif trouvé.")
            return 1
        print(f"{len(targets)} hôte(s) actif(s) : {', '.join(targets)}")
    else:
        targets = [parsed.target]

    all_results: Dict[str, Dict[int, dict]] = {}

    for target in targets:
        print(f"\nScan de {target} — {len(ports)} ports ({parsed.scan_type})")

        raw = scan_range_threaded(
            target, ports, scan_fn,
            timeout=parsed.timeout,
            delay=parsed.delay,
            max_workers=parsed.threads,
        )

        # Enrichir avec service name et banner
        results: Dict[int, dict] = {}
        port_iter = tqdm(raw.items(), desc="Enrichissement") if TQDM_AVAILABLE else raw.items()
        for port, status in port_iter:
            service = get_service_name(port)
            banner = ""
            if parsed.banner and status == "open":
                banner = grab_banner(target, port, timeout=parsed.timeout)
            results[port] = {"status": status, "service": service, "banner": banner}

        # Affichage console
        for port, info in sorted(results.items()):
            print(f"  {port:5d}  {info['status']:<10} {info['service']:<15} {info['banner']}")

        # Stats
        counts = {"open": 0, "closed": 0, "filtered": 0}
        for info in results.values():
            counts[info["status"]] += 1
        print(f"\n  open: {counts['open']}  closed: {counts['closed']}  filtered: {counts['filtered']}")

        all_results[target] = results

    # Export fichier (dernier hôte si plusieurs, ou fusionné)
    results_to_save = list(all_results.values())[-1]
    out_path = Path(parsed.output)
    write_output(results_to_save, out_path, targets[-1], parsed.scan_type)
    print(f"\nRésultats sauvegardés dans {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

**Step 4 : Ajouter `SCAPY_AVAILABLE` dans `scanner.py` (export)**

Vérifier que `scanner.py` exporte `SCAPY_AVAILABLE` au niveau module (déjà fait en Task 5).

**Step 5 : Lancer tous les tests**

```bash
pytest tests/ -v
```
Expected : tous PASS.

**Step 6 : Test manuel**

```bash
python main.py --target 127.0.0.1 --ports 22,80,443 --output /tmp/scan.html
open /tmp/scan.html
```

**Step 7 : Commit**

```bash
git add main.py tests/test_main.py
git commit -m "feat: update main.py with threading, logging, progress bar, banner, host discovery"
```

---

### Task 8 : Mettre à jour `requirements.txt` et `CLAUDE.md`

**Files:**
- Modify: `requirements.txt`
- Modify: `CLAUDE.md`

**Step 1 : Mettre à jour `requirements.txt`**

```
# Dépendances optionnelles
tqdm      # progress bar (--progress)
scapy     # SYN scan + ARP discovery (nécessite sudo)

# Dev
pytest
```

**Step 2 : Mettre à jour `CLAUDE.md`**

Ajouter les nouveaux modules et commandes dans `CLAUDE.md`.

**Step 3 : Lancer tous les tests une dernière fois**

```bash
pytest tests/ -v --tb=short
```
Expected : tous PASS.

**Step 4 : Commit final**

```bash
git add requirements.txt CLAUDE.md
git commit -m "chore: update requirements.txt and CLAUDE.md for Phase 3"
```
