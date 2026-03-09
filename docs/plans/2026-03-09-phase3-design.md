# Design — Phase 3 : Scanner réseau étendu

**Date :** 2026-03-09
**Projet :** Port_scanner_Reseau
**Portée :** Toutes les fonctionnalités Phase 3 (haute, moyenne, bonus)

---

## Architecture générale

Approche retenue : **modules séparés** (B).

```
Port_scanner_Reseau/
├── scanner.py       # scan_port_connect() + scan_port_syn() + scan_range_threaded()
│                    # + get_service_name() + grab_banner()
├── discovery.py     # host_discovery() — ARP (scapy) + ICMP fallback
├── output.py        # write_output() — txt/json/csv/html (extrait de main.py)
├── main.py          # CLI argparse + orchestration + logging + progress bar
├── requirements.txt # scapy, tqdm
└── reports/
```

**Flux d'exécution :**
1. `main.py` parse les args
2. Si `--discover` : `discovery.py` → liste d'hôtes actifs
3. Pour chaque hôte : scan parallèle via `scan_range_threaded()` dans `scanner.py`
4. Résultats enrichis (service name, banner si `--banner`) → `output.py`
5. Logging via `logging` tout au long

**Dépendances optionnelles :**
- `scapy` absent → SYN scan et ARP discovery désactivés avec message explicite
- `tqdm` absent → progress bar silencieusement ignorée
- `sudo` absent → SYN scan refusé avec message clair

---

## scanner.py

Nouvelles fonctions (les existantes `scan_port_connect`, `scan_range` restent inchangées) :

### `scan_port_syn(ip, port, timeout) -> str`
- Forge un paquet SYN via scapy
- SYN-ACK reçu → `"open"`, RST → `"closed"`, timeout → `"filtered"`
- Lève `ScapyUnavailableError` si scapy absent ou pas sudo

### `scan_range_threaded(ip, ports, scan_fn, timeout, delay, max_workers) -> dict[int, str]`
- `ThreadPoolExecutor` avec `max_workers` configurable (défaut : 100)
- `delay` entre chaque port si `--delay` spécifié
- Retourne `dict[port] = résultat`, identique à `scan_range()`

### `get_service_name(port) -> str`
- `socket.getservbyport()` avec fallback `"unknown"`

### `grab_banner(ip, port, timeout) -> str`
- Connexion TCP + lecture réponse du service
- Retourne chaîne vide si échec ou timeout

### Format interne des résultats (Phase 3)
```python
dict[port] = {
    "status": "open",    # "open" | "closed" | "filtered"
    "service": "http",   # socket.getservbyport() ou "unknown"
    "banner": "Apache"   # vide si --banner absent ou échec
}
```

---

## discovery.py

### `discover_hosts(network, timeout) -> list[str]`
- Essaie ARP si scapy disponible + sudo
- Fallback automatique sur ICMP si scapy absent
- Retourne liste d'IPs actives

### `_arp_sweep(network, timeout) -> list[str]`
- scapy : envoie ARP request sur le sous-réseau (ex. `"192.168.1.0/24"`)
- Plus fiable en réseau local (non bloqué par firewall ICMP)

### `_icmp_sweep(network, timeout) -> list[str]`
- `subprocess.run("ping -c 1 -W 1 <ip>")` pour chaque IP du sous-réseau
- Parallélisé via `ThreadPoolExecutor`

**Usage CLI :**
```bash
python main.py --target 192.168.1.0/24 --discover --ports 22,80
```

---

## output.py

Extraction de `write_output()` depuis `main.py` + ajout HTML.

### `write_output(results, output_path, target, scan_type)`
- Dispatch selon extension : `.txt` / `.json` / `.csv` / `.html`

### `_write_html(results, output_path, target, scan_type)`
- Entête : cible, date, type de scan, stats (X open / Y closed / Z filtered)
- Tableau coloré : vert=open, rouge=closed, gris=filtered
- Colonnes : Port | Service | Statut | Banner
- CSS inline (aucune dépendance externe)

---

## main.py — Nouveaux arguments CLI

| Argument | Valeurs | Défaut |
|---|---|---|
| `--scan-type` | `connect\|syn` | `connect` |
| `--threads` | int | `100` |
| `--delay` | float (secondes) | `0.0` |
| `--discover` | flag | désactivé |
| `--log-level` | `DEBUG\|INFO\|WARNING` | `INFO` |
| `--banner` | flag | désactivé |

Args existants (`--target`, `--ports`, `--output`, `--timeout`) inchangés.

**Orchestration :**
```
parse args
→ configurer logging
→ si --discover : discovery.py → liste d'hôtes
→ sinon : [target] comme seul hôte
→ pour chaque hôte :
    → scan_range_threaded() avec tqdm progress bar
    → enrichir résultats (service name, banner si --banner)
→ afficher résumé console (stats open/closed/filtered)
→ write_output() → fichier
```
