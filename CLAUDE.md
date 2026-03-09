# CLAUDE.md

Ce fichier fournit des indications à Claude Code lors du travail sur ce dépôt.

## Commandes

```bash
# Activer l'environnement virtuel
source .venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt

# Lancer l'interface interactive (recommandé)
python cli.py

# Lancer l'interface interactive en mode SYN scan (nécessite sudo + scapy)
sudo /chemin/absolu/.venv/bin/python cli.py

# Lancer un scan directement en ligne de commande
python main.py --target 127.0.0.1 --ports 22,80,443
python main.py --target 192.168.1.1 --ports 1-1024 --threads 200 --output scan.html
python main.py --target 192.168.1.0/24 --discover --ports 22,80 --scan-type syn
python main.py --target 127.0.0.1 --ports 22,80,443 --banner --output results.json

# Vérification rapide d'un port
python scanner.py

# Lancer les tests
python -m pytest tests/ -v
```

## Architecture

Le projet est organisé en plusieurs modules :

- **`cli.py`** — interface interactive simplifiée pour non-experts. Propose des profils prédéfinis (rapide / standard / complet / personnalisé), une vitesse simplifiée (Rapide / Normal / Lent) et auto-détecte le type de scan selon les droits root.
- **`main.py`** — point d'entrée CLI complet via `argparse`. Supporte `--threads`, `--scan-type`, `--banner`, `--discover`, `--delay`, `--log-level`. Résultats au format `dict[port] = {"status", "service", "banner"}`.
- **`scanner.py`** — bibliothèque de scan TCP. Expose :
  - `scan_port_connect(ip, port, timeout)` → `"open"` | `"closed"` | `"filtered"`
  - `scan_port_syn(ip, port, timeout)` → `"open"` | `"closed"` | `"filtered"` (nécessite scapy + sudo)
  - `scan_range(ip, start_port, end_port, timeout)` → `dict[port, statut]`
  - `scan_range_threaded(ip, ports, scan_fn, timeout, delay, max_workers)` → `dict[port, statut]`
  - `get_service_name(port)` → nom du service
  - `grab_banner(ip, port, timeout)` → bannière du service
  - `SCAPY_AVAILABLE` — booléen indiquant si scapy est installé
- **`output.py`** — fonctions d'export. `write_output(results, path, target, scan_type)` écrit en `.txt`, `.json`, `.csv` ou `.html`.
- **`discovery.py`** — découverte d'hôtes. `discover_hosts(network, timeout)` sonde un sous-réseau CIDR via ARP (scapy) ou ping ICMP en repli ; retourne une liste d'IPs actives.

## Profils CLI (`cli.py`)

| Profil | Ports | Usage |
|--------|-------|-------|
| Scan rapide | 22,80,443,3389,8080 | Vérification rapide des services courants |
| Scan standard | 1–1024 | Audit réseau général |
| Scan complet | 1–65535 | Analyse exhaustive (lent) |
| Personnalisé | au choix | Ports spécifiques |

## Vitesses CLI (`cli.py`)

| Vitesse | Threads | Timeout | Délai |
|---------|---------|---------|-------|
| Rapide (LAN) | 400 | 0.3 s | 0 |
| Normal | 100 | 1.0 s | 0 |
| Lent (discret) | 20 | 2.0 s | 0.1 s |

## Comportement du scan

- **open** : poignée de main TCP réussie
- **closed** : connexion refusée (RST reçu)
- **filtered** : délai expiré ou hôte inaccessible

Les scans sont parallélisés via `ThreadPoolExecutor`.

## Dépendances optionnelles

```bash
pip install -r requirements.txt
```

- `tqdm` — barre de progression
- `scapy` — SYN scan et découverte ARP (nécessite également sudo)
- `pytest` — exécution des tests
