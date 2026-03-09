# CLAUDE.md

Ce fichier fournit des indications à Claude Code lors du travail sur ce dépôt.

## Démarrage

### Depuis VS Code (terminal intégré)

Ouvrir le dossier `Port_scanner_Reseau` dans VS Code, puis dans le terminal intégré (`Ctrl+`` ` `` ou `Terminal → New Terminal`) :

```bash
# Activer l'environnement virtuel
source .venv/bin/activate

# Lancer le CLI interactif
python cli.py

# Ou directement en ligne de commande
python main.py --target 127.0.0.1 --ports 22,80,443
```

### Depuis l'exécutable (sans Python ni venv)

Les exécutables compilés sont dans `dist/` — aucune installation requise :

```bash
# CLI interactif
./dist/port-scan-cli

# CLI complet
./dist/port-scan --target 127.0.0.1 --ports 22,80,443
```

Pour les lancer depuis n'importe où sur le Mac :
```bash
sudo cp dist/port-scan dist/port-scan-cli /usr/local/bin/
# Puis depuis n'importe quel dossier :
port-scan-cli
port-scan --target 127.0.0.1 --ports 80
```

> Les résultats sont sauvegardés dans le **dossier depuis lequel la commande est lancée**, sauf si `--output` spécifie un chemin complet.

### Mode TCP connect (sans privilèges)

Scan standard, aucun droit particulier requis.

```bash
cd /chemin/vers/Port_scanner_Reseau
source .venv/bin/activate
python cli.py
```

Le CLI affiche : `Mode : TCP connect (standard)`

### Mode SYN scan (raw packets, nécessite sudo)

Plus discret, envoie des paquets bruts sans établir de connexion complète.
Nécessite `sudo` et `scapy` installé.

```bash
cd /chemin/vers/Port_scanner_Reseau
sudo $(pwd)/.venv/bin/python cli.py
```

> `sudo` nécessite un chemin absolu. `$(pwd)` l'insère automatiquement si vous êtes déjà dans le dossier du projet.

Le CLI affiche : `Mode : SYN scan (avancé, root détecté)`

> Le mode est **auto-détecté** selon les droits root — aucun choix à faire dans le CLI.

---

## Commandes

```bash
# Activer l'environnement virtuel
source .venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt

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
- **`main.py`** — point d'entrée CLI complet via `argparse`. Supporte `--threads`, `--scan-type`, `--banner`, `--discover`, `--delay`, `--log-level`. Résultats au format `dict[port] = {"status", "service", "banner"}`. Inclut la validation des entrées : `valider_cible()`, `valider_port()`, `valider_fichier_sortie()`, `parse_ports()`.
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

| Vitesse | Threads | Timeout | Délai | max-rate | Randomize |
|---------|---------|---------|-------|----------|-----------|
| Rapide (LAN) | 400 | 0.3 s | 0 | — | non |
| Normal | 100 | 1.0 s | 0 | — | non |
| Lent (discret) | 20 | 2.0 s | 0.1 s | — | non |
| Furtif (anti-détection) | 5 | 3.0 s | 0 | 2 pkt/s | oui |

> **Note :** avec `--max-rate`, les envois sont sérialisés par un verrou global — `--threads` n'a pas d'effet sur le débit réseau dans ce mode.

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
