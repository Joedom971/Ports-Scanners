# Architecture du projet — Scanner de ports réseau

## Vue d'ensemble

Le projet est un scanner de ports TCP écrit en Python, organisé en **5 modules** qui collaborent ensemble. Chaque module a un rôle précis et délimité.

---

## Les 5 fichiers et leur rôle

### `scanner.py` — Le moteur

C'est le cœur du projet. Il contient toute la logique de scan et d'analyse réseau.

**Fonctions disponibles :**
- `scan_port_connect(ip, port, timeout)` → `"open"` | `"closed"` | `"filtered"` — connexion TCP standard, compatible tous OS
- `scan_port_syn(ip, port, timeout)` → `"open"` | `"closed"` | `"filtered"` — paquet SYN brut via scapy (nécessite sudo)
- `scan_range_threaded(ip, ports, scan_fn, ...)` → dict — lance des centaines de scans en parallèle via `ThreadPoolExecutor`
- `get_service_name(port)` → nom du service (`"http"`, `"ssh"`, etc.)
- `grab_banner(ip, port, timeout)` → première ligne de réponse du service
- `detect_service_version(ip, port, service_name, timeout)` → version extraite via probe spécifique au protocole (HTTP HEAD, SMTP EHLO, etc.)
- `detect_os(ip, timeout)` → `"Linux/Unix"` | `"Windows"` | `"Network device"` | `"unknown"` — fingerprinting TTL
- `detect_firewall(ip, port, timeout)` → `"open"` | `"closed"` | `"filtered-silent"` | `"filtered-active"` | `"filtered"` — distingue DROP silencieux vs REJECT ICMP
- `resoudre_cible(cible)` → résolution DNS unique avant le scan

**Ne dépend d'aucun autre fichier du projet.** C'est une bibliothèque autonome.

**Compatibilité Windows :** `geteuid` via `getattr(os, "geteuid", lambda: 1)()`, `ECONNREFUSED` via `_ECONNREFUSED_CODES` (inclut `WSAECONNREFUSED`).

---

### `discovery.py` — La détection d'hôtes

Avant de scanner les ports d'une machine, encore faut-il savoir quelles machines sont actives sur le réseau.

**Ce qu'il fait :**
- Envoie des requêtes ARP en broadcast pour détecter les machines sur le réseau local (`_arp_sweep`) — via scapy
- En repli, envoie des pings ICMP en parallèle vers toutes les adresses d'un sous-réseau (`_icmp_sweep`)
- Retourne la liste des IPs qui répondent (`discover_hosts`)

**Compatibilité ping cross-plateforme :**
- Linux : `ping -c 1 -W <secondes>`
- macOS : `ping -c 1 -W <millisecondes>`
- Windows : `ping -n 1 -w <millisecondes>`

**Appelé par `main.py`** uniquement quand l'option `--discover` est activée.

---

### `output.py` — L'export des résultats

Une fois le scan terminé, ce module se charge d'écrire les résultats dans un fichier.

**Formats supportés :**
- `.txt` — texte brut, un port par ligne avec statut, service, bannière, version
- `.json` — données structurées complètes
- `.csv` — tableau compatible Excel, colonnes : port, status, service, banner, os, version, firewall
- `.html` — rapport visuel coloré avec tableau, statistiques et CSS intégré (vert=open, rouge=closed, gris=filtered)
- `.xml` — format compatible Nmap/Metasploit (`<nmaprun>/<host>/<ports>/<port>`)

**Appelé par `main.py`** à la fin du scan. En cas de scan multi-hôtes, un fichier est créé par hôte.

---

### `main.py` — Le chef d'orchestre

C'est le point d'entrée principal. Il parse les arguments en ligne de commande et coordonne tous les autres modules.

**Ce qu'il fait :**
1. Valide les entrées utilisateur — `valider_cible()` (IPv4, IPv6, CIDR, hostname), `valider_port()`, `valider_fichier_sortie()`, `parse_ports()`
2. Résout le nom d'hôte en IP une seule fois (`resoudre_cible`)
3. Appelle `discovery.py` si `--discover` est actif
4. Appelle `scanner.py` pour scanner les ports en parallèle
5. Enrichit les résultats : nom de service, bannière, version, OS, type de pare-feu
6. Affiche les résultats dans le terminal
7. Appelle `output.py` — un fichier par hôte si multi-hôtes

**Format des résultats :**
```python
results[port] = {
    "status":  "open" | "closed" | "filtered",
    "service": "ssh" | "http" | ...,
    "banner":  "SSH-2.0-OpenSSH_8.9" | "",
    "os":      "Linux/Unix" | "Windows" | "unknown" | "",
    "version": "nginx/1.18.0" | "",
    "firewall": "filtered-silent" | "filtered-active" | "",
}
```

**Options CLI disponibles :**

| Option | Description |
|--------|-------------|
| `--target` | IP, IPv6, hostname ou CIDR |
| `--ports` | `22,80,443` ou `1-1024` ou combinaison |
| `--scan-type` | `connect` (défaut) ou `syn` |
| `--output` | `.txt`, `.json`, `.csv`, `.html`, `.xml` |
| `--threads` | Connexions parallèles (défaut 100) |
| `--timeout` | Délai par port en secondes |
| `--banner` | Lire la bannière des services ouverts |
| `--version-detect` | Détecter la version via probe protocole |
| `--os-detect` | Détecter l'OS via TTL (sudo requis) |
| `--firewall-detect` | Distinguer DROP vs REJECT (sudo requis) |
| `--discover` | Découvrir les hôtes actifs avant le scan |
| `--randomize` | Mélanger l'ordre des ports |
| `--max-rate` | Débit max en paquets/seconde |
| `--delay` | Pause fixe entre ports |
| `--jitter` | Délai aléatoire entre ports |

**Importe :** `scanner.py` + `output.py` + `discovery.py` (optionnel)

---

### `cli.py` — L'interface interactive

Une surcouche conviviale par-dessus `main.py`. Au lieu de taper des arguments en ligne de commande, l'utilisateur répond à des questions.

**Ce qu'il fait :**
- Pose des questions pas-à-pas (cible, profil, vitesse, options, format de rapport)
- Traduit les choix simples (ex. "Rapide") en paramètres techniques (threads=400, timeout=0.3)
- Détecte automatiquement si le programme tourne avec les droits root (SYN scan ou TCP connect)
- Propose les options avancées : découverte, bannières, version des services, pare-feu, OS
- Affichage sécurisé pour Windows (`_print_safe`) — repli ASCII si le terminal ne supporte pas UTF-8
- Construit la liste d'arguments et appelle `main.py`

**Importe :** `main.py` uniquement (via `from main import main`)

---

## Schéma des interactions

```
Utilisateur
    │
    ├── python cli.py          ──► cli.py
    │                                │
    │                                ▼
    └── python main.py [args]  ──► main.py
                                     │
                        ┌────────────┼────────────┐
                        ▼            ▼             ▼
                  scanner.py   discovery.py   output.py
```

**Flux d'un scan complet avec toutes les options :**

```
cli.py (optionnel)
  └─► main.py
        ├─► valider_cible() / parse_ports()       [validation]
        ├─► resoudre_cible()                       [scanner.py — DNS unique]
        ├─► discover_hosts()                       [discovery.py — si --discover]
        ├─► scan_range_threaded()                  [scanner.py — scan parallèle]
        │     └─► scan_port_connect() / syn()      [par port]
        ├─► detect_os()                            [scanner.py — si --os-detect]
        ├─► get_service_name()                     [scanner.py — enrichissement]
        ├─► grab_banner()                          [scanner.py — si --banner]
        ├─► detect_service_version()               [scanner.py — si --version-detect]
        ├─► detect_firewall()                      [scanner.py — si --firewall-detect, ports filtrés]
        └─► write_output()                         [output.py — fichier(s) de résultats]
```

---

## Résumé des dépendances

| Fichier | Importe | Est importé par |
|---------|---------|-----------------|
| `scanner.py` | `socket`, `errno`, `threading`, `concurrent.futures`, `scapy` (optionnel) | `main.py` |
| `discovery.py` | `subprocess`, `ipaddress`, `platform`, `concurrent.futures`, `scapy` (optionnel) | `main.py` |
| `output.py` | `csv`, `json`, `html`, `xml.etree.ElementTree`, `datetime` | `main.py` |
| `main.py` | `scanner`, `output`, `discovery`, `argparse`, `logging` | `cli.py` |
| `cli.py` | `main`, `os` | — |
