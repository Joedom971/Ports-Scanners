# Rapport de conception

## Architecture

Le projet est organisé en modules séparés selon les responsabilités :

| Module | Rôle |
|--------|------|
| `cli.py` | Interface interactive simplifiée pour l'utilisateur final |
| `main.py` | Point d'entrée CLI complet via `argparse` |
| `scanner.py` | Bibliothèque de scan TCP (connect et SYN) |
| `output.py` | Export des résultats (txt, json, csv, html) |
| `discovery.py` | Découverte d'hôtes sur un réseau |
| `tests/` | Tests unitaires (pytest) |
| `reports/` | Documentation du projet |

## Modules

### `cli.py`
Interface pas-à-pas pour non-experts. Propose :
- Des profils prédéfinis (rapide, standard, complet, personnalisé)
- Une vitesse simplifiée (Rapide / Normal / Lent) qui configure threads, timeout et délai
- Auto-détection du mode de scan selon les droits root (TCP connect ou SYN)

### `main.py`
CLI complet exposant toutes les options :
- `--target` — cible (IP, hostname, CIDR)
- `--ports` — spécification des ports (ex. `22,80-85,443`)
- `--scan-type` — `connect` ou `syn`
- `--threads` — parallélisme (défaut : 100)
- `--timeout` — délai par port en secondes (défaut : 1.0)
- `--delay` — délai entre ports pour le rate limiting (défaut : 0)
- `--discover` — découverte d'hôtes avant le scan
- `--banner` — récupération de bannière sur les ports ouverts
- `--output` — fichier de sortie (.txt / .json / .csv / .html)
- `--log-level` — niveau de journalisation

### `scanner.py`
Fonctions de bas niveau :
- `scan_port_connect(ip, port, timeout)` — scan via connexion TCP complète
- `scan_port_syn(ip, port, timeout)` — scan via raw packet SYN (nécessite scapy + sudo)
- `scan_range_threaded(ip, ports, scan_fn, timeout, delay, max_workers)` — scan parallèle
- `get_service_name(port)` — nom du service associé au port
- `grab_banner(ip, port, timeout)` — lecture de la bannière du service

### `output.py`
Fonction unique `write_output(results, path, target, scan_type)` qui détecte l'extension et écrit :
- `.txt` — texte brut tabulé
- `.json` — données structurées
- `.csv` — compatible tableur
- `.html` — rapport visuel avec couleurs et statistiques

### `discovery.py`
- `discover_hosts(network, timeout)` — balayage ARP (scapy) avec repli ICMP ping
- `_arp_sweep(network, timeout)` — envoi de paquets ARP sur le sous-réseau
- `_icmp_sweep(network, timeout)` — ping parallèle sur tous les hôtes du CIDR

## Format interne des résultats

```python
dict[int, dict]
# Exemple :
{
    80:  {"status": "open",     "service": "http",  "banner": "Apache/2.4"},
    22:  {"status": "closed",   "service": "ssh",   "banner": ""},
    443: {"status": "filtered", "service": "https", "banner": ""},
}
```

## Bibliothèques utilisées

| Bibliothèque | Usage |
|-------------|-------|
| `socket` | Connexions TCP et résolution de noms |
| `concurrent.futures` | Parallélisme via ThreadPoolExecutor |
| `argparse` | Parsing des arguments CLI |
| `json`, `csv` | Sérialisation des résultats |
| `subprocess` | Ping ICMP pour la découverte d'hôtes |
| `ipaddress` | Calcul des hôtes d'un sous-réseau CIDR |
| `scapy` *(optionnel)* | SYN scan et balayage ARP |
| `tqdm` *(optionnel)* | Barre de progression |

## Observations réseau (Wireshark)

### TCP connect
- Établit la poignée de main complète (SYN → SYN-ACK → ACK)
- Port ouvert : connexion établie, puis fermée proprement
- Port fermé : la cible répond RST
- Port filtré : aucune réponse, le scanner attend le timeout

### SYN scan
- Envoie uniquement le SYN (raw packet via scapy)
- Port ouvert : reçoit SYN-ACK, n'envoie pas le ACK final → connexion jamais établie
- Port fermé : reçoit RST-ACK
- Port filtré : aucune réponse
- Plus discret : aucune connexion complète n'est enregistrée dans les logs applicatifs
