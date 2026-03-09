# Plan d'implémentation — Phase 3

**Date :** 2026-03-09
**Statut :** Toutes les tâches complétées ✅

---

## Résumé

| Tâche | Description | Statut |
|-------|-------------|--------|
| 1 | Infrastructure de tests (`tests/`) | ✅ |
| 2 | `output.py` + export HTML | ✅ |
| 3 | `get_service_name` + `grab_banner` dans `scanner.py` | ✅ |
| 4 | `scan_range_threaded` dans `scanner.py` | ✅ |
| 5 | `scan_port_syn` dans `scanner.py` | ✅ |
| 6 | `discovery.py` (ARP + ICMP) | ✅ |
| 7 | Réécriture `main.py` + `tests/test_main.py` | ✅ |
| 8 | `requirements.txt` + `CLAUDE.md` | ✅ |

**Total : 48 tests, tous passants.**

---

## Tâche 1 — Infrastructure de tests

Création du dossier `tests/` avec `__init__.py`.
Vérification que pytest collecte sans erreur.

---

## Tâche 2 — `output.py`

Extraction de `write_output()` depuis `main.py` + ajout du format HTML.

Formats supportés : `.txt` / `.json` / `.csv` / `.html`

Le HTML inclut :
- En-tête : cible, date, type de scan
- Statistiques : open / closed / filtered
- Tableau coloré (vert = open, rouge = closed, gris = filtered)

---

## Tâche 3 — `get_service_name` + `grab_banner`

Ajouts dans `scanner.py` :

- `get_service_name(port)` — utilise `socket.getservbyport()`, fallback `"unknown"`
- `grab_banner(ip, port, timeout)` — connexion TCP + lecture première ligne de réponse

---

## Tâche 4 — `scan_range_threaded`

Ajout dans `scanner.py` :

- `ThreadPoolExecutor` avec `max_workers` configurable
- Paramètre `delay` pour le rate limiting
- Accepte n'importe quelle fonction de scan via `scan_fn`

---

## Tâche 5 — `scan_port_syn`

Ajout dans `scanner.py` :

- Forge un paquet SYN via scapy
- SYN-ACK → `"open"`, RST → `"closed"`, timeout → `"filtered"`
- Retourne `"filtered"` si scapy absent ou pas root (pas de crash)

---

## Tâche 6 — `discovery.py`

Nouveau module :

- `discover_hosts(network, timeout)` — ARP si scapy disponible, sinon ICMP
- `_arp_sweep()` — scapy ARP broadcast
- `_icmp_sweep()` — ping parallèle sur tous les hôtes du CIDR

---

## Tâche 7 — Réécriture `main.py`

Nouveaux arguments ajoutés :

| Argument | Description |
|----------|-------------|
| `--scan-type` | `connect` ou `syn` |
| `--threads` | Nombre de threads parallèles |
| `--delay` | Délai entre ports (rate limiting) |
| `--discover` | Activer la découverte d'hôtes |
| `--banner` | Activer le banner grabbing |
| `--log-level` | Niveau de journalisation |

---

## Tâche 8 — Fichiers de configuration

- `requirements.txt` mis à jour : `tqdm`, `scapy`, `pytest`
- `CLAUDE.md` mis à jour : nouveaux modules, commandes, profils CLI

---

## Ajouts post-plan

Ces éléments ont été ajoutés après la complétion du plan initial :

| Élément | Description |
|---------|-------------|
| `cli.py` | Interface interactive simplifiée pour non-experts |
| Profils prédéfinis | Rapide / Standard / Complet / Personnalisé |
| Vitesses simplifiées | Rapide / Normal / Lent (cache threads/timeout/delay) |
| Auto-détection du mode | SYN si root, TCP connect sinon |
| Gestion `Ctrl+C` | Arrêt propre sans traceback |
| Virgule décimale | Acceptée en plus du point |
