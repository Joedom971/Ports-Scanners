# Plan d'implémentation

**Date :** 2026-03-09 (mis à jour 2026-03-10)
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
| 8 | `requirements.txt` | ✅ |
| 9 | Détection OS via TTL fingerprinting (`--os-detect`) | ✅ |
| 10 | Détection version des services (`--version-detect`) | ✅ |
| 11 | Détection type de pare-feu (`--firewall-detect`) | ✅ |
| 12 | Export XML compatible Nmap (`--output scan.xml`) | ✅ |
| 13 | Compatibilité Windows / macOS / Linux | ✅ |

**Total : 74 tests, tous passants.**

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

---

## Tâche 9 — Détection d'OS (`--os-detect`)

Ajout dans `scanner.py` : `detect_os(ip, timeout)`

- Envoie un paquet SYN sur les ports 80, 443, 22 via scapy
- Analyse le TTL de la réponse SYN-ACK :
  - TTL ≤ 64 → `"Linux/Unix"`
  - TTL ≤ 128 → `"Windows"`
  - TTL > 128 → `"Network device"`
  - Pas de réponse → `"unknown"`
- Nécessite scapy + sudo ; retourne `"unknown"` sinon

---

## Tâche 10 — Détection de version (`--version-detect`)

Ajout dans `scanner.py` : `detect_service_version(ip, port, service_name, timeout)`

- Dictionnaire `_SERVICE_PROBES` : requête adaptée par protocole (HTTP HEAD, SMTP EHLO, etc.)
- HTTP/HTTPS : extrait l'en-tête `Server:` de la réponse
- SSH, FTP, SMTP : retourne la première ligne de réponse
- Fonctionne sans sudo

---

## Tâche 11 — Détection de pare-feu (`--firewall-detect`)

Ajout dans `scanner.py` : `detect_firewall(ip, port, timeout)`

- Analyse la réponse à un paquet SYN brut (scapy) :
  - SYN-ACK → `"open"`
  - RST → `"closed"`
  - Réponse ICMP → `"filtered-active"` (pare-feu REJECT)
  - Timeout → `"filtered-silent"` (pare-feu DROP)
- Repli sur `scan_port_connect()` si scapy indisponible ou pas root
- Appliqué uniquement aux ports déjà classés `"filtered"` par le scan initial

---

## Tâche 12 — Export XML (`--output scan.xml`)

Ajout dans `output.py` : `_write_xml(results, path, target, scan_type)`

- Format compatible Nmap/Metasploit : `<nmaprun>/<host>/<ports>/<port>`
- Chaque `<port>` contient `<state>`, `<service>` (avec attributs version/banner), `<firewall>`
- Caractères spéciaux échappés automatiquement par `ElementTree`
- Extension `.xml` ajoutée dans `valider_fichier_sortie()` dans `main.py`

---

## Tâche 13 — Compatibilité cross-plateforme

Corrections appliquées sur tous les modules :

| Fichier | Correction |
|---------|------------|
| `scanner.py` | `getattr(os, "geteuid", lambda: 1)()` — `geteuid` inexistant sur Windows |
| `scanner.py` | `_ECONNREFUSED_CODES` inclut `WSAECONNREFUSED` (code Windows) |
| `discovery.py` | Ping adapté par OS : `-W` secondes (Linux), `-W` ms (macOS), `-n -w` ms (Windows) |
| `main.py` | `valider_cible()` accepte les adresses IPv6 via `ipaddress.ip_address()` |
| `main.py` | Scan multi-hôtes : un fichier de résultats par hôte |
| `cli.py` | `_print_safe()` — repli ASCII si terminal Windows ne supporte pas UTF-8 |

---

## Ajouts post-plan initial (Phase 2)

Ces éléments ont été ajoutés après la complétion du plan initial :

| Élément | Description |
|---------|-------------|
| `cli.py` | Interface interactive simplifiée pour non-experts |
| Profils prédéfinis | Rapide / Standard / Complet / Personnalisé |
| Vitesses simplifiées | Rapide / Normal / Lent / Furtif (cache threads/timeout/delay/max-rate) |
| Auto-détection du mode | SYN si root, TCP connect sinon |
| Gestion `Ctrl+C` | Arrêt propre sans traceback |
| Virgule décimale | Acceptée en plus du point |
| `test_sanitisation.py` | 29 tests de validation des entrées utilisateur |
| Options furtivité | `--randomize`, `--max-rate`, `--jitter` |
