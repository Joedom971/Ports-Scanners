# Rapport de tests

## Tests automatisés

Le projet dispose de 19 tests unitaires organisés en 4 fichiers :

```
tests/
├── test_scanner.py    (7 tests)
├── test_output.py     (5 tests)
├── test_discovery.py  (3 tests)
└── test_main.py       (4 tests)
```

Lancer les tests :
```bash
python -m pytest tests/ -v
```

Résultat attendu : **19 passed**

---

## Couverture par module

### `test_scanner.py`

| Test | Description |
|------|-------------|
| `test_get_service_name_known` | Port 22 → "ssh", port 80 → "http", port 443 → "https" |
| `test_get_service_name_unknown` | Port 19999 → "unknown" |
| `test_grab_banner_success` | Mock socket → bannière "SSH-2.0-OpenSSH_8.9" retournée |
| `test_grab_banner_timeout` | Timeout socket → retourne "" |
| `test_scan_range_threaded_returns_all_ports` | 3 ports soumis → 3 résultats retournés |
| `test_scan_range_threaded_status` | Port 80 → "open", port 443 → "closed" via fake_scan |
| `test_scan_port_syn_no_scapy` | Sans scapy → retourne "filtered" sans crasher |

### `test_output.py`

| Test | Description |
|------|-------------|
| `test_write_txt` | Port 80 open et port 22 closed présents dans le fichier |
| `test_write_json` | Clé "80" avec status "open" et service "http" |
| `test_write_csv` | Ports 80 et 22 présents dans les lignes CSV |
| `test_write_html` | Balise `<table>`, cible, "open", bannière "Apache" présents |
| `test_html_stats` | Statistique "open: 1" présente dans le HTML |

### `test_discovery.py`

| Test | Description |
|------|-------------|
| `test_icmp_sweep_finds_active_host` | Mock ping → 192.168.1.1 détecté dans /30 |
| `test_discover_hosts_returns_list` | Retourne une liste contenant l'IP active |
| `test_discover_hosts_single_ip` | IP unique → retournée si elle répond |

### `test_main.py`

| Test | Description |
|------|-------------|
| `test_cli_basic` | Scan port 80 → code retour 0, fichier créé |
| `test_cli_json_output` | Port 80 "open" → JSON avec `data["80"]["status"] == "open"` |
| `test_cli_syn_no_scapy` | SYN scan sans scapy → avertissement affiché, pas de crash |
| `test_cli_threads_option` | `--threads 50` → `scan_range_threaded` appelé avec `max_workers=50` |

---

## Tests manuels effectués

| Cible | Ports | Mode | Résultat |
|-------|-------|------|---------|
| 127.0.0.1 | 22,80,443 | TCP connect | Résultats cohérents selon services actifs |
| 192.168.128.1 | 22,80,443,3389,8080 | SYN scan | Port 443 fermé, autres filtrés |
| 192.168.128.1 | 1-1024 | SYN scan | 1 fermé (443), 1023 filtrés (timeout=0 → invalide) |

---

## Cas limites connus

| Cas | Comportement |
|-----|-------------|
| Timeout = 0 | Tous les ports apparaissent "filtered" — timeout minimum de 0.1s appliqué dans le CLI |
| Décimal avec virgule (ex. `0,5`) | Accepté et converti automatiquement en `0.5` |
| Port invalide (0 ou > 65535) | `ValueError` levée par `parse_ports` |
| Hôte introuvable | Retourne "filtered" sur tous les ports |
| SYN scan sans sudo | Retourne "filtered" sur tous les ports + warning dans les logs |
| Ctrl+C pendant le scan | Arrêt propre, message "Scan interrompu." sans traceback |
