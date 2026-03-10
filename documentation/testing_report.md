# Rapport de tests

## Tests automatisés

Le projet dispose de **74 tests unitaires** organisés en 5 fichiers :

```
tests/
├── test_scanner.py       (27 tests)
├── test_output.py        (10 tests)
├── test_discovery.py     (3 tests)
├── test_main.py          (4 tests + 1 sanitisation)
└── test_sanitisation.py  (29 tests)
```

Lancer les tests :
```bash
python -m pytest tests/ -v
```

Résultat attendu : **74 passed**

---

## Couverture par module

### `test_scanner.py` — 27 tests

| Test | Description |
|------|-------------|
| `test_get_service_name_known` | Port 22 → "ssh", port 80 → "http", port 443 → "https" |
| `test_get_service_name_unknown` | Port 19999 → "unknown" |
| `test_grab_banner_success` | Mock socket → bannière "SSH-2.0-OpenSSH_8.9" retournée |
| `test_grab_banner_timeout` | Timeout socket → retourne "" |
| `test_scan_range_threaded_returns_all_ports` | 3 ports soumis → 3 résultats retournés |
| `test_scan_range_threaded_status` | Port 80 → "open", port 443 → "closed" via fake_scan |
| `test_scan_port_syn_no_scapy` | Sans scapy → retourne "filtered" sans crasher |
| `test_randomize_tous_ports_presents` | Tous les ports présents après shuffle |
| `test_randomize_ordre_different` | Ordre différent après randomize |
| `test_randomize_false_ne_mute_pas` | Liste originale non modifiée si randomize=False |
| `test_max_rate_respecte_intervalle` | Délai minimum respecté avec max_rate |
| `test_jitter_applique_delai_variable` | Délai variable appliqué avec jitter |
| `test_resoudre_cible_ip_inchangee` | IP retournée telle quelle |
| `test_resoudre_cible_localhost` | "localhost" → "127.0.0.1" |
| `test_resoudre_cible_inconnu` | Hostname inconnu → `socket.gaierror` |
| `test_resoudre_cible_ne_plante_pas_sur_cidr` | CIDR retourné tel quel |
| `test_detect_os_returns_known_os_string` | Retourne une valeur valide parmi les 4 possibles |
| `test_detect_os_returns_unknown_without_scapy` | Sans scapy → "unknown" |
| `test_detect_os_returns_unknown_on_no_response` | sr1 retourne None → "unknown" (geteuid patché à 0) |
| `test_detect_service_version_returns_string` | Retourne toujours une chaîne |
| `test_detect_service_version_http_extracts_server_header` | HTTP → extrait "nginx/1.18.0" de l'en-tête Server: |
| `test_detect_service_version_fallback_first_line` | SSH → retourne première ligne de réponse |
| `test_detect_service_version_returns_empty_on_connection_failure` | Connexion refusée → "" |
| `test_detect_firewall_returns_valid_status` | Retourne un statut parmi les 5 valeurs valides |
| `test_detect_firewall_without_scapy` | Sans scapy → retourne résultat de scan_port_connect |
| `test_detect_firewall_silent_on_no_response` | sr1 retourne None → "filtered-silent" |
| `test_detect_firewall_closed_on_rst` | Réponse TCP avec flag RST → "closed" |
| `test_detect_firewall_active_on_icmp` | Réponse ICMP (pas TCP) → "filtered-active" |

### `test_output.py` — 10 tests

| Test | Description |
|------|-------------|
| `test_write_txt` | Ports 22 et 80 présents, version entre crochets si présente |
| `test_write_json` | Clé "80" avec status "open" et service "http" |
| `test_write_csv` | Headers incluent "os", "version", "firewall" ; valeurs correctes |
| `test_write_html` | Balises `<table>`, cible, "open", bannière présents |
| `test_html_stats` | Statistique "open: 1" présente dans le HTML |
| `test_write_xml_creates_valid_file` | Racine `<nmaprun>`, 2 éléments `<port>` |
| `test_write_xml_port_attributes` | `portid="443"`, `protocol="tcp"`, `state="closed"` |
| `test_write_xml_service_version_attribute` | Attribut `version="OpenSSH_8.9"` sur `<service>` |
| `test_write_xml_firewall_element_present` | Élément `<firewall type="filtered-active"/>` présent |
| `test_write_xml_escapes_special_characters` | `<`, `>`, `&` dans bannière → XML valide, valeur préservée |

### `test_discovery.py` — 3 tests

| Test | Description |
|------|-------------|
| `test_icmp_sweep_finds_active_host` | Mock ping → 192.168.1.1 détecté dans /30 |
| `test_discover_hosts_returns_list` | Retourne une liste contenant l'IP active |
| `test_discover_hosts_single_ip` | IP unique → retournée si elle répond |

### `test_main.py` — 4 tests

| Test | Description |
|------|-------------|
| `test_cli_basic` | Scan port 80 → code retour 0, fichier créé |
| `test_cli_json_output` | Port 80 "open" → JSON avec `data["80"]["status"] == "open"` |
| `test_cli_syn_no_scapy` | SYN scan sans scapy → avertissement affiché, pas de crash |
| `test_cli_threads_option` | `--threads 50` → `scan_range_threaded` appelé avec `max_workers=50` |

### `test_sanitisation.py` — 29 tests

| Test | Description |
|------|-------------|
| `test_valider_port_valide` | Ports 1, 80, 65535 acceptés |
| `test_valider_port_zero` | Port 0 → `ValueError` |
| `test_valider_port_trop_grand` | Port 65536 → `ValueError` |
| `test_valider_port_negatif` | Port -1 → `ValueError` |
| `test_valider_cible_ip` | IP simple acceptée |
| `test_valider_cible_cidr` | CIDR accepté |
| `test_valider_cible_hostname` | Hostname valide accepté |
| `test_valider_cible_vide` | Chaîne vide → `ValueError` |
| `test_valider_cible_caracteres_interdits` | Injection dans la cible → `ValueError` |
| `test_valider_cible_trop_long` | Hostname > 253 chars → `ValueError` |
| `test_valider_fichier_sortie_*` | Extensions valides (.txt .json .csv .html .xml), invalides, traversal relatif bloqué |
| `test_parse_ports_*` | Port simple, plage, liste, combinaison, déduplication, plage inversée, invalides |

---

## Cas limites couverts

| Cas | Comportement |
|-----|-------------|
| Timeout = 0 | Refusé par validation — message d'erreur explicite |
| Décimal avec virgule (`0,5`) | Accepté et converti automatiquement en `0.5` |
| Port invalide (0 ou > 65535) | `ValueError` levée par `parse_ports` |
| Hôte introuvable | Message d'erreur + code retour 1 |
| SYN scan sans sudo | Retourne "filtered" + warning dans les logs |
| `--os-detect` sans sudo | "unknown" + warning affiché dans le terminal |
| `--firewall-detect` sans sudo | Repli sur `scan_port_connect` → "open"/"closed"/"filtered" |
| Ctrl+C pendant le scan | Arrêt propre, message "Scan interrompu." sans traceback |
| IPv6 comme cible | Accepté par le validateur |
| Scan multi-hôtes | Un fichier de résultats créé par hôte |
| Bannière avec `<`, `>`, `&` | Export XML correct — caractères échappés par ElementTree |
| HTTPS sur port 443 (version detect) | Pas de probe TLS — repli sur `\r\n` générique, limitation documentée |
