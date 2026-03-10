# Conception — Scanner réseau étendu

**Date :** 2026-03-09 (mis à jour 2026-03-10)
**Statut :** Implémenté et mergé sur `main`

---

## Objectif

Étendre le scanner de la Phase 1/2 (scan TCP séquentiel basique) en un outil complet :
- Scan parallèle via threads
- SYN scan (raw packets via scapy)
- Découverte d'hôtes (ARP + ICMP)
- Noms de services et bannières
- Détection de version des services (probes protocoles)
- Détection d'OS via TTL fingerprinting
- Détection du type de pare-feu (DROP silencieux vs REJECT actif)
- Export multi-formats : HTML, XML, JSON, CSV, TXT
- Interface CLI interactive
- Compatibilité Windows / macOS / Linux

---

## Architecture retenue : modules séparés

```
Port_scanner_Reseau/
├── cli.py          # Interface interactive simplifiée (non-experts)
├── main.py         # CLI complet via argparse
├── scanner.py      # Bibliothèque de scan (connect, SYN, threaded, banner, version, OS, firewall)
├── discovery.py    # Découverte d'hôtes (ARP + ICMP)
├── output.py       # Export résultats (txt / json / csv / html / xml)
├── requirements.txt
├── tests/
│   ├── test_scanner.py
│   ├── test_output.py
│   ├── test_discovery.py
│   ├── test_main.py
│   └── test_sanitisation.py
└── documentation/
```

---

## Format interne des résultats

```python
dict[int, dict]
# Exemple :
{
    22:  {"status": "open",     "service": "ssh",   "banner": "SSH-2.0-OpenSSH_8.9",
          "os": "Linux/Unix",   "version": "OpenSSH_8.9", "firewall": ""},
    80:  {"status": "open",     "service": "http",  "banner": "Apache/2.4.54",
          "os": "",             "version": "Apache/2.4.54 (Ubuntu)", "firewall": ""},
    443: {"status": "closed",   "service": "https", "banner": "",
          "os": "",             "version": "", "firewall": ""},
    8080:{"status": "filtered", "service": "http-alt", "banner": "",
          "os": "",             "version": "", "firewall": "filtered-silent"},
}
```

---

## Flux d'exécution

```
cli.py / main.py  →  parse les paramètres + validation des entrées
                  →  résolution DNS unique (resoudre_cible)
                  →  si --discover : discovery.py → liste d'hôtes actifs
                  →  si --os-detect : detect_os() → TTL fingerprinting (scapy + sudo)
                  →  pour chaque hôte :
                       scan_range_threaded() dans scanner.py
                       enrichissement par port :
                         get_service_name()
                         grab_banner() si --banner
                         detect_service_version() si --version-detect
                         detect_firewall() si --firewall-detect (ports filtrés uniquement)
                  →  affichage console + stats
                  →  write_output() dans output.py → fichier (un par hôte si multi-hôtes)
```

---

## Choix techniques

| Problème | Solution retenue | Raison |
|----------|-----------------|--------|
| Parallélisme | `ThreadPoolExecutor` | Standard library, simple, efficace pour I/O |
| SYN scan | `scapy` optionnel | Pas de dépendance forcée, fallback propre |
| Découverte | ARP → fallback ICMP | ARP plus fiable en LAN, ICMP universel |
| Export HTML | CSS inline | Aucune dépendance externe, fichier autonome |
| Export XML | `xml.etree.ElementTree` | Standard library, compatible Nmap/Metasploit |
| Interface | `cli.py` séparé de `main.py` | Garde `main.py` utilisable en CLI directe |
| Détection OS | TTL fingerprinting (scapy) | Simple, efficace, pas de probe intrusif |
| Détection version | Probes protocole-spécifiques | Plus précis que bannière brute |
| Détection pare-feu | Analyse réponse SYN (scapy) | Distingue DROP vs REJECT vs RST |
| Compatibilité Windows | `getattr(os, "geteuid", lambda: 1)()` | `geteuid` inexistant sur Windows |
| `ECONNREFUSED` Windows | `_ECONNREFUSED_CODES` set | Code erreur différent (`WSAECONNREFUSED`) |
| Ping Linux vs macOS | Détection `platform.system()` | `-W` en secondes (Linux) vs ms (macOS) |

---

## Dépendances optionnelles

| Package | Usage | Sans ce package |
|---------|-------|-----------------|
| `scapy` | SYN scan, ARP discovery, OS detect, firewall detect | Fallback TCP connect / ICMP ping / "unknown" |
| `tqdm` | Barre de progression | Silencieusement ignoré |
