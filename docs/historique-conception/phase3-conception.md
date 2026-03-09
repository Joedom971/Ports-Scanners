# Conception — Phase 3 : Scanner réseau étendu

**Date :** 2026-03-09
**Statut :** Implémenté et mergé sur `main`

---

## Objectif

Étendre le scanner de la Phase 1/2 (scan TCP séquentiel basique) en un outil complet :
- Scan parallèle via threads
- SYN scan (raw packets via scapy)
- Découverte d'hôtes (ARP + ICMP)
- Noms de services et bannières
- Export HTML
- Interface CLI interactive

---

## Architecture retenue : modules séparés

```
Port_scanner_Reseau/
├── cli.py          # Interface interactive simplifiée (non-experts)
├── main.py         # CLI complet via argparse
├── scanner.py      # Bibliothèque de scan (connect, SYN, threaded, banner)
├── discovery.py    # Découverte d'hôtes (ARP + ICMP)
├── output.py       # Export résultats (txt / json / csv / html)
├── requirements.txt
├── tests/
│   ├── test_scanner.py
│   ├── test_output.py
│   ├── test_discovery.py
│   └── test_main.py
└── documentation/
```

---

## Format interne des résultats

Passage de `dict[port] = str` (Phase 1/2) à :

```python
dict[int, dict]
# Exemple :
{
    80:  {"status": "open",     "service": "http",  "banner": "Apache/2.4"},
    22:  {"status": "filtered", "service": "ssh",   "banner": ""},
    443: {"status": "closed",   "service": "https", "banner": ""},
}
```

---

## Flux d'exécution

```
cli.py / main.py  →  parse les paramètres
                  →  si --discover : discovery.py → liste d'hôtes actifs
                  →  pour chaque hôte :
                       scan_range_threaded() dans scanner.py
                       enrichissement : get_service_name() + grab_banner()
                  →  affichage console + stats
                  →  write_output() dans output.py → fichier
```

---

## Choix techniques

| Problème | Solution retenue | Raison |
|----------|-----------------|--------|
| Parallélisme | `ThreadPoolExecutor` | Standard library, simple, efficace pour I/O |
| SYN scan | `scapy` optionnel | Pas de dépendance forcée, fallback propre |
| Découverte | ARP → fallback ICMP | ARP plus fiable en LAN, ICMP universel |
| Export HTML | CSS inline | Aucune dépendance externe, fichier autonome |
| Interface | `cli.py` séparé de `main.py` | Garde `main.py` utilisable en CLI directe |

---

## Dépendances optionnelles

| Package | Usage | Sans ce package |
|---------|-------|-----------------|
| `scapy` | SYN scan + ARP discovery | Fallback TCP connect / ICMP ping |
| `tqdm` | Barre de progression | Silencieusement ignoré |
