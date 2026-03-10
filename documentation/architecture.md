# Architecture du projet — Scanner de ports réseau

## Vue d'ensemble

Le projet est un scanner de ports TCP écrit en Python, organisé en **5 modules** qui collaborent ensemble. Chaque module a un rôle précis et délimité.

---

## Les 5 fichiers et leur rôle

### `scanner.py` — Le moteur

C'est le cœur du projet. Il contient toute la logique de scan réseau.

**Ce qu'il fait :**
- Ouvre une connexion TCP vers un port et observe si elle réussit (`scan_port_connect`)
- Forge un paquet SYN brut via scapy pour un scan plus discret (`scan_port_syn`)
- Lance des centaines de scans en parallèle via des threads (`scan_range_threaded`)
- Identifie le nom du service sur un port (`get_service_name`)
- Lit la bannière d'un service (ex. `SSH-2.0-OpenSSH`) (`grab_banner`)

**Ne dépend d'aucun autre fichier du projet.** C'est une bibliothèque autonome.

---

### `discovery.py` — La détection d'hôtes

Avant de scanner les ports d'une machine, encore faut-il savoir quelles machines sont actives sur le réseau.

**Ce qu'il fait :**
- Envoie des requêtes ARP en broadcast pour détecter les machines sur le réseau local (`_arp_sweep`)
- En repli, envoie des pings ICMP en parallèle vers toutes les adresses d'un sous-réseau (`_icmp_sweep`)
- Retourne la liste des IPs qui répondent (`discover_hosts`)

**Appelé par `main.py`** uniquement quand l'option `--discover` est activée.

---

### `output.py` — L'export des résultats

Une fois le scan terminé, ce module se charge d'écrire les résultats dans un fichier.

**Ce qu'il fait :**
- Détecte l'extension du fichier de sortie et choisit le bon format
- Écrit en `.txt` (texte brut), `.json`, `.csv` ou `.html`
- Le rapport HTML inclut un tableau coloré, des statistiques et un style CSS intégré

**Appelé par `main.py`** à la fin du scan.

---

### `main.py` — Le chef d'orchestre

C'est le point d'entrée principal. Il parse les arguments en ligne de commande et coordonne tous les autres modules.

**Ce qu'il fait :**
1. Valide les entrées utilisateur (cible, ports, fichier de sortie)
2. Résout le nom d'hôte en IP une seule fois
3. Appelle `discovery.py` si `--discover` est actif
4. Appelle `scanner.py` pour scanner les ports
5. Enrichit les résultats avec les noms de services et bannières
6. Affiche les résultats dans le terminal
7. Appelle `output.py` pour sauvegarder dans un fichier

**Importe :** `scanner.py` + `output.py` + `discovery.py` (optionnel)

---

### `cli.py` — L'interface interactive

Une surcouche conviviale par-dessus `main.py`. Au lieu de taper des arguments en ligne de commande, l'utilisateur répond à des questions.

**Ce qu'il fait :**
- Pose des questions pas-à-pas (cible, profil, vitesse, format de rapport)
- Traduit les choix simples (ex. "Rapide") en paramètres techniques (threads=400, timeout=0.3)
- Détecte automatiquement si le programme tourne avec les droits root (SYN scan ou TCP connect)
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

**En pratique, voici ce qui se passe quand on lance un scan :**

```
cli.py (optionnel)
  └─► main.py
        ├─► valider_cible() / parse_ports()     [validation des entrées]
        ├─► resoudre_cible()                    [scanner.py — DNS une seule fois]
        ├─► discover_hosts()                    [discovery.py — si --discover]
        ├─► scan_range_threaded()               [scanner.py — scan parallèle]
        │     └─► scan_port_connect() ou        [scanner.py — pour chaque port]
        │         scan_port_syn()
        ├─► get_service_name()                  [scanner.py — enrichissement]
        ├─► grab_banner()                       [scanner.py — si --banner]
        └─► write_output()                      [output.py — sauvegarde fichier]
```

---

## Flux d'un scan complet

```
1. L'utilisateur tape : python main.py --target 192.168.1.1 --ports 1-1024 --output scan.html

2. main.py valide la cible et les ports

3. main.py résout "192.168.1.1" en IP (déjà une IP ici, pas de DNS nécessaire)

4. scanner.py lance 100 threads en parallèle
   Chaque thread tente une connexion TCP sur un port différent
   → retourne "open", "closed" ou "filtered"

5. Pour chaque port, main.py appelle get_service_name()
   → "80" devient "http", "22" devient "ssh", etc.

6. main.py affiche les résultats dans le terminal

7. output.py génère scan.html avec un tableau coloré
   → vert = open, rouge = closed, gris = filtered
```

---

## Résumé des dépendances

| Fichier | Importe | Est importé par |
|---------|---------|-----------------|
| `scanner.py` | — | `main.py` |
| `discovery.py` | — | `main.py` |
| `output.py` | — | `main.py` |
| `main.py` | `scanner`, `output`, `discovery` | `cli.py` |
| `cli.py` | `main` | — |
