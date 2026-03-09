# Scanner de ports réseau

Un outil Python pour analyser les ports ouverts sur une machine ou un réseau local.
Développé dans le cadre d'un projet d'apprentissage réseau.

---

## C'est quoi un scanner de ports ?

Chaque machine connectée à un réseau communique via des **ports**. Un port, c'est comme une porte d'entrée numérotée (de 1 à 65535) par laquelle un service peut recevoir des connexions.

Exemples de ports connus :
| Port | Service |
|------|---------|
| 22 | SSH (accès distant sécurisé) |
| 80 | HTTP (sites web) |
| 443 | HTTPS (sites web sécurisés) |
| 3389 | Bureau à distance Windows |

Un scanner de ports **tente de se connecter** à chaque port d'une machine et observe la réponse :
- **open** → le port répond, un service tourne derrière
- **closed** → le port répond mais refuse la connexion (rien ne tourne)
- **filtered** → pas de réponse (pare-feu ou machine éteinte)

Cet outil sert à cartographier les services actifs sur un réseau — utile pour l'administration système, l'audit de sécurité, ou simplement comprendre ce qui tourne sur son réseau.

---

## Comment ça fonctionne ?

### Le scan TCP connect (mode par défaut)

C'est la méthode la plus simple. Pour chaque port, le scanner effectue une **poignée de main TCP complète** (le protocole de base d'internet) :

```
Scanner  →  SYN        →  Machine cible
Scanner  ←  SYN-ACK    ←  Machine cible  (port ouvert)
Scanner  →  ACK        →  Machine cible
Scanner  →  FIN        →  Machine cible  (on ferme proprement)
```

Si la machine répond `RST` (reset) au lieu de `SYN-ACK`, le port est fermé.
Si rien ne répond après le délai configuré, le port est filtré.

### Le scan SYN (mode furtif, nécessite sudo)

Plus discret. Le scanner envoie uniquement le premier paquet `SYN` sans jamais finaliser la connexion. La connexion n'est jamais établie complètement, donc elle n'apparaît pas dans les logs des applications.

```
Scanner  →  SYN        →  Machine cible
Scanner  ←  SYN-ACK    ←  Machine cible  (port ouvert, mais on n'envoie pas le ACK)
```

Ce mode nécessite des droits administrateur (`sudo`) car il envoie des **paquets bruts** (raw packets) directement au niveau réseau, sans passer par le système d'exploitation.

### Le parallélisme (pourquoi c'est rapide)

Scanner 1024 ports un par un à 1 seconde de timeout = **17 minutes**.
Avec 100 threads parallèles = **quelques secondes**.

Le projet utilise `ThreadPoolExecutor` : un groupe de fils d'exécution (threads) qui travaillent simultanément, chacun scannant un port différent.

---

## Structure du projet

```
Port_scanner_Reseau/
├── cli.py          → Interface interactive pas-à-pas (pour débuter)
├── main.py         → Interface ligne de commande complète
├── scanner.py      → Moteur de scan (la logique principale)
├── output.py       → Export des résultats (txt, json, csv, html)
├── discovery.py    → Découverte des machines actives sur un réseau
├── tests/          → Tests automatisés (57 tests)
└── documentation/  → Rapports de conception, tests, éthique
```

---

## Les librairies utilisées

### Bibliothèque standard Python (aucune installation)

**`socket`**
La librairie réseau de base de Python. C'est elle qui effectue réellement les connexions TCP. Elle permet d'ouvrir une socket (point de connexion), de la connecter à une adresse IP + port, et de lire/écrire des données.
```python
sock.connect_ex(("192.168.1.1", 80))  # retourne 0 si ouvert
```

**`concurrent.futures` (ThreadPoolExecutor)**
Gère le pool de threads parallèles. Au lieu de lancer et gérer chaque thread manuellement, `ThreadPoolExecutor` distribue automatiquement le travail entre N threads et collecte les résultats.
```python
with ThreadPoolExecutor(max_workers=100) as executor:
    futures = {executor.submit(scanner, port): port for port in ports}
```

**`subprocess`**
Permet d'exécuter des commandes système depuis Python — utilisé pour lancer des pings (`ping -c 1 192.168.1.1`) lors de la découverte d'hôtes par ICMP.

**`ipaddress`**
Analyse et manipule les adresses IP et les réseaux CIDR (`192.168.1.0/24`). Permet de calculer la liste de toutes les adresses d'un sous-réseau sans faire les calculs binaires à la main.

**`argparse`**
Gère les arguments en ligne de commande (`--target`, `--ports`, etc.). Génère automatiquement le message `--help`.

**`json` / `csv`**
Export des résultats dans ces formats standards.

**`threading`**
Utilisé pour le rate limiting global : un `Lock` (verrou) partagé entre tous les threads garantit qu'un seul paquet est envoyé à la fois quand `--max-rate` est activé.

**`html`**
Échappe les caractères spéciaux (`<`, `>`, `&`) dans le rapport HTML pour éviter les injections de code.

---

### Librairies optionnelles (à installer séparément)

**`scapy`**
La librairie Python de manipulation de paquets réseau. Elle permet de forger des paquets TCP/IP bruts "à la main" — c'est ce qui rend le SYN scan possible. Sans scapy, le scanner bascule automatiquement en TCP connect.
```python
pkt = IP(dst="192.168.1.1") / TCP(dport=80, flags="S")  # paquet SYN forgé
resp = sr1(pkt, timeout=1)  # envoi et attente de réponse
```
Scapy est aussi utilisée pour le balayage ARP lors de la découverte d'hôtes sur un réseau local.

**`tqdm`**
Affiche une barre de progression dans le terminal pendant le scan. Purement cosmétique — si absent, le scanner fonctionne normalement sans barre.

**`pytest`**
Framework de tests automatisés. Permet de vérifier que chaque fonction du projet se comporte correctement avec 57 tests unitaires.

---

## Les fonctionnalités de furtivité

Pour réduire la détection par les systèmes de surveillance réseau (IDS) :

**`--randomize`** — mélange l'ordre des ports avant le scan. Un scan séquentiel (1, 2, 3, 4...) est une signature immédiatement reconnaissable par un IDS.

**`--max-rate 2`** — limite le débit à 2 paquets par seconde via un verrou global partagé entre tous les threads. Sans ça, 100 threads enverraient 100 paquets simultanément.

**`--jitter 0.3`** — ajoute un délai aléatoire entre 0 et 0.3 secondes. Un délai fixe produit un rythme régulier détectable ; un délai variable ressemble plus à du trafic humain.

**Résolution DNS unique** — si tu scannes `monserveur.local`, le nom est résolu en IP une seule fois au départ, pas à chaque connexion. Évite N requêtes DNS visibles sur le réseau.

---

## Installation et utilisation

### Prérequis

- Python 3.10 ou plus récent
- VS Code *(recommandé)*

### Première installation (VS Code)

```bash
# Dans le terminal VS Code (Ctrl+`)
python3 -m venv .venv          # crée un environnement Python isolé
source .venv/bin/activate       # l'active
pip install -r requirements.txt # installe les dépendances
```

### Lancer le scanner

```bash
# Mode interactif (recommandé)
python cli.py

# Ligne de commande directe
python main.py --target 192.168.1.1 --ports 22,80,443 --output rapport.html
```

### Lancer les tests

```bash
python -m pytest tests/ -v
# 57 tests, résultat attendu : 57 passed
```

---

## Exemple de résultat

```
Scan de 192.168.1.1 — 5 ports (connect)
   22  open       ssh             SSH-2.0-OpenSSH_8.9
   80  filtered   http
  443  closed     https
 3389  filtered   ms-wbt-server
 8080  filtered   http-alt

  open: 1  closed: 1  filtered: 3
```

---

## ⚠️ Avertissement légal

Scanner un réseau **sans autorisation** est illégal.

En Belgique, la loi du 28 novembre 2000 sur la criminalité informatique punit l'accès non autorisé à un système informatique. La directive européenne NIS2 renforce ces obligations pour les infrastructures critiques.

**Usages autorisés :** ton propre réseau, une machine que tu administres, un environnement de test, un pentest avec accord écrit du propriétaire.

**Usages interdits :** scanner des machines ou réseaux tiers sans permission.
