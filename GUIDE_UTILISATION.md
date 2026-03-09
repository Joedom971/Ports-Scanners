# Scanner de ports réseau

Un outil pour analyser les ports ouverts sur une machine ou un réseau.
Fonctionne en mode interactif (questions/réponses) ou en ligne de commande.

---

## Prérequis

### Pour utiliser l'exécutable (le plus simple)
- Un Mac **Intel (x86_64)**
- Aucune installation requise

> ⚠️ Sur Mac **M1 / M2 / M3**, l'exécutable ne fonctionne pas — utilise la méthode VS Code ci-dessous.

### Pour utiliser depuis VS Code
- [Python 3.10 ou plus récent](https://www.python.org/downloads/)
- [VS Code](https://code.visualstudio.com/)

---

## Installation (VS Code uniquement)

À faire **une seule fois** après avoir ouvert le dossier `Port_scanner_Reseau` dans VS Code :

```bash
# 1. Ouvrir le terminal intégré : Ctrl+` (ou Terminal → New Terminal)

# 2. Créer l'environnement virtuel
python3 -m venv .venv

# 3. Activer l'environnement
source .venv/bin/activate

# 4. Installer les dépendances
pip install -r requirements.txt
```

---

## Utilisation

### Mode interactif (recommandé pour débuter)

Le scanner pose des questions pas-à-pas : cible, ports, vitesse, format du rapport.

**Depuis VS Code :**
```bash
source .venv/bin/activate
python cli.py
```

**Depuis l'exécutable :**
```bash
./dist/port-scan-cli
```

**Exemple de session :**
```
╔══════════════════════════════════════════════╗
║          Scanner de ports réseau             ║
║  Mode : TCP connect (standard)               ║
╚══════════════════════════════════════════════╝

── Quelle machine voulez-vous analyser ? ───────
  Adresse IP ou nom de la machine [Entrée = 127.0.0.1] : 192.168.1.1

── Que voulez-vous scanner ? ───────────────────
  1. Scan rapide — ports courants (web, SSH, bureau à distance)  ← recommandé
  2. Scan standard — tous les ports réservés (1 à 1024)
  3. Scan complet — tous les ports (1 à 65535, lent)
  4. Personnalisé — je choisis moi-même
```

---

### Mode ligne de commande (avancé)

**Depuis VS Code :**
```bash
source .venv/bin/activate
python main.py --target 192.168.1.1 --ports 22,80,443
```

**Depuis l'exécutable :**
```bash
./dist/port-scan --target 192.168.1.1 --ports 22,80,443
```

**Exemples :**
```bash
# Scan des ports courants, résultat en HTML
python main.py --target 192.168.1.1 --ports 22,80,443 --output rapport.html

# Scan d'une plage de ports complète
python main.py --target 192.168.1.1 --ports 1-1024 --output scan.json

# Scan discret (2 paquets/seconde, ordre aléatoire)
python main.py --target 192.168.1.1 --ports 1-1024 --max-rate 2 --randomize

# Scan d'un réseau entier (découverte d'hôtes)
python main.py --target 192.168.1.0/24 --discover --ports 22,80
```

---

## Options disponibles

| Option | Description | Exemple |
|--------|-------------|---------|
| `--target` | IP, hostname ou réseau CIDR | `192.168.1.1` |
| `--ports` | Ports à scanner | `22,80,443` ou `1-1024` |
| `--output` | Fichier de résultats | `scan.html` |
| `--scan-type` | `connect` (défaut) ou `syn` (sudo requis) | `--scan-type syn` |
| `--threads` | Nombre de connexions parallèles | `--threads 200` |
| `--timeout` | Délai par port en secondes | `--timeout 0.5` |
| `--discover` | Découvrir les hôtes actifs avant le scan | |
| `--banner` | Afficher les infos des services ouverts | |
| `--randomize` | Mélanger l'ordre des ports | |
| `--max-rate` | Limiter le débit (paquets/seconde) | `--max-rate 5` |
| `--jitter` | Ajouter un délai aléatoire | `--jitter 0.3` |

---

## Formats de rapport

| Extension | Description |
|-----------|-------------|
| `.html` | Rapport visuel coloré, s'ouvre dans un navigateur |
| `.txt` | Texte brut |
| `.csv` | Compatible Excel / tableur |
| `.json` | Données structurées |

---

## Résultats des scans

Les fichiers de résultats sont sauvegardés dans le **dossier depuis lequel la commande est lancée**, sauf si tu spécifies un chemin complet :

```bash
python main.py --target 192.168.1.1 --ports 80 --output ~/Desktop/scan.html
```

---

## ⚠️ Avertissement légal

Ce scanner est destiné à un usage **sur des machines et réseaux dont tu as l'autorisation**.
Scanner un système sans permission est illégal (en Belgique : loi du 28 novembre 2000 sur la criminalité informatique).
Utilise cet outil uniquement sur ton propre réseau ou dans le cadre d'un test autorisé.
