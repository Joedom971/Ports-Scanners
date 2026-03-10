# Scanner de ports réseau — Guide d'utilisation

Un outil pour analyser les ports ouverts sur une machine ou un réseau.
Fonctionne en mode interactif (questions/réponses) ou en ligne de commande directe.

---

## Sommaire

1. [Prérequis et installation](#1-prérequis-et-installation)
2. [Activer l'environnement avant chaque session](#2-activer-lenvironnement-avant-chaque-session)
3. [Mode TCP connect — scan standard](#3-mode-tcp-connect--scan-standard)
4. [Mode SYN scan — scan discret](#4-mode-syn-scan--scan-discret)
5. [Toutes les options disponibles](#5-toutes-les-options-disponibles)
6. [Formats de rapport](#6-formats-de-rapport)
7. [Avertissement légal](#7-avertissement-légal)

---

## 1. Prérequis et installation

> À faire **une seule fois** sur ton ordinateur.

### Étape 1 — Installer Python

- Télécharger Python 3.10 ou plus récent sur [python.org/downloads](https://www.python.org/downloads/)
- **Windows :** pendant l'installation, cocher **"Add Python to PATH"** (case en bas de la fenêtre)
- **macOS / Linux :** Python est souvent déjà installé ; vérifier avec `python3 --version` dans le terminal

### Étape 2 — Ouvrir un terminal dans le dossier du projet

**Windows :**
1. Ouvrir le dossier `Port_scanner_Reseau` dans l'Explorateur
2. Cliquer dans la barre d'adresse, taper `cmd` ou `powershell`, appuyer sur Entrée

**macOS :**
1. Ouvrir le Terminal (Spotlight → chercher "Terminal")
2. Taper `cd ` (avec un espace) puis glisser le dossier `Port_scanner_Reseau` dans la fenêtre, appuyer sur Entrée

**Linux :**
1. Clic droit dans le dossier → "Ouvrir un terminal ici" (selon la distribution)
2. Ou : ouvrir un terminal et taper `cd /chemin/vers/Port_scanner_Reseau`

### Étape 3 — Créer l'environnement virtuel

```bash
python3 -m venv .venv        # macOS / Linux
python  -m venv .venv        # Windows (si "python3" ne fonctionne pas)
```

### Étape 4 — Activer l'environnement

```bash
source .venv/bin/activate    # macOS / Linux
.venv\Scripts\activate       # Windows (PowerShell ou cmd)
```

> Le nom `(.venv)` apparaît au début de la ligne de commande quand c'est activé.

### Étape 5 — Installer les dépendances

```bash
pip install -r requirements.txt
```

---

## 2. Activer l'environnement avant chaque session

> À faire **à chaque fois** que tu ouvres un nouveau terminal.

```bash
source .venv/bin/activate    # macOS / Linux
.venv\Scripts\activate       # Windows
```

---

## 3. Mode TCP connect — scan standard

> **Aucun droit particulier requis.** Fonctionne sur tous les systèmes.

Ce mode établit une connexion TCP complète sur chaque port. C'est la méthode par défaut.

### Lancer le mode interactif (recommandé pour débuter)

Le programme pose des questions une par une : quelle machine scanner, quels ports, à quelle vitesse, où sauvegarder.

**macOS / Linux :**
```bash
source .venv/bin/activate
python cli.py
```

**Windows :**
```
.venv\Scripts\activate
python cli.py
```

### Lancer en ligne de commande directe

**macOS / Linux :**
```bash
source .venv/bin/activate

# Scan des ports courants (web, SSH, bureau à distance)
python main.py --target 192.168.1.1 --ports 22,80,443,3389,8080

# Scan de tous les ports réservés (1 à 1024), résultat en HTML
python main.py --target 192.168.1.1 --ports 1-1024 --output rapport.html

# Scan avec détection des versions de services et export XML
python main.py --target 192.168.1.1 --ports 22,80,443 --version-detect --output scan.xml

# Scan discret (2 paquets/seconde, ordre aléatoire)
python main.py --target 192.168.1.1 --ports 1-1024 --max-rate 2 --randomize

# Découvrir les machines actives sur un réseau, puis scanner leurs ports
python main.py --target 192.168.1.0/24 --discover --ports 22,80
```

**Windows :** les commandes sont identiques, remplacer uniquement l'activation :
```
.venv\Scripts\activate
python main.py --target 192.168.1.1 --ports 22,80,443
```

---

## 4. Mode SYN scan — scan discret

> **Nécessite des droits administrateur.** Requiert aussi la librairie `scapy` et un pilote réseau bas niveau.
>
> Ce mode envoie seulement un paquet SYN sans finaliser la connexion — plus discret car les connexions n'apparaissent pas dans les logs des applications.

### Prérequis supplémentaires selon l'OS

#### macOS

Rien de plus à installer. `scapy` est déjà inclus dans `requirements.txt`.

Lancer le scan avec `sudo` (demande le mot de passe administrateur) :

```bash
# Mode interactif en SYN scan
sudo $(pwd)/.venv/bin/python cli.py

# Ligne de commande directe
sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 --ports 1-1024 --scan-type syn
```

> `$(pwd)` insère automatiquement le chemin absolu du dossier courant.
> `sudo python` seul ne fonctionnerait pas car il utiliserait le Python système, pas celui du venv.

#### Linux

Même chose que macOS. Utiliser `sudo` avec le chemin absolu du Python du venv :

```bash
# Trouver le chemin absolu du Python du venv
which python   # après avoir activé le venv — affiche quelque chose comme /home/user/projet/.venv/bin/python

# Mode interactif
sudo /home/user/Port_scanner_Reseau/.venv/bin/python cli.py

# Ligne de commande
sudo /home/user/Port_scanner_Reseau/.venv/bin/python main.py --target 192.168.1.1 --ports 1-1024 --scan-type syn
```

> Remplacer `/home/user/Port_scanner_Reseau/` par le vrai chemin du dossier sur ta machine.

#### Windows

Windows nécessite un pilote réseau supplémentaire pour les paquets bruts :

1. Télécharger et installer **Npcap** sur [npcap.com](https://npcap.com/#download)
   - Pendant l'installation, cocher **"Install Npcap in WinPcap API-compatible mode"**

2. Ouvrir **PowerShell en tant qu'administrateur** :
   - Chercher "PowerShell" dans le menu Démarrer
   - Clic droit → **"Exécuter en tant qu'administrateur"**

3. Naviguer vers le dossier du projet et activer le venv :
   ```
   cd C:\chemin\vers\Port_scanner_Reseau
   .venv\Scripts\activate
   ```

4. Lancer le scan SYN :
   ```
   python cli.py
   ```
   (le mode SYN est détecté automatiquement quand le script est lancé avec les droits admin)

   Ou en ligne de commande :
   ```
   python main.py --target 192.168.1.1 --ports 1-1024 --scan-type syn
   ```

### Exemples de scans SYN avancés (macOS / Linux)

```bash
# SYN scan standard
sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 --ports 1-1024 --scan-type syn

# SYN scan discret : 2 paquets/seconde, ordre aléatoire, délai variable
sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 --ports 1-1024 \
  --scan-type syn --max-rate 2 --randomize --jitter 0.3

# Détection du type de pare-feu (DROP silencieux vs REJECT actif)
sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 --ports 1-1024 \
  --scan-type syn --firewall-detect

# Détection de l'OS de la cible
sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 --ports 22,80 \
  --scan-type syn --os-detect
```

---

## 5. Toutes les options disponibles

```bash
python main.py --help
```

| Option | Description | Exemple |
|--------|-------------|---------|
| `--target` | IP, hostname ou réseau CIDR | `192.168.1.1` ou `192.168.1.0/24` |
| `--ports` | Ports à scanner | `22,80,443` ou `1-1024` ou `22,80-90` |
| `--output` | Fichier de résultats | `--output scan.html` ou `--output scan.xml` |
| `--scan-type` | `connect` (défaut) ou `syn` (sudo requis) | `--scan-type syn` |
| `--threads` | Connexions parallèles (défaut : 100) | `--threads 200` |
| `--timeout` | Délai par port en secondes (défaut : 1.0) | `--timeout 0.5` |
| `--banner` | Lire la bannière des services ouverts | `--ports 22,80 --banner` |
| `--version-detect` | Détecter la version des services ouverts | `--ports 22,80 --version-detect` |
| `--os-detect` | Détecter l'OS de la cible (sudo requis) | `--ports 22,80 --os-detect` |
| `--firewall-detect` | Détecter le type de filtrage (sudo requis) | `--ports 1-1024 --firewall-detect` |
| `--discover` | Découvrir les hôtes actifs avant le scan | `--target 192.168.1.0/24 --discover` |
| `--randomize` | Mélanger l'ordre des ports | `--ports 1-1024 --randomize` |
| `--max-rate` | Débit max en paquets/seconde | `--max-rate 2` |
| `--delay` | Pause fixe entre chaque port | `--delay 0.1` |
| `--jitter` | Délai aléatoire en secondes | `--jitter 0.3` |

### Options qui nécessitent `sudo` (macOS/Linux) ou admin (Windows)

| Option | Pourquoi |
|--------|----------|
| `--scan-type syn` | Envoie des paquets réseau bruts (raw sockets) |
| `--os-detect` | Analyse les réponses au niveau réseau via scapy |
| `--firewall-detect` | Analyse les réponses ICMP via scapy |

---

## 6. Formats de rapport

| Extension | Description | Comment l'ouvrir |
|-----------|-------------|------------------|
| `.html` | Rapport visuel coloré | Double-clic → navigateur web |
| `.xml` | Format compatible Nmap / Metasploit | Éditeur de texte ou outil de sécurité |
| `.json` | Données structurées | Éditeur de texte ou VS Code |
| `.csv` | Tableau | Excel, LibreOffice Calc |
| `.txt` | Texte brut | N'importe quel éditeur |

```bash
# Exemples de sortie
python main.py --target 192.168.1.1 --ports 1-1024 --output rapport.html
python main.py --target 192.168.1.1 --ports 1-1024 --output scan.xml
python main.py --target 192.168.1.1 --ports 1-1024 --output resultats.csv
```

---

## 7. Avertissement légal

Scanner un réseau **sans autorisation est illégal**.

En Belgique : loi du 28 novembre 2000 sur la criminalité informatique.
En France : articles 323-1 à 323-7 du Code pénal.

**Usages autorisés :** ton propre réseau, une machine que tu administres, un environnement de test, un pentest avec accord écrit du propriétaire.

**Usages interdits :** scanner des machines ou réseaux tiers sans permission explicite.
