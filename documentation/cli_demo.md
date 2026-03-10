# Démonstration du CLI

---

## Mode interactif — `python cli.py`

```
╔══════════════════════════════════════════════╗
║          Scanner de ports réseau             ║
║  Mode : TCP connect (standard)               ║
╚══════════════════════════════════════════════╝

  Répondez aux questions ci-dessous.
  Appuyez sur Entrée pour garder la valeur recommandée.

  ── Quelle machine voulez-vous analyser ? ───────
  Exemples : 192.168.1.1  |  monserveur.local  |  192.168.1.0/24
  Adresse IP ou nom de la machine [Entrée = 127.0.0.1] : 192.168.1.1

  ── Que voulez-vous scanner ? ───────────────────

  Choisissez un profil :
    1. Scan rapide   — ports courants (web, SSH, bureau à distance)  ← recommandé
    2. Scan standard — tous les ports réservés (1 à 1024)
    3. Scan complet  — tous les ports (1 à 65535, lent)
    4. Personnalisé  — je choisis moi-même
  Votre choix [Entrée = 1] : 1

  ── Quelle vitesse de scan ? ────────────────────

  Choisissez une vitesse :
    1. Rapide  (réseau local)
    2. Normal  (recommandé)  ← recommandé
    3. Lent    (discret)
    4. Furtif  (anti-détection)
  Votre choix [Entrée = 2] :

  ── Options supplémentaires ─────────────────────
  (Entrée = non pour toutes)
  Chercher d'abord les appareils actifs sur le réseau ? [o/N] : n
  Afficher les infos des services trouvés (version, bannière) ? [o/N] : o
  Détecter la version des services trouvés (ex: Apache/2.4) ? [o/N] : o
  Détecter le type de pare-feu (DROP silencieux vs REJECT actif) ? [o/N] : n
  Tenter de détecter l'OS de la cible ? [o/N] : n

  ── Où sauvegarder les résultats ? ──────────────

  Format du rapport :
    1. Rapport visuel HTML  (s'ouvre dans un navigateur)  ← recommandé
    2. Fichier texte .txt   (simple)
    3. Tableau CSV          (Excel / tableur)
    4. Données JSON         (développeurs)
    5. Format XML           (compatible Nmap / Metasploit)
  Votre choix [Entrée = 1] :
  Nom du fichier de résultats [Entrée = scan_results.html] :

╔══════════════════════════════════════════════╗
║               Récapitulatif                  ║
╠══════════════════════════════════════════════╣
║  Cible       : 192.168.1.1                    ║
║  Ports       : 22,80,443,3389,8080            ║
║  Vitesse     : Normal                         ║
║  Mode        : connect                        ║
║  Découverte  : non                            ║
║  Infos srv.  : oui                            ║
║  Ver. svc    : oui                            ║
║  Pare-feu    : non                            ║
║  Détect. OS  : non                            ║
║  Rapport     : scan_results.html              ║
╚══════════════════════════════════════════════╝

Lancer le scan ? [O/n] :

Scan de 192.168.1.1 — 5 ports (connect)
     22  open       ssh             SSH-2.0-OpenSSH_8.9  [OpenSSH_8.9]
     80  open       http            Apache/2.4.54         [Apache/2.4.54 (Ubuntu)]
    443  closed     https
   3389  filtered   ms-wbt-server
   8080  filtered   http-alt

  open: 2  closed: 1  filtered: 2

Résultats sauvegardés dans scan_results.html
```

---

## Mode ligne de commande — `python main.py`

### Scan simple

```
$ python main.py --target 192.168.1.1 --ports 22,80,443

Scan de 192.168.1.1 — 3 ports (connect)
     22  open       ssh
     80  open       http
    443  closed     https

  open: 2  closed: 1  filtered: 0

Résultats sauvegardés dans scan_results.txt
```

### Scan avec bannières et détection de version

```
$ python main.py --target 192.168.1.1 --ports 22,80,443 --banner --version-detect

Scan de 192.168.1.1 — 3 ports (connect)
     22  open       ssh             SSH-2.0-OpenSSH_8.9   [OpenSSH_8.9]
     80  open       http            Apache/2.4.54          [Apache/2.4.54 (Ubuntu)]
    443  closed     https

  open: 2  closed: 1  filtered: 0

Résultats sauvegardés dans scan_results.txt
```

### Scan avec détection OS et export XML

```
$ sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 \
    --ports 22,80,443 --os-detect --version-detect --output scan.xml

  OS détecté : Linux/Unix

Scan de 192.168.1.1 — 3 ports (connect)
     22  open       ssh             SSH-2.0-OpenSSH_8.9   [OpenSSH_8.9]
     80  open       http            Apache/2.4.54          [Apache/2.4.54 (Ubuntu)]
    443  closed     https

  open: 2  closed: 1  filtered: 0

Résultats sauvegardés dans scan.xml
```

### Scan avec détection de pare-feu

```
$ sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 \
    --ports 1-1024 --firewall-detect --output scan.html

Scan de 192.168.1.1 — 1024 ports (connect)
     22  open       ssh
     80  open       http
    443  closed     https
    ...
   8080  filtered   (filtered-silent)   http-alt
   8443  filtered   (filtered-active)   https-alt
    ...

  open: 2  closed: 87  filtered: 935

Résultats sauvegardés dans scan.html
```

### Scan d'une plage avec export HTML

```
$ python main.py --target 192.168.1.1 --ports 1-1024 --threads 200 --output rapport.html

Scan de 192.168.1.1 — 1024 ports (connect)
     21  open       ftp
     22  open       ssh             SSH-2.0-OpenSSH_8.9
     80  open       http            Apache/2.4.54
    443  closed     https
    ...

  open: 3  closed: 87  filtered: 934

Résultats sauvegardés dans rapport.html
```

### Scan furtif SYN (nécessite sudo)

```
$ sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 \
    --ports 1-1024 --scan-type syn --max-rate 2 --randomize

Scan de 192.168.1.1 — 1024 ports (syn)
     80  open       http
     22  open       ssh
    443  closed     https
    ...

  open: 2  closed: 89  filtered: 933

Résultats sauvegardés dans scan_results.txt
```

### Découverte d'hôtes sur un réseau, puis scan

```
$ python main.py --target 192.168.1.0/24 --discover --ports 22,80

3 hôte(s) actif(s) : 192.168.1.1, 192.168.1.10, 192.168.1.42

Scan de 192.168.1.1 — 2 ports (connect)
     22  open       ssh
     80  open       http

Scan de 192.168.1.10 — 2 ports (connect)
     22  open       ssh
     80  filtered   http

Scan de 192.168.1.42 — 2 ports (connect)
     22  filtered   ssh
     80  open       http

Résultats de 192.168.1.1 sauvegardés dans scan_results_192_168_1_1.txt
Résultats de 192.168.1.10 sauvegardés dans scan_results_192_168_1_10.txt
Résultats de 192.168.1.42 sauvegardés dans scan_results_192_168_1_42.txt
```
