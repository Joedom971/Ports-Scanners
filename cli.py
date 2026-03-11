"""Interface CLI interactive pour le scanner de ports.

Lance un assistant simple pas-à-pas.

Utilisation :
  python cli.py
"""

import os


def _print_safe(text: str) -> None:
    """Affiche du texte en remplaçant les caractères non-ASCII si nécessaire."""
    try:
        print(text)
    except UnicodeEncodeError:
        # Remplacement des caractères de bordure par des équivalents ASCII
        ascii_text = (text
            .replace("╔", "+").replace("╗", "+").replace("╚", "+").replace("╝", "+")
            .replace("║", "|").replace("═", "=").replace("─", "-")
            .replace("┄", "-")
        )
        print(ascii_text)


# ── Vitesse → paramètres techniques ───────────────────────────────────────────
# Chaque vitesse configure automatiquement threads, timeout, délai et options de furtivité.
# L'utilisateur choisit une vitesse simple ; les détails techniques sont gérés ici.
VITESSES = {
    "Rapide  (réseau local)":    {"threads": 400, "timeout": 0.3, "delay": 0.0, "jitter": 0.0,  "max_rate": 0.0,  "randomize": False},
    "Normal  (recommandé)":      {"threads": 100, "timeout": 1.0, "delay": 0.0, "jitter": 0.0,  "max_rate": 0.0,  "randomize": False},
    "Lent    (discret)":         {"threads": 20,  "timeout": 2.0, "delay": 0.1, "jitter": 0.0,  "max_rate": 0.0,  "randomize": False},
    # Mode furtif : peu de threads, débit limité à 2 paquets/s, ordre des ports aléatoire
    "Furtif  (anti-détection)":  {"threads": 5,   "timeout": 3.0, "delay": 0.0, "jitter": 0.0,  "max_rate": 2.0,  "randomize": True},
}

# ── Profils de scan ────────────────────────────────────────────────────────────
# Associe chaque profil à une spécification de ports (None = l'utilisateur saisit lui-même)
PROFILS = {
    "Scan rapide   — ports courants (web, SSH, bureau à distance)": "22,80,443,3389,8080",
    "Scan standard — tous les ports réservés (1 à 1024)":           "1-1024",
    "Scan complet  — tous les ports (1 à 65535, lent)":             "1-65535",
    "Personnalisé  — je choisis moi-même":                          None,
}


def choisir(question: str, options: list, defaut_idx: int = 0) -> str:
    """Affiche un menu numéroté et retourne l'option choisie par l'utilisateur."""
    print(f"\n  {question}")
    for i, opt in enumerate(options, 1):
        marqueur = "  ← recommandé" if i == defaut_idx + 1 else ""
        print(f"    {i}. {opt}{marqueur}")
    while True:
        rep = input(f"  Votre choix [Entrée = {defaut_idx + 1}] : ").strip()
        if not rep:
            # Entrée vide → on prend le choix par défaut
            return options[defaut_idx]
        if rep.isdigit() and 1 <= int(rep) <= len(options):
            return options[int(rep) - 1]
        print("  Choix invalide, entrez un numéro.")


def demander(question: str, defaut: str = "") -> str:
    """Affiche une question et retourne la saisie de l'utilisateur (ou la valeur par défaut)."""
    indication = f" [Entrée = {defaut}]" if defaut else ""
    rep = input(f"  {question}{indication} : ").strip()
    return rep if rep else defaut  # si l'utilisateur appuie sur Entrée, utilise le défaut


def oui_non(question: str, defaut: bool = True) -> bool:
    """Pose une question oui/non et retourne True ou False."""
    indication = "[O/n]" if defaut else "[o/N]"
    rep = input(f"  {question} {indication} : ").strip().lower()
    if not rep:
        return defaut  # Entrée vide → valeur par défaut
    # Accepte "o", "oui", "y", "yes" comme réponse positive
    return rep in ("o", "oui", "y", "yes")


def separateur(titre: str = "") -> None:
    """Affiche une ligne de séparation visuelle avec un titre optionnel."""
    if titre:
        print(f"\n  ── {titre} {'─' * (44 - len(titre))}")
    else:
        print(f"\n  {'─' * 48}")


def main() -> int:
    # Détecte si le programme tourne avec les droits root (uid 0)
    # getattr avec lambda évite l'erreur sur Windows où os.geteuid n'existe pas
    est_root = getattr(os, "geteuid", lambda: 1)() == 0

    # Affichage de l'en-tête avec le mode de scan détecté automatiquement
    _print_safe("\n╔══════════════════════════════════════════════╗")
    _print_safe("║          Scanner de ports réseau             ║")
    if est_root:
        _print_safe("║  Mode : SYN scan (avancé, root détecté)      ║")
    else:
        _print_safe("║  Mode : TCP connect (standard)               ║")
    _print_safe("╚══════════════════════════════════════════════╝")
    print("\n  Répondez aux questions ci-dessous.")
    print("  Appuyez sur Entrée pour garder la valeur recommandée.")

    # ── 1. Cible ──────────────────────────────────────────────────────────────
    separateur("Quelle machine voulez-vous analyser ?")
    print("  Exemples : 192.168.1.1  |  monserveur.local  |  192.168.1.0/24")
    target = demander("Adresse IP ou nom de la machine", "127.0.0.1")

    # ── 2. Profil ─────────────────────────────────────────────────────────────
    separateur("Que voulez-vous scanner ?")
    profil_choisi = choisir(
        "Choisissez un profil :",
        list(PROFILS.keys()),
        defaut_idx=0,
    )
    ports = PROFILS[profil_choisi]
    if ports is None:
        # Profil "Personnalisé" : l'utilisateur saisit ses propres ports
        print("\n  Exemples : 80  |  22,80,443  |  1-1024  |  22,80-85")
        ports = demander("Entrez les ports à scanner", "22,80,443")

    # ── 3. Vitesse ────────────────────────────────────────────────────────────
    separateur("Quelle vitesse de scan ?")
    vitesse_choisie = choisir(
        "Choisissez une vitesse :",
        list(VITESSES.keys()),
        defaut_idx=1,  # "Normal" est recommandé par défaut
    )
    # Récupère les paramètres techniques associés à la vitesse choisie
    perf = VITESSES[vitesse_choisie]

    # ── 4. Options extras ─────────────────────────────────────────────────────
    separateur("Options supplémentaires")
    print("  (Entrée = non pour toutes)")
    discover = oui_non(
        "Chercher d'abord les appareils actifs sur le réseau ?",
        defaut=False,
    )
    banner = oui_non(
        "Afficher les infos des services trouvés (version, bannière) ?",
        defaut=False,
    )
    version_detect = oui_non(
        "Détecter la version des services trouvés (ex: Apache/2.4) ?",
        defaut=False,
    )
    
    # --- NOUVELLE OPTION : SCAN DE VULNÉRABILITÉS ---
    vuln_scan = False
    if version_detect or banner:
        vuln_scan = oui_non(
            "Rechercher des vulnérabilités (CVE) sur ces versions (nécessite Internet) ?",
            defaut=False,
        )
    # ------------------------------------------------

    firewall_detect_asked = oui_non(
        "Détecter le type de pare-feu (DROP silencieux vs REJECT actif) ?",
        defaut=False,
    )
    if firewall_detect_asked and not est_root:
        print("  Note : --firewall-detect nécessite sudo (macOS/Linux) ou admin (Windows).")
    firewall_detect = firewall_detect_asked and est_root

    os_detect_asked = oui_non(
        "Tenter de détecter l'OS de la cible ?",
        defaut=False,
    )
    if os_detect_asked and not est_root:
        print("  Note : --os-detect nécessite sudo (macOS/Linux) ou admin (Windows).")
    os_detect = os_detect_asked and est_root

    # ── 5. Rapport ────────────────────────────────────────────────────────────
    separateur("Où sauvegarder les résultats ?")
    format_choisi = choisir(
        "Format du rapport :",
        [
            "Rapport visuel HTML  (s'ouvre dans un navigateur)",
            "Fichier texte .txt   (simple)",
            "Tableau CSV          (Excel / tableur)",
            "Données JSON         (développeurs)",
        ],
        defaut_idx=0,
    )
    # Détermine l'extension du fichier selon le format choisi
    if "HTML" in format_choisi:
        ext = ".html"
    elif ".txt" in format_choisi:
        ext = ".txt"
    elif "CSV" in format_choisi:
        ext = ".csv"
    else:
        ext = ".json"

    nom_fichier = demander("Nom du fichier de résultats", f"scan_results{ext}")
    # S'assure que le fichier a bien la bonne extension
    if not nom_fichier.endswith(ext):
        nom_fichier += ext

    # ── Récapitulatif ─────────────────────────────────────────────────────────
    # Le type de scan est déterminé automatiquement selon les droits root
    scan_type_val = "syn" if est_root else "connect"
    threads   = perf["threads"]
    timeout   = perf["timeout"]
    delay     = perf["delay"]
    max_rate  = perf["max_rate"]
    jitter    = perf.get("jitter", 0.0)
    randomize = perf["randomize"]

    # Affiche un résumé de tous les paramètres avant de lancer le scan
    _print_safe("\n╔══════════════════════════════════════════════╗")
    _print_safe("║                Récapitulatif                 ║")
    _print_safe("╠══════════════════════════════════════════════╣")
    _print_safe(f"║  Cible       : {target:<31}║")
    _print_safe(f"║  Ports       : {ports:<31}║")
    _print_safe(f"║  Vitesse     : {vitesse_choisie.split('(')[0].strip():<31}║")
    _print_safe(f"║  Mode        : {scan_type_val:<31}║")
    _print_safe(f"║  Découverte  : {'oui' if discover else 'non':<31}║")
    _print_safe(f"║  Infos srv.  : {'oui' if banner else 'non':<31}║")
    _print_safe(f"║  Ver. svc    : {'oui' if version_detect else 'non':<31}║")
    _print_safe(f"║  Anal. CVE   : {'oui' if vuln_scan else 'non':<31}║")
    _print_safe(f"║  Pare-feu    : {'oui' if firewall_detect else 'non':<31}║")
    _print_safe(f"║  Détect. OS  : {'oui' if os_detect else 'non':<31}║")
    _print_safe(f"║  Rapport     : {nom_fichier:<31}║")
    _print_safe("╚══════════════════════════════════════════════╝")

    if not oui_non("\nLancer le scan ?", defaut=True):
        print("\n  Scan annulé.")
        return 0

    # ── Lancement ─────────────────────────────────────────────────────────────
    # Importe et appelle main.py avec les paramètres construits par le CLI interactif
    from main import main as run_scan

    # Construit la liste d'arguments comme si l'utilisateur les avait tapés en ligne de commande
    scan_args = [
        "--target",    target,
        "--ports",     ports,
        "--scan-type", scan_type_val,
        "--output",    nom_fichier,
        "--timeout",   str(timeout),
        "--threads",   str(threads),
        "--delay",     str(delay),
        "--log-level", "WARNING",  # minimise les logs pendant le scan interactif
        "--max-rate",  str(max_rate),
        "--jitter",    str(jitter),
    ]
    # Ajoute les flags booléens uniquement s'ils sont activés
    if randomize:
        scan_args.append("--randomize")
    if discover:
        scan_args.append("--discover")
    if banner:
        scan_args.append("--banner")
    if version_detect:
        scan_args.append("--version-detect")
    if vuln_scan:
        scan_args.append("--vuln-scan")
    if firewall_detect:
        scan_args.append("--firewall-detect")
    if os_detect:
        scan_args.append("--os-detect")

    print()
    try:
        return run_scan(scan_args)
    except KeyboardInterrupt:
        print("\n\n  Scan interrompu.")
        return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n\n  Annulé.")
        raise SystemExit(1)