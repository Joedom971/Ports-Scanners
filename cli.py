"""Interface CLI interactive pour le scanner de ports.

Lance un assistant simple pas-à-pas.

Utilisation :
  python cli.py
"""

import os


# ── Vitesse → paramètres techniques ───────────────────────────────────────────
VITESSES = {
    "Rapide  (réseau local)":    {"threads": 400, "timeout": 0.3, "delay": 0.0, "jitter": 0.0,  "max_rate": 0.0,  "randomize": False},
    "Normal  (recommandé)":      {"threads": 100, "timeout": 1.0, "delay": 0.0, "jitter": 0.0,  "max_rate": 0.0,  "randomize": False},
    "Lent    (discret)":         {"threads": 20,  "timeout": 2.0, "delay": 0.1, "jitter": 0.0,  "max_rate": 0.0,  "randomize": False},
    "Furtif  (anti-détection)":  {"threads": 5,   "timeout": 3.0, "delay": 0.0, "jitter": 0.0,  "max_rate": 2.0,  "randomize": True},
}

# ── Profils de scan ────────────────────────────────────────────────────────────
PROFILS = {
    "Scan rapide   — ports courants (web, SSH, bureau à distance)": "22,80,443,3389,8080",
    "Scan standard — tous les ports réservés (1 à 1024)":          "1-1024",
    "Scan complet  — tous les ports (1 à 65535, lent)":            "1-65535",
    "Personnalisé  — je choisis moi-même":                         None,
}


def choisir(question: str, options: list, defaut_idx: int = 0) -> str:
    """Menu numéroté, retourne le choix."""
    print(f"\n  {question}")
    for i, opt in enumerate(options, 1):
        marqueur = "  ← recommandé" if i == defaut_idx + 1 else ""
        print(f"    {i}. {opt}{marqueur}")
    while True:
        rep = input(f"  Votre choix [Entrée = {defaut_idx + 1}] : ").strip()
        if not rep:
            return options[defaut_idx]
        if rep.isdigit() and 1 <= int(rep) <= len(options):
            return options[int(rep) - 1]
        print("  Choix invalide, entrez un numéro.")


def demander(question: str, defaut: str = "") -> str:
    """Saisie libre avec valeur par défaut."""
    indication = f" [Entrée = {defaut}]" if defaut else ""
    rep = input(f"  {question}{indication} : ").strip()
    return rep if rep else defaut


def oui_non(question: str, defaut: bool = True) -> bool:
    """Question oui/non."""
    indication = "[O/n]" if defaut else "[o/N]"
    rep = input(f"  {question} {indication} : ").strip().lower()
    if not rep:
        return defaut
    return rep in ("o", "oui", "y", "yes")


def separateur(titre: str = "") -> None:
    if titre:
        print(f"\n  ── {titre} {'─' * (44 - len(titre))}")
    else:
        print(f"\n  {'─' * 48}")


def main() -> int:
    est_root = getattr(os, "geteuid", lambda: 1)() == 0

    print("\n╔══════════════════════════════════════════════╗")
    print("║          Scanner de ports réseau             ║")
    if est_root:
        print("║  Mode : SYN scan (avancé, root détecté)      ║")
    else:
        print("║  Mode : TCP connect (standard)               ║")
    print("╚══════════════════════════════════════════════╝")
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
        print("\n  Exemples : 80  |  22,80,443  |  1-1024  |  22,80-85")
        ports = demander("Entrez les ports à scanner", "22,80,443")

    # ── 3. Vitesse ────────────────────────────────────────────────────────────
    separateur("Quelle vitesse de scan ?")
    vitesse_choisie = choisir(
        "Choisissez une vitesse :",
        list(VITESSES.keys()),
        defaut_idx=1,
    )
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
    if "HTML" in format_choisi:
        ext = ".html"
    elif ".txt" in format_choisi:
        ext = ".txt"
    elif "CSV" in format_choisi:
        ext = ".csv"
    else:
        ext = ".json"

    nom_fichier = demander("Nom du fichier de résultats", f"scan_results{ext}")
    if not nom_fichier.endswith(ext):
        nom_fichier += ext

    # ── Récapitulatif ─────────────────────────────────────────────────────────
    scan_type_val = "syn" if est_root else "connect"
    threads   = perf["threads"]
    timeout   = perf["timeout"]
    delay     = perf["delay"]
    max_rate  = perf["max_rate"]
    jitter    = perf.get("jitter", 0.0)
    randomize = perf["randomize"]

    print("\n╔══════════════════════════════════════════════╗")
    print("║               Récapitulatif                  ║")
    print("╠══════════════════════════════════════════════╣")
    print(f"║  Cible       : {target:<31}║")
    print(f"║  Ports       : {ports:<31}║")
    print(f"║  Vitesse     : {vitesse_choisie.split('(')[0].strip():<31}║")
    print(f"║  Mode        : {scan_type_val:<31}║")
    print(f"║  Découverte  : {'oui' if discover else 'non':<31}║")
    print(f"║  Infos srv.  : {'oui' if banner else 'non':<31}║")
    print(f"║  Rapport     : {nom_fichier:<31}║")
    print("╚══════════════════════════════════════════════╝")

    if not oui_non("\nLancer le scan ?", defaut=True):
        print("\n  Scan annulé.")
        return 0

    # ── Lancement ─────────────────────────────────────────────────────────────
    from main import main as run_scan

    scan_args = [
        "--target",    target,
        "--ports",     ports,
        "--scan-type", scan_type_val,
        "--output",    nom_fichier,
        "--timeout",   str(timeout),
        "--threads",   str(threads),
        "--delay",     str(delay),
        "--log-level", "WARNING",
        "--max-rate",  str(max_rate),
        "--jitter",    str(jitter),
    ]
    if randomize:
        scan_args.append("--randomize")
    if discover:
        scan_args.append("--discover")
    if banner:
        scan_args.append("--banner")

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
