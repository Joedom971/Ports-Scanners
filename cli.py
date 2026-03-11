"""Interactive CLI interface for the port scanner.

Launches a simple step-by-step wizard.

Usage:
  python cli.py
"""

import os


def _print_safe(text: str) -> None:
    """Prints text, replacing non-ASCII characters if necessary."""
    try:
        print(text)
    except UnicodeEncodeError:
        # Replace border characters with their ASCII equivalents
        ascii_text = (text
            .replace("╔", "+").replace("╗", "+").replace("╚", "+").replace("╝", "+")
            .replace("║", "|").replace("═", "=").replace("─", "-")
            .replace("┄", "-")
        )
        print(ascii_text)


# ── Speed → technical parameters ──────────────────────────────────────────────
# Each speed automatically configures threads, timeout, delay and stealth options.
# The user picks a simple speed; the technical details are handled here.
VITESSES = {
    # LAN: short timeout, many threads — responses arrive in < 10ms on a local network
    "Rapide  (réseau local)":    {"threads": 400, "timeout": 0.3, "delay": 0.0, "jitter": 0.0,  "max_rate": 0.0,  "randomize": False},
    # Normal: balanced for LAN/WAN — timeout reduced to 0.5s, more threads to compensate
    "Normal  (recommandé)":      {"threads": 200, "timeout": 0.5, "delay": 0.0, "jitter": 0.0,  "max_rate": 0.0,  "randomize": False},
    # Slow: fewer threads and inter-port delay to reduce network noise
    "Lent    (discret)":         {"threads": 20,  "timeout": 2.0, "delay": 0.1, "jitter": 0.0,  "max_rate": 0.0,  "randomize": False},
    # Stealth: few threads, rate limited to 2 packets/s, randomised port order
    "Furtif  (anti-détection)":  {"threads": 5,   "timeout": 3.0, "delay": 0.0, "jitter": 0.0,  "max_rate": 2.0,  "randomize": True},
}

# ── Scan profiles ──────────────────────────────────────────────────────────────
# Maps each profile to a port specification (None = the user enters their own)
PROFILS = {
    "Scan rapide   — ports courants (web, SSH, bureau à distance)": "22,80,443,3389,8080",
    "Scan standard — tous les ports réservés (1 à 1024)":          "1-1024",
    "Scan complet  — tous les ports (1 à 65535, lent)":            "1-65535",
    "Personnalisé  — je choisis moi-même":                         None,
}


def choisir(question: str, options: list, defaut_idx: int = 0) -> str:
    """Displays a numbered menu and returns the option chosen by the user."""
    print(f"\n  {question}")
    for i, opt in enumerate(options, 1):
        marqueur = "  ← recommandé" if i == defaut_idx + 1 else ""
        print(f"    {i}. {opt}{marqueur}")
    while True:
        rep = input(f"  Votre choix [Entrée = {defaut_idx + 1}] : ").strip()
        if not rep:
            # Empty input → use the default choice
            return options[defaut_idx]
        if rep.isdigit() and 1 <= int(rep) <= len(options):
            return options[int(rep) - 1]
        print("  Choix invalide, entrez un numéro.")


def demander(question: str, defaut: str = "") -> str:
    """Displays a question and returns the user's input (or the default value)."""
    indication = f" [Entrée = {defaut}]" if defaut else ""
    rep = input(f"  {question}{indication} : ").strip()
    return rep if rep else defaut  # if the user presses Enter, use the default


def oui_non(question: str, defaut: bool = True) -> bool:
    """Asks a yes/no question and returns True or False."""
    indication = "[O/n]" if defaut else "[o/N]"
    rep = input(f"  {question} {indication} : ").strip().lower()
    if not rep:
        return defaut  # empty input → default value
    # Accept "o", "oui", "y", "yes" as a positive answer
    return rep in ("o", "oui", "y", "yes")


def separateur(titre: str = "") -> None:
    """Displays a visual separator line with an optional title."""
    if titre:
        print(f"\n  ── {titre} {'─' * (44 - len(titre))}")
    else:
        print(f"\n  {'─' * 48}")


def main() -> int:
    # Detect whether the program is running with root privileges (uid 0)
    # getattr with a lambda avoids an error on Windows where os.geteuid does not exist
    est_root = getattr(os, "geteuid", lambda: 1)() == 0

    # Display the header with the automatically detected scan mode
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
        # "Custom" profile: the user enters their own ports
        print("\n  Exemples : 80  |  22,80,443  |  1-1024  |  22,80-85")
        ports = demander("Entrez les ports à scanner", "22,80,443")

    # ── 3. Vitesse ────────────────────────────────────────────────────────────
    separateur("Quelle vitesse de scan ?")
    vitesse_choisie = choisir(
        "Choisissez une vitesse :",
        list(VITESSES.keys()),
        defaut_idx=1,  # "Normal" is the recommended default
    )
    # Retrieve the technical parameters associated with the chosen speed
    perf = VITESSES[vitesse_choisie]

    # ── 4. Options extras ─────────────────────────────────────────────────────
    separateur("Options supplémentaires")

    if est_root:
        # In SYN scan mode, several options are automatically disabled to preserve stealth.
        # Each disabled option is explained so the user understands why it is unavailable.
        print("  Mode SYN actif — options incompatibles avec la furtivité désactivées :\n")
        print("  [✗] Découverte réseau  — ARP sweep / ping ICMP génèrent du bruit détectable")
        print("      avant même le début du scan de ports.")
        print("  [✗] Banner grabbing    — ouvre une connexion TCP complète (SYN+ACK+ACK)")
        print("      enregistrée dans les logs applicatifs du serveur cible.")
        print("  [✗] Détection version  — même raison que le banner grabbing.")
        print()
        discover       = False
        banner         = False
        version_detect = False
    else:
        print("  (Entrée = non pour toutes)")
        # In TCP connect mode, all options are available freely
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
    # Determine the file extension based on the chosen format
    if "HTML" in format_choisi:
        ext = ".html"
    elif ".txt" in format_choisi:
        ext = ".txt"
    elif "CSV" in format_choisi:
        ext = ".csv"
    else:
        ext = ".json"

    nom_fichier = demander("Nom du fichier de résultats", f"scan_results{ext}")
    # Ensure the file has the correct extension
    if not nom_fichier.endswith(ext):
        nom_fichier += ext

    # ── Summary ───────────────────────────────────────────────────────────────
    # The scan type is determined automatically based on root privileges
    scan_type_val = "syn" if est_root else "connect"
    threads   = perf["threads"]
    timeout   = perf["timeout"]
    delay     = perf["delay"]
    max_rate  = perf["max_rate"]
    jitter    = perf.get("jitter", 0.0)
    randomize = perf["randomize"]

    # In SYN scan mode, force stealth settings regardless of the chosen speed profile:
    #   - randomize: shuffles port order to avoid sequential scanning signatures (IDS)
    #   - jitter: adds random variation to inter-packet timing to break regular patterns
    if est_root:
        randomize = True
        jitter = max(jitter, 0.05)  # minimum 50ms jitter if not already set higher

    # Display a summary of all parameters before launching the scan
    _print_safe("\n╔══════════════════════════════════════════════╗")
    _print_safe("║               Récapitulatif                  ║")
    _print_safe("╠══════════════════════════════════════════════╣")
    _print_safe(f"║  Cible       : {target:<31}║")
    _print_safe(f"║  Ports       : {ports:<31}║")
    _print_safe(f"║  Vitesse     : {vitesse_choisie.split('(')[0].strip():<31}║")
    _print_safe(f"║  Mode        : {scan_type_val:<31}║")
    if not est_root:
        _print_safe(f"║  Découverte  : {'oui' if discover else 'non':<31}║")
    if not est_root:
        # Banner and version-detect are only available in TCP connect mode
        _print_safe(f"║  Infos srv.  : {'oui' if banner else 'non':<31}║")
        _print_safe(f"║  Ver. svc    : {'oui' if version_detect else 'non':<31}║")
    _print_safe(f"║  Pare-feu    : {'oui' if firewall_detect else 'non':<31}║")
    _print_safe(f"║  Détect. OS  : {'oui' if os_detect else 'non':<31}║")
    _print_safe(f"║  Rapport     : {nom_fichier:<31}║")
    _print_safe("╚══════════════════════════════════════════════╝")

    if not oui_non("\nLancer le scan ?", defaut=True):
        print("\n  Scan annulé.")
        return 0

    # ── Launch ────────────────────────────────────────────────────────────────
    # Import and call main.py with the parameters built by the interactive CLI
    from main import main as run_scan

    # Build the argument list as if the user had typed them on the command line
    scan_args = [
        "--target",    target,
        "--ports",     ports,
        "--scan-type", scan_type_val,
        "--output",    nom_fichier,
        "--timeout",   str(timeout),
        "--threads",   str(threads),
        "--delay",     str(delay),
        "--log-level", "WARNING",  # minimise log output during interactive scan
        "--max-rate",  str(max_rate),
        "--jitter",    str(jitter),
    ]
    # Add boolean flags only when they are enabled
    if randomize:
        scan_args.append("--randomize")
    if discover:
        scan_args.append("--discover")
    if banner:
        scan_args.append("--banner")
    if version_detect:
        scan_args.append("--version-detect")
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
