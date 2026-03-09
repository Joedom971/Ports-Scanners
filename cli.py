"""Interface CLI interactive pour le scanner de ports.

Lance un assistant pas-à-pas pour configurer et exécuter un scan.

Utilisation :
  python cli.py
"""

import sys
from pathlib import Path


def demander(question: str, defaut: str = "") -> str:
    """Affiche une question et retourne la saisie (ou la valeur par défaut)."""
    indication = f" [{defaut}]" if defaut else ""
    reponse = input(f"  {question}{indication} : ").strip()
    return reponse if reponse else defaut


def choisir(question: str, options: list, defaut: str = "") -> str:
    """Affiche un menu numéroté et retourne le choix."""
    print(f"\n  {question}")
    for i, opt in enumerate(options, 1):
        marqueur = " (défaut)" if opt == defaut else ""
        print(f"    {i}. {opt}{marqueur}")
    while True:
        rep = input("  Votre choix (numéro) : ").strip()
        if not rep and defaut:
            return defaut
        if rep.isdigit() and 1 <= int(rep) <= len(options):
            return options[int(rep) - 1]
        print("  Choix invalide, réessayez.")


def oui_non(question: str, defaut: bool = False) -> bool:
    """Pose une question oui/non."""
    indication = "[O/n]" if defaut else "[o/N]"
    rep = input(f"  {question} {indication} : ").strip().lower()
    if not rep:
        return defaut
    return rep in ("o", "oui", "y", "yes")


def afficher_titre(texte: str) -> None:
    print(f"\n{'─' * 50}")
    print(f"  {texte}")
    print(f"{'─' * 50}")


def main() -> int:
    print("\n╔══════════════════════════════════════════════╗")
    print("║        Scanner de ports — Interface CLI      ║")
    print("╚══════════════════════════════════════════════╝")

    # ── 1. Cible ──────────────────────────────────────
    afficher_titre("1. Cible")
    target = demander("Adresse IP, nom d'hôte ou CIDR", "127.0.0.1")

    # ── 2. Ports ──────────────────────────────────────
    afficher_titre("2. Ports à scanner")
    print("  Exemples : 80  |  22,80,443  |  1-1024  |  22,80-85")
    ports = demander("Spécification des ports", "22,80,443")

    # ── 3. Type de scan ───────────────────────────────
    afficher_titre("3. Type de scan")
    scan_type = choisir(
        "Méthode de scan :",
        ["connect (TCP connect, sans privilèges)", "syn (SYN scan, nécessite sudo + scapy)"],
        defaut="connect (TCP connect, sans privilèges)",
    )
    scan_type_val = "connect" if scan_type.startswith("connect") else "syn"

    # ── 4. Threads ────────────────────────────────────
    afficher_titre("4. Performances")
    threads_str = demander("Nombre de threads parallèles", "100")
    threads = int(threads_str) if threads_str.isdigit() else 100

    timeout_str = demander("Délai par port en secondes", "1.0")
    try:
        timeout = float(timeout_str)
    except ValueError:
        timeout = 1.0

    delay_str = demander("Délai entre ports en secondes (rate limiting)", "0")
    try:
        delay = float(delay_str)
    except ValueError:
        delay = 0.0

    # ── 5. Options avancées ───────────────────────────
    afficher_titre("5. Options avancées")
    discover = oui_non("Activer la découverte d'hôtes avant le scan ?", defaut=False)
    banner = oui_non("Activer le banner grabbing (ports ouverts) ?", defaut=False)

    # ── 6. Sortie ─────────────────────────────────────
    afficher_titre("6. Fichier de sortie")
    format_sortie = choisir(
        "Format du fichier de résultats :",
        [".txt (texte brut)", ".json", ".csv", ".html (rapport visuel)"],
        defaut=".txt (texte brut)",
    )
    ext = format_sortie.split(" ")[0]

    nom_fichier = demander("Nom du fichier de sortie", f"scan_results{ext}")
    if not nom_fichier.endswith(ext):
        nom_fichier += ext

    # ── 7. Niveau de log ──────────────────────────────
    afficher_titre("7. Journalisation")
    log_level = choisir(
        "Niveau de journalisation :",
        ["INFO", "DEBUG", "WARNING"],
        defaut="INFO",
    )

    # ── Récapitulatif ─────────────────────────────────
    print("\n╔══════════════════════════════════════════════╗")
    print("║               Récapitulatif                  ║")
    print("╠══════════════════════════════════════════════╣")
    print(f"║  Cible          : {target:<27}║")
    print(f"║  Ports          : {ports:<27}║")
    print(f"║  Type de scan   : {scan_type_val:<27}║")
    print(f"║  Threads        : {threads:<27}║")
    print(f"║  Timeout        : {timeout:<27}║")
    print(f"║  Délai          : {delay:<27}║")
    print(f"║  Découverte     : {'oui' if discover else 'non':<27}║")
    print(f"║  Banner         : {'oui' if banner else 'non':<27}║")
    print(f"║  Sortie         : {nom_fichier:<27}║")
    print(f"║  Log            : {log_level:<27}║")
    print("╚══════════════════════════════════════════════╝")

    if not oui_non("\nLancer le scan ?", defaut=True):
        print("\n  Scan annulé.")
        return 0

    # ── Lancement ─────────────────────────────────────
    from main import main as run_scan

    scan_args = [
        "--target", target,
        "--ports", ports,
        "--scan-type", scan_type_val,
        "--output", nom_fichier,
        "--timeout", str(timeout),
        "--threads", str(threads),
        "--delay", str(delay),
        "--log-level", log_level,
    ]
    if discover:
        scan_args.append("--discover")
    if banner:
        scan_args.append("--banner")

    print()
    return run_scan(scan_args)


if __name__ == "__main__":
    raise SystemExit(main())
