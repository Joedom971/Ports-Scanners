# main.py
"""Interface en ligne de commande pour le scanner de ports.

Supporte :
  - hôte / adresse IP cible ou sous-réseau CIDR
  - plage de ports (ex. 1-1024, 22,80,443, ou combinaison)
  - SYN scan (nécessite scapy + sudo) ou TCP connect
  - scan parallèle (ThreadPoolExecutor)
  - host discovery (ARP ou ICMP)
  - banner grabbing, service names, rate limiting
  - export console + fichier (.txt/.json/.csv/.html)

Utilisation :
  python main.py --target 192.168.1.1 --ports 20-1024 --output scan.json
  python main.py --target 192.168.1.0/24 --discover --ports 22,80 --scan-type syn
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

from scanner import (
    grab_banner,
    get_service_name,
    scan_port_connect,
    scan_port_syn,
    scan_range_threaded,
    SCAPY_AVAILABLE,
)
from output import write_output

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


def valider_port(port: int) -> int:
    """Vérifie qu'un port est dans la plage valide (1-65535)."""
    if not 1 <= port <= 65535:
        raise ValueError(f"Port invalide : {port} (doit être entre 1 et 65535)")
    return port


def valider_cible(cible: str) -> str:
    """Vérifie qu'une cible est une IP, un hostname ou un CIDR valide."""
    import ipaddress
    cible = cible.strip()
    if not cible:
        raise ValueError("La cible ne peut pas être vide.")
    # Tentative CIDR
    try:
        ipaddress.ip_network(cible, strict=False)
        return cible
    except ValueError:
        pass
    # Hostname / IP simple : vérification basique des caractères
    caracteres_autorises = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
    if not all(c in caracteres_autorises for c in cible):
        raise ValueError(f"Cible invalide : '{cible}' contient des caractères non autorisés.")
    if len(cible) > 253:
        raise ValueError(f"Cible invalide : nom d'hôte trop long ({len(cible)} caractères).")
    return cible


def valider_fichier_sortie(chemin: str) -> Path:
    """Vérifie que le chemin de sortie est sûr (extension valide, pas de traversée relative)."""
    chemin = chemin.strip()
    if not chemin:
        raise ValueError("Le nom du fichier de sortie ne peut pas être vide.")
    extensions_valides = {".txt", ".json", ".csv", ".html"}
    path = Path(chemin)
    if path.suffix.lower() not in extensions_valides:
        raise ValueError(f"Extension invalide : '{path.suffix}'. Utilisez .txt, .json, .csv ou .html.")
    # Bloquer la traversée de répertoire dans les chemins relatifs (ex. ../../etc/passwd)
    if not path.is_absolute():
        try:
            path.resolve().relative_to(Path.cwd().resolve())
        except ValueError:
            raise ValueError(f"Chemin non autorisé : '{chemin}' tente de sortir du dossier courant.")
    return path


def parse_ports(port_str: str) -> List[int]:
    """Convertit une spécification de ports en liste d'entiers.

    Accepte : "22", "20-25", "22,80,443", "22,80-85"
    """
    ports: List[int] = []
    try:
        for part in port_str.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start_str, end_str = part.split("-", 1)
                start, end = valider_port(int(start_str)), valider_port(int(end_str))
                if start > end:
                    start, end = end, start
                ports.extend(range(start, end + 1))
            else:
                ports.append(valider_port(int(part)))
    except (ValueError, TypeError) as e:
        raise ValueError(f"Spécification de ports invalide : {e}")
    if not ports:
        raise ValueError("Aucun port valide trouvé dans la spécification.")
    return sorted(set(ports))


def main(args: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Scanner de ports TCP")
    parser.add_argument("--target", required=True, help="Hôte, IP ou sous-réseau CIDR cible")
    parser.add_argument("--ports", required=True,
                        help="Ports à scanner (ex. 1-1024 ou 22,80,443 ou 20-25,80)")
    parser.add_argument("--scan-type", choices=["connect", "syn"], default="connect",
                        help="Type de scan (défaut: connect)")
    parser.add_argument("--output", default="scan_results.txt",
                        help="Fichier de sortie (.txt/.json/.csv/.html)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Délai par port en secondes (défaut: 1.0)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Nombre de threads parallèles (défaut: 100)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Délai entre ports en secondes (défaut: 0)")
    parser.add_argument("--discover", action="store_true",
                        help="Activer le host discovery avant le scan")
    parser.add_argument("--banner", action="store_true",
                        help="Activer le banner grabbing (ports ouverts uniquement)")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING"], default="INFO",
                        help="Niveau de log (défaut: INFO)")

    parsed = parser.parse_args(args=args)

    logging.basicConfig(
        level=getattr(logging, parsed.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # Validation des valeurs numériques
    if parsed.timeout <= 0:
        print("Erreur : --timeout doit être strictement positif.")
        return 1
    if parsed.delay < 0:
        print("Erreur : --delay doit être >= 0.")
        return 1

    # Sanitisation des entrées
    try:
        target_sanitise = valider_cible(parsed.target)
        ports = parse_ports(parsed.ports)
        out_path = valider_fichier_sortie(parsed.output)
    except ValueError as e:
        print(f"Erreur : {e}")
        return 1

    # Créer le dossier de sortie si nécessaire
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Choisir la fonction de scan
    if parsed.scan_type == "syn":
        if not SCAPY_AVAILABLE:
            print("AVERTISSEMENT : scapy non disponible. Installez-le : pip install scapy")
            print("Fallback sur TCP connect.")
            scan_fn = scan_port_connect
        else:
            scan_fn = scan_port_syn
    else:
        scan_fn = scan_port_connect

    # Host discovery
    if parsed.discover:
        from discovery import discover_hosts
        logging.info(f"Host discovery sur {target_sanitise}...")
        targets = discover_hosts(target_sanitise, timeout=parsed.timeout)
        if not targets:
            print("Aucun hôte actif trouvé.")
            return 1
        print(f"{len(targets)} hôte(s) actif(s) : {', '.join(targets)}")
    else:
        targets = [target_sanitise]

    all_results: Dict[str, Dict[int, dict]] = {}

    for target in targets:
        print(f"\nScan de {target} — {len(ports)} ports ({parsed.scan_type})")

        raw = scan_range_threaded(
            target, ports, scan_fn,
            timeout=parsed.timeout,
            delay=parsed.delay,
            max_workers=parsed.threads,
        )

        # Enrichir avec service name et banner
        results: Dict[int, dict] = {}
        port_iter = tqdm(raw.items(), desc="Enrichissement") if TQDM_AVAILABLE else raw.items()
        for port, status in port_iter:
            service = get_service_name(port)
            banner = ""
            if parsed.banner and status == "open":
                banner = grab_banner(target, port, timeout=parsed.timeout)
            results[port] = {"status": status, "service": service, "banner": banner}

        # Affichage console
        for port, info in sorted(results.items()):
            print(f"  {port:5d}  {info['status']:<10} {info['service']:<15} {info['banner']}")

        # Stats
        counts = {"open": 0, "closed": 0, "filtered": 0}
        for info in results.values():
            counts[info["status"]] = counts.get(info["status"], 0) + 1
        print(f"\n  open: {counts['open']}  closed: {counts['closed']}  filtered: {counts['filtered']}")

        all_results[target] = results

    # Export fichier
    if len(targets) > 1:
        print(f"\nNote : scan multi-hôtes — seuls les résultats de {targets[-1]} sont sauvegardés dans le fichier.")
    results_to_save = list(all_results.values())[-1]
    write_output(results_to_save, out_path, targets[-1], parsed.scan_type)
    print(f"\nRésultats sauvegardés dans {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
