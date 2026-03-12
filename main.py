# main.py
"""Command-line interface for the port scanner.

Supports:
  - target host / IP address or CIDR subnet
  - port ranges (e.g. 1-1024, 22,80,443, or a combination)
  - SYN scan (requires scapy + sudo) or TCP connect
  - parallel scan (ThreadPoolExecutor)
  - host discovery (ARP or ICMP)
  - banner grabbing, service names, rate limiting
  - console + file export (.txt/.json/.csv/.html)

Usage:
  python main.py --target 192.168.1.1 --ports 20-1024 --output scan.json
  python main.py --target 192.168.1.0/24 --discover --ports 22,80 --scan-type syn
"""

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from scanner import (
    detect_firewall,
    detect_os,
    detect_service_version,
    grab_banner,
    get_service_name,
    resoudre_cible,
    scan_port_connect,
    scan_port_syn,
    scan_range_threaded,
    SCAPY_AVAILABLE,
)
from output import write_output, print_summary

# Attempt to import tqdm to display a progress bar.
# If tqdm is not installed, execution continues without a bar.
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


def valider_port(port: int) -> int:
    """Checks that a port is within the valid range (1-65535)."""
    if not 1 <= port <= 65535:
        raise ValueError(f"Port invalide : {port} (doit être entre 1 et 65535)")
    return port


def valider_cible(cible: str) -> str:
    """Checks that a target is a valid IP, hostname, or CIDR."""
    import ipaddress
    cible = cible.strip()
    if not cible:
        raise ValueError("La cible ne peut pas être vide.")
    # Attempt to parse as CIDR (e.g. "192.168.1.0/24")
    try:
        ipaddress.ip_network(cible, strict=False)
        return cible
    except ValueError:
        pass
    # Attempt to parse as a plain IP address (IPv4 or IPv6)
    try:
        ipaddress.ip_address(cible)
        return cible
    except ValueError:
        pass
    # Hostname / plain IP: basic check of allowed characters
    caracteres_autorises = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
    if not all(c in caracteres_autorises for c in cible):
        raise ValueError(f"Cible invalide : '{cible}' contient des caractères non autorisés.")
    if len(cible) > 253:
        # The DNS standard limits hostnames to 253 characters maximum
        raise ValueError(f"Cible invalide : nom d'hôte trop long ({len(cible)} caractères).")
    return cible


def valider_fichier_sortie(chemin: str) -> Path:
    """Checks that the output path is safe (valid extension, no relative traversal)."""
    chemin = chemin.strip()
    if not chemin:
        raise ValueError("Le nom du fichier de sortie ne peut pas être vide.")
    extensions_valides = {".txt", ".json", ".csv", ".html", ".xml"}
    path = Path(chemin)
    if path.suffix.lower() not in extensions_valides:
        raise ValueError(f"Extension invalide : '{path.suffix}'. Utilisez .txt, .json, .csv, .html ou .xml.")
    # Block directory traversal in relative paths (e.g. ../../etc/passwd)
    if not path.is_absolute():
        try:
            path.resolve().relative_to(Path.cwd().resolve())
        except ValueError:
            raise ValueError(f"Chemin non autorisé : '{chemin}' tente de sortir du dossier courant.")
    return path


def parse_ports(port_str: str) -> List[int]:
    """Converts a port specification string into a list of integers.

    Accepts: "22", "20-25", "22,80,443", "22,80-85"
    """
    ports: List[int] = []
    try:
        # Split the string by commas (e.g. "22,80-85" → ["22", "80-85"])
        for part in port_str.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                # Port range: "80-85" → ports 80, 81, 82, 83, 84, 85
                start_str, end_str = part.split("-", 1)
                start, end = valider_port(int(start_str)), valider_port(int(end_str))
                if start > end:
                    start, end = end, start  # fix reversed range (e.g. "85-80")
                ports.extend(range(start, end + 1))
            else:
                # Single port
                ports.append(valider_port(int(part)))
    except (ValueError, TypeError) as e:
        raise ValueError(f"Spécification de ports invalide : {e}")
    if not ports:
        raise ValueError("Aucun port valide trouvé dans la spécification.")
    # sorted(set(...)) : remove duplicates and sort in ascending order
    return sorted(set(ports))


def main(args: Optional[List[str]] = None) -> int:
    # Define all accepted command-line arguments
    parser = argparse.ArgumentParser(description="Scanner de ports TCP")
    parser.add_argument("--target", required=True, help="Hôte, IP ou sous-réseau CIDR cible")
    parser.add_argument("--ports", required=True,
                        help="Ports à scanner (ex. 1-1024 ou 22,80,443 ou 20-25,80)")
    parser.add_argument("--scan-type", choices=["connect", "syn"], default="connect",
                        help="Type de scan (défaut: connect)")
    parser.add_argument("--output", default="scan_results.txt",
                        help="Fichier de sortie (.txt/.json/.csv/.html/.xml)")
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
    parser.add_argument("--randomize", action="store_true",
                        help="Randomiser l'ordre des ports pour réduire la détection")
    parser.add_argument("--max-rate", type=float, default=0.0,
                        help="Débit max en paquets/seconde (0 = illimité)")
    parser.add_argument("--jitter", type=float, default=0.0,
                        help="Variation aléatoire du délai en secondes (0 = désactivé)")
    parser.add_argument("--os-detect", action="store_true",
                        help="Tenter de détecter le système d'exploitation (nécessite scapy + sudo)")
    parser.add_argument("--version-detect", action="store_true",
                        help="Détecter la version des services ouverts (probe actif par protocole)")
    parser.add_argument("--firewall-detect", action="store_true",
                        help="Distinguer les types de filtrage pare-feu (nécessite scapy + sudo)")

    parsed = parser.parse_args(args=args)

    # Configure the logging system (DEBUG = very verbose, WARNING = alerts only)
    logging.basicConfig(
        level=getattr(logging, parsed.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # Validate numeric values before starting the scan
    if parsed.timeout <= 0:
        print("Erreur : --timeout doit être strictement positif.")
        return 1
    if parsed.threads < 1:
        print("Erreur : --threads doit être >= 1.")
        return 1
    if parsed.delay < 0:
        print("Erreur : --delay doit être >= 0.")
        return 1
    if parsed.max_rate < 0:
        print("Erreur : --max-rate doit être >= 0.")
        return 1
    if parsed.jitter < 0:
        print("Erreur : --jitter doit être >= 0.")
        return 1
    if parsed.max_rate > 0 and parsed.threads > 1:
        # In max-rate mode, sends are serialised → multiple threads have no effect
        print(f"Note : --max-rate sérialise les envois — --threads {parsed.threads} n'a pas d'effet. "
              f"Les paquets seront envoyés à {parsed.max_rate} pkt/s.")

    # Sanitise user inputs (protection against malformed values)
    try:
        target_sanitise = valider_cible(parsed.target)
        ports = parse_ports(parsed.ports)
        out_path = valider_fichier_sortie(parsed.output)
    except ValueError as e:
        print(f"Erreur : {e}")
        return 1

    # Create the destination directory if the output path contains subdirectories
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Select the scan function based on the requested type
    if parsed.scan_type == "syn":
        if not SCAPY_AVAILABLE:
            print("AVERTISSEMENT : scapy non disponible. Installez-le : pip install scapy")
            print("Fallback sur TCP connect.")
            scan_fn = scan_port_connect
        else:
            scan_fn = scan_port_syn  # SYN scan via raw packets
    else:
        scan_fn = scan_port_connect  # standard TCP connect scan

    # Single DNS resolution: resolve the hostname once instead of once per scanned port
    # (avoids N DNS queries for N ports).
    # CIDRs (e.g. 192.168.1.0/24) are handled by discover_hosts → no resolution here.
    import ipaddress as _ipaddress
    _is_cidr = False
    try:
        _ipaddress.ip_network(target_sanitise, strict=False)
        _is_cidr = "/" in target_sanitise  # confirm it is a network, not a plain IP
    except ValueError:
        pass
    if not _is_cidr:
        try:
            target_sanitise = resoudre_cible(target_sanitise)
        except OSError as e:
            print(f"Erreur : impossible de résoudre '{target_sanitise}' — {e}")
            return 1

    # Host discovery: detect active machines on the network before scanning their ports
    if parsed.discover:
        from discovery import discover_hosts
        logging.info(f"Host discovery sur {target_sanitise}...")
        targets = discover_hosts(target_sanitise, timeout=parsed.timeout)
        if not targets:
            print("Aucun hôte actif trouvé.")
            return 1
        print(f"{len(targets)} hôte(s) actif(s) : {', '.join(targets)}")
    else:
        # No discovery: scan only the provided target
        targets = [target_sanitise]

    # Dictionary to store results for all scanned hosts
    all_results: Dict[str, Dict[int, dict]] = {}

    # --- FEATURE  : STATISTIK GENERATOR (début) ---
    # Start the timer before the scan loop to measure total execution time across all hosts
    start_time = time.time()

    for target in targets:
        print(f"\nScan de {target} — {len(ports)} ports ({parsed.scan_type})")

        # Launch the multi-threaded scan over all ports
        raw = scan_range_threaded(
            target, ports, scan_fn,
            timeout=parsed.timeout,
            delay=parsed.delay,
            max_workers=parsed.threads,
            randomize=parsed.randomize,
            max_rate=parsed.max_rate,
            jitter=parsed.jitter,
        )

        os_guess = detect_os(target, timeout=parsed.timeout) if parsed.os_detect else ""
        if parsed.os_detect:
            if os_guess not in ("unknown", ""):
                print(f"  OS détecté : {os_guess}")
            else:
                logging.warning("OS detection skipped — requires scapy and sudo (root privileges).")

        # Enrichment: add the service name and banner to each raw result
        results: Dict[int, dict] = {}
        # tqdm shows a progress bar if available, otherwise plain iteration
        port_iter = tqdm(raw.items(), desc="Loading") if TQDM_AVAILABLE else raw.items()
        for port, status in port_iter:
            service = get_service_name(port)
            banner = ""
            # Banner grabbing only on open ports (pointless on closed/filtered)
            if parsed.banner and status == "open":
                banner = grab_banner(target, port, timeout=parsed.timeout)
            version = ""
            if parsed.version_detect and status == "open":
                version = detect_service_version(target, port, service, timeout=parsed.timeout)
            firewall = ""
            if parsed.firewall_detect and status == "filtered":
                firewall = detect_firewall(target, port, timeout=parsed.timeout)
            results[port] = {
                "status": status,
                "service": service,
                "banner": banner,
                "os": os_guess,
                "version": version,
                "firewall": firewall,
            }

        # Display results in the terminal, sorted by port number
        for port, info in sorted(results.items()):
            version_str = f"  [{info.get('version')}]" if info.get("version") else ""
            fw_str = f" ({info.get('firewall')})" if info.get("firewall") else ""
            print(f"  {port:5d}  {info['status']:<10}{fw_str:<22} {info['service']:<15} {info['banner']}{version_str}")

        all_results[target] = results

    # Stop the timer after all hosts have been scanned      ---STATISTIK GENERATOR (fin)---
    elapsed = time.time() - start_time

    # Display the global analytical summary via output.py
    # all_results is passed directly so every (host, port) pair is counted
    print_summary(all_results, elapsed)
    # --- FEATURE  : STATISTIK GENERATOR (fin) ---

    # Export results to a file
    if len(all_results) == 1:
        # Single host: standard behaviour
        target_key = list(all_results.keys())[0]
        write_output(all_results[target_key], out_path, target_key, parsed.scan_type)
        print(f"\nRésultats sauvegardés dans {out_path}")
    else:
        # Multiple hosts: one file per host (base_name_IP.ext)
        for host_ip, host_results in all_results.items():
            safe_ip = host_ip.replace(".", "_").replace(":", "_")
            host_path = out_path.parent / f"{out_path.stem}_{safe_ip}{out_path.suffix}"
            write_output(host_results, host_path, host_ip, parsed.scan_type)
            print(f"  Résultats de {host_ip} sauvegardés dans {host_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
