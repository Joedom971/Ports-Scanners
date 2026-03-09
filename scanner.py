"""Scanner de ports TCP basique.

Ce module fournit un scanner de ports en mode connect via les sockets Python.

Fonctions :
  - scan_port_connect(ip, port) -> statut
  - scan_range(ip, start_port, end_port) -> dict[port] = statut

Valeurs de statut :
  - "open"     (ouvert)
  - "closed"   (fermé)
  - "filtered" (filtré)

"""

import errno
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from typing import Callable, Dict, List

try:
    from scapy.all import IP, TCP, sr1, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def scan_port_connect(ip: str, port: int, timeout: float = 1.0) -> str:
    """Scanne un seul port TCP via connect().

    Args:
        ip: adresse IPv4/IPv6 ou nom d'hôte cible.
        port: numéro de port TCP (1-65535).
        timeout: délai d'expiration du socket en secondes.

    Returns:
        "open"     si la connexion a réussi.
        "closed"   si la connexion a été refusée.
        "filtered" si le délai a expiré ou l'hôte est inaccessible.
    """

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            err = sock.connect_ex((ip, port))
        except (socket.gaierror, socket.herror, OSError):
            return "filtered"

        if err == 0:
            return "open"

        if err in (errno.ECONNREFUSED,):
            return "closed"

        return "filtered"


def scan_range(ip: str, start_port: int, end_port: int, timeout: float = 1.0) -> Dict[int, str]:
    """Scanne une plage de ports TCP.

    Args:
        ip: adresse IPv4/IPv6 ou nom d'hôte cible.
        start_port: premier port (inclus).
        end_port: dernier port (inclus).
        timeout: délai d'expiration par port.

    Returns:
        Dictionnaire port -> statut.
    """

    results: Dict[int, str] = {}
    for port in range(start_port, end_port + 1):
        results[port] = scan_port_connect(ip, port, timeout=timeout)
    return results


def get_service_name(port: int) -> str:
    """Retourne le nom du service associé au port, ou 'unknown'."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Tente de lire la bannière du service sur ce port TCP.

    Returns:
        Chaîne de la bannière (première ligne), ou "" si échec.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) != 0:
                return ""
            sock.sendall(b"\r\n")
            data = sock.recv(1024)
            return data.decode(errors="ignore").strip().splitlines()[0]
    except (socket.timeout, OSError, IndexError):
        return ""


def scan_range_threaded(
    ip: str,
    ports: List[int],
    scan_fn: Callable,
    timeout: float = 1.0,
    delay: float = 0.0,
    max_workers: int = 100,
) -> Dict[int, str]:
    """Scanne une liste de ports en parallèle via ThreadPoolExecutor."""
    results: Dict[int, str] = {}

    def _scan(port: int) -> tuple:
        if delay > 0:
            time.sleep(delay)
        return port, scan_fn(ip, port, timeout=timeout)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan, p): p for p in ports}
        for future in as_completed(futures):
            port, status = future.result()
            results[port] = status

    return results


def scan_port_syn(ip: str, port: int, timeout: float = 1.0) -> str:
    """Scanne un port via SYN scan (raw packets, nécessite scapy + sudo).

    Returns:
        "open"     si SYN-ACK reçu.
        "closed"   si RST reçu.
        "filtered" si timeout ou scapy/sudo indisponible.
    """
    if not SCAPY_AVAILABLE:
        import logging
        logging.warning("scapy non disponible — fallback sur filtered.")
        return "filtered"

    import os
    if os.geteuid() != 0:
        import logging
        logging.warning("SYN scan nécessite sudo. Retourne filtered.")
        return "filtered"

    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout)

    if resp is None:
        return "filtered"
    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        if flags == 0x12:
            return "open"
        if flags == 0x14:
            return "closed"
    return "filtered"


if __name__ == "__main__":
    # Vérification rapide
    print(scan_port_connect("127.0.0.1", 80))
