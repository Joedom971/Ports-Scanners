"""Scanner de ports TCP.

Ce module fournit un scanner de ports TCP via les sockets Python et scapy (optionnel).

Fonctions :
  - scan_port_connect(ip, port, timeout)                          -> statut
  - scan_port_syn(ip, port, timeout)                              -> statut (nécessite scapy + sudo)
  - scan_range(ip, start_port, end_port, timeout)                 -> dict[port, statut]
  - scan_range_threaded(ip, ports, scan_fn, timeout, delay, ...)  -> dict[port, statut]
  - get_service_name(port)                                        -> nom du service
  - grab_banner(ip, port, timeout)                                -> bannière du service

Valeurs de statut :
  - "open"     (ouvert)
  - "closed"   (fermé)
  - "filtered" (filtré ou inaccessible)

"""

import errno
import ipaddress
import random
import socket
import threading
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
        ip: adresse IPv4 ou nom d'hôte cible (IPv6 non supporté).
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


def resoudre_cible(cible: str) -> str:
    """Résout un hostname en adresse IP une seule fois.

    Si la cible est déjà une IP, la retourne telle quelle.
    Lève socket.gaierror si la résolution échoue.
    """
    try:
        ipaddress.ip_address(cible)
        return cible  # déjà une IP
    except ValueError:
        return socket.gethostbyname(cible)


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
    randomize: bool = False,
    max_rate: float = 0.0,
    jitter: float = 0.0,
) -> Dict[int, str]:
    """Scanne une liste de ports en parallèle via ThreadPoolExecutor.

    Args:
        max_rate: nombre maximal de paquets par seconde (0 = illimité).
                  Quand max_rate > 0, il remplace delay : un verrou global
                  sérialise les envois pour respecter l'intervalle minimum
                  entre deux paquets (true rate limiting).
        jitter: variation aléatoire ajoutée au délai (en secondes).
                Le délai réel est random.uniform(delay, delay + jitter).
                Ignoré si max_rate > 0.
    """
    results: Dict[int, str] = {}

    if randomize:
        ports = list(ports)
        random.shuffle(ports)

    rate_lock = threading.Lock()
    last_send: List[float] = [0.0]  # liste mutable pour accès depuis closure

    def _scan(port: int) -> tuple:
        if max_rate > 0:
            interval = 1.0 / max_rate
            with rate_lock:
                now = time.time()
                wait = interval - (now - last_send[0])
                if wait > 0:
                    time.sleep(wait)
                last_send[0] = time.time()
        elif delay > 0 or jitter > 0:
            time.sleep(random.uniform(delay, delay + jitter))
        return port, scan_fn(ip, port, timeout=timeout)

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_scan, p): p for p in ports}
            for future in as_completed(futures):
                port, status = future.result()
                results[port] = status
    except KeyboardInterrupt:
        # Le bloc `with` gère l'arrêt de l'executor via __exit__
        raise

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
        flags = int(resp[TCP].flags)
        if flags & 0x12 == 0x12:   # SYN + ACK
            return "open"
        if flags & 0x04:            # RST
            return "closed"
    return "filtered"


if __name__ == "__main__":
    # Vérification rapide
    print(scan_port_connect("127.0.0.1", 80))
