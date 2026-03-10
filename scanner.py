"""Scanner de ports TCP.

Ce module fournit un scanner de ports TCP via les sockets Python et scapy (optionnel).

Fonctions :
  - scan_port_connect(ip, port, timeout)                          -> statut
  - scan_port_syn(ip, port, timeout)                              -> statut (nécessite scapy + sudo)
  - scan_range(ip, start_port, end_port, timeout)                 -> dict[port, statut]
  - scan_range_threaded(ip, ports, scan_fn, timeout, delay, ...)  -> dict[port, statut]
  - get_service_name(port)                                        -> nom du service
  - grab_banner(ip, port, timeout)                                -> bannière du service
  - detect_service_version(ip, port, service_name, timeout)       -> version du service
  - detect_os(ip, timeout)                                        -> système d'exploitation estimé
  - detect_firewall(ip, port, timeout)                            -> type de filtrage pare-feu

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

# Tentative d'import de scapy (librairie pour manipuler des paquets réseau bruts).
# Si scapy n'est pas installé, on désactive silencieusement le SYN scan.
try:
    from scapy.all import IP, TCP, ICMP, sr1, conf as scapy_conf
    scapy_conf.verb = 0  # désactive les messages de log de scapy
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

    # AF_INET = protocole IPv4, SOCK_STREAM = connexion TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)  # au-delà de ce délai, on considère le port filtré
        try:
            # connect_ex retourne 0 si la connexion réussit, sinon un code d'erreur
            err = sock.connect_ex((ip, port))
        except (socket.gaierror, socket.herror, OSError):
            # gaierror = erreur de résolution DNS, herror = erreur d'hôte, OSError = erreur réseau
            return "filtered"

        if err == 0:
            return "open"  # connexion TCP établie → port ouvert

        if err in (errno.ECONNREFUSED,):
            # ECONNREFUSED = la machine a répondu RST (port fermé mais hôte joignable)
            return "closed"

        # Tout autre code d'erreur (timeout, réseau inaccessible, etc.)
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
    # Scan séquentiel port par port (sans parallélisme)
    for port in range(start_port, end_port + 1):
        results[port] = scan_port_connect(ip, port, timeout=timeout)
    return results


def resoudre_cible(cible: str) -> str:
    """Résout un hostname en adresse IP une seule fois.

    Si la cible est déjà une IP, la retourne telle quelle.
    Lève socket.gaierror si la résolution échoue.
    """
    try:
        # Vérifie si la cible est déjà une adresse IP valide
        ipaddress.ip_address(cible)
        return cible  # déjà une IP, pas besoin de résolution DNS
    except ValueError:
        # Ce n'est pas une IP → on résout le nom d'hôte via DNS
        return socket.gethostbyname(cible)


def get_service_name(port: int) -> str:
    """Retourne le nom du service associé au port, ou 'unknown'."""
    try:
        # getservbyport consulte la base de données des services du système (/etc/services)
        return socket.getservbyport(port)
    except OSError:
        # Port non répertorié dans la base système
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
                return ""  # impossible de se connecter
            # Envoie une ligne vide pour déclencher la réponse du service
            sock.sendall(b"\r\n")
            # Lit jusqu'à 1024 octets de réponse
            data = sock.recv(1024)
            # Décode les octets en texte (ignore les caractères non-ASCII) et retourne la 1ère ligne
            return data.decode(errors="ignore").strip().splitlines()[0]
    except (socket.timeout, OSError, IndexError):
        return ""


# Requêtes spécifiques envoyées pour identifier la version du service
_SERVICE_PROBES: Dict[str, bytes] = {
    "http":   b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    "ftp":    b"",    # le serveur envoie la bannière dès la connexion
    "smtp":   b"EHLO probe\r\n",
    "ssh":    b"",    # idem
    "pop3":   b"",
    "imap":   b"",
    "telnet": b"",
}


def detect_service_version(ip: str, port: int, service_name: str, timeout: float = 2.0) -> str:
    """Envoie un probe spécifique au protocole pour identifier la version du service.

    Va au-delà du simple banner grab en utilisant une requête adaptée au protocole
    attendu (HTTP HEAD, SMTP EHLO, etc.) pour extraire le nom et la version du logiciel.

    Args:
        service_name: nom retourné par get_service_name() (ex. "http", "ssh", "smtp").

    Returns:
        Chaîne de version extraite (ex. "nginx/1.18.0", "SSH-2.0-OpenSSH_8.9"),
        ou "" si la connexion échoue ou que la réponse n'est pas exploitable.

    Note : HTTPS (port 443) n'est pas supporté — une négociation TLS serait nécessaire.
    """
    probe = _SERVICE_PROBES.get(service_name.lower(), b"\r\n")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) != 0:
                return ""
            if probe:
                sock.sendall(probe)
            data = sock.recv(1024)
            response = data.decode(errors="ignore").strip()
            if not response:
                return ""
            # Pour HTTP : cherche l'en-tête "Server:" qui contient le nom du serveur web
            if service_name.lower() in ("http", "https"):
                for line in response.splitlines():
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()
            # Pour SSH, FTP, SMTP et les autres : la première ligne contient l'identification
            lines = response.splitlines()
            return lines[0] if lines else ""
    except (socket.timeout, OSError):
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

    # Mélange l'ordre des ports pour rendre le scan moins détectable par un IDS
    if randomize:
        ports = list(ports)
        random.shuffle(ports)

    # Verrou partagé entre tous les threads pour le rate limiting
    rate_lock = threading.Lock()
    # Liste mutable pour stocker le timestamp du dernier envoi (accessible depuis la closure _scan)
    last_send: List[float] = [0.0]

    def _scan(port: int) -> tuple:
        """Fonction interne : applique le délai puis scanne un port."""
        if max_rate > 0:
            # Mode rate limiting : calcule le temps à attendre avant le prochain envoi
            interval = 1.0 / max_rate  # ex: max_rate=2 → interval=0.5s entre chaque paquet
            with rate_lock:
                # Le verrou garantit qu'un seul thread envoie à la fois
                now = time.time()
                wait = interval - (now - last_send[0])
                if wait > 0:
                    time.sleep(wait)  # attend si on va trop vite
                last_send[0] = time.time()  # mémorise l'heure d'envoi
        elif delay > 0 or jitter > 0:
            # Mode délai simple : attend un temps aléatoire entre delay et delay+jitter
            time.sleep(random.uniform(delay, delay + jitter))
        return port, scan_fn(ip, port, timeout=timeout)

    try:
        # Lance jusqu'à max_workers threads en parallèle
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Soumet toutes les tâches de scan à l'executor
            futures = {executor.submit(_scan, p): p for p in ports}
            # Récupère les résultats au fur et à mesure qu'ils se terminent
            for future in as_completed(futures):
                port, status = future.result()
                results[port] = status
    except KeyboardInterrupt:
        # Ctrl+C : le bloc `with` arrête proprement l'executor avant de propager l'interruption
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
    # Les raw packets nécessitent les droits root (uid 0)
    if os.geteuid() != 0:
        import logging
        logging.warning("SYN scan nécessite sudo. Retourne filtered.")
        return "filtered"

    # Forge un paquet IP/TCP avec le flag SYN activé
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    # Envoie le paquet et attend une réponse (sr1 = send/receive 1 paquet)
    resp = sr1(pkt, timeout=timeout)

    if resp is None:
        return "filtered"  # pas de réponse → port filtré ou hôte inaccessible

    if resp.haslayer(TCP):
        flags = int(resp[TCP].flags)
        # 0x12 = SYN (0x02) + ACK (0x10) → le port répond : il est ouvert
        if flags & 0x12 == 0x12:
            return "open"
        # 0x04 = RST → la machine refuse la connexion : port fermé
        if flags & 0x04:
            return "closed"
    return "filtered"


def detect_os(ip: str, timeout: float = 1.0) -> str:
    """Tente de détecter le système d'exploitation via TCP fingerprinting.

    Analyse le TTL de la réponse SYN-ACK (ou RST) pour estimer l'OS.
    Nécessite scapy et sudo (raw sockets).

    Limitation : le TTL observé est le TTL initial moins le nombre de sauts.
    Un hôte Windows (TTL initial 128) à 65+ sauts peut être classifié Linux/Unix.
    Les résultats sont indicatifs, pas garantis.

    Returns:
        "Linux/Unix"     — TTL <= 64
        "Windows"        — TTL <= 128
        "Network device" — TTL > 128
        "unknown"        — pas de réponse ou scapy/sudo indisponible
    """
    if not SCAPY_AVAILABLE:
        return "unknown"

    import os as _os
    if _os.geteuid() != 0:
        return "unknown"

    # Sonde les ports courants pour obtenir une réponse SYN-ACK
    for probe_port in (80, 443, 22):
        pkt = IP(dst=ip) / TCP(dport=probe_port, flags="S")
        resp = sr1(pkt, timeout=timeout)
        if resp is not None and resp.haslayer(IP) and resp.haslayer(TCP):
            ttl = resp[IP].ttl
            # Les OS initialisent le TTL à une valeur fixe ; on arrondit au palier connu
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Network device"
    return "unknown"


def detect_firewall(ip: str, port: int, timeout: float = 1.0) -> str:
    """Distingue les différents types de filtrage réseau sur un port.

    Analyse la réponse à un paquet SYN pour déterminer si un pare-feu est actif :
      - SYN-ACK reçu    → "open"            (port ouvert)
      - RST reçu        → "closed"          (port fermé, pas de pare-feu)
      - ICMP reçu       → "filtered-active" (pare-feu REJECT — envoie un message d'erreur)
      - Timeout         → "filtered-silent" (pare-feu DROP — silence total)

    Sans scapy ou sans sudo, utilise scan_port_connect comme repli (retourne
    "open", "closed" ou "filtered" sans distinguer les types de filtrage).

    Returns:
        "open" | "closed" | "filtered-silent" | "filtered-active" | "filtered"

    Note : le champ "firewall" dans les résultats est "" quand le check n'a pas été exécuté
    (port non filtré, ou --firewall-detect non activé). Une valeur vide ne signifie pas
    l'absence de pare-feu.
    """
    import os as _os

    if not SCAPY_AVAILABLE or _os.geteuid() != 0:
        # Repli sur TCP connect standard si scapy/sudo indisponible
        return scan_port_connect(ip, port, timeout=timeout)

    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout)

    if resp is None:
        # Aucune réponse : le pare-feu DROP silencieusement les paquets
        return "filtered-silent"

    if resp.haslayer(TCP):
        flags = int(resp[TCP].flags)
        if flags & 0x12 == 0x12:
            return "open"      # SYN-ACK → port ouvert
        if flags & 0x04:
            return "closed"    # RST → port fermé, pas de pare-feu devant

    if resp.haslayer(ICMP):
        # ICMP port-unreachable : le pare-feu REJECT (rejette activement)
        return "filtered-active"

    return "filtered-silent"


if __name__ == "__main__":
    # Vérification rapide
    print(scan_port_connect("127.0.0.1", 80))
