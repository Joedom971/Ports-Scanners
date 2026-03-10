"""Découverte d'hôtes : balayage ARP (scapy) avec repli ICMP (ping)."""

import ipaddress
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

# Tentative d'import de scapy pour le balayage ARP.
# Si scapy n'est pas installé, on utilisera le ping ICMP à la place.
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def discover_hosts(network: str, timeout: float = 1.0) -> List[str]:
    """Découvre les hôtes actifs sur un réseau ou vérifie une IP unique.

    Utilise ARP si scapy disponible, sinon ICMP ping.

    Args:
        network: sous-réseau CIDR (ex. "192.168.1.0/24") ou IP unique.
        timeout: délai d'attente par hôte.

    Returns:
        Liste des IPs actives.
    """
    if SCAPY_AVAILABLE:
        try:
            # ARP est plus fiable sur un réseau local (LAN) car il opère au niveau Ethernet
            return _arp_sweep(network, timeout)
        except Exception:
            pass  # si ARP échoue (ex. interface réseau non supportée), on bascule sur ICMP
    # Repli sur le ping ICMP, compatible avec tous les systèmes
    return _icmp_sweep(network, timeout)


def _arp_sweep(network: str, timeout: float) -> List[str]:
    """Envoie des requêtes ARP sur le sous-réseau."""
    # Ether(dst="ff:ff:ff:ff:ff:ff") = trame Ethernet diffusée à toutes les machines du réseau
    # ARP(pdst=network) = demande "qui a cette IP ?" à toutes les adresses du sous-réseau
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    # srp = send/receive au niveau Ethernet ; answered = liste des réponses reçues
    answered, _ = srp(pkt, timeout=timeout, verbose=False)
    # Pour chaque réponse, extrait l'adresse IP source (psrc = protocol source)
    return [rcv.psrc for _, rcv in answered]


def _icmp_sweep(network: str, timeout: float) -> List[str]:
    """Ping chaque hôte du réseau en parallèle."""
    try:
        # Calcule la liste de toutes les IPs du sous-réseau CIDR
        # ex. "192.168.1.0/24" → ["192.168.1.1", "192.168.1.2", ..., "192.168.1.254"]
        net = ipaddress.ip_network(network, strict=False)
        hosts = [str(h) for h in net.hosts()]  # .hosts() exclut l'adresse réseau et le broadcast
    except ValueError:
        # Ce n'est pas un CIDR valide → on traite comme une IP unique
        hosts = [network]

    # Détecte le système d'exploitation pour construire la commande ping adaptée
    system = platform.system()  # "Darwin", "Linux" ou "Windows"
    active: List[str] = []

    def ping(ip: str):
        """Lance un ping unique vers une IP et retourne l'IP si elle répond."""
        if system == "Windows":
            # Windows : -n = nombre de paquets, -w = timeout en millisecondes
            timeout_ms = max(1, int(timeout * 1000))
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        elif system == "Darwin":
            # macOS : -c = nombre de paquets, -W = timeout en millisecondes
            timeout_ms = max(1, int(timeout * 1000))
            cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
        else:
            # Linux : -c = nombre de paquets, -W = timeout en secondes (entier)
            timeout_s = max(1, int(timeout))
            cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]

        try:
            result = subprocess.run(
                cmd,  # -c 1 = 1 seul paquet
                stdout=subprocess.DEVNULL,  # ignore la sortie standard
                stderr=subprocess.DEVNULL,  # ignore les erreurs
                timeout=timeout + 2,
            )
            # returncode == 0 signifie que le ping a reçu une réponse
            return ip if result.returncode == 0 else None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    # Lance tous les pings en parallèle pour aller beaucoup plus vite
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ping, h): h for h in hosts}
        for future in as_completed(futures):
            ip = future.result()
            if ip:
                active.append(ip)

    # Retourne la liste triée par ordre numérique d'adresse IP
    return sorted(active)
