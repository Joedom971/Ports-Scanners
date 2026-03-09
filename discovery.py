"""Découverte d'hôtes : balayage ARP (scapy) avec repli ICMP (ping)."""

import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

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
            return _arp_sweep(network, timeout)
        except Exception:
            pass
    return _icmp_sweep(network, timeout)


def _arp_sweep(network: str, timeout: float) -> List[str]:
    """Envoie des requêtes ARP sur le sous-réseau."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(pkt, timeout=timeout, verbose=False)
    return [rcv.psrc for _, rcv in answered]


def _icmp_sweep(network: str, timeout: float) -> List[str]:
    """Ping chaque hôte du réseau en parallèle."""
    try:
        net = ipaddress.ip_network(network, strict=False)
        hosts = [str(h) for h in net.hosts()]
    except ValueError:
        # IP unique
        hosts = [network]

    timeout_ms = max(1, int(timeout * 1000))
    active: List[str] = []

    def ping(ip: str):
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_ms), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return ip if result.returncode == 0 else None

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ping, h): h for h in hosts}
        for future in as_completed(futures):
            ip = future.result()
            if ip:
                active.append(ip)

    return sorted(active)
