"""Host discovery: ARP sweep (scapy) with ICMP ping fallback."""

import ipaddress
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

# Attempt to import scapy for the ARP sweep.
# If scapy is not installed, ICMP ping will be used instead.
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def discover_hosts(network: str, timeout: float = 1.0) -> List[str]:
    """Discovers active hosts on a network or checks a single IP.

    Uses ARP if scapy is available, otherwise falls back to ICMP ping.

    Args:
        network: CIDR subnet (e.g. "192.168.1.0/24") or single IP.
        timeout: wait delay per host.

    Returns:
        List of active IPs.
    """
    if SCAPY_AVAILABLE:
        try:
            # ARP is more reliable on a local network (LAN) as it operates at the Ethernet level
            return _arp_sweep(network, timeout)
        except Exception:
            pass  # if ARP fails (e.g. unsupported network interface), fall back to ICMP
    # Fall back to ICMP ping, compatible with all systems
    return _icmp_sweep(network, timeout)


def _arp_sweep(network: str, timeout: float) -> List[str]:
    """Sends ARP requests across the subnet."""
    # Ether(dst="ff:ff:ff:ff:ff:ff") = Ethernet frame broadcast to all machines on the network
    # ARP(pdst=network) = asks "who has this IP?" for every address in the subnet
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    # srp = send/receive at the Ethernet level; answered = list of received replies
    answered, _ = srp(pkt, timeout=timeout, verbose=False)
    # For each reply, extract the source IP address (psrc = protocol source)
    return [rcv.psrc for _, rcv in answered]


def _icmp_sweep(network: str, timeout: float) -> List[str]:
    """Pings each host on the network in parallel."""
    try:
        # Compute the list of all IPs in the CIDR subnet
        # e.g. "192.168.1.0/24" → ["192.168.1.1", "192.168.1.2", ..., "192.168.1.254"]
        net = ipaddress.ip_network(network, strict=False)
        hosts = [str(h) for h in net.hosts()]  # .hosts() excludes the network and broadcast addresses
    except ValueError:
        # Not a valid CIDR → treat as a single IP
        hosts = [network]

    # Detect the operating system to build the appropriate ping command
    system = platform.system()  # "Darwin", "Linux" or "Windows"
    active: List[str] = []

    def ping(ip: str):
        """Sends a single ping to an IP and returns the IP if it responds."""
        if system == "Windows":
            # Windows: -n = packet count, -w = timeout in milliseconds
            timeout_ms = max(1, int(timeout * 1000))
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        elif system == "Darwin":
            # macOS: -c = packet count, -W = timeout in milliseconds
            timeout_ms = max(1, int(timeout * 1000))
            cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
        else:
            # Linux: -c = packet count, -W = timeout in seconds (integer)
            timeout_s = max(1, int(timeout))
            cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]

        try:
            result = subprocess.run(
                cmd,  # -c 1 = 1 packet only
                stdout=subprocess.DEVNULL,  # discard standard output
                stderr=subprocess.DEVNULL,  # discard errors
                timeout=timeout + 2,
            )
            # returncode == 0 means the ping received a reply
            return ip if result.returncode == 0 else None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    # Run all pings in parallel for much faster execution
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ping, h): h for h in hosts}
        for future in as_completed(futures):
            ip = future.result()
            if ip:
                active.append(ip)

    # Return the list sorted in numerical IP address order
    return sorted(active)
