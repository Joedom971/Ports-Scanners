"""TCP port scanner.

This module provides a TCP port scanner using Python sockets and scapy (optional).

Functions:
  - scan_port_connect(ip, port, timeout)                          -> status
  - scan_port_syn(ip, port, timeout)                              -> status (requires scapy + sudo)
  - scan_range_threaded(ip, ports, scan_fn, timeout, delay, ...)  -> dict[port, status]
  - get_service_name(port)                                        -> service name
  - grab_banner(ip, port, timeout)                                -> service banner
  - detect_service_version(ip, port, service_name, timeout)       -> service version
  - detect_os(ip, timeout)                                        -> estimated operating system
  - detect_firewall(ip, port, timeout)                            -> firewall filtering type

Status values:
  - "open"     (open)
  - "closed"   (closed)
  - "filtered" (filtered or unreachable)

"""

import errno
import ipaddress
import random
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from typing import Callable, Dict, List

# Attempt to import scapy (library for manipulating raw network packets).
# If scapy is not installed, SYN scan is silently disabled.
try:
    from scapy.all import IP, TCP, ICMP, sr1, send, conf as scapy_conf
    scapy_conf.verb = 0  # disable scapy log messages
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# "Connection refused" error codes by platform
# ECONNREFUSED = 111 on Linux/macOS, WSAECONNREFUSED = 10061 on Windows
_ECONNREFUSED_CODES = {errno.ECONNREFUSED}
if hasattr(errno, "WSAECONNREFUSED"):
    _ECONNREFUSED_CODES.add(errno.WSAECONNREFUSED)


def scan_port_connect(ip: str, port: int, timeout: float = 1.0) -> str:
    """Scans a single TCP port via connect().

    Args:
        ip: target IPv4 address or hostname (IPv6 not supported).
        port: TCP port number (1-65535).
        timeout: socket expiry delay in seconds.

    Returns:
        "open"     if the connection succeeded.
        "closed"   if the connection was refused.
        "filtered" if the timeout expired or the host is unreachable.
    """

    # AF_INET = IPv4 protocol, SOCK_STREAM = TCP connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)  # beyond this delay, the port is considered filtered
        try:
            # connect_ex returns 0 if the connection succeeds, otherwise an error code
            err = sock.connect_ex((ip, port))
        except (socket.gaierror, socket.herror, OSError):
            # gaierror = DNS resolution error, herror = host error, OSError = network error
            return "filtered"

        if err == 0:
            return "open"  # TCP connection established → port is open

        if err in _ECONNREFUSED_CODES:
            # ECONNREFUSED = the machine responded with RST (port closed but host reachable)
            return "closed"

        # Any other error code (timeout, unreachable network, etc.)
        return "filtered"


def resolve_target(target: str) -> str:
    """Resolves a hostname to an IP address once.

    If the target is already an IP, returns it as-is.
    Raises socket.gaierror if resolution fails.
    """
    try:
        # Check if the target is already a valid IP address
        ipaddress.ip_address(target)
        return target  # already an IP, no DNS resolution needed
    except ValueError:
        # Not an IP → resolve the hostname via DNS
        return socket.gethostbyname(target)


# Extended service dictionary — covers modern services not in /etc/services
SERVICES_DICT = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 119: "NNTP", 123: "NTP", 143: "IMAP", 161: "SNMP",
    194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    500: "ISAKMP", 587: "SMTP Submission", 636: "LDAPS",
    989: "FTPS", 990: "FTPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle DB", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel SSL", 2181: "Zookeeper",
    2222: "DirectAdmin", 2483: "Oracle DB SSL", 2484: "Oracle DB SSL",
    3000: "Development Server", 3128: "Squid Proxy", 3306: "MySQL",
    3389: "RDP", 3690: "Subversion", 4444: "Metasploit Handler",
    4567: "Ruby Server", 5000: "Flask / Dev Server", 5432: "PostgreSQL",
    5601: "Kibana", 5672: "RabbitMQ", 5900: "VNC",
    5985: "WinRM HTTP", 5986: "WinRM HTTPS", 6379: "Redis",
    6667: "IRC", 7001: "WebLogic", 7002: "WebLogic SSL",
    7070: "Web Server", 7200: "Splunk", 7474: "Neo4j",
    8000: "HTTP-ALT", 8008: "HTTP Proxy", 8009: "AJP",
    8080: "HTTP Proxy", 8081: "HTTP ALT", 8088: "Splunk Web",
    8090: "HTTP", 8443: "HTTPS ALT", 8888: "Jupyter Notebook",
    9000: "SonarQube", 9042: "Cassandra", 9090: "Prometheus",
    9092: "Kafka", 9200: "Elasticsearch", 9418: "Git",
    9999: "Debug / Dev", 10000: "Webmin", 11211: "Memcached",
    27017: "MongoDB",
}


def get_service_name(port: int) -> str:
    """Returns the service name associated with the port, or 'unknown'.

    Checks the extended dictionary first, then falls back to the system
    services database (/etc/services).
    """
    service = SERVICES_DICT.get(port)
    if service:
        return service
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Attempts to read the service banner on this TCP port.

    Some services (SSH, FTP, SMTP…) send their banner immediately upon connection
    without requiring anything to be sent. A passive recv() is tried first;
    if the service does not respond spontaneously, \r\n is sent to trigger it
    (HTTP-like behaviour).

    Returns:
        Banner string (first line), or "" on failure.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) != 0:
                return ""
            # Passive attempt: some services banner immediately upon connection
            try:
                sock.settimeout(min(0.5, timeout))
                data = sock.recv(1024)
            except socket.timeout:
                data = b""
            # If nothing received, send \r\n to trigger a response
            if not data:
                sock.settimeout(timeout)
                sock.sendall(b"\r\n")
                data = sock.recv(1024)
            return data.decode(errors="ignore").strip().splitlines()[0]
    except (socket.timeout, OSError, IndexError):
        return ""


# Protocol-specific probes sent to identify the service version
_SERVICE_PROBES: Dict[str, bytes] = {
    # Web
    "http":       b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    "https":      b"",         # TLS handshake required — fallback to generic \r\n
    # Mail
    "smtp":       b"EHLO probe\r\n",
    "smtp submission": b"EHLO probe\r\n",
    "smtps":      b"EHLO probe\r\n",
    "pop3":       b"",         # banner on connect
    "pop3s":      b"",
    "imap":       b"",         # banner on connect
    "imaps":      b"",
    # Remote access
    "ssh":        b"",         # banner on connect
    "ftp":        b"",         # banner on connect
    "ftp-data":   b"",
    "ftps":       b"",
    "telnet":     b"",         # banner on connect
    # Databases
    "mysql":      b"",         # MySQL sends greeting packet on connect
    "postgresql":  b"",        # PostgreSQL sends error on raw connect (contains version)
    # DNS — version.bind query (TXT class CHAOS)
    "dns":        b"\x00\x1e"  # length prefix for TCP DNS
                  b"\xaa\xaa"  # transaction ID
                  b"\x01\x00"  # standard query
                  b"\x00\x01"  # 1 question
                  b"\x00\x00\x00\x00\x00\x00"  # no answer/authority/additional
                  b"\x07version\x04bind\x00"    # version.bind
                  b"\x00\x10"  # type TXT
                  b"\x00\x03", # class CHAOS
    # Chat / messaging
    "irc":        b"NICK probe\r\nUSER probe 0 * :probe\r\n",
    # VNC
    "vnc":        b"",         # sends "RFB xxx.yyy" on connect
    # Redis
    "redis":      b"INFO server\r\n",
    # HTTP proxies / alt ports
    "http-alt":   b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
}


def detect_service_version(ip: str, port: int, service_name: str, timeout: float = 2.0) -> str:
    """Sends a protocol-specific probe to identify the service version.

    Goes beyond a simple banner grab by using a request tailored to the expected
    protocol (HTTP HEAD, SMTP EHLO, etc.) to extract the software name and version.

    Args:
        service_name: name returned by get_service_name() (e.g. "http", "ssh", "smtp").

    Returns:
        Extracted version string (e.g. "nginx/1.18.0", "SSH-2.0-OpenSSH_8.9"),
        or "" if the connection fails or the response is not usable.

    Note: HTTPS (port 443) is not supported — a TLS handshake would be required.
    """
    svc = service_name.lower()
    probe = _SERVICE_PROBES.get(svc, b"\r\n")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) != 0:
                return ""
            if probe:
                sock.sendall(probe)
            data = sock.recv(1024)
            if not data:
                return ""

            # MySQL: greeting packet contains version as null-terminated string starting at byte 5
            if svc == "mysql":
                try:
                    raw = data[5:]
                    version = raw[:raw.index(b"\x00")].decode(errors="ignore")
                    return f"MySQL {version}" if version else ""
                except (ValueError, IndexError):
                    return ""

            # DNS: parse TXT response for version.bind
            if svc == "dns":
                try:
                    txt = data.decode(errors="ignore")
                    # Look for version string in the response
                    for candidate in re.findall(r"[\d]+\.[\d]+[.\w-]*", txt):
                        return f"BIND {candidate}"
                except Exception:
                    pass
                return ""

            # VNC: sends "RFB xxx.yyy\n" on connect
            if svc == "vnc":
                txt = data.decode(errors="ignore").strip()
                if txt.startswith("RFB"):
                    return txt
                return ""

            # Redis: parse INFO server response
            if svc == "redis":
                txt = data.decode(errors="ignore")
                for line in txt.splitlines():
                    if line.startswith("redis_version:"):
                        return f"Redis {line.split(':',1)[1].strip()}"
                return ""

            response = data.decode(errors="ignore").strip()
            if not response:
                return ""

            # HTTP: look for the "Server:" header
            if svc in ("http", "https", "http-alt"):
                for line in response.splitlines():
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()

            # IRC: look for server version in welcome messages
            if svc == "irc":
                for line in response.splitlines():
                    match = re.search(r"(unreal|inspircd|ircd)[^\s]*[\s/]*([\d.]+)", line, re.IGNORECASE)
                    if match:
                        return f"{match.group(1)}{match.group(2)}"
                # Return first line as fallback
                lines = response.splitlines()
                return lines[0] if lines else ""

            # SSH, FTP, SMTP, POP3, IMAP, Telnet and others: first line
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
    """Scans a list of ports in parallel using ThreadPoolExecutor.

    Args:
        max_rate: maximum number of packets per second (0 = unlimited).
                  When max_rate > 0, it replaces delay: a global lock
                  serialises sends to respect the minimum interval
                  between two packets (true rate limiting).
        jitter: random variation added to the delay (in seconds).
                The actual delay is random.uniform(delay, delay + jitter).
                Ignored when max_rate > 0.
    """
    results: Dict[int, str] = {}

    # Shuffle port order to make the scan less detectable by an IDS
    if randomize:
        ports = list(ports)
        random.shuffle(ports)

    # Lock shared across all threads for rate limiting
    rate_lock = threading.Lock()
    # Mutable list to store the timestamp of the last send (accessible from the _scan closure)
    last_send: List[float] = [0.0]

    def _scan(port: int) -> tuple:
        """Inner function: applies the delay then scans a port."""
        if max_rate > 0:
            # Rate limiting mode: compute the time to wait before the next send
            interval = 1.0 / max_rate  # e.g. max_rate=2 → interval=0.5s between each packet
            with rate_lock:
                # The lock ensures only one thread sends at a time
                now = time.time()
                wait = interval - (now - last_send[0])
                if wait > 0:
                    time.sleep(wait)  # wait if sending too fast
                last_send[0] = time.time()  # record the send timestamp
        elif delay > 0 or jitter > 0:
            # Simple delay mode: wait a random time between delay and delay+jitter
            time.sleep(random.uniform(delay, delay + jitter))
        return port, scan_fn(ip, port, timeout=timeout)

    # Launch up to max_workers threads in parallel.
    # The executor is managed manually (not with `with`) so that Ctrl+C can
    # call shutdown(wait=False) without being overridden by __exit__(wait=True).
    executor = ThreadPoolExecutor(max_workers=max_workers)
    futures = {executor.submit(_scan, p): p for p in ports}
    try:
        # Collect results as they complete
        for future in as_completed(futures):
            port, status = future.result()
            results[port] = status
    except KeyboardInterrupt:
        # Cancel all pending futures (not yet started) immediately.
        # cancel_futures=True is available in Python 3.9+.
        # Already-running threads finish their current sr1() call, but no new ones start.
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        # Normal exit: shut down without waiting (all futures already completed above)
        executor.shutdown(wait=False)

    return results


def scan_port_syn(ip: str, port: int, timeout: float = 1.0) -> str:
    """Scans a port via SYN scan (raw packets, requires scapy + sudo).

    Returns:
        "open"     if SYN-ACK received.
        "closed"   if RST received.
        "filtered" if timeout or scapy/sudo unavailable.
    """
    if not SCAPY_AVAILABLE:
        import logging
        logging.warning("scapy not available — falling back to filtered.")
        return "filtered"

    import os
    # Raw packets require root privileges (uid 0)
    if getattr(os, "geteuid", lambda: 1)() != 0:
        import logging
        logging.warning("SYN scan requires sudo. Returning filtered.")
        return "filtered"

    # Craft an IP/TCP packet with the SYN flag set
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    # Send the packet and wait for a response (sr1 = send/receive 1 packet)
    resp = sr1(pkt, timeout=timeout)

    if resp is None:
        return "filtered"  # no response → port filtered or host unreachable

    if resp.haslayer(TCP):
        flags = int(resp[TCP].flags)
        # 0x12 = SYN (0x02) + ACK (0x10) → the port responds: it is open
        if flags & 0x12 == 0x12:
            # Send a RST to cleanly close the half-open connection.
            # Without this, the target keeps the entry in its connection table
            # until the TCP timeout — on a large scan, this can exhaust the table.
            # send() not sr1(): a RST does not expect a response (RFC 793).
            rst = IP(dst=ip) / TCP(dport=port, sport=resp[TCP].dport, flags="R", seq=resp[TCP].ack)
            send(rst)
            return "open"
        # 0x04 = RST → the machine refuses the connection: port closed
        if flags & 0x04:
            return "closed"
    return "filtered"


def detect_os(ip: str, timeout: float = 1.0) -> str:
    """Attempts to detect the operating system via TCP fingerprinting.

    Analyses the TTL of the SYN-ACK (or RST) response to estimate the OS.
    Requires scapy and sudo (raw sockets).

    Limitation: the observed TTL is the initial TTL minus the number of hops.
    A Windows host (initial TTL 128) at 65+ hops may be classified as Linux/Unix.
    Results are indicative, not guaranteed.

    Returns:
        "Linux/Unix"     — TTL <= 64
        "Windows"        — TTL <= 128
        "Network device" — TTL > 128
        "unknown"        — no response or scapy/sudo unavailable
    """
    if not SCAPY_AVAILABLE:
        return "unknown"

    import os as _os
    if getattr(_os, "geteuid", lambda: 1)() != 0:
        return "unknown"

    # Probe common ports to obtain a SYN-ACK response
    for probe_port in (80, 443, 22):
        pkt = IP(dst=ip) / TCP(dport=probe_port, flags="S")
        resp = sr1(pkt, timeout=timeout)
        if resp is not None and resp.haslayer(IP) and resp.haslayer(TCP):
            flags = int(resp[TCP].flags)
            if flags & 0x12 == 0x12:
                # SYN-ACK received: cleanly close the half-open connection
                rst = IP(dst=ip) / TCP(dport=probe_port, sport=resp[TCP].dport, flags="R", seq=resp[TCP].ack)
                send(rst)
            ttl = resp[IP].ttl
            # OSes initialise TTL to a fixed value; round to the nearest known threshold
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Network device"
    return "unknown"


def detect_firewall(ip: str, port: int, timeout: float = 1.0) -> str:
    """Distinguishes between different types of network filtering on a port.

    Analyses the response to a SYN packet to determine whether a firewall is active:
      - SYN-ACK received → "open"            (port open)
      - RST received     → "closed"          (port closed, no firewall)
      - ICMP received    → "filtered-active" (firewall REJECT — sends an error message)
      - Timeout          → "filtered-silent" (firewall DROP — complete silence)

    Without scapy or sudo, falls back to scan_port_connect (returns
    "open", "closed" or "filtered" without distinguishing filtering types).

    Returns:
        "open" | "closed" | "filtered-silent" | "filtered-active" | "filtered"

    Note: the "firewall" field in results is "" when the check was not run
    (port not filtered, or --firewall-detect not enabled). An empty value does not mean
    the absence of a firewall.
    """
    import os as _os

    if not SCAPY_AVAILABLE or getattr(_os, "geteuid", lambda: 1)() != 0:
        # Fall back to standard TCP connect if scapy/sudo is unavailable
        return scan_port_connect(ip, port, timeout=timeout)

    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout)

    if resp is None:
        # No response: the firewall silently DROPs packets
        return "filtered-silent"

    if resp.haslayer(TCP):
        flags = int(resp[TCP].flags)
        if flags & 0x12 == 0x12:
            # Close the half-open connection before returning the result
            rst = IP(dst=ip) / TCP(dport=port, sport=resp[TCP].dport, flags="R", seq=resp[TCP].ack)
            send(rst)
            return "open"      # SYN-ACK → port open
        if flags & 0x04:
            return "closed"    # RST → port closed, no firewall in front

    if resp.haslayer(ICMP):
        # ICMP port-unreachable: the firewall REJECTs (actively rejects)
        return "filtered-active"

    return "filtered-silent"


if __name__ == "__main__":
    # Quick sanity check
    print(scan_port_connect("127.0.0.1", 80))
