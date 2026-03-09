"""Basic TCP port scanner.

This module provides a simple connect-style port scanner using Python sockets.

Functions:
  - scan_port_connect(ip, port) -> status
  - scan_range(ip, start_port, end_port) -> dict[port] = status

Status values:
  - "open"
  - "closed"
  - "filtered"

"""

import errno
import socket
from typing import Dict


def scan_port_connect(ip: str, port: int, timeout: float = 1.0) -> str:
    """Scan a single TCP port using a connect().

    Args:
        ip: target IPv4/IPv6 address or hostname.
        port: TCP port number (1-65535).
        timeout: socket timeout in seconds.

    Returns:
        "open" if connection succeeded.
        "closed" if connection was refused.
        "filtered" if timed out or inaccessible.
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
    """Scan a range of TCP ports.

    Args:
        ip: target IPv4/IPv6 address or hostname.
        start_port: first port (inclusive).
        end_port: last port (inclusive).
        timeout: per-port socket timeout.

    Returns:
        Dict mapping port -> status.
    """

    results: Dict[int, str] = {}
    for port in range(start_port, end_port + 1):
        results[port] = scan_port_connect(ip, port, timeout=timeout)
    return results


if __name__ == "__main__":
    # Quick sanity check
    print(scan_port_connect("127.0.0.1", 80))
