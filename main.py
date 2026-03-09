"""CLI wrapper for the port scanner.

Supports:
  - target host/IP
  - port range (e.g. 1-1024)
  - output to console and file (.txt/.json/.csv/.html)

Usage:
  python main.py --target 192.168.1.1 --ports 20-1024 --output scan.json
"""

import argparse
from pathlib import Path
from typing import Dict, List, Optional

from scanner import scan_port_connect
from output import write_output


def parse_ports(port_str: str) -> List[int]:
    """Parse port specification into a list of ports.

    Accepts:
      - "22" (single port)
      - "20-25" (inclusive range)
      - "22,80,443" (comma-separated list)
      - Combination: "22,80-85"
    """

    ports: List[int] = []
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start = int(start_str)
            end = int(end_str)
            if start > end:
                start, end = end, start
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))

    return sorted(set(ports))


def main(args: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Basic TCP port scanner")
    parser.add_argument("--target", required=True, help="Target hostname or IP")
    parser.add_argument(
        "--ports",
        required=True,
        help="Port range (e.g. 1-1024 or 22,80,443 or 20-25,80)",
    )
    parser.add_argument(
        "--output",
        default="scan_results.txt",
        help="Output file path (.txt/.json/.csv/.html). Default: scan_results.txt",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Per-port timeout in seconds (default: 1.0)",
    )

    parsed = parser.parse_args(args=args)

    target = parsed.target
    ports = parse_ports(parsed.ports)

    print(f"Scanning {target} ports: {ports[0]}-{ports[-1]} ({len(ports)} ports)")

    # Scan each requested port.
    results: Dict[int, dict] = {}
    for port in ports:
        status = scan_port_connect(target, port, timeout=parsed.timeout)
        results[port] = {"status": status, "service": "", "banner": ""}
        print(f"{port:5d}: {status}")

    out_path = Path(parsed.output)
    write_output(results, out_path, target, "connect")
    print(f"Saved results to {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
