# main.py
"""Command-line interface for the port scanner.

Supports:
  - target host / IP address or CIDR subnet
  - port ranges (e.g. 1-1024, 22,80,443, or a combination)
  - SYN scan (requires scapy + sudo) or TCP connect
  - parallel scan (ThreadPoolExecutor)
  - host discovery (ARP or ICMP)
  - banner grabbing, service names, rate limiting
  - vulnerability analysis (CVE lookup via NVD API)
  - console + file export (.txt/.json/.csv/.html)

Usage:
  python main.py --target 192.168.1.1 --ports 20-1024 --output scan.json
  python main.py --target 192.168.1.0/24 --discover --ports 22,80 --scan-type syn --vuln-scan
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
    resolve_target,
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

# Attempt to import the vulnerability analyzer module.
# If requests is not installed, vuln scanning is silently disabled.
try:
    from vuln_analyzer import analyze_vulnerabilities
    VULN_ANALYSIS_AVAILABLE = True
except ImportError:
    VULN_ANALYSIS_AVAILABLE = False


def validate_port(port: int) -> int:
    """Checks that a port is within the valid range (1-65535)."""
    if not 1 <= port <= 65535:
        raise ValueError(f"Invalid port: {port} (must be between 1 and 65535)")
    return port


def validate_target(target: str) -> str:
    """Checks that a target is a valid IP, hostname, or CIDR."""
    import ipaddress
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty.")
    # Attempt to parse as CIDR (e.g. "192.168.1.0/24")
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    # Attempt to parse as a plain IP address (IPv4 or IPv6)
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    # Hostname / plain IP: basic check of allowed characters
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
    if not all(c in allowed_chars for c in target):
        raise ValueError(f"Invalid target: '{target}' contains unauthorized characters.")
    if len(target) > 253:
        # The DNS standard limits hostnames to 253 characters maximum
        raise ValueError(f"Invalid target: hostname too long ({len(target)} characters).")
    return target


def validate_output_file(path_str: str) -> Path:
    """Checks that the output path is safe (valid extension, no relative traversal)."""
    path_str = path_str.strip()
    if not path_str:
        raise ValueError("Output file name cannot be empty.")
    valid_extensions = {".txt", ".json", ".csv", ".html", ".xml"}
    path = Path(path_str)
    if path.suffix.lower() not in valid_extensions:
        raise ValueError(f"Invalid extension: '{path.suffix}'. Use .txt, .json, .csv, .html or .xml.")
    # Block directory traversal in relative paths (e.g. ../../etc/passwd)
    if not path.is_absolute():
        try:
            path.resolve().relative_to(Path.cwd().resolve())
        except ValueError:
            raise ValueError(f"Unauthorized path: '{path_str}' attempts to escape the current directory.")
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
                start, end = validate_port(int(start_str)), validate_port(int(end_str))
                if start > end:
                    start, end = end, start  # fix reversed range (e.g. "85-80")
                ports.extend(range(start, end + 1))
            else:
                # Single port
                ports.append(validate_port(int(part)))
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid port specification: {e}")
    if not ports:
        raise ValueError("No valid port found in the specification.")
    # sorted(set(...)) : remove duplicates and sort in ascending order
    return sorted(set(ports))


def main(args: Optional[List[str]] = None) -> int:
    # Define all accepted command-line arguments
    parser = argparse.ArgumentParser(description="TCP Port Scanner")
    parser.add_argument("--target", required=True, help="Target host, IP or CIDR subnet")
    parser.add_argument("--ports", required=True,
                        help="Ports to scan (e.g. 1-1024 or 22,80,443 or 20-25,80)")
    parser.add_argument("--scan-type", choices=["connect", "syn"], default="connect",
                        help="Scan type (default: connect)")
    parser.add_argument("--output", default="scan_results.txt",
                        help="Output file (.txt/.json/.csv/.html/.xml)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Per-port timeout in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Number of parallel threads (default: 100)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Delay between ports in seconds (default: 0)")
    parser.add_argument("--discover", action="store_true",
                        help="Enable host discovery before scanning")
    parser.add_argument("--banner", action="store_true",
                        help="Enable banner grabbing (open ports only)")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING"], default="INFO",
                        help="Log level (default: INFO)")
    parser.add_argument("--randomize", action="store_true",
                        help="Randomize port order to reduce detection")
    parser.add_argument("--max-rate", type=float, default=0.0,
                        help="Max rate in packets/second (0 = unlimited)")
    parser.add_argument("--jitter", type=float, default=0.0,
                        help="Random delay variation in seconds (0 = disabled)")
    parser.add_argument("--os-detect", action="store_true",
                        help="Attempt OS detection (requires scapy + sudo)")
    parser.add_argument("--version-detect", action="store_true",
                        help="Detect service versions (active protocol probing)")
    parser.add_argument("--firewall-detect", action="store_true",
                        help="Distinguish firewall filtering types (requires scapy + sudo)")
    parser.add_argument("--vuln-scan", action="store_true",
                        help="Search for known CVEs based on detected banners/versions (requires Internet)")

    parsed = parser.parse_args(args=args)

    # Configure the logging system (DEBUG = very verbose, WARNING = alerts only)
    logging.basicConfig(
        level=getattr(logging, parsed.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # Validate numeric values before starting the scan
    if parsed.timeout <= 0:
        print("Error: --timeout must be strictly positive.")
        return 1
    if parsed.threads < 1:
        print("Error: --threads must be >= 1.")
        return 1
    if parsed.delay < 0:
        print("Error: --delay must be >= 0.")
        return 1
    if parsed.max_rate < 0:
        print("Error: --max-rate must be >= 0.")
        return 1
    if parsed.jitter < 0:
        print("Error: --jitter must be >= 0.")
        return 1
    if parsed.max_rate > 0 and parsed.threads > 1:
        # In max-rate mode, sends are serialised → multiple threads have no effect
        print(f"Note: --max-rate serialises sends — --threads {parsed.threads} has no effect. "
              f"Packets will be sent at {parsed.max_rate} pkt/s.")

    if parsed.vuln_scan and not VULN_ANALYSIS_AVAILABLE:
        logging.warning("--vuln-scan is enabled but vuln_analyzer module (or requests library) is missing. "
                        "CVE analysis will be skipped.")

    # Sanitise user inputs (protection against malformed values)
    try:
        sanitised_target = validate_target(parsed.target)
        ports = parse_ports(parsed.ports)
        out_path = validate_output_file(parsed.output)
    except ValueError as e:
        print(f"Error: {e}")
        return 1

    # Create the destination directory if the output path contains subdirectories
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Select the scan function based on the requested type
    if parsed.scan_type == "syn":
        if not SCAPY_AVAILABLE:
            print("WARNING: scapy not available. Install it: pip install scapy")
            print("Falling back to TCP connect.")
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
        _ipaddress.ip_network(sanitised_target, strict=False)
        _is_cidr = "/" in sanitised_target  # confirm it is a network, not a plain IP
    except ValueError:
        pass
    if not _is_cidr:
        try:
            sanitised_target = resolve_target(sanitised_target)
        except OSError as e:
            print(f"Error: unable to resolve '{sanitised_target}' — {e}")
            return 1

    # Host discovery: detect active machines on the network before scanning their ports
    if parsed.discover:
        from discovery import discover_hosts
        logging.info(f"Host discovery on {sanitised_target}...")
        targets = discover_hosts(sanitised_target, timeout=parsed.timeout)
        if not targets:
            print("No active hosts found.")
            return 1
        print(f"{len(targets)} active host(s): {', '.join(targets)}")
    else:
        # No discovery: scan only the provided target
        targets = [sanitised_target]

    # Dictionary to store results for all scanned hosts
    all_results: Dict[str, Dict[int, dict]] = {}

    # --- FEATURE: STATISTIK GENERATOR (start) ---
    # Start the timer before the scan loop to measure total execution time across all hosts
    start_time = time.time()

    for target in targets:
        print(f"\nScanning {target} — {len(ports)} ports ({parsed.scan_type})")

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
                print(f"  OS detected: {os_guess}")
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
            # Vulnerability analysis: prefer active version detection, fall back to banner
            vulns = []
            if parsed.vuln_scan and VULN_ANALYSIS_AVAILABLE and status == "open":
                vuln_target = version if version else banner
                if vuln_target:
                    vulns = analyze_vulnerabilities(vuln_target)
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
                "vulns": vulns,
            }

        all_results[target] = results

    # Stop the timer after all hosts have been scanned      ---STATISTIK GENERATOR (end)---
    elapsed = time.time() - start_time

    # Display the global analytical summary via output.py
    # all_results is passed directly so every (host, port) pair is counted
    print_summary(all_results, elapsed)
    # --- FEATURE: STATISTIK GENERATOR (end) ---

    # Export results to a file
    if len(all_results) == 1:
        # Single host: standard behaviour
        target_key = list(all_results.keys())[0]
        write_output(all_results[target_key], out_path, target_key, parsed.scan_type)
        print(f"\nResults saved to {out_path}")
    else:
        # Multiple hosts: one file per host (base_name_IP.ext)
        for host_ip, host_results in all_results.items():
            safe_ip = host_ip.replace(".", "_").replace(":", "_")
            host_path = out_path.parent / f"{out_path.stem}_{safe_ip}{out_path.suffix}"
            write_output(host_results, host_path, host_ip, parsed.scan_type)
            print(f"  Results for {host_ip} saved to {host_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
