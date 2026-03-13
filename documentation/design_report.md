# Design Report

## Architecture

The project is organized into separate modules by responsibility:

| Module | Role |
|--------|------|
| `cli.py` | Simplified interactive interface for end users |
| `main.py` | Full CLI entry point via `argparse` |
| `scanner.py` | TCP scanning library (connect and SYN) |
| `output.py` | Results export (txt, json, csv, html, xml) |
| `discovery.py` | Host discovery on a network |
| `vuln_analyzer.py` | Vulnerability analysis using CVE databases |
| `tests/` | Unit tests (pytest) |
| `documentation/` | Project documentation (reports, design) |

## Modules

### `cli.py`
Step-by-step interface for non-experts. Provides:
- Predefined profiles (quick, standard, full, custom)
- Simplified speed settings (Fast / Normal / Slow) that configure threads, timeout, and delay
- Root users can choose between SYN scan and TCP connect (non-root users default to TCP connect)

### `main.py`
Full CLI exposing all options:
- `--target` — target (IP, hostname, CIDR)
- `--ports` — port specification (e.g. `22,80-85,443`)
- `--scan-type` — `connect` or `syn`
- `--threads` — parallelism (default: 100)
- `--timeout` — per-port timeout in seconds (default: 1.0)
- `--delay` — delay between ports for rate limiting (default: 0)
- `--discover` — host discovery before scanning
- `--banner` — banner grabbing on open ports
- `--vuln-scan` — vulnerability analysis on open ports using CVE databases
- `--version-detect` — detect service versions via protocol probes
- `--os-detect` — detect OS via TTL fingerprinting (requires sudo)
- `--firewall-detect` — distinguish DROP vs REJECT (requires sudo)
- `--vuln-scan` — vulnerability analysis on open ports using NVD API
- `--output` — output file (.txt / .json / .csv / .html / .xml)
- `--randomize` — shuffle port order
- `--max-rate` — max rate in packets/second
- `--jitter` — random delay between ports
- `--log-level` — logging level

Input validation: `validate_target()` (supports IPv4, IPv6, CIDR, hostname), `validate_port()`, `parse_ports()`.

Target resolution: `resolve_target()` — DNS resolution before scanning.

Terminal output: statistics summary only (no per-port display). Per-port details are written to the report file.

### `scanner.py`
Low-level functions:
- `scan_port_connect(ip, port, timeout)` — scan via full TCP connection
- `scan_port_syn(ip, port, timeout)` — scan via raw SYN packet (requires scapy + sudo)
- `scan_range_threaded(ip, ports, scan_fn, timeout, delay, max_workers, randomize, max_rate, jitter)` — parallel scanning
- `get_service_name(port)` — service name for a given port; uses a built-in dictionary first, then falls back to `socket.getservbyport()`
- `grab_banner(ip, port, timeout)` — read the service banner
- `detect_service_version(ip, port, service_name, timeout)` — protocol-specific probes (HTTP, SMTP, MySQL, DNS, VNC, Redis, IRC, PostgreSQL, etc.)
- `detect_os(ip, timeout)` — TTL fingerprinting via scapy (requires sudo)
- `detect_firewall(ip, port, timeout)` — distinguishes DROP vs REJECT via scapy (requires sudo)
- `resolve_target(target)` — single DNS resolution before scanning

### `output.py`
Single function `write_output(results, path, target, scan_type)` that detects the file extension and writes:
- `.txt` — plain text with target/OS header, one port per line with CVE details
- `.json` — structured data with `meta` (target, scan_type, os, date) and `ports` sections
- `.csv` — spreadsheet-compatible with os, version, firewall, vulns columns
- `.html` — visual report with colors, statistics, OS in header, CVE badges with tooltips
- `.xml` — Nmap-compatible format with `<os>` element and CVE descriptions

All formats display the detected OS in the header/metadata.

### `discovery.py`
- `discover_hosts(network, timeout)` — ARP sweep (scapy) with ICMP ping fallback
- `_arp_sweep(network, timeout)` — sends ARP packets on the subnet
- `_icmp_sweep(network, timeout)` — parallel ping on all hosts in the CIDR

### `vuln_analyzer.py`
- `parse_banner(banner)` — dynamic regex extraction of `(software, version)` (SSH-specific + generic pattern)
- `analyze_vulnerabilities(banner)` — queries NVD API for CVEs with CVSS >= 7.0, in-memory cache
- Returns `[{"id": "CVE-...", "cvss": 9.8, "description": "..."}]`
- Logging via `logging.debug`/`logging.warning` (no print to avoid polluting tqdm)
- `--vuln-scan` flag triggers the analysis on open ports

## Internal Results Format

```python
dict[int, dict]
# Example:
{
    80:  {"status": "open",     "service": "http",  "banner": "Apache/2.4",
          "os": "Linux/Unix",   "version": "Apache/2.4.54", "firewall": "",
          "vulns": [{"id": "CVE-2024-XXXX", "cvss": 9.8, "description": "..."}]},
    22:  {"status": "closed",   "service": "ssh",   "banner": "",
          "os": "",             "version": "", "firewall": "", "vulns": []},
    443: {"status": "filtered", "service": "https", "banner": "",
          "os": "",             "version": "", "firewall": "filtered-silent", "vulns": []},
}
```

## Libraries Used

| Library | Usage |
|---------|-------|
| `socket` | TCP connections and name resolution |
| `concurrent.futures` | Parallelism via ThreadPoolExecutor |
| `argparse` | CLI argument parsing |
| `json`, `csv` | Results serialization |
| `subprocess` | ICMP ping for host discovery |
| `ipaddress` | Computing hosts from a CIDR subnet |
| `requests` | HTTP requests for vulnerability database queries |
| `scapy` *(optional)* | SYN scan and ARP sweep |
| `tqdm` *(optional)* | Progress bar |

## Network Observations (Wireshark)

### TCP connect
- Completes the full handshake (SYN → SYN-ACK → ACK)
- Open port: connection established, then closed cleanly
- Closed port: target responds with RST
- Filtered port: no response, the scanner waits until timeout

### SYN scan
- Sends only the SYN (raw packet via scapy)
- Open port: receives SYN-ACK, sends RST to cleanly close the half-open connection
- Closed port: receives RST-ACK
- Filtered port: no response
- More stealthy: no full connection is logged in application logs
- Known limitation: on Linux without an iptables rule, the kernel sends its own RST before scapy (race condition inherent to userspace raw sockets)
