# Project Architecture — Network Port Scanner

## Overview

The project is a TCP port scanner written in Python, organized into **6 modules** that work together. Each module has a clear and well-defined role.

---

## The 6 files and their roles

### `scanner.py` — The engine

This is the core of the project. It contains all the scanning and network analysis logic.

**Available functions:**
- `scan_port_connect(ip, port, timeout)` -> `"open"` | `"closed"` | `"filtered"` — standard TCP connection, compatible with all OS
- `scan_port_syn(ip, port, timeout)` -> `"open"` | `"closed"` | `"filtered"` — raw SYN packet via scapy (requires sudo)
- `scan_range_threaded(ip, ports, scan_fn, ...)` -> dict — launches hundreds of scans in parallel via `ThreadPoolExecutor`
- `get_service_name(port)` -> service name (`"http"`, `"ssh"`, etc.) — checks a built-in dictionary of 77 services first, then falls back to `socket.getservbyport()`
- `grab_banner(ip, port, timeout)` -> first response line from the service
- `detect_service_version(ip, port, service_name, timeout)` -> version extracted via protocol-specific probe (HTTP HEAD, SMTP EHLO, MySQL greeting, DNS version.bind, VNC RFB, Redis INFO, IRC, PostgreSQL, etc.)
- `detect_os(ip, timeout)` -> `"Linux/Unix"` | `"Windows"` | `"Network device"` | `"unknown"` — TTL fingerprinting
- `detect_firewall(ip, port, timeout)` -> `"open"` | `"closed"` | `"filtered-silent"` | `"filtered-active"` | `"filtered"` — distinguishes silent DROP vs ICMP REJECT
- `resolve_target(target)` -> single DNS resolution before scanning

**Does not depend on any other project file.** It is a standalone library.

**Windows compatibility:** `geteuid` via `getattr(os, "geteuid", lambda: 1)()`, `ECONNREFUSED` via `_ECONNREFUSED_CODES` (includes `WSAECONNREFUSED`).

---

### `discovery.py` — Host detection

Before scanning ports on a machine, you first need to know which machines are active on the network.

**What it does:**
- Sends ARP broadcast requests to detect machines on the local network (`_arp_sweep`) — via scapy
- Falls back to sending parallel ICMP pings to all addresses in a subnet (`_icmp_sweep`)
- Returns the list of responding IPs (`discover_hosts`)

**Cross-platform ping compatibility:**
- Linux: `ping -c 1 -W <seconds>`
- macOS: `ping -c 1 -W <milliseconds>`
- Windows: `ping -n 1 -w <milliseconds>`

**Called by `main.py`** only when the `--discover` option is enabled.

---

### `output.py` — Results export

Once the scan is complete, this module handles writing the results to a file. All formats include the detected OS in the header/metadata.

**Supported formats:**
- `.txt` — plain text with target/OS header, one port per line with status, service, banner, version, CVEs
- `.json` — structured data with `meta` section (target, scan_type, os, date) and `ports` section
- `.csv` — spreadsheet-compatible table, columns: port, status, service, banner, os, version, firewall, vulns
- `.html` — colored visual report with table, statistics, OS in header, CVE badges with tooltips, embedded CSS (green=open, red=closed, gray=filtered)
- `.xml` — Nmap/Metasploit compatible format (`<nmaprun>/<host>/<os>/<ports>/<port>/<vulnerabilities>`)

**Called by `main.py`** at the end of the scan. For multi-host scans, one file is created per host.

---

### `vuln_analyzer.py` — Vulnerability analysis

Queries the NVD (NIST) API for known CVEs based on detected service versions.

**What it does:**
- `parse_banner(banner)` — extracts `(software, version)` via dynamic regex (SSH-specific pattern first, then generic `software/version` pattern)
- `analyze_vulnerabilities(banner)` — queries the NVD API for CVEs with CVSS >= 7.0, sorted by severity
- Uses an in-memory cache (`_CVE_CACHE`) to avoid redundant API calls
- Returns list of dicts: `{"id": "CVE-...", "cvss": 9.8, "description": "..."}`
- Logging via `logging.debug`/`logging.warning` (no `print` to avoid polluting tqdm progress bar)

**Called by `main.py`** when the `--vuln-scan` option is enabled.

---

### `main.py` — The orchestrator

This is the main entry point. It parses command-line arguments and coordinates all other modules.

**What it does:**
1. Validates user input — `validate_target()` (IPv4, IPv6, CIDR, hostname), `validate_port()`, `validate_output_file()`, `parse_ports()`
2. Resolves the hostname to an IP once (`resolve_target`)
3. Calls `discovery.py` if `--discover` is active
4. Calls `scanner.py` to scan ports in parallel
5. Enriches the results: service name, banner, version, OS, firewall type
6. Calls `vuln_analyzer.py` if `--vuln-scan` is active
7. Displays statistics summary in the terminal (no per-port output)
8. Calls `output.py` — one file per host for multi-host scans

**Results format:**
```python
results[port] = {
    "status":   "open" | "closed" | "filtered",
    "service":  "ssh" | "http" | ...,
    "banner":   "SSH-2.0-OpenSSH_8.9" | "",
    "os":       "Linux/Unix" | "Windows" | "unknown" | "",
    "version":  "nginx/1.18.0" | "",
    "firewall": "filtered-silent" | "filtered-active" | "",
    "vulns":    [{"id": "CVE-...", "cvss": 9.8, "description": "..."}] | [],
}
```

**Available CLI options:**

| Option | Description |
|--------|-------------|
| `--target` | IP, IPv6, hostname or CIDR |
| `--ports` | `22,80,443` or `1-1024` or combination |
| `--scan-type` | `connect` (default) or `syn` |
| `--output` | `.txt`, `.json`, `.csv`, `.html`, `.xml` |
| `--threads` | Parallel connections (default 100) |
| `--timeout` | Per-port timeout in seconds |
| `--banner` | Read banners from open services |
| `--version-detect` | Detect version via protocol probe |
| `--os-detect` | Detect OS via TTL (sudo required) |
| `--firewall-detect` | Distinguish DROP vs REJECT (sudo required) |
| `--vuln-scan` | Scan for known CVEs via NVD API |
| `--discover` | Discover active hosts before scanning |
| `--randomize` | Shuffle port order |
| `--max-rate` | Maximum rate in packets/second |
| `--delay` | Fixed pause between ports |
| `--jitter` | Random delay between ports |

**Imports:** `scanner.py` + `output.py` + `discovery.py` (optional) + `vuln_analyzer.py` (optional)

---

### `cli.py` — The interactive interface

A user-friendly layer on top of `main.py`. Instead of typing command-line arguments, the user answers questions step by step.

**What it does:**
- Asks questions step by step (target, profile, speed, options, report format)
- Translates simple choices (e.g. "Fast") into technical parameters (threads=400, timeout=0.3)
- Root users can now choose between SYN scan and TCP connect modes
- Offers advanced options: discovery, banners, service version, firewall, OS
- Safe display for Windows (`_print_safe`) — ASCII fallback if the terminal does not support UTF-8
- Builds the argument list and calls `main.py`

**Imports:** `main.py` only (via `from main import main`)

---

## Interaction diagram

```
User
    |
    +-- python cli.py          --> cli.py
    |                                |
    |                                v
    +-- python main.py [args]  --> main.py
                                     |
                        +------------+------------+------------+
                        v            v             v            v
                  scanner.py   discovery.py   output.py   vuln_analyzer.py
```

**Full scan flow with all options enabled:**

```
cli.py (optional)
  +-> main.py
        +-> validate_target() / parse_ports()       [validation]
        +-> resolve_target()                         [scanner.py — single DNS]
        +-> discover_hosts()                         [discovery.py — if --discover]
        +-> scan_range_threaded()                    [scanner.py — parallel scan]
        |     +-> scan_port_connect() / syn()        [per port]
        +-> detect_os()                              [scanner.py — if --os-detect]
        +-> get_service_name()                       [scanner.py — enrichment]
        +-> grab_banner()                            [scanner.py — if --banner]
        +-> detect_service_version()                 [scanner.py — if --version-detect]
        +-> detect_firewall()                        [scanner.py — if --firewall-detect, filtered ports]
        +-> analyze_vulns()                          [vuln_analyzer.py — if --vuln-scan]
        +-> write_output()                           [output.py — result file(s)]
```

---

## Dependency summary

| File | Imports | Imported by |
|------|---------|-------------|
| `scanner.py` | `socket`, `errno`, `re`, `threading`, `concurrent.futures`, `scapy` (optional) | `main.py` |
| `discovery.py` | `subprocess`, `ipaddress`, `platform`, `concurrent.futures`, `scapy` (optional) | `main.py` |
| `output.py` | `csv`, `json`, `html`, `xml.etree.ElementTree`, `datetime` | `main.py` |
| `vuln_analyzer.py` | `requests`, `re`, `logging`, `time` | `main.py` |
| `main.py` | `scanner`, `output`, `discovery`, `vuln_analyzer`, `argparse`, `logging` | `cli.py` |
| `cli.py` | `main`, `os` | — |
