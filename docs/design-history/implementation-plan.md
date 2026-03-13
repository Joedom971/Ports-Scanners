# Implementation Plan

**Date:** 2026-03-09 (updated 2026-03-13)
**Status:** All tasks completed ✅

---

## Summary

| Task | Description | Status |
|------|-------------|--------|
| 1 | Test infrastructure (`tests/`) | ✅ |
| 2 | `output.py` + HTML export | ✅ |
| 3 | `get_service_name` + `grab_banner` in `scanner.py` | ✅ |
| 4 | `scan_range_threaded` in `scanner.py` | ✅ |
| 5 | `scan_port_syn` in `scanner.py` | ✅ |
| 6 | `discovery.py` (ARP + ICMP) | ✅ |
| 7 | Rewrite `main.py` + `tests/test_main.py` | ✅ |
| 8 | `requirements.txt` | ✅ |
| 9 | OS detection via TTL fingerprinting (`--os-detect`) | ✅ |
| 10 | Service version detection (`--version-detect`) | ✅ |
| 11 | Firewall type detection (`--firewall-detect`) | ✅ |
| 12 | Nmap-compatible XML export (`--output scan.xml`) | ✅ |
| 13 | Windows / macOS / Linux compatibility | ✅ |
| 14 | Vulnerability scanning (`--vuln-scan`) | ✅ |

**Total: 76 tests, all passing.**

---

## Task 1 — Test infrastructure

Created `tests/` directory with `__init__.py`.
Verified that pytest collects without errors.

---

## Task 2 — `output.py`

Extracted `write_output()` from `main.py` + added HTML format.

Supported formats: `.txt` / `.json` / `.csv` / `.html`

The HTML includes:
- Header: target, date, scan type
- Statistics: open / closed / filtered
- Color-coded table (green = open, red = closed, gray = filtered)

---

## Task 3 — `get_service_name` + `grab_banner`

Added to `scanner.py`:

- `get_service_name(port)` — uses `socket.getservbyport()`, fallback `"unknown"`
- `grab_banner(ip, port, timeout)` — TCP connection + reads first line of response

---

## Task 4 — `scan_range_threaded`

Added to `scanner.py`:

- `ThreadPoolExecutor` with configurable `max_workers`
- `delay` parameter for rate limiting
- Accepts any scan function via `scan_fn`

---

## Task 5 — `scan_port_syn`

Added to `scanner.py`:

- Forges a SYN packet via scapy
- SYN-ACK → `"open"`, RST → `"closed"`, timeout → `"filtered"`
- Returns `"filtered"` if scapy is missing or not root (no crash)

---

## Task 6 — `discovery.py`

New module:

- `discover_hosts(network, timeout)` — ARP if scapy available, otherwise ICMP
- `_arp_sweep()` — scapy ARP broadcast
- `_icmp_sweep()` — parallel ping on all hosts in the CIDR

---

## Task 7 — Rewrite `main.py`

New arguments added:

| Argument | Description |
|----------|-------------|
| `--scan-type` | `connect` or `syn` |
| `--threads` | Number of parallel threads |
| `--delay` | Delay between ports (rate limiting) |
| `--discover` | Enable host discovery |
| `--banner` | Enable banner grabbing |
| `--log-level` | Logging level |

---

## Task 8 — Configuration files

- `requirements.txt` updated: `tqdm`, `scapy`, `pytest`, `requests`

---

## Task 9 — OS detection (`--os-detect`)

Added to `scanner.py`: `detect_os(ip, timeout)`

- Sends a SYN packet on ports 80, 443, 22 via scapy
- Analyzes the TTL from the SYN-ACK response:
  - TTL ≤ 64 → `"Linux/Unix"`
  - TTL ≤ 128 → `"Windows"`
  - TTL > 128 → `"Network device"`
  - No response → `"unknown"`
- Requires scapy + sudo; returns `"unknown"` otherwise

---

## Task 10 — Version detection (`--version-detect`)

Added to `scanner.py`: `detect_service_version(ip, port, service_name, timeout)`

- `_SERVICE_PROBES` dictionary: protocol-specific request (HTTP HEAD, SMTP EHLO, etc.)
- HTTP/HTTPS: extracts the `Server:` header from the response
- SSH, FTP, SMTP: returns the first line of the response
- Works without sudo

---

## Task 11 — Firewall detection (`--firewall-detect`)

Added to `scanner.py`: `detect_firewall(ip, port, timeout)`

- Analyzes the response to a raw SYN packet (scapy):
  - SYN-ACK → `"open"`
  - RST → `"closed"`
  - ICMP response → `"filtered-active"` (firewall REJECT)
  - Timeout → `"filtered-silent"` (firewall DROP)
- Falls back to `scan_port_connect()` if scapy unavailable or not root
- Applied only to ports already classified as `"filtered"` by the initial scan

---

## Task 12 — XML export (`--output scan.xml`)

Added to `output.py`: `_write_xml(results, path, target, scan_type)`

- Nmap/Metasploit compatible format: `<nmaprun>/<host>/<ports>/<port>`
- Each `<port>` contains `<state>`, `<service>` (with version/banner attributes), `<firewall>`
- Special characters automatically escaped by `ElementTree`
- `.xml` extension added to `validate_output_file()` in `main.py`

---

## Task 13 — Cross-platform compatibility

Fixes applied across all modules:

| File | Fix |
|------|-----|
| `scanner.py` | `getattr(os, "geteuid", lambda: 1)()` — `geteuid` does not exist on Windows |
| `scanner.py` | `_ECONNREFUSED_CODES` includes `WSAECONNREFUSED` (Windows error code) |
| `discovery.py` | OS-adapted ping: `-W` seconds (Linux), `-W` ms (macOS), `-n -w` ms (Windows) |
| `main.py` | `validate_target()` accepts IPv6 addresses via `ipaddress.ip_address()` |
| `main.py` | Multi-host scan: one result file per host |
| `cli.py` | `_print_safe()` — ASCII fallback if Windows terminal doesn't support UTF-8 |

---

## Task 14 — Vulnerability scanning (`--vuln-scan`)

New module `vuln_analyzer.py`:

- `scan_vulnerabilities(service_name, version)` — queries the NVD API for known CVEs
- Local CVE cache to avoid repeated API calls and reduce latency
- Results added as `"vulns"` key in per-port result dict (list of CVE objects)
- Each CVE entry contains: `cve` (ID), `severity` (CRITICAL/HIGH/MEDIUM/LOW), `description`
- Requires `requests` package; `--vuln-scan` unavailable without it
- Integrated into `main.py` via `--vuln-scan` flag
- Works with any scan type (connect or SYN)

---

## Post-plan additions (Phase 2)

These items were added after the initial plan was completed:

| Item | Description |
|------|-------------|
| `cli.py` | Simplified interactive interface for non-experts |
| Preset profiles | Quick / Standard / Full / Custom |
| Simplified speeds | Fast / Normal / Slow / Stealth (hides threads/timeout/delay/max-rate) |
| Auto mode detection | SYN if root, TCP connect otherwise |
| `Ctrl+C` handling | Clean shutdown without traceback |
| Decimal comma | Accepted in addition to decimal point |
| `test_sanitisation.py` | 29 input validation tests |
| Stealth options | `--randomize`, `--max-rate`, `--jitter` |
