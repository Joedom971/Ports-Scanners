# Design — Extended Network Scanner

**Date:** 2026-03-09 (updated 2026-03-13)
**Status:** Implemented and merged on `main`

---

## Objective

Extend the Phase 1/2 scanner (basic sequential TCP scan) into a full-featured tool:
- Parallel scanning via threads
- SYN scan (raw packets via scapy)
- Host discovery (ARP + ICMP)
- Service names and banners
- Service version detection (protocol probes)
- OS detection via TTL fingerprinting
- Firewall type detection (silent DROP vs active REJECT)
- Vulnerability scanning via NVD/CVE database
- Multi-format export: HTML, XML, JSON, CSV, TXT
- Interactive CLI interface
- Windows / macOS / Linux compatibility

---

## Architecture: separate modules

```
Port_scanner_Reseau/
├── cli.py            # Simplified interactive interface (non-experts)
├── main.py           # Full CLI via argparse
├── scanner.py        # Scan library (connect, SYN, threaded, banner, version, OS, firewall)
├── discovery.py      # Host discovery (ARP + ICMP)
├── output.py         # Result export (txt / json / csv / html / xml)
├── vuln_analyzer.py  # Vulnerability scanning (NVD API, CVE cache)
├── requirements.txt
├── tests/
│   ├── test_scanner.py
│   ├── test_output.py
│   ├── test_discovery.py
│   ├── test_main.py
│   └── test_sanitisation.py
└── documentation/
```

---

## Internal result format

```python
dict[int, dict]
# Example:
{
    22:  {"status": "open",     "service": "ssh",   "banner": "SSH-2.0-OpenSSH_8.9",
          "os": "Linux/Unix",   "version": "OpenSSH_8.9", "firewall": "",
          "vulns": [{"cve": "CVE-2023-XXXXX", "severity": "HIGH", "description": "..."}]},
    80:  {"status": "open",     "service": "http",  "banner": "Apache/2.4.54",
          "os": "",             "version": "Apache/2.4.54 (Ubuntu)", "firewall": "",
          "vulns": []},
    443: {"status": "closed",   "service": "https", "banner": "",
          "os": "",             "version": "", "firewall": "",
          "vulns": []},
    8080:{"status": "filtered", "service": "http-alt", "banner": "",
          "os": "",             "version": "", "firewall": "filtered-silent",
          "vulns": []},
}
```

---

## Execution flow

```
cli.py / main.py  →  parse parameters + input validation
                  →  single DNS resolution (resolve_target)
                  →  if --discover: discovery.py → list of active hosts
                  →  if --os-detect: detect_os() → TTL fingerprinting (scapy + sudo)
                  →  for each host:
                       scan_range_threaded() in scanner.py
                       per-port enrichment:
                         get_service_name()
                         grab_banner() if --banner
                         detect_service_version() if --version-detect
                         detect_firewall() if --firewall-detect (filtered ports only)
                  →  if --vuln-scan: vuln_analyzer.py → CVE lookup per service/version
                  →  console display + stats
                  →  write_output() in output.py → file (one per host if multi-host)
```

---

## Technical choices

| Problem | Solution | Reason |
|---------|----------|--------|
| Parallelism | `ThreadPoolExecutor` | Standard library, simple, efficient for I/O |
| SYN scan | Optional `scapy` | No forced dependency, clean fallback |
| Discovery | ARP → fallback ICMP | ARP more reliable on LAN, ICMP universal |
| HTML export | Inline CSS | No external dependency, self-contained file |
| XML export | `xml.etree.ElementTree` | Standard library, Nmap/Metasploit compatible |
| Interface | Separate `cli.py` from `main.py` | Keeps `main.py` usable as direct CLI |
| OS detection | TTL fingerprinting (scapy) | Simple, effective, non-intrusive |
| Version detection | Protocol-specific probes | More precise than raw banner |
| Firewall detection | SYN response analysis (scapy) | Distinguishes DROP vs REJECT vs RST |
| Windows compatibility | `getattr(os, "geteuid", lambda: 1)()` | `geteuid` does not exist on Windows |
| `ECONNREFUSED` Windows | `_ECONNREFUSED_CODES` set | Different error code (`WSAECONNREFUSED`) |
| Ping Linux vs macOS | `platform.system()` detection | `-W` in seconds (Linux) vs ms (macOS) |
| Vulnerability scanning | NVD API + local CVE cache | Free public API, offline cache for speed |

---

## Dependencies

| Package | Usage | Without this package |
|---------|-------|----------------------|
| `scapy` | SYN scan, ARP discovery, OS detect, firewall detect | Fallback TCP connect / ICMP ping / "unknown" |
| `tqdm` | Progress bar | Silently ignored |
| `requests` | NVD API queries for vulnerability scanning | `--vuln-scan` unavailable |
