# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Activate virtual environment
source .venv/bin/activate

# Run a scan (basic usage)
python main.py --target 127.0.0.1 --ports 20-1024

# Run a scan with specific ports and JSON output
python main.py --target 192.168.1.1 --ports 22,80,443 --output results.json

# Run with custom timeout and CSV output
python main.py --target example.com --ports 1-1024 --timeout 0.5 --output results.csv

# Run with threading, HTML output
python main.py --target 192.168.1.1 --ports 20-1024 --threads 100 --output scan.html

# Run SYN scan with host discovery (requires scapy + sudo)
python main.py --target 192.168.1.0/24 --discover --ports 22,80 --scan-type syn

# Run with banner grabbing
python main.py --target 127.0.0.1 --ports 22,80,443 --banner --output results.json

# Quick single-port check (runs scanner module directly)
python scanner.py

# Run tests
python -m pytest tests/ -v
```

## Architecture

The project is split into multiple modules:

- **`scanner.py`** — core TCP scanning library. Exposes:
  - `scan_port_connect(ip, port, timeout)` → `"open"` | `"closed"` | `"filtered"`
  - `scan_port_syn(ip, port, timeout)` → `"open"` | `"closed"` | `"filtered"` (requires scapy + sudo)
  - `scan_range(ip, start_port, end_port, timeout)` → `dict[port, status]`
  - `scan_range_threaded(ip, ports, scan_fn, timeout, delay, max_workers)` → `dict[port, status]`
  - `get_service_name(port)` → service name string
  - `grab_banner(ip, port, timeout)` → banner string
  - `SCAPY_AVAILABLE` — bool flag indicating whether scapy is installed
- **`output.py`** — export functions. Writes results to `.txt`, `.json`, `.csv`, or `.html` via `write_output(results, path, target, scan_type)`.
- **`discovery.py`** — host discovery. `discover_hosts(target, timeout)` probes a CIDR subnet using ARP (via scapy) or ICMP ping fallback; returns list of active IP strings.
- **`main.py`** — full-featured CLI entry point. Parses args via `argparse`, supports threading (`--threads`), SYN scan (`--scan-type syn`), banner grabbing (`--banner`), host discovery (`--discover`), rate limiting (`--delay`), and structured logging (`--log-level`).

Port spec parsing (`parse_ports`) in `main.py` supports ranges (`20-25`), single ports (`22`), comma lists (`22,80,443`), and combinations (`22,80-85`).

Optional dependencies (install via `pip install -r requirements.txt`):
- `tqdm` — progress bar during enrichment
- `scapy` — required for SYN scan and ARP host discovery (also requires root/sudo)

## Scan Behavior

- **open**: full TCP 3-way handshake succeeded
- **closed**: RST received (`ECONNREFUSED`)
- **filtered**: timeout or unreachable (no response)

Scans are parallelised via `ThreadPoolExecutor`. The default timeout is 1.0 second per port and the default thread count is 100.
