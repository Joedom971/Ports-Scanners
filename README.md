# Network Port Scanner

A Python tool for analyzing open ports on a machine or local network.
Developed as part of a networking learning project.

---

## What is a port scanner?

Every machine connected to a network communicates through **ports**. A port is like a numbered door (from 1 to 65535) through which a service can receive connections.

Examples of well-known ports:
| Port | Service |
|------|---------|
| 22 | SSH (secure remote access) |
| 80 | HTTP (websites) |
| 443 | HTTPS (secure websites) |
| 3389 | Windows Remote Desktop |

A port scanner **attempts to connect** to each port on a machine and observes the response:
- **open** — the port responds, a service is running behind it
- **closed** — the port responds but refuses the connection (nothing is running)
- **filtered** — no response (firewall or machine is down)

This tool is used to map active services on a network — useful for system administration, security auditing, or simply understanding what is running on your network.

---

## How does it work?

### TCP connect scan (default mode)

This is the simplest method. For each port, the scanner performs a **full TCP handshake** (the basic internet protocol):

```
Scanner  ->  SYN        ->  Target machine
Scanner  <-  SYN-ACK    <-  Target machine  (port open)
Scanner  ->  ACK        ->  Target machine
Scanner  ->  FIN        ->  Target machine  (clean close)
```

If the machine responds with `RST` (reset) instead of `SYN-ACK`, the port is closed.
If nothing responds after the configured timeout, the port is filtered.

### SYN scan (stealth mode, requires sudo)

More discreet. The scanner only sends the first `SYN` packet without ever completing the connection. The connection is never fully established, so it does not appear in application logs.

```
Scanner  ->  SYN        ->  Target machine
Scanner  <-  SYN-ACK    <-  Target machine  (port open, but we don't send the ACK)
```

This mode requires administrator privileges (`sudo`) because it sends **raw packets** directly at the network level, bypassing the operating system's TCP stack.

### Parallelism (why it's fast)

Scanning 1024 ports one by one at 1 second timeout = **17 minutes**.
With 100 parallel threads = **a few seconds**.

The project uses `ThreadPoolExecutor`: a pool of execution threads that work simultaneously, each scanning a different port.

---

## Project structure

```
Port_scanner_Reseau/
├── cli.py              -> Step-by-step interactive interface (beginner-friendly)
├── main.py             -> Full command-line interface
├── scanner.py          -> Scan engine (core logic)
├── output.py           -> Results export (txt, json, csv, html, xml)
├── discovery.py        -> Active host discovery on a network
├── vuln_analyzer.py    -> Vulnerability analysis (CVE lookup via NVD API)
├── tests/              -> Automated tests (76 tests)
└── documentation/      -> Design reports, tests, ethics
```

---

## Libraries used

### Python standard library (no installation needed)

**`socket`**
Python's core networking library. It is what actually performs TCP connections. It allows opening a socket (connection endpoint), connecting it to an IP address + port, and reading/writing data.
```python
sock.connect_ex(("192.168.1.1", 80))  # returns 0 if open
```

**`concurrent.futures` (ThreadPoolExecutor)**
Manages the parallel thread pool. Instead of launching and managing each thread manually, `ThreadPoolExecutor` automatically distributes work among N threads and collects results.
```python
with ThreadPoolExecutor(max_workers=100) as executor:
    futures = {executor.submit(scanner, port): port for port in ports}
```

**`subprocess`**
Allows executing system commands from Python — used to run pings (`ping -c 1 192.168.1.1`) during ICMP host discovery.

**`ipaddress`**
Parses and manipulates IP addresses and CIDR networks (`192.168.1.0/24`). Computes the list of all addresses in a subnet without manual binary calculations.

**`argparse`**
Handles command-line arguments (`--target`, `--ports`, etc.). Automatically generates the `--help` message.

**`json` / `csv`**
Exports results in these standard formats.

**`threading`**
Used for global rate limiting: a shared `Lock` between all threads ensures only one packet is sent at a time when `--max-rate` is enabled.

**`html`**
Escapes special characters (`<`, `>`, `&`) in the HTML report to prevent code injection.

---

### Optional libraries (installed separately)

**`scapy`**
The Python library for network packet manipulation. It allows forging raw TCP/IP packets "by hand" — this is what makes the SYN scan possible. Without scapy, the scanner automatically falls back to TCP connect.
```python
pkt = IP(dst="192.168.1.1") / TCP(dport=80, flags="S")  # forged SYN packet
resp = sr1(pkt, timeout=1)  # send and wait for response
```
Scapy is also used for ARP sweeping during host discovery on a local network.

**`tqdm`**
Displays a progress bar in the terminal during the scan. Purely cosmetic — if absent, the scanner works normally without a progress bar.

**`pytest`**
Automated testing framework. Used to verify that each function in the project behaves correctly with 76 unit tests.

**`requests`**
HTTP library used by `vuln_analyzer.py` for querying the NVD (National Vulnerability Database) API to look up known CVEs associated with detected service versions.

---

## Advanced options

### Host discovery — `--discover`

Before scanning ports, detects which machines are active on the network.

```bash
python main.py --target 192.168.1.0/24 --discover --ports 22,80
```

Without `--discover`, the scanner directly attempts to connect to the target's ports. With `--discover`, it first sends ARP requests (or ICMP pings) to list responding machines, then scans only those. Useful on a `/24` subnet to avoid wasting time on inactive IPs.

---

### Service banners — `--banner`

Reads the first response sent by each open service.

```bash
python main.py --target 192.168.1.1 --ports 22,80,443 --banner
```

When a port is open, the service behind it often displays an identification line upon connection — this is the **banner**. It may contain the software name and version (`SSH-2.0-OpenSSH_8.9`, `Apache/2.4.54`). This information helps identify installed software and detect outdated versions.

---

### Version detection — `--version-detect`

Identifies the exact software version running behind each open port.

```bash
python main.py --target 192.168.1.1 --ports 22,80,443 --version-detect
```

For each open port, the scanner sends a protocol-appropriate request and extracts the version from the response. Supported protocols include HTTP (HEAD), SMTP (EHLO), FTP, SSH, MySQL (greeting packet), PostgreSQL, DNS (version.bind), VNC (RFB), Redis (INFO), IRC, and more. Example: an open port 80 may reveal `Apache/2.4.54` or `nginx/1.18.0`. Works without sudo.

---

### Vulnerability scan — `--vuln-scan`

Searches for known CVEs on detected service versions (requires Internet).

```bash
python main.py --target 192.168.1.1 --ports 22,80,443 --version-detect --vuln-scan
```

When combined with `--version-detect`, the scanner queries the NVD (National Vulnerability Database) API for known vulnerabilities (CVEs) matching the detected software versions. Results include CVE identifiers, severity scores, and descriptions. Requires the `requests` library and an active Internet connection.

---

### OS detection — `--os-detect`

Attempts to guess the target machine's operating system.

```bash
sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 --ports 22,80 --os-detect
```

The technique used is **TTL fingerprinting**: each OS responds with a different TTL value in network packets (Linux/Unix <= 64, Windows <= 128, network devices > 128). Requires `scapy` and `sudo` as it sends raw packets.

---

### Firewall detection — `--firewall-detect`

Distinguishes silently blocked ports (DROP) from actively rejected ports (REJECT).

```bash
sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 --ports 1-1024 --firewall-detect
```

A standard `filtered` port can mean two very different things: either the firewall silently ignores the packet (`filtered-silent` — DROP rule), or it responds with an ICMP "destination unreachable" message (`filtered-active` — REJECT rule). This distinction helps understand the firewall configuration. Requires `scapy` and `sudo`.

---

### Threads — `--threads`

Controls the number of connections launched in parallel.

```bash
python main.py --target 192.168.1.1 --ports 1-1024 --threads 200
```

Default: 100 threads. Increasing speeds up the scan but generates more simultaneous traffic (more detectable, more load on the target). Decreasing slows it down but is more discreet. On a fast local network, 400 threads is reasonable. Over the internet, 50 is wiser.

---

### Timeout — `--timeout`

Maximum wait time per port, in seconds.

```bash
python main.py --target 192.168.1.1 --ports 1-1024 --timeout 0.5
```

Default: 1 second. If the target does not respond within this delay, the port is marked `filtered`. Reducing the timeout speeds up the scan but risks classifying `open` or `closed` ports as `filtered` if the connection is slow. On a local network, 0.3 s is enough. Over the internet, keep 1 to 2 s.

---

## Stealth features

To reduce detection by network monitoring systems (IDS):

**`--randomize`** — shuffles the port order before scanning. A sequential scan (1, 2, 3, 4...) is an immediately recognizable signature for an IDS. With `--randomize`, the order is unpredictable.

**`--delay 0.1`** — adds a fixed pause between each scanned port. Simple and predictable, but reduces load. Use when you just want to slow down without complexity. Example: `--delay 0.1` = 100 ms between each port.

**`--max-rate 2`** — limits the global throughput to N packets per second via a shared lock between all threads. More precise than `--delay` because it controls the actual send rate independently of the thread count. `--max-rate 2` = maximum 2 packets per second, regardless of how many threads are running.

> **Difference between `--delay` and `--max-rate`:** `--delay` adds a pause in each thread individually — with 100 threads and `--delay 0.1`, you still send 100 packets every 0.1 s. `--max-rate` serializes all sends globally — with `--max-rate 2`, exactly 2 packets per second are sent in total.

**`--jitter 0.3`** — adds a random delay between 0 and 0.3 seconds. A fixed delay produces a regular rhythm that is detectable; a variable delay looks more like human traffic.

**Single DNS resolution** — if you scan `myserver.local`, the hostname is resolved to an IP once at the start, not on every connection. This avoids N visible DNS queries on the network.

---

## Installation and usage

### Prerequisites

- Python 3.10 or newer
- A terminal (cmd / PowerShell on Windows, Terminal on macOS/Linux)

### Installation (one-time setup)

```bash
# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Windows (PowerShell or cmd)
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### Running the scanner

```bash
# Interactive mode (recommended — asks questions one by one, displays statistics summary)
python cli.py

# Direct command line
python main.py --target 192.168.1.1 --ports 22,80,443 --output report.html

# SYN stealth scan (requires sudo on macOS/Linux, admin on Windows)
sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 --ports 1-1024 --scan-type syn

# Full scan with vulnerability detection
python main.py --target 192.168.1.1 --ports 1-1024 --version-detect --vuln-scan --output report.html
```

> The interactive CLI (`cli.py`) displays only a statistics summary at the end of the scan. Root users can choose between SYN and TCP connect scan modes.

> For detailed per-system instructions (Linux / macOS / Windows) and SYN scan setup, see **[USAGE_GUIDE.md](USAGE_GUIDE.md)**.

### Running the tests

```bash
python -m pytest tests/ -v
# 76 tests, expected result: 76 passed
```

---

## Result format

The scan returns a dictionary per port:

```python
{
    port: {
        "status": "open" | "closed" | "filtered",
        "service": "http",
        "banner": "Apache/2.4.54 ...",
        "os": "Linux/Unix",
        "version": "Apache/2.4.54",
        "firewall": "open",
        "vulns": [{"id": "CVE-2024-XXXX", "cvss": 9.8, "description": "..."}]
    }
}
```

### Example output

```
Scanning 192.168.1.1 — 26 ports (connect)

--- Scan Summary ---
  Ports scanned   : 26
  Ports open      : 2
  Ports closed    : 1
  Ports filtered  : 23
  Open rate       : 7.69%
  Execution time  : 1.23 seconds

Results saved to scan_results.html
```

> Per-port details (status, service, banner, version, CVEs) are written to the report file only — not displayed in the terminal. All report formats (HTML, XML, JSON, CSV, TXT) include the detected OS in the header.

---

## Legal disclaimer

Scanning a network **without authorization** is illegal.

In Belgium, the law of November 28, 2000 on computer crime punishes unauthorized access to a computer system. The European NIS2 directive strengthens these obligations for critical infrastructure.

**Authorized uses:** your own network, a machine you administer, a test environment, a pentest with written agreement from the owner.

**Prohibited uses:** scanning third-party machines or networks without permission.
