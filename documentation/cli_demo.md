# CLI Demo

---

## Interactive mode — `python cli.py`

### Standard user (no root)

```
╔══════════════════════════════════════════════╗
║           Network Port Scanner               ║
║  Mode: TCP connect (standard)                ║
╚══════════════════════════════════════════════╝

  Answer the questions below.
  Press Enter to keep the recommended value.

  ── Which machine do you want to scan? ────────
  Examples: 192.168.1.1  |  myserver.local  |  192.168.1.0/24
  IP address or hostname [Enter = 127.0.0.1] : 192.168.1.1

  ── What do you want to scan? ─────────────────

  Choose a profile:
    1. Quick scan    — common ports (web, SSH, remote desktop)  <- recommended
    2. Standard scan — all reserved ports (1 to 1024)
    3. Full scan     — all ports (1 to 65535, slow)
    4. Custom        — I choose myself
  Your choice [Enter = 1] : 1

  ── Scan speed? ───────────────────────────────

  Choose a speed:
    1. Fast    (local network)
    2. Normal  (recommended)  <- recommended
    3. Slow    (discreet)
    4. Stealth (anti-detection)
  Your choice [Enter = 2] :

  ── Additional options ────────────────────────
  (Enter = no for all)
  Search for active devices on the network first? [y/N] : n
  Display service info (version, banner)? [y/N] : y
  Detect service versions (e.g. Apache/2.4)? [y/N] : y
  Search for vulnerabilities (CVE) on these versions (requires Internet)? [y/N] : y
  Detect firewall type (silent DROP vs active REJECT)? [y/N] : n
  Attempt to detect the target OS? [y/N] : n

  ── Where to save the results? ────────────────

  Report format:
    1. Visual HTML report  (opens in a browser)  <- recommended
    2. Plain text .txt     (simple)
    3. CSV table           (Excel / spreadsheet)
    4. JSON data           (developers)
  Your choice [Enter = 1] :
  Results file name [Enter = scan_results.html] :

╔══════════════════════════════════════════════╗
║                  Summary                     ║
╠══════════════════════════════════════════════╣
║  Target      : 192.168.1.1                   ║
║  Ports       : 22,80,443,3389,8080           ║
║  Speed       : Normal                        ║
║  Mode        : connect                       ║
║  Discovery   : no                            ║
║  Svc info    : yes                           ║
║  Svc version : yes                           ║
║  CVE scan    : yes                           ║
║  Firewall    : no                            ║
║  OS detect   : no                            ║
║  Report      : scan_results.html             ║
╚══════════════════════════════════════════════╝

Start the scan? [Y/n] :

Scanning 192.168.1.1 — 5 ports (connect)

--- Scan Summary ---
  Ports scanned   : 5
  Ports open      : 2
  Ports closed    : 1
  Ports filtered  : 2
  Open rate       : 40.00%
  Execution time  : 1.23 seconds

Results saved to scan_results.html
```

### Root user (sudo) — scan mode choice

```
╔══════════════════════════════════════════════╗
║           Network Port Scanner               ║
║  Root detected — SYN and connect available   ║
╚══════════════════════════════════════════════╝

  Answer the questions below.
  Press Enter to keep the recommended value.

  ── Which machine do you want to scan? ────────
  Examples: 192.168.1.1  |  myserver.local  |  192.168.1.0/24
  IP address or hostname [Enter = 127.0.0.1] : 192.168.1.1

  ── Scan mode ─────────────────────────────────

  Choose a scan mode:
    1. SYN scan   — stealthy, half-open (no full TCP connection)  <- recommended
    2. TCP connect — full connection, enables all options (banner, CVE...)
  Your choice [Enter = 1] : 1

  ── What do you want to scan? ─────────────────

  Choose a profile:
    1. Quick scan    — common ports (web, SSH, remote desktop)  <- recommended
    2. Standard scan — all reserved ports (1 to 1024)
    3. Full scan     — all ports (1 to 65535, slow)
    4. Custom        — I choose myself
  Your choice [Enter = 1] : 2

  ── Scan speed? ───────────────────────────────

  Choose a speed:
    1. Fast    (local network)
    2. Normal  (recommended)  <- recommended
    3. Slow    (discreet)
    4. Stealth (anti-detection)
  Your choice [Enter = 2] :

  ── Additional options ────────────────────────
  SYN mode active — options incompatible with stealth disabled:

  [x] Network discovery  — ARP sweep / ICMP ping generate detectable noise
      before the port scan even begins.
  [x] Banner grabbing    — opens a full TCP connection (SYN+ACK+ACK)
      logged by the target's application layer.
  [x] Version detection  — same reason as banner grabbing.
  [x] Firewall detection — sends additional SYN probes on each filtered
      port, multiplying detectable traffic.

  Attempt to detect the target OS? [y/N] : y

  ── Where to save the results? ────────────────

  Report format:
    1. Visual HTML report  (opens in a browser)  <- recommended
    2. Plain text .txt     (simple)
    3. CSV table           (Excel / spreadsheet)
    4. JSON data           (developers)
  Your choice [Enter = 1] :
  Results file name [Enter = scan_results.html] :

╔══════════════════════════════════════════════╗
║                  Summary                     ║
╠══════════════════════════════════════════════╣
║  Target      : 192.168.1.1                   ║
║  Ports       : 1-1024                        ║
║  Speed       : Normal                        ║
║  Mode        : syn                           ║
║  OS detect   : yes                           ║
║  Report      : scan_results.html             ║
╚══════════════════════════════════════════════╝

Start the scan? [Y/n] :

  OS detected: Linux/Unix

Scanning 192.168.1.1 — 1024 ports (syn)

--- Scan Summary ---
  Ports scanned   : 1024
  Ports open      : 7
  Ports closed    : 82
  Ports filtered  : 935
  Open rate       : 0.68%
  Execution time  : 45.12 seconds

Results saved to scan_results.html
```

---

## Command-line mode — `python main.py`

### Simple scan

```
$ python main.py --target 192.168.1.1 --ports 22,80,443

Scanning 192.168.1.1 — 3 ports (connect)

--- Scan Summary ---
  Ports scanned   : 3
  Ports open      : 2
  Ports closed    : 1
  Ports filtered  : 0
  Open rate       : 66.67%
  Execution time  : 1.05 seconds

Results saved to scan_results.txt
```

### Scan with banners and version detection

```
$ python main.py --target 192.168.1.1 --ports 22,80,443 --banner --version-detect

Scanning 192.168.1.1 — 3 ports (connect)

--- Scan Summary ---
  Ports scanned   : 3
  Ports open      : 2
  Ports closed    : 1
  Ports filtered  : 0
  Open rate       : 66.67%
  Execution time  : 2.31 seconds

Results saved to scan_results.txt
```

### Scan with vulnerability detection (CVE)

```
$ python main.py --target 192.168.1.1 --ports 22,80 --version-detect --vuln-scan

[*] NVD search: apache 2.2.8...
[*] NVD search: openssh 4.7...

Scanning 192.168.1.1 — 2 ports (connect)

--- Scan Summary ---
  Ports scanned   : 2
  Ports open      : 2
  Ports closed    : 0
  Ports filtered  : 0
  Open rate       : 100.00%
  Execution time  : 5.87 seconds

Results saved to scan_results.txt
```

### Scan with OS detection and XML export

```
$ sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 \
    --ports 22,80,443 --os-detect --version-detect --output scan.xml

  OS detected: Linux/Unix

Scanning 192.168.1.1 — 3 ports (connect)

--- Scan Summary ---
  Ports scanned   : 3
  Ports open      : 2
  Ports closed    : 1
  Ports filtered  : 0
  Open rate       : 66.67%
  Execution time  : 3.14 seconds

Results saved to scan.xml
```

### Scan with firewall detection

```
$ sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 \
    --ports 1-1024 --firewall-detect --output scan.html

Scanning 192.168.1.1 — 1024 ports (connect)

--- Scan Summary ---
  Ports scanned   : 1024
  Ports open      : 2
  Ports closed    : 87
  Ports filtered  : 935  (silent: 900, active: 35)
  Open rate       : 0.20%
  Execution time  : 32.45 seconds

Results saved to scan.html
```

### Stealth SYN scan (requires sudo)

```
$ sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 \
    --ports 1-1024 --scan-type syn --max-rate 2 --randomize

Scanning 192.168.1.1 — 1024 ports (syn)

--- Scan Summary ---
  Ports scanned   : 1024
  Ports open      : 2
  Ports closed    : 89
  Ports filtered  : 933
  Open rate       : 0.20%
  Execution time  : 512.00 seconds

Results saved to scan_results.txt
```

### Host discovery on a network, then scan

```
$ python main.py --target 192.168.1.0/24 --discover --ports 22,80

3 active host(s): 192.168.1.1, 192.168.1.10, 192.168.1.42

Scanning 192.168.1.1 — 2 ports (connect)
Scanning 192.168.1.10 — 2 ports (connect)
Scanning 192.168.1.42 — 2 ports (connect)

--- Scan Summary ---
  Ports scanned   : 6
  Ports open      : 4
  Ports closed    : 0
  Ports filtered  : 2
  Open rate       : 66.67%
  Execution time  : 3.21 seconds

Results for 192.168.1.1 saved to scan_results_192_168_1_1.txt
Results for 192.168.1.10 saved to scan_results_192_168_1_10.txt
Results for 192.168.1.42 saved to scan_results_192_168_1_42.txt
```
