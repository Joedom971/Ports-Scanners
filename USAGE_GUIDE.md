# Network Port Scanner — User Guide

A tool for analyzing open ports on a machine or network.
Works in interactive mode (step-by-step questions) or via direct command line.

---

## Table of Contents

1. [Prerequisites and Installation](#1-prerequisites-and-installation)
2. [Activate the Environment Before Each Session](#2-activate-the-environment-before-each-session)
3. [TCP Connect Mode — Standard Scan](#3-tcp-connect-mode--standard-scan)
4. [SYN Scan Mode — Stealth Scan](#4-syn-scan-mode--stealth-scan)
5. [All Available Options](#5-all-available-options)
6. [Vulnerability Scanning](#6-vulnerability-scanning)
7. [Report Formats](#7-report-formats)
8. [Legal Disclaimer](#8-legal-disclaimer)

---

## 1. Prerequisites and Installation

> This only needs to be done **once** on your computer.

### Step 1 — Install Python

- Download Python 3.10 or newer from [python.org/downloads](https://www.python.org/downloads/)
- **Windows:** during installation, check **"Add Python to PATH"** (checkbox at the bottom of the window)
- **macOS / Linux:** Python is often already installed; verify with `python3 --version` in the terminal

### Step 2 — Open a Terminal in the Project Folder

**Windows:**
1. Open the `Port_scanner_Reseau` folder in File Explorer
2. Click in the address bar, type `cmd` or `powershell`, press Enter

**macOS:**
1. Open the Terminal (Spotlight → search for "Terminal")
2. Type `cd ` (with a space) then drag the `Port_scanner_Reseau` folder into the window, press Enter

**Linux:**
1. Right-click in the folder → "Open a terminal here" (depending on your distribution)
2. Or: open a terminal and type `cd /path/to/Port_scanner_Reseau`

### Step 3 — Create the Virtual Environment

```bash
python3 -m venv .venv        # macOS / Linux
python  -m venv .venv        # Windows (if "python3" doesn't work)
```

### Step 4 — Activate the Environment

```bash
source .venv/bin/activate    # macOS / Linux
.venv\Scripts\activate       # Windows (PowerShell or cmd)
```

> The name `(.venv)` appears at the beginning of the command line when activated.

### Step 5 — Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 2. Activate the Environment Before Each Session

> This must be done **every time** you open a new terminal.

```bash
source .venv/bin/activate    # macOS / Linux
.venv\Scripts\activate       # Windows
```

---

## 3. TCP Connect Mode — Standard Scan

> **No special privileges required.** Works on all systems.

This mode establishes a full TCP connection on each port. It is the default method.

### Launch Interactive Mode (recommended for beginners)

The program asks questions one by one: which machine to scan, which ports, at what speed, where to save.

**macOS / Linux:**
```bash
source .venv/bin/activate
python cli.py
```

**Windows:**
```
.venv\Scripts\activate
python cli.py
```

### Launch via Direct Command Line

**macOS / Linux:**
```bash
source .venv/bin/activate

# Scan common ports (web, SSH, remote desktop)
python main.py --target 192.168.1.1 --ports 22,80,443,3389,8080

# Scan all reserved ports (1 to 1024), output as HTML
python main.py --target 192.168.1.1 --ports 1-1024 --output report.html

# Scan with service version detection and XML export
python main.py --target 192.168.1.1 --ports 22,80,443 --version-detect --output scan.xml

# Stealth scan (2 packets/second, randomized order)
python main.py --target 192.168.1.1 --ports 1-1024 --max-rate 2 --randomize

# Discover active hosts on a network, then scan their ports
python main.py --target 192.168.1.0/24 --discover --ports 22,80
```

**Windows:** the commands are identical, just change the activation line:
```
.venv\Scripts\activate
python main.py --target 192.168.1.1 --ports 22,80,443
```

---

## 4. SYN Scan Mode — Stealth Scan

> **Requires administrator privileges.** Also requires the `scapy` library and a low-level network driver.
>
> This mode sends only a SYN packet without completing the connection — more stealthy because the connections do not appear in application logs.
>
> When running as root/admin, the interactive CLI (`cli.py`) lets you **choose** between SYN scan and TCP connect scan. SYN is no longer auto-forced.

### Additional Prerequisites by OS

#### macOS

Nothing else to install. `scapy` is already included in `requirements.txt`.

Launch the scan with `sudo` (prompts for the administrator password):

```bash
# Interactive mode — choose SYN or TCP connect when prompted
sudo $(pwd)/.venv/bin/python cli.py

# Direct command line — SYN scan
sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 --ports 1-1024 --scan-type syn
```

> `$(pwd)` automatically inserts the absolute path of the current directory.
> `sudo python` alone would not work because it would use the system Python, not the one from the venv.

#### Linux

Same as macOS. Use `sudo` with the absolute path to the venv Python:

```bash
# Find the absolute path of the venv Python
which python   # after activating the venv — shows something like /home/user/project/.venv/bin/python

# Interactive mode
sudo /home/user/Port_scanner_Reseau/.venv/bin/python cli.py

# Direct command line
sudo /home/user/Port_scanner_Reseau/.venv/bin/python main.py --target 192.168.1.1 --ports 1-1024 --scan-type syn
```

> Replace `/home/user/Port_scanner_Reseau/` with the actual path of the folder on your machine.

#### Windows

Windows requires an additional network driver for raw packets:

1. Download and install **Npcap** from [npcap.com](https://npcap.com/#download)
   - During installation, check **"Install Npcap in WinPcap API-compatible mode"**

2. Open **PowerShell as Administrator**:
   - Search for "PowerShell" in the Start menu
   - Right-click → **"Run as administrator"**

3. Navigate to the project folder and activate the venv:
   ```
   cd C:\path\to\Port_scanner_Reseau
   .venv\Scripts\activate
   ```

4. Launch the scan:
   ```
   python cli.py
   ```
   (when running as admin, the CLI will let you choose between SYN and TCP connect scan)

   Or via direct command line:
   ```
   python main.py --target 192.168.1.1 --ports 1-1024 --scan-type syn
   ```

### Advanced SYN Scan Examples (macOS / Linux)

```bash
# Standard SYN scan
sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 --ports 1-1024 --scan-type syn

# Stealth SYN scan: 2 packets/second, randomized order, variable delay
sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 --ports 1-1024 \
  --scan-type syn --max-rate 2 --randomize --jitter 0.3

# Firewall type detection (silent DROP vs active REJECT)
sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 --ports 1-1024 \
  --scan-type syn --firewall-detect

# Target OS detection
sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 --ports 22,80 \
  --scan-type syn --os-detect
```

---

## 5. All Available Options

```bash
python main.py --help
```

| Option | Description | Example |
|--------|-------------|---------|
| `--target` | IP, hostname or CIDR network | `192.168.1.1` or `192.168.1.0/24` |
| `--ports` | Ports to scan | `22,80,443` or `1-1024` or `22,80-90` |
| `--output` | Output file for results | `--output scan.html` or `--output scan.xml` |
| `--scan-type` | `connect` (default) or `syn` (sudo required) | `--scan-type syn` |
| `--threads` | Parallel connections (default: 100) | `--threads 200` |
| `--timeout` | Timeout per port in seconds (default: 1.0) | `--timeout 0.5` |
| `--banner` | Read the banner of open services | `--ports 22,80 --banner` |
| `--version-detect` | Detect the version of open services | `--ports 22,80 --version-detect` |
| `--os-detect` | Detect the target's OS (sudo required) | `--ports 22,80 --os-detect` |
| `--firewall-detect` | Detect the type of filtering (sudo required) | `--ports 1-1024 --firewall-detect` |
| `--vuln-scan` | Search for known CVEs on detected service versions (requires Internet and `--version-detect` or `--banner`) | `--ports 22,80 --version-detect --vuln-scan` |
| `--discover` | Discover active hosts before scanning | `--target 192.168.1.0/24 --discover` |
| `--randomize` | Shuffle port order | `--ports 1-1024 --randomize` |
| `--max-rate` | Max rate in packets/second | `--max-rate 2` |
| `--delay` | Fixed pause between each port | `--delay 0.1` |
| `--jitter` | Random delay in seconds | `--jitter 0.3` |

### Options that Require `sudo` (macOS/Linux) or Admin (Windows)

| Option | Why |
|--------|-----|
| `--scan-type syn` | Sends raw network packets (raw sockets) |
| `--os-detect` | Analyzes network-level responses via scapy |
| `--firewall-detect` | Analyzes ICMP responses via scapy |

---

## 6. Vulnerability Scanning

The `--vuln-scan` option queries public CVE databases for known vulnerabilities matching the service versions detected during the scan. It requires an Internet connection and works best combined with `--version-detect` or `--banner` so the scanner has version information to look up.

### Basic Usage

```bash
# Scan ports and check for known CVEs on detected versions
python main.py --target 192.168.1.1 --ports 22,80,443 --version-detect --vuln-scan

# Combine with banner grabbing for additional version info
python main.py --target 192.168.1.1 --ports 22,80,443 --banner --vuln-scan

# Full audit: version detection + vulnerability scan + HTML report
python main.py --target 192.168.1.1 --ports 1-1024 --version-detect --vuln-scan --output report.html
```

### With SYN Scan (macOS / Linux)

```bash
# SYN scan + version detection + vulnerability lookup
sudo $(pwd)/.venv/bin/python main.py --target 192.168.1.1 --ports 1-1024 \
  --scan-type syn --version-detect --vuln-scan --output audit.xml
```

> The vulnerability scan adds processing time as it queries external databases for each detected service version.

---

## 7. Report Formats

| Extension | Description | How to Open |
|-----------|-------------|-------------|
| `.html` | Color-coded visual report | Double-click → web browser |
| `.xml` | Nmap / Metasploit compatible format | Text editor or security tool |
| `.json` | Structured data | Text editor or VS Code |
| `.csv` | Spreadsheet | Excel, LibreOffice Calc |
| `.txt` | Plain text | Any text editor |

```bash
# Output examples
python main.py --target 192.168.1.1 --ports 1-1024 --output report.html
python main.py --target 192.168.1.1 --ports 1-1024 --output scan.xml
python main.py --target 192.168.1.1 --ports 1-1024 --output results.csv
```

---

## 8. Legal Disclaimer

Scanning a network **without authorization is illegal**.

In Belgium: law of November 28, 2000 on computer crime.
In France: articles 323-1 to 323-7 of the Penal Code.

**Authorized uses:** your own network, a machine you administer, a test environment, a pentest with written agreement from the owner.

**Prohibited uses:** scanning third-party machines or networks without explicit permission.
