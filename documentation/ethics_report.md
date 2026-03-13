# Ethics and Legal Report

## Fundamental Rule

> **Never scan a machine without explicit permission from its owner.**

Scanning a system without permission is illegal in most countries, even without malicious intent.

## Legal Framework

| Country | Applicable Law |
|---------|---------------|
| Belgium | Law of 28 November 2000 on computer crime |
| France | Articles 323-1 to 323-7 of the Penal Code |
| European Union | NIS2 Directive (2022/2555) |

An unauthorized port scan can be classified as **unauthorized access to a computer system**.

## Authorized Uses

- Scanning **your own infrastructure** (personal machine, personal server)
- Scanning within an **isolated lab network** (VM, test environment)
- Scanning as part of a **pentest with a signed contract**
- Scanning as part of a **bug bounty program** (defined scope)

## Prohibited Uses

- Scanning public servers without authorization
- Scanning the network of a company, school, or ISP without written agreement
- Using scan results to exploit vulnerabilities on third-party systems

## Stealth and Detection

### How a Scan Can Be Detected
- **IDS/IPS** (Snort, Suricata) — detect port scans by signature
- **Firewall logs** — every connection attempt can be recorded
- **Honeypots** — ports deliberately left open to trap scanners

### Reducing Footprint (within an authorized context)
- Use **SYN scan** (fewer traces in application logs)
- Reduce the number of threads (`--threads 20`)
- Add a delay between ports (`--delay 0.1`)
- Limit the range of scanned ports

## Disclaimer

This project is intended for **educational and lab use only**.
The author disclaims all responsibility in case of misuse or illegal use.
