"""Interactive CLI interface for the port scanner.

Launches a simple step-by-step wizard.

Usage:
  python cli.py
"""

import os


def _print_safe(text: str) -> None:
    """Prints text, replacing non-ASCII characters if necessary."""
    try:
        print(text)
    except UnicodeEncodeError:
        # Replace border characters with their ASCII equivalents
        ascii_text = (text
            .replace("╔", "+").replace("╗", "+").replace("╚", "+").replace("╝", "+")
            .replace("║", "|").replace("═", "=").replace("─", "-")
            .replace("┄", "-")
        )
        print(ascii_text)


# ── Speed → technical parameters ──────────────────────────────────────────────
# Each speed automatically configures threads, timeout, delay and stealth options.
# The user picks a simple speed; the technical details are handled here.
SPEEDS = {
    # LAN: short timeout, many threads — responses arrive in < 10ms on a local network
    "Fast    (local network)":    {"threads": 400, "timeout": 0.3, "delay": 0.0, "jitter": 0.0,  "max_rate": 0.0,  "randomize": False},
    # Normal: balanced for LAN/WAN — 1.0s absorbs latency spikes, 100 threads avoids socket/NAT exhaustion
    "Normal  (recommended)":      {"threads": 100, "timeout": 1.0, "delay": 0.0, "jitter": 0.0,  "max_rate": 0.0,  "randomize": False},
    # Slow: fewer threads and inter-port delay to reduce network noise
    "Slow    (discreet)":         {"threads": 20,  "timeout": 2.0, "delay": 0.1, "jitter": 0.0,  "max_rate": 0.0,  "randomize": False},
    # Stealth: few threads, rate limited to 2 packets/s, randomised port order
    "Stealth (anti-detection)":   {"threads": 5,   "timeout": 3.0, "delay": 0.0, "jitter": 0.0,  "max_rate": 2.0,  "randomize": True},
}

# ── Scan profiles ──────────────────────────────────────────────────────────────
# Maps each profile to a port specification (None = the user enters their own)
PROFILES = {
    "Quick scan    — common ports (web, SSH, remote desktop)": "22,80,443,3389,8080",
    "Standard scan — all reserved ports (1 to 1024)":          "1-1024",
    "Full scan     — all ports (1 to 65535, slow)":            "1-65535",
    "Custom        — I choose myself":                         None,
}


def choose(question: str, options: list, default_idx: int = 0) -> str:
    """Displays a numbered menu and returns the option chosen by the user."""
    print(f"\n  {question}")
    for i, opt in enumerate(options, 1):
        marker = "  <- recommended" if i == default_idx + 1 else ""
        print(f"    {i}. {opt}{marker}")
    while True:
        rep = input(f"  Your choice [Enter = {default_idx + 1}] : ").strip()
        if not rep:
            # Empty input → use the default choice
            return options[default_idx]
        if rep.isdigit() and 1 <= int(rep) <= len(options):
            return options[int(rep) - 1]
        print("  Invalid choice, enter a number.")


def ask(question: str, default: str = "") -> str:
    """Displays a question and returns the user's input (or the default value)."""
    hint = f" [Enter = {default}]" if default else ""
    rep = input(f"  {question}{hint} : ").strip()
    return rep if rep else default  # if the user presses Enter, use the default


def yes_no(question: str, default: bool = True) -> bool:
    """Asks a yes/no question and returns True or False."""
    hint = "[Y/n]" if default else "[y/N]"
    rep = input(f"  {question} {hint} : ").strip().lower()
    if not rep:
        return default  # empty input → default value
    # Accept "y", "yes", "o", "oui" as a positive answer
    return rep in ("y", "yes", "o", "oui")


def separator(title: str = "") -> None:
    """Displays a visual separator line with an optional title."""
    if title:
        print(f"\n  ── {title} {'─' * (44 - len(title))}")
    else:
        print(f"\n  {'─' * 48}")


def main() -> int:
    # Detect whether the program is running with root privileges (uid 0)
    # getattr with a lambda avoids an error on Windows where os.geteuid does not exist
    is_root = getattr(os, "geteuid", lambda: 1)() == 0

    # Display the header with the automatically detected scan mode
    _print_safe("\n╔══════════════════════════════════════════════╗")
    _print_safe("║           Network Port Scanner               ║")
    if is_root:
        _print_safe("║  Mode: SYN scan (advanced, root detected)    ║")
    else:
        _print_safe("║  Mode: TCP connect (standard)                ║")
    _print_safe("╚══════════════════════════════════════════════╝")
    print("\n  Answer the questions below.")
    print("  Press Enter to keep the recommended value.")

    # ── 1. Target ─────────────────────────────────────────────────────────────
    separator("Which machine do you want to scan?")
    print("  Examples: 192.168.1.1  |  myserver.local  |  192.168.1.0/24")
    target = ask("IP address or hostname", "127.0.0.1")

    # ── 2. Profile ────────────────────────────────────────────────────────────
    separator("What do you want to scan?")
    chosen_profile = choose(
        "Choose a profile:",
        list(PROFILES.keys()),
        default_idx=0,
    )
    ports = PROFILES[chosen_profile]
    if ports is None:
        # "Custom" profile: the user enters their own ports
        print("\n  Examples: 80  |  22,80,443  |  1-1024  |  22,80-85")
        ports = ask("Enter the ports to scan", "22,80,443")

    # ── 3. Speed ──────────────────────────────────────────────────────────────
    separator("Scan speed?")
    chosen_speed = choose(
        "Choose a speed:",
        list(SPEEDS.keys()),
        default_idx=1,  # "Normal" is the recommended default
    )
    # Retrieve the technical parameters associated with the chosen speed
    perf = SPEEDS[chosen_speed]

    # ── 4. Extra options ──────────────────────────────────────────────────────
    separator("Additional options")

    if is_root:
        # In SYN scan mode, several options are automatically disabled to preserve stealth.
        # Each disabled option is explained so the user understands why it is unavailable.
        print("  SYN mode active — options incompatible with stealth disabled:\n")
        print("  [x] Network discovery  — ARP sweep / ICMP ping generate detectable noise")
        print("      before the port scan even begins.")
        print("  [x] Banner grabbing    — opens a full TCP connection (SYN+ACK+ACK)")
        print("      logged by the target's application layer.")
        print("  [x] Version detection  — same reason as banner grabbing.")
        print("  [x] Firewall detection — sends additional SYN probes on each filtered")
        print("      port, multiplying detectable traffic.")
        print()
        discover        = False
        banner          = False
        version_detect  = False
        vuln_scan       = False
        firewall_detect = False
    else:
        print("  (Enter = no for all)")
        # In TCP connect mode, all options are available freely
        discover = yes_no(
            "Search for active devices on the network first?",
            default=False,
        )
        banner = yes_no(
            "Display service info (version, banner)?",
            default=False,
        )
        version_detect = yes_no(
            "Detect service versions (e.g. Apache/2.4)?",
            default=False,
        )
        # Vuln scan only makes sense if we have banners or versions to analyse
        vuln_scan = False
        if version_detect or banner:
            vuln_scan = yes_no(
                "Search for vulnerabilities (CVE) on these versions (requires Internet)?",
                default=False,
            )

    # In SYN mode, firewall_detect was already set to False above.
    # In TCP connect mode, ask the user — firewall-detect needs sudo.
    if not is_root:
        firewall_detect_asked = yes_no(
            "Detect firewall type (silent DROP vs active REJECT)?",
            default=False,
        )
        if firewall_detect_asked:
            print("  Note: --firewall-detect requires sudo (macOS/Linux) or admin (Windows).")
        firewall_detect = False  # not root → can't use scapy anyway

    os_detect_asked = yes_no(
        "Attempt to detect the target OS?",
        default=False,
    )
    if os_detect_asked and not is_root:
        print("  Note: --os-detect requires sudo (macOS/Linux) or admin (Windows).")
    os_detect = os_detect_asked and is_root

    # ── 5. Report ─────────────────────────────────────────────────────────────
    separator("Where to save the results?")
    chosen_format = choose(
        "Report format:",
        [
            "Visual HTML report  (opens in a browser)",
            "Plain text .txt     (simple)",
            "CSV table           (Excel / spreadsheet)",
            "JSON data           (developers)",
        ],
        default_idx=0,
    )
    # Determine the file extension based on the chosen format
    if "HTML" in chosen_format:
        ext = ".html"
    elif ".txt" in chosen_format:
        ext = ".txt"
    elif "CSV" in chosen_format:
        ext = ".csv"
    else:
        ext = ".json"

    filename = ask("Results file name", f"scan_results{ext}")
    # Ensure the file has the correct extension
    if not filename.endswith(ext):
        filename += ext

    # ── Summary ───────────────────────────────────────────────────────────────
    # The scan type is determined automatically based on root privileges
    scan_type_val = "syn" if is_root else "connect"
    threads   = perf["threads"]
    timeout   = perf["timeout"]
    delay     = perf["delay"]
    max_rate  = perf["max_rate"]
    jitter    = perf.get("jitter", 0.0)
    randomize = perf["randomize"]

    # In SYN scan mode, force stealth settings regardless of the chosen speed profile:
    #   - randomize: shuffles port order to avoid sequential scanning signatures (IDS)
    #   - jitter: adds random variation to inter-packet timing to break regular patterns
    if is_root:
        randomize = True
        jitter = max(jitter, 0.05)  # minimum 50ms jitter if not already set higher

    # Truncate long values to fit the recap box (31 chars max)
    def _trunc(val: str, max_len: int = 31) -> str:
        return val[:28] + "..." if len(val) > max_len else val

    # Display a summary of all parameters before launching the scan
    _print_safe("\n╔══════════════════════════════════════════════╗")
    _print_safe("║                  Summary                     ║")
    _print_safe("╠══════════════════════════════════════════════╣")
    _print_safe(f"║  Target      : {_trunc(target):<31}║")
    _print_safe(f"║  Ports       : {_trunc(ports):<31}║")
    _print_safe(f"║  Speed       : {_trunc(chosen_speed.split('(')[0].strip()):<31}║")
    _print_safe(f"║  Mode        : {scan_type_val:<31}║")
    if not is_root:
        _print_safe(f"║  Discovery   : {'yes' if discover else 'no':<31}║")
        _print_safe(f"║  Svc info    : {'yes' if banner else 'no':<31}║")
        _print_safe(f"║  Svc version : {'yes' if version_detect else 'no':<31}║")
        _print_safe(f"║  CVE scan    : {'yes' if vuln_scan else 'no':<31}║")
        _print_safe(f"║  Firewall    : {'yes' if firewall_detect else 'no':<31}║")
    _print_safe(f"║  OS detect   : {'yes' if os_detect else 'no':<31}║")
    _print_safe(f"║  Report      : {_trunc(filename):<31}║")
    _print_safe("╚══════════════════════════════════════════════╝")

    if not yes_no("\nStart the scan?", default=True):
        print("\n  Scan cancelled.")
        return 0

    # ── Launch ────────────────────────────────────────────────────────────────
    # Import and call main.py with the parameters built by the interactive CLI
    from main import main as run_scan

    # Build the argument list as if the user had typed them on the command line
    scan_args = [
        "--target",    target,
        "--ports",     ports,
        "--scan-type", scan_type_val,
        "--output",    filename,
        "--timeout",   str(timeout),
        "--threads",   str(threads),
        "--delay",     str(delay),
        "--log-level", "WARNING",  # minimise log output during interactive scan
        "--max-rate",  str(max_rate),
        "--jitter",    str(jitter),
    ]
    # Add boolean flags only when they are enabled
    if randomize:
        scan_args.append("--randomize")
    if discover:
        scan_args.append("--discover")
    if banner:
        scan_args.append("--banner")
    if version_detect:
        scan_args.append("--version-detect")
    if vuln_scan:
        scan_args.append("--vuln-scan")
    if firewall_detect:
        scan_args.append("--firewall-detect")
    if os_detect:
        scan_args.append("--os-detect")

    print()
    try:
        return run_scan(scan_args)
    except KeyboardInterrupt:
        print("\n\n  Scan interrupted.")
        return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n\n  Cancelled.")
        raise SystemExit(1)
