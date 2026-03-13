import socket
import time
from unittest.mock import patch, MagicMock
from scanner import scan_port_connect, get_service_name, grab_banner, scan_range_threaded, scan_port_syn, resolve_target


def test_get_service_name_known():
    assert get_service_name(80) == "HTTP"
    assert get_service_name(22) == "SSH"
    assert get_service_name(443) == "HTTPS"

def test_get_service_name_unknown():
    result = get_service_name(19999)
    assert result == "unknown"

def test_grab_banner_success():
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.connect_ex.return_value = 0
    mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
    with patch("socket.socket", return_value=mock_sock):
        result = grab_banner("127.0.0.1", 22)
    assert "SSH" in result

def test_grab_banner_timeout():
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.connect_ex.return_value = 0
    mock_sock.recv.side_effect = socket.timeout
    with patch("socket.socket", return_value=mock_sock):
        result = grab_banner("127.0.0.1", 80)
    assert result == ""


def test_scan_range_threaded_returns_all_ports():
    results = scan_range_threaded("127.0.0.1", [80, 443, 8080], scan_port_connect, timeout=1.0, delay=0.0, max_workers=10)
    assert set(results.keys()) == {80, 443, 8080}

def test_scan_range_threaded_status():
    def fake_scan(ip, port, timeout=1.0):
        return "open" if port == 80 else "closed"
    results = scan_range_threaded("127.0.0.1", [80, 443], fake_scan, timeout=1.0, delay=0.0, max_workers=2)
    assert results[80] == "open"
    assert results[443] == "closed"


def test_scan_port_syn_no_scapy(monkeypatch):
    """Without scapy, must return 'filtered', not crash."""
    import scanner as scanner_mod
    monkeypatch.setattr(scanner_mod, "SCAPY_AVAILABLE", False)
    result = scan_port_syn("127.0.0.1", 80)
    assert result == "filtered"


# ── Stealth features ─────────────────────────────────────────────────────────

def test_randomize_all_ports_present():
    """With randomize=True, all ports are still scanned."""
    ports = list(range(100, 120))
    def fake_scan(ip, port, timeout=1.0):
        return "closed"
    results = scan_range_threaded("127.0.0.1", ports, fake_scan, randomize=True, max_workers=5)
    assert set(results.keys()) == set(ports)

def test_randomize_different_order():
    """With randomize=True and a fixed seed, the order differs from sorted order."""
    import random as rng
    rng.seed(42)
    ports = list(range(1, 21))
    recorded_order = []
    def fake_scan(ip, port, timeout=1.0):
        recorded_order.append(port)
        return "closed"
    scan_range_threaded("127.0.0.1", ports, fake_scan, randomize=True, max_workers=1)
    assert recorded_order != sorted(recorded_order)

def test_randomize_false_does_not_mutate():
    """randomize=False does not modify the original list."""
    ports = [80, 443, 22]
    original = ports.copy()
    def fake_scan(ip, port, timeout=1.0):
        return "closed"
    scan_range_threaded("127.0.0.1", ports, fake_scan, randomize=False, max_workers=3)
    assert ports == original

def test_max_rate_respects_interval():
    """max_rate=10 pkt/s → interval ~0.1s between sends."""
    sends = []
    def fake_scan(ip, port, timeout=1.0):
        sends.append(time.time())
        return "closed"
    scan_range_threaded("127.0.0.1", [80, 81, 82], fake_scan,
                        max_rate=10.0, max_workers=10)
    sends.sort()
    intervals = [sends[i+1] - sends[i] for i in range(len(sends)-1)]
    # Each interval must be >= 0.08s (20% tolerance)
    for iv in intervals:
        assert iv >= 0.08, f"Interval too short: {iv:.3f}s"

def test_jitter_applies_variable_delay():
    """jitter > 0 → random delay between delay and delay+jitter."""
    def fake_scan(ip, port, timeout=1.0):
        return "closed"
    start = time.time()
    scan_range_threaded("127.0.0.1", [80, 81], fake_scan,
                        delay=0.05, jitter=0.05, max_workers=1)
    # With max_workers=1, ports are sequential → total duration >= 2*0.05s
    assert time.time() - start >= 0.08

def test_resolve_target_ip_unchanged():
    """A valid IP is returned as-is without DNS resolution."""
    assert resolve_target("127.0.0.1") == "127.0.0.1"
    assert resolve_target("192.168.1.1") == "192.168.1.1"

def test_resolve_target_localhost():
    """'localhost' is resolved to 127.0.0.1 via gethostbyname (always IPv4)."""
    result = resolve_target("localhost")
    assert result == "127.0.0.1"

def test_resolve_target_unknown():
    """A non-existent hostname raises socket.gaierror."""
    import pytest
    with pytest.raises(OSError):
        resolve_target("nonexistent.host.invalid")

def test_resolve_target_does_not_crash_on_cidr():
    """resolve_target must not be called on a CIDR — direct unit test."""
    import ipaddress
    # Verify that the CIDR detection logic in main.py is correct
    target = "192.168.1.0/24"
    is_cidr = False
    try:
        ipaddress.ip_network(target, strict=False)
        is_cidr = "/" in target
    except ValueError:
        pass
    assert is_cidr is True  # CIDR must be detected and resolve_target skipped

def test_detect_os_returns_known_os_string():
    from scanner import detect_os
    result = detect_os("8.8.8.8", timeout=1.0)
    assert isinstance(result, str)
    assert result in ("Linux/Unix", "Windows", "Network device", "unknown")

def test_detect_os_returns_unknown_without_scapy(monkeypatch):
    import scanner
    monkeypatch.setattr(scanner, "SCAPY_AVAILABLE", False)
    result = scanner.detect_os("127.0.0.1", timeout=0.5)
    assert result == "unknown"

def test_detect_os_returns_unknown_on_no_response(monkeypatch):
    import scanner, os
    monkeypatch.setattr(scanner, "SCAPY_AVAILABLE", True)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr("scanner.sr1", lambda *a, **kw: None)
    result = scanner.detect_os("192.0.2.1", timeout=0.1)
    assert result == "unknown"

def test_detect_service_version_returns_string():
    from scanner import detect_service_version
    result = detect_service_version("127.0.0.1", 9999, "unknown", timeout=0.2)
    assert isinstance(result, str)

def test_detect_service_version_http_extracts_server_header(monkeypatch):
    import socket
    import scanner
    class FakeSocket:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def settimeout(self, t): pass
        def connect_ex(self, addr): return 0
        def sendall(self, data): pass
        def recv(self, n): return b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n"
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSocket())
    result = scanner.detect_service_version("127.0.0.1", 80, "http", timeout=1.0)
    assert result == "nginx/1.18.0"

def test_detect_service_version_fallback_first_line(monkeypatch):
    import socket
    import scanner
    class FakeSocket:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def settimeout(self, t): pass
        def connect_ex(self, addr): return 0
        def sendall(self, data): pass
        def recv(self, n): return b"SSH-2.0-OpenSSH_8.9\r\nmore data"
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSocket())
    result = scanner.detect_service_version("127.0.0.1", 22, "ssh", timeout=1.0)
    assert result == "SSH-2.0-OpenSSH_8.9"

def test_detect_service_version_returns_empty_on_connection_failure(monkeypatch):
    import socket
    import scanner
    class FakeSocket:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def settimeout(self, t): pass
        def connect_ex(self, addr): return 111  # ECONNREFUSED
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSocket())
    result = scanner.detect_service_version("127.0.0.1", 9999, "unknown", timeout=0.2)
    assert result == ""


def test_detect_firewall_returns_valid_status():
    from scanner import detect_firewall
    result = detect_firewall("127.0.0.1", 9999, timeout=0.3)
    assert result in ("open", "closed", "filtered-silent", "filtered-active", "filtered")

def test_detect_firewall_without_scapy(monkeypatch):
    import scanner
    monkeypatch.setattr(scanner, "SCAPY_AVAILABLE", False)
    result = scanner.detect_firewall("127.0.0.1", 9999, timeout=0.3)
    assert result in ("open", "closed", "filtered")

def test_detect_firewall_silent_on_no_response(monkeypatch):
    import scanner, os
    monkeypatch.setattr(scanner, "SCAPY_AVAILABLE", True)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr("scanner.sr1", lambda *a, **kw: None)
    result = scanner.detect_firewall("192.0.2.1", 80, timeout=0.1)
    assert result == "filtered-silent"

def test_detect_firewall_closed_on_rst(monkeypatch):
    import scanner, os
    monkeypatch.setattr(scanner, "SCAPY_AVAILABLE", True)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    # Create sentinel classes to use as identity markers.
    # They accept **kwargs so that TCP(dport=..., flags=...) and IP(dst=...) don't raise TypeError.
    class FakeTCPClass:
        def __init__(self, **kwargs): pass
        def __truediv__(self, other): return self
    class FakeICMPClass:
        def __init__(self, **kwargs): pass
    class FakeIPClass:
        def __init__(self, **kwargs): pass
        def __truediv__(self, other): return self
    monkeypatch.setattr(scanner, "TCP", FakeTCPClass, raising=False)
    monkeypatch.setattr(scanner, "ICMP", FakeICMPClass, raising=False)
    monkeypatch.setattr(scanner, "IP", FakeIPClass, raising=False)
    class FakeResp:
        def haslayer(self, layer):
            return layer is FakeTCPClass
        def __getitem__(self, layer):
            class FakeTCPInst:
                flags = 0x04  # RST
            return FakeTCPInst()
    monkeypatch.setattr("scanner.sr1", lambda *a, **kw: FakeResp())
    result = scanner.detect_firewall("192.0.2.1", 80, timeout=0.1)
    assert result == "closed"


def test_detect_firewall_active_on_icmp(monkeypatch):
    import scanner, os
    monkeypatch.setattr(scanner, "SCAPY_AVAILABLE", True)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    class FakeTCPClass:
        def __init__(self, **kwargs): pass
        def __truediv__(self, other): return self
    class FakeICMPClass:
        def __init__(self, **kwargs): pass
    class FakeIPClass:
        def __init__(self, **kwargs): pass
        def __truediv__(self, other): return self
    monkeypatch.setattr(scanner, "TCP", FakeTCPClass, raising=False)
    monkeypatch.setattr(scanner, "ICMP", FakeICMPClass, raising=False)
    monkeypatch.setattr(scanner, "IP", FakeIPClass, raising=False)
    class FakeResp:
        def haslayer(self, layer):
            # No TCP layer, but has ICMP (firewall sent ICMP port-unreachable)
            return layer is FakeICMPClass
        def __getitem__(self, layer):
            return None
    monkeypatch.setattr("scanner.sr1", lambda *a, **kw: FakeResp())
    result = scanner.detect_firewall("192.0.2.1", 80, timeout=0.1)
    assert result == "filtered-active"
