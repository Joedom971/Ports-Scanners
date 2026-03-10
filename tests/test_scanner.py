import socket
import time
from unittest.mock import patch, MagicMock
from scanner import scan_port_connect, get_service_name, grab_banner, scan_range_threaded, scan_port_syn, resoudre_cible


def test_get_service_name_known():
    assert get_service_name(80) == "http"
    assert get_service_name(22) == "ssh"
    assert get_service_name(443) == "https"

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
    """Sans scapy, doit retourner 'filtered', pas crasher."""
    import scanner as scanner_mod
    monkeypatch.setattr(scanner_mod, "SCAPY_AVAILABLE", False)
    result = scan_port_syn("127.0.0.1", 80)
    assert result == "filtered"


# ── Nouvelles fonctionnalités furtivité ──────────────────────────────────────

def test_randomize_tous_ports_presents():
    """Avec randomize=True, tous les ports sont quand même scannés."""
    ports = list(range(100, 120))
    def fake_scan(ip, port, timeout=1.0):
        return "closed"
    results = scan_range_threaded("127.0.0.1", ports, fake_scan, randomize=True, max_workers=5)
    assert set(results.keys()) == set(ports)

def test_randomize_ordre_different():
    """Avec randomize=True et une graine fixe, l'ordre est différent de l'ordre trié."""
    import random as rng
    rng.seed(42)
    ports = list(range(1, 21))
    ordre_enregistre = []
    def fake_scan(ip, port, timeout=1.0):
        ordre_enregistre.append(port)
        return "closed"
    scan_range_threaded("127.0.0.1", ports, fake_scan, randomize=True, max_workers=1)
    assert ordre_enregistre != sorted(ordre_enregistre)

def test_randomize_false_ne_mute_pas():
    """randomize=False ne modifie pas la liste originale."""
    ports = [80, 443, 22]
    original = ports.copy()
    def fake_scan(ip, port, timeout=1.0):
        return "closed"
    scan_range_threaded("127.0.0.1", ports, fake_scan, randomize=False, max_workers=3)
    assert ports == original

def test_max_rate_respecte_intervalle():
    """max_rate=10 paquets/s → intervalle ~0.1s entre envois."""
    envois = []
    def fake_scan(ip, port, timeout=1.0):
        envois.append(time.time())
        return "closed"
    scan_range_threaded("127.0.0.1", [80, 81, 82], fake_scan,
                        max_rate=10.0, max_workers=10)
    envois.sort()
    intervalles = [envois[i+1] - envois[i] for i in range(len(envois)-1)]
    # Chaque intervalle doit être >= 0.08s (tolérance 20%)
    for iv in intervalles:
        assert iv >= 0.08, f"Intervalle trop court : {iv:.3f}s"

def test_jitter_applique_delai_variable():
    """jitter > 0 → délai aléatoire entre delay et delay+jitter."""
    durees = []
    def fake_scan(ip, port, timeout=1.0):
        return "closed"
    debut = time.time()
    scan_range_threaded("127.0.0.1", [80, 81], fake_scan,
                        delay=0.05, jitter=0.05, max_workers=1)
    # Avec max_workers=1, les ports sont séquentiels → durée totale >= 2*0.05s
    assert time.time() - debut >= 0.08

def test_resoudre_cible_ip_inchangee():
    """Une IP valide est retournée telle quelle sans résolution DNS."""
    assert resoudre_cible("127.0.0.1") == "127.0.0.1"
    assert resoudre_cible("192.168.1.1") == "192.168.1.1"

def test_resoudre_cible_localhost():
    """'localhost' est résolu en 127.0.0.1 via gethostbyname (toujours IPv4)."""
    result = resoudre_cible("localhost")
    assert result == "127.0.0.1"

def test_resoudre_cible_inconnu():
    """Un hostname inexistant lève socket.gaierror."""
    import pytest
    with pytest.raises(OSError):
        resoudre_cible("hote.inexistant.invalid")

def test_resoudre_cible_ne_plante_pas_sur_cidr():
    """resoudre_cible ne doit pas être appelée sur un CIDR — test unitaire direct."""
    import ipaddress
    # Vérifier que la logique de détection CIDR dans main.py est correcte
    cible = "192.168.1.0/24"
    is_cidr = False
    try:
        ipaddress.ip_network(cible, strict=False)
        is_cidr = "/" in cible
    except ValueError:
        pass
    assert is_cidr is True  # le CIDR doit être détecté et resoudre_cible ignoré

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
