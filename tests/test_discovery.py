# tests/test_discovery.py
from unittest.mock import patch, MagicMock
import subprocess
from discovery import discover_hosts, _icmp_sweep


def test_icmp_sweep_finds_active_host():
    def fake_run(cmd, **kwargs):
        m = MagicMock()
        m.returncode = 0 if "192.168.1.1" in cmd else 1
        return m

    with patch("subprocess.run", side_effect=fake_run):
        result = _icmp_sweep("192.168.1.0/30", timeout=1)
    assert "192.168.1.1" in result


def test_discover_hosts_returns_list():
    with patch("discovery._icmp_sweep", return_value=["192.168.1.1"]):
        with patch("discovery.SCAPY_AVAILABLE", False):
            result = discover_hosts("192.168.1.0/30", timeout=1)
    assert isinstance(result, list)
    assert "192.168.1.1" in result


def test_discover_hosts_single_ip():
    """Une IP unique (pas un réseau) retourne juste cette IP si elle répond."""
    with patch("discovery._icmp_sweep", return_value=["10.0.0.1"]):
        with patch("discovery.SCAPY_AVAILABLE", False):
            result = discover_hosts("10.0.0.1", timeout=1)
    assert "10.0.0.1" in result
