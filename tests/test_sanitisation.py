# tests/test_sanitisation.py
"""Tests for user input validation functions."""

import pytest
from pathlib import Path
from main import validate_port, validate_target, validate_output_file, parse_ports


# ── validate_port ─────────────────────────────────────────────────────────────

def test_validate_port_valid():
    assert validate_port(1) == 1
    assert validate_port(80) == 80
    assert validate_port(65535) == 65535

def test_validate_port_zero():
    with pytest.raises(ValueError):
        validate_port(0)

def test_validate_port_too_large():
    with pytest.raises(ValueError):
        validate_port(65536)

def test_validate_port_negative():
    with pytest.raises(ValueError):
        validate_port(-1)


# ── validate_target ───────────────────────────────────────────────────────────

def test_validate_target_ip():
    assert validate_target("192.168.1.1") == "192.168.1.1"

def test_validate_target_cidr():
    assert validate_target("192.168.1.0/24") == "192.168.1.0/24"

def test_validate_target_hostname():
    assert validate_target("my-server.local") == "my-server.local"

def test_validate_target_localhost():
    assert validate_target("127.0.0.1") == "127.0.0.1"

def test_validate_target_empty():
    with pytest.raises(ValueError):
        validate_target("")

def test_validate_target_forbidden_chars():
    with pytest.raises(ValueError):
        validate_target("192.168.1.1; rm -rf /")

def test_validate_target_too_long():
    with pytest.raises(ValueError):
        validate_target("a" * 254)


# ── validate_output_file ─────────────────────────────────────────────────────

def test_validate_output_file_txt():
    p = validate_output_file("scan.txt")
    assert isinstance(p, Path)

def test_validate_output_file_json():
    assert validate_output_file("results.json").suffix == ".json"

def test_validate_output_file_csv():
    assert validate_output_file("scan.csv").suffix == ".csv"

def test_validate_output_file_html():
    assert validate_output_file("report.html").suffix == ".html"

def test_validate_output_file_invalid_extension():
    with pytest.raises(ValueError):
        validate_output_file("scan.exe")

def test_validate_output_file_empty():
    with pytest.raises(ValueError):
        validate_output_file("")

def test_validate_output_file_relative_traversal():
    with pytest.raises(ValueError):
        validate_output_file("../../etc/passwd.txt")

def test_validate_output_file_absolute_allowed(tmp_path):
    # Absolute paths outside cwd are allowed (e.g. /tmp/scan.json)
    p = validate_output_file(str(tmp_path / "scan.json"))
    assert p.suffix == ".json"


# ── parse_ports ───────────────────────────────────────────────────────────────

def test_parse_ports_simple():
    assert parse_ports("80") == [80]

def test_parse_ports_range():
    assert parse_ports("20-22") == [20, 21, 22]

def test_parse_ports_list():
    assert parse_ports("22,80,443") == [22, 80, 443]

def test_parse_ports_combination():
    assert parse_ports("22,80-82,443") == [22, 80, 81, 82, 443]

def test_parse_ports_deduplicates():
    assert parse_ports("80,80,80") == [80]

def test_parse_ports_reversed_range():
    # Reversed range is silently corrected
    assert parse_ports("85-80") == [80, 81, 82, 83, 84, 85]

def test_parse_ports_port_zero():
    with pytest.raises(ValueError):
        parse_ports("0")

def test_parse_ports_port_too_large():
    with pytest.raises(ValueError):
        parse_ports("65536")

def test_parse_ports_empty():
    with pytest.raises(ValueError):
        parse_ports("")

def test_parse_ports_invalid():
    with pytest.raises(ValueError):
        parse_ports("abc")


# ── threads validation ────────────────────────────────────────────────────────

def test_threads_zero_returns_error():
    from main import main
    result = main(["--target", "127.0.0.1", "--ports", "80", "--threads", "0"])
    assert result == 1

def test_threads_negative_returns_error():
    from main import main
    result = main(["--target", "127.0.0.1", "--ports", "80", "--threads", "-1"])
    assert result == 1
