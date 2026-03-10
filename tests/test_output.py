# tests/test_output.py
import json, csv
from pathlib import Path
import pytest
from output import write_output

RESULTS = {
    80:  {"status": "open",     "service": "http",  "banner": "Apache"},
    22:  {"status": "closed",   "service": "ssh",   "banner": ""},
    443: {"status": "filtered", "service": "https", "banner": ""},
}

def test_write_txt(tmp_path):
    out = tmp_path / "scan.txt"
    write_output(RESULTS, out, "127.0.0.1", "connect")
    lines = out.read_text().splitlines()
    assert any("80" in l and "open" in l for l in lines)
    assert any("22" in l and "closed" in l for l in lines)

def test_write_json(tmp_path):
    out = tmp_path / "scan.json"
    write_output(RESULTS, out, "127.0.0.1", "connect")
    data = json.loads(out.read_text())
    assert data["80"]["status"] == "open"
    assert data["22"]["service"] == "ssh"

def test_write_csv(tmp_path):
    out = tmp_path / "scan.csv"
    write_output(RESULTS, out, "127.0.0.1", "connect")
    rows = list(csv.DictReader(out.open()))
    ports = [int(r["port"]) for r in rows]
    assert 80 in ports and 22 in ports

def test_write_html(tmp_path):
    out = tmp_path / "scan.html"
    write_output(RESULTS, out, "127.0.0.1", "connect")
    html = out.read_text()
    assert "<table" in html
    assert "127.0.0.1" in html
    assert "open" in html
    assert "Apache" in html
    assert "green" in html or "#" in html

def test_html_stats(tmp_path):
    out = tmp_path / "scan.html"
    write_output(RESULTS, out, "10.0.0.1", "syn")
    html = out.read_text()
    assert "1 open" in html or "open: 1" in html

import xml.etree.ElementTree as ET
import tempfile

def test_write_xml_creates_valid_file():
    from output import write_output
    results = {
        22: {"status": "open", "service": "ssh", "banner": "SSH-2.0-OpenSSH_8.9",
             "os": "Linux/Unix", "version": "OpenSSH_8.9", "firewall": ""},
        80: {"status": "filtered", "service": "http", "banner": "",
             "os": "", "version": "", "firewall": "filtered-silent"},
    }
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        path = Path(f.name)
    write_output(results, path, "192.168.1.1", "connect")
    tree = ET.parse(path)
    root = tree.getroot()
    assert root.tag == "nmaprun"
    ports = root.findall(".//port")
    assert len(ports) == 2

def test_write_xml_port_attributes():
    from output import write_output
    results = {
        443: {"status": "closed", "service": "https", "banner": "",
              "os": "", "version": "", "firewall": ""},
    }
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        path = Path(f.name)
    write_output(results, path, "10.0.0.1", "syn")
    tree = ET.parse(path)
    root = tree.getroot()
    port_elem = root.find(".//port")
    assert port_elem.get("portid") == "443"
    assert port_elem.get("protocol") == "tcp"
    state = port_elem.find("state")
    assert state.get("state") == "closed"

def test_write_xml_service_version_attribute():
    from output import write_output
    results = {
        22: {"status": "open", "service": "ssh", "banner": "",
             "os": "", "version": "OpenSSH_8.9", "firewall": ""},
    }
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        path = Path(f.name)
    write_output(results, path, "10.0.0.1", "connect")
    tree = ET.parse(path)
    root = tree.getroot()
    svc = root.find(".//service")
    assert svc.get("version") == "OpenSSH_8.9"

def test_write_xml_firewall_element_present():
    from output import write_output
    results = {
        80: {"status": "filtered", "service": "http", "banner": "",
             "os": "", "version": "", "firewall": "filtered-active"},
    }
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        path = Path(f.name)
    write_output(results, path, "10.0.0.1", "connect")
    tree = ET.parse(path)
    root = tree.getroot()
    fw = root.find(".//firewall")
    assert fw is not None
    assert fw.get("type") == "filtered-active"
