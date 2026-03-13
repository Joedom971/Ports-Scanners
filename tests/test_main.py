# tests/test_main.py
from unittest.mock import patch, MagicMock
from pathlib import Path
from main import main


def test_cli_basic(tmp_path):
    out = tmp_path / "result.txt"
    with patch("main.scan_range_threaded", return_value={80: "closed"}):
        code = main(["--target", "127.0.0.1", "--ports", "80", "--output", str(out)])
    assert code == 0
    assert out.exists()


def test_cli_json_output(tmp_path):
    import json
    out = tmp_path / "result.json"
    with patch("main.scan_range_threaded", return_value={80: "open"}):
        main(["--target", "127.0.0.1", "--ports", "80", "--output", str(out)])
    data = json.loads(out.read_text())
    assert "80" in data["ports"]
    assert data["ports"]["80"]["status"] == "open"


def test_cli_syn_no_scapy(tmp_path, capsys):
    out = tmp_path / "result.txt"
    with patch("main.SCAPY_AVAILABLE", False):
        with patch("main.scan_range_threaded", return_value={80: "closed"}):
            main(["--target", "127.0.0.1", "--ports", "80",
                  "--scan-type", "syn", "--output", str(out)])
    captured = capsys.readouterr()
    assert "scapy" in captured.out.lower() or out.exists()


def test_cli_threads_option(tmp_path):
    out = tmp_path / "result.txt"
    with patch("main.scan_range_threaded", return_value={80: "closed"}) as mock_fn:
        main(["--target", "127.0.0.1", "--ports", "80",
              "--threads", "50", "--output", str(out)])
    mock_fn.assert_called_once()
    _, kwargs = mock_fn.call_args
    assert kwargs.get("max_workers") == 50
