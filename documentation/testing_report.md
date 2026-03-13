# Testing Report

## Automated Tests

The project includes **76 unit tests** organized across 5 files:

```
tests/
├── test_scanner.py       (29 tests)
├── test_output.py        (10 tests)
├── test_discovery.py     (3 tests)
├── test_main.py          (4 tests)
└── test_sanitisation.py  (16 tests: 14 validation + 2 threads)
```

Run the tests:
```bash
python -m pytest tests/ -v
```

Expected result: **76 passed**

---

## Coverage by Module

### `test_scanner.py` — 29 tests

| Test | Description |
|------|-------------|
| `test_get_service_name_known` | Port 22 → "SSH", port 80 → "HTTP", port 443 → "HTTPS" |
| `test_get_service_name_unknown` | Port 19999 → "unknown" |
| `test_grab_banner_success` | Mock socket → banner "SSH-2.0-OpenSSH_8.9" returned |
| `test_grab_banner_timeout` | Socket timeout → returns "" |
| `test_scan_range_threaded_returns_all_ports` | 3 ports submitted → 3 results returned |
| `test_scan_range_threaded_status` | Port 80 → "open", port 443 → "closed" via fake_scan |
| `test_scan_port_syn_no_scapy` | Without scapy → returns "filtered" without crashing |
| `test_randomize_all_ports_present` | All ports still present after shuffle |
| `test_randomize_different_order` | Order differs after randomize |
| `test_randomize_false_does_not_mutate` | Original list not modified when randomize=False |
| `test_max_rate_respects_interval` | Minimum interval respected with max_rate |
| `test_jitter_applies_variable_delay` | Variable delay applied with jitter |
| `test_resolve_target_ip_unchanged` | IP returned as-is without DNS resolution |
| `test_resolve_target_localhost` | "localhost" → "127.0.0.1" |
| `test_resolve_target_unknown` | Unknown hostname → `socket.gaierror` |
| `test_resolve_target_does_not_crash_on_cidr` | CIDR returned as-is |
| `test_detect_os_returns_known_os_string` | Returns a valid value among the 4 possibilities |
| `test_detect_os_returns_unknown_without_scapy` | Without scapy → "unknown" |
| `test_detect_os_returns_unknown_on_no_response` | sr1 returns None → "unknown" (geteuid patched to 0) |
| `test_detect_service_version_returns_string` | Always returns a string |
| `test_detect_service_version_http_extracts_server_header` | HTTP → extracts "nginx/1.18.0" from Server: header |
| `test_detect_service_version_fallback_first_line` | SSH → returns first line of response |
| `test_detect_service_version_returns_empty_on_connection_failure` | Connection refused → "" |
| `test_detect_firewall_returns_valid_status` | Returns a status among the 5 valid values |
| `test_detect_firewall_without_scapy` | Without scapy → returns scan_port_connect result |
| `test_detect_firewall_silent_on_no_response` | sr1 returns None → "filtered-silent" |
| `test_detect_firewall_closed_on_rst` | TCP response with RST flag → "closed" |
| `test_detect_firewall_active_on_icmp` | ICMP response (not TCP) → "filtered-active" |

### `test_output.py` — 10 tests

| Test | Description |
|------|-------------|
| `test_write_txt` | Ports 22 and 80 present, version in brackets if available |
| `test_write_json` | Key "22" with status "open" and service "ssh" |
| `test_write_csv` | Headers include "os", "version", "firewall"; correct values |
| `test_write_html` | Tags `<table>`, target, "open", banner present |
| `test_html_stats` | Statistic "open: 1" present in HTML |
| `test_write_xml_creates_valid_file` | Root `<nmaprun>`, 2 `<port>` elements |
| `test_write_xml_port_attributes` | `portid="443"`, `protocol="tcp"`, `state="closed"` |
| `test_write_xml_service_version_attribute` | Attribute `version="OpenSSH_8.9"` on `<service>` |
| `test_write_xml_firewall_element_present` | Element `<firewall type="filtered-active"/>` present |
| `test_write_xml_escapes_special_characters` | `<`, `>`, `&` in banner → valid XML, value preserved |

### `test_discovery.py` — 3 tests

| Test | Description |
|------|-------------|
| `test_icmp_sweep_finds_active_host` | Mock ping → 192.168.1.1 detected in /30 |
| `test_discover_hosts_returns_list` | Returns a list containing the active IP |
| `test_discover_hosts_single_ip` | Single IP → returned if it responds |

### `test_main.py` — 4 tests

| Test | Description |
|------|-------------|
| `test_cli_basic` | Scan port 80 → return code 0, file created |
| `test_cli_json_output` | Port 80 "open" → JSON with `data["80"]["status"] == "open"` |
| `test_cli_syn_no_scapy` | SYN scan without scapy → warning displayed, no crash |
| `test_cli_threads_option` | `--threads 50` → `scan_range_threaded` called with `max_workers=50` |

### `test_sanitisation.py` — 16 tests (14 validation + 2 threads)

| Test | Description |
|------|-------------|
| `test_validate_port_valid` | Ports 1, 80, 65535 accepted |
| `test_validate_port_zero` | Port 0 → `ValueError` |
| `test_validate_port_too_large` | Port 65536 → `ValueError` |
| `test_validate_port_negative` | Port -1 → `ValueError` |
| `test_validate_target_ip` | Simple IP accepted |
| `test_validate_target_cidr` | CIDR accepted |
| `test_validate_target_hostname` | Valid hostname accepted |
| `test_validate_target_empty` | Empty string → `ValueError` |
| `test_validate_target_forbidden_chars` | Injection in target → `ValueError` |
| `test_validate_target_too_long` | Hostname > 253 chars → `ValueError` |
| `test_validate_output_file_*` | Valid extensions (.txt .json .csv .html .xml), invalid, relative traversal blocked |
| `test_parse_ports_*` | Single port, range, list, combination, deduplication, reversed range, invalid |
| `test_threads_zero_returns_error` | `--threads 0` → return code 1 |
| `test_threads_negative_returns_error` | `--threads -1` → return code 1 |

---

## Edge Cases Covered

| Case | Behavior |
|------|----------|
| Timeout = 0 | Rejected by validation — explicit error message |
| Decimal with comma (`0,5`) | Accepted and automatically converted to `0.5` |
| Invalid port (0 or > 65535) | `ValueError` raised by `parse_ports` |
| Host not found | Error message + return code 1 |
| SYN scan without sudo | Returns "filtered" + warning in logs |
| `--os-detect` without sudo | "unknown" + warning displayed in terminal |
| `--firewall-detect` without sudo | Fallback to `scan_port_connect` → "open"/"closed"/"filtered" |
| Ctrl+C during scan | Clean stop, "Scan interrupted." message without traceback |
| IPv6 as target | Accepted by the validator |
| Multi-host scan | One result file created per host |
| Banner with `<`, `>`, `&` | Correct XML export — characters escaped by ElementTree |
| HTTPS on port 443 (version detect) | No TLS probe — fallback to generic `\r\n`, limitation documented |
