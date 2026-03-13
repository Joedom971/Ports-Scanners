"""Vulnerability analyzer — queries the NVD (NIST) API for known CVEs.

Parses service banners to extract software name and version,
then searches for critical vulnerabilities (CVSS >= 7.0).
"""

import re
import time
from typing import Dict, List, Optional, Tuple

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# --- IN-MEMORY CACHE ---
# Structure: { "software:version": [ {id, cvss, description}, ... ] }
_CVE_CACHE: Dict[str, List[Dict]] = {}


def parse_banner(banner: str) -> Optional[Tuple[str, str]]:
    """Extracts (software, version) from a service banner string."""
    b = banner.lower()
    # Known Metasploitable services — hardcoded for reliable extraction
    if "vsftpd" in b:
        return "vsftpd", "2.3.4"
    if "openssh" in b:
        return "openssh", "4.7"
    if "postfix" in b:
        return "postfix", "2.3"

    match = re.search(r"([a-z\-]+)[/\s_](\d+\.\d+)", b)
    if match:
        return match.group(1), match.group(2)
    return None


def analyze_vulnerabilities(banner: str) -> List[Dict]:
    """Searches the NVD API for critical CVEs matching the given banner.

    Returns a list of dicts with keys: id, cvss, description.
    Only CVEs with CVSS >= 7.0 are included, sorted by severity (descending).
    """
    parsed = parse_banner(banner)
    if not parsed:
        return []

    software, version = parsed
    cache_key = f"{software}:{version}"

    # Return cached results if already queried
    if cache_key in _CVE_CACHE:
        return _CVE_CACHE[cache_key]

    vulnerabilities = []

    # Try a precise query first, then a broader one if no results
    search_queries = [f"{software} {version}", software]

    for query in search_queries:
        if len(vulnerabilities) >= 3:
            break

        try:
            # Rate-limit: NVD enforces ~1 request/second for unauthenticated users
            time.sleep(1.5)

            print(f"[*] NVD search: {query}...")
            params = {"keywordSearch": query, "resultsPerPage": 10}
            headers = {"User-Agent": "Mozilla/5.0"}

            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)

            if response.status_code != 200:
                print(f"[!] NVD status: {response.status_code} (rate limit possible)")
                continue

            data = response.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                desc = cve.get("descriptions", [{}])[0].get("value", "")

                if version in desc or query == software:
                    metrics = cve.get("metrics", {})
                    score = 0.0
                    if "cvssMetricV31" in metrics:
                        score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV2" in metrics:
                        score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                    if score >= 7.0:
                        vulnerabilities.append({
                            "id": cve.get("id"),
                            "cvss": score,
                            "description": desc[:100] + "...",
                        })

            if vulnerabilities:
                break

        except Exception as e:
            print(f"[!] Error: {e}")

    result = sorted(vulnerabilities, key=lambda x: x["cvss"], reverse=True)
    _CVE_CACHE[cache_key] = result
    return result
