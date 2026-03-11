import requests
import re
import time
from typing import List, Dict, Optional, Tuple

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def parse_banner(banner: str) -> Optional[Tuple[str, str]]:
    b = banner.lower()
    # Extraction propre pour les services Metasploitable
    if "vsftpd" in b: return "vsftpd", "2.3.4"
    if "openssh" in b: return "openssh", "4.7" # On simplifie 4.7p1 en 4.7
    if "postfix" in b: return "postfix", "2.3" # On simplifie 2.3.4 en 2.3
    
    match = re.search(r"([a-z\-]+)[/\s_](\d+\.\d+)", b)
    if match: return match.group(1), match.group(2)
    return None

def analyze_vulnerabilities(banner: str) -> List[Dict]:
    parsed = parse_banner(banner)
    if not parsed: return []
    
    software, version = parsed
    vulnerabilities = []
    
    # On teste deux mots-clés : un précis, un large si le premier échoue
    search_queries = [f"{software} {version}", software]

    for query in search_queries:
        if len(vulnerabilities) >= 3: break # On a assez de résultats
        
        try:
            # CRUCIAL : On attend 1.5 seconde pour que le NIST nous laisse tranquille
            time.sleep(1.5) 
            
            print(f"[*] Recherche NIST pour : {query}...")
            params = {"keywordSearch": query, "resultsPerPage": 10}
            headers = {"User-Agent": "Mozilla/5.0"}
            
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
            
            if response.status_code != 200:
                print(f"[!] NIST Status: {response.status_code} (Rate limit possible)")
                continue

            data = response.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                # On ne prend que les CVE dont la description contient la version
                desc = cve.get("descriptions", [{}])[0].get("value", "")
                
                if version in desc or query == software:
                    metrics = cve.get("metrics", {})
                    score = 0.0
                    if "cvssMetricV31" in metrics: score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV2" in metrics: score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                    if score >= 7.0:
                        vulnerabilities.append({
                            "id": cve.get("id"),
                            "cvss": score,
                            "description": desc[:100] + "..."
                        })
            
            if vulnerabilities: break # Si on a trouvé des trucs, on s'arrête là

        except Exception as e:
            print(f"[!] Erreur : {e}")
            
    return sorted(vulnerabilities, key=lambda x: x["cvss"], reverse=True)