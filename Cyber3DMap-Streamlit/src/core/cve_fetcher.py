import requests
import time
import yaml
import os
import streamlit as st

with open(os.path.join(os.path.dirname(__file__), "../configs/config.yaml")) as f:
    config = yaml.safe_load(f)

def fetch_cve(service: str) -> list:
    """Fetch CVEs for a service from NVD API with caching and retries."""
    if not service:
        return []
    
    # Initialize cache if missing
    if "cve_cache" not in st.session_state:
        st.session_state.cve_cache = {}
    
    # Check cache
    if service in st.session_state.cve_cache:
        st.write(f"Using cached CVEs for service: {service}")
        return st.session_state.cve_cache[service]
    
    for attempt in range(3):
        try:
            url = f"{config['cve']['api_url']}?keywordSearch={service}"
            res = requests.get(url, timeout=5)
            time.sleep(config['cve']['rate_limit'])
            if res.status_code == 200:
                cves = [
                    {
                        "id": vuln["cve"]["id"],
                        "cvss": vuln["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
                        if "cvssMetricV31" in vuln["cve"]["metrics"] else 0
                    }
                    for vuln in res.json().get("vulnerabilities", [])[:config['cve']['max_cves']]
                ]
                st.session_state.cve_cache[service] = cves
                st.write(f"Fetched {len(cves)} CVEs for service: {service}")
                return cves
            else:
                st.warning(f"NVD API returned status {res.status_code} for service: {service}")
        except Exception as e:
            st.warning(f"Attempt {attempt + 1} failed for service {service}: {str(e)}")
            if attempt < 2:
                time.sleep(2)
            continue
    st.error(f"Failed to fetch CVEs for service: {service}")
    return []