import requests

def fetch_certspotter_subdomains(domain: str):
    """Fetch subdomains using CertSpotter API."""
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        res = requests.get(url, timeout=30)
        found_subs = []
        try:
            certs = res.json()
        except Exception:
            print(f"[CertSpotter] Request failed: Expecting value: line 1 column 1 (char 0)")
            return []
        for cert in certs:
            for name in cert.get("dns_names", []):
                if name.lower().endswith(f".{domain}"):
                    found_subs.append(name.lower())
        return found_subs
    except requests.exceptions.Timeout as e:
        print(f"[CertSpotter] Request failed: HTTPSConnectionPool(host='api.certspotter.com', port=443): Read timed out. (read timeout=30)")
        return []
    except Exception as e:
        print(f"[CertSpotter] Request failed: {e}")
        return []
