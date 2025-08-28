import requests

def fetch_certspotter_subdomains(domain: str):
    """Fetch subdomains using CertSpotter API."""
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        res = requests.get(url, timeout=30)
        found_subs = []
        for cert in res.json():
            for name in cert.get("dns_names", []):
                if name.lower().endswith(f".{domain}"):
                    found_subs.append(name.lower())
        return found_subs
    except Exception as e:
        print(f"[CertSpotter] Request failed: {e}")
        return []
