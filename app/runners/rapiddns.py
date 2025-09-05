import requests

def fetch_rapiddns_subdomains(domain: str):
    """Fetch subdomains using RapidDNS."""
    url = f"https://rapiddns.io/subdomain/{domain}?plain=1"
    try:
        res = requests.get(url, timeout=30)
        found_subs = res.text.lower().splitlines()
        return found_subs
    except requests.exceptions.Timeout as e:
        print(f"[RapidDNS] Request failed: HTTPSConnectionPool(host='rapiddns.io', port=443): Read timed out. (read timeout=30)")
        return []
    except Exception as e:
        print(f"[RapidDNS] Request failed: {e}")
        return []
