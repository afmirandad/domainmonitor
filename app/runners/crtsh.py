import requests

def fetch_crtsh_subdomains(domain: str):
    """Fetch subdomains using crt.sh."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        res = requests.get(url, timeout=30)
        found_subs = []
        names = [item["name_value"].lower() for item in res.json()]
        for name in names:
            for sub in name.split('\n'):
                if sub.endswith(f".{domain}"):
                    found_subs.append(sub)
        return found_subs
    except Exception as e:
        print(f"[crt.sh] Request failed: {e}")
        return []
