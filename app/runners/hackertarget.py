import requests

def fetch_hackertarget_subdomains(domain: str):
    """Fetch subdomains using HackerTarget API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        res = requests.get(url, timeout=30)
        found_subs = []
        for line in res.text.strip().splitlines():
            if ',' in line:
                sub, _ = line.split(",", 1)
                found_subs.append(sub.lower())
        return found_subs
    except Exception as e:
        print(f"[HackerTarget] Request failed: {e}")
        return []
