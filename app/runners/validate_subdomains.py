import dns.resolver

def validate_subdomains(subdomains):
    """Validate subdomains via DNS resolution."""
    active = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    for sub in subdomains:
        try:
            resolver.resolve(sub, "A")
            active.append(sub)
        except Exception:
            pass
    return active
