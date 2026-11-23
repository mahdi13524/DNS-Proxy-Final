import re

def normalize(domain):
    return domain.strip().lower().rstrip('.') if isinstance(domain, str) else ''

def valid(domain):
    return bool(domain and len(domain) <= 253 and all(len(part) <= 63 and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', part) for part in domain.split('.')))

def matches(domain, rules):
    return any(domain == rule or domain.endswith('.' + rule) for rule in rules)
