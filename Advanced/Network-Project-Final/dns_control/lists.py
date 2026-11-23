from .config import list_path
from .domain import normalize, valid


def inspect(name):
    """Return valid normalized domains plus line-numbered invalid entries."""
    path = list_path(name)
    if not path.exists():
        return {"domains": [], "warnings": []}
    domains = set()
    warnings = []
    for number, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        domain = normalize(value)
        if not valid(domain) or "*" in domain:
            warnings.append({"line": number, "value": value, "reason": "Invalid domain"})
            continue
        domains.add(domain)
    return {"domains": sorted(domains), "warnings": warnings}


def read(name):
    return set(inspect(name)["domains"])


def edit(name, domain, action):
    if name not in ("ads", "sanctions") or action not in ("add", "remove"):
        raise ValueError("Invalid list operation")
    domain = normalize(domain)
    if not valid(domain):
        raise ValueError("Invalid domain")
    domains = read(name)
    if action == "add":
        domains.add(domain)
    else:
        domains.discard(domain)
    path = list_path(name)
    temp = path.with_suffix(".tmp")
    temp.write_text("".join(d + "\n" for d in sorted(domains)), encoding="utf-8")
    temp.replace(path)
    return sorted(domains)


def replace(name, content):
    """Replace a policy list atomically; invalid lines are skipped and reported."""
    if name not in ("ads", "sanctions"):
        raise ValueError("Invalid list name")
    if not isinstance(content, str):
        raise ValueError("List content must be text")
    if len(content) > 100000:
        raise ValueError("Policy list is too large (maximum 100,000 characters)")
    domains = set()
    warnings = []
    for number, raw in enumerate(content.splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        domain = normalize(value)
        if not valid(domain) or "*" in domain:
            warnings.append({"line": number, "value": value, "reason": "Invalid domain"})
            continue
        domains.add(domain)
    path = list_path(name)
    temp = path.with_suffix(".tmp")
    temp.write_text("".join(d + "\n" for d in sorted(domains)), encoding="utf-8")
    temp.replace(path)
    return {"domains": sorted(domains), "warnings": warnings, "invalid_count": len(warnings)}
