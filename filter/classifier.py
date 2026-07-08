import re
from config import ENV_RULES
import re



def sanitize_filename(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9._-]', '_', name)

def export_domains_txt(domains, target_domain):
    """
    Export all discovered domains to a TXT file.
    """
    from pathlib import Path

    reports_dir = Path("reports_output")
    reports_dir.mkdir(exist_ok=True)

    safe_name = sanitize_filename(target_domain)
    txt_path = reports_dir / f"{safe_name}_all_domains.txt"

    unique_domains = sorted(set(domains))

    with open(txt_path, "w", encoding="utf-8") as f:
        for domain in unique_domains:
            f.write(domain.strip() + "\n")

    print(f"[+] Exported {len(unique_domains)} domains to {txt_path}")



_COMPILED = [(env, re.compile(pattern)) for env, pattern in ENV_RULES]


def classify(domain):
    """
    Return the environment class for a domain.
    Returns 'production' if no non-prod pattern matches.
    """
    d = domain.lower()
    for env, pattern in _COMPILED:
        if pattern.search(d):
            return env
    return "production"


def is_nonprod(domain):
    return classify(domain) != "production"
