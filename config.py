from pathlib import Path
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



# ---------------------------------------------------------------------------
# Generic domain scope — all brands and subsidiaries
# ---------------------------------------------------------------------------
DOMAIN_SCOPE = [
    # Generic core
    "generic.com"
]

# ---------------------------------------------------------------------------
# Non-production environment classification rules (priority order)
# ---------------------------------------------------------------------------
ENV_RULES = [
    ("sandbox",  r"sandbox"),
    ("preprod",  r"preprod|(?:^|[-\.])pp(?:[-\.]|$)"),
    ("training", r"training"),
    ("uat",      r"uat"),
    ("qat",      r"(?:^|[-\.])qat(?:[-\.\d]|$)"),
    ("perf",     r"(?:^|[-\.])(?:perf|plb|plab|prf)(?:[-\.\d]|$)|\.perf\."),
    ("load",     r"(?:^|[-\.])load(?:[-\.\d]|$)"),
    ("npe",      r"npe"),
    ("staging",  r"stg|(?:^|[-\.])stage(?:[-\.\d]|$)|staging"),
    ("qlab",     r"qlab"),
    ("dev",      r"(?:^|[-\.])dev(?:[-\.\d]|$)"),
    ("lab",      r"(?:^|[-\.])lab(?:[-\.\d]|$)"),
    ("test",     r"(?:^|[-\.])test(?:[-\.\d]|$)|(?:^|[-\.])tst(?:[-\.\d]|$)"),
    ("beta",     r"(?:^|[-\.])(?:beta|alpha|preview)(?:[-\.\d]|$)"),
]

# ---------------------------------------------------------------------------
# CT log sources
# ---------------------------------------------------------------------------
CT_LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

# Fallback hardcoded logs if the log list fetch fails
FALLBACK_CT_LOGS = [
    {"name": "Google Argon2025h1",     "url": "https://ct.googleapis.com/logs/us1/argon2025h1/"},
    {"name": "Google Argon2025h2",     "url": "https://ct.googleapis.com/logs/us1/argon2025h2/"},
    {"name": "Google Xenon2025h1",     "url": "https://ct.googleapis.com/logs/us1/xenon2025h1/"},
    {"name": "Google Xenon2025h2",     "url": "https://ct.googleapis.com/logs/us1/xenon2025h2/"},
    {"name": "Google Argon2026h1",     "url": "https://ct.googleapis.com/logs/us1/argon2026h1/"},
    {"name": "Google Argon2026h2",     "url": "https://ct.googleapis.com/logs/us1/argon2026h2/"},
    {"name": "Cloudflare Nimbus2025",  "url": "https://ct.cloudflare.com/logs/nimbus2025/"},
    {"name": "Cloudflare Nimbus2026",  "url": "https://ct.cloudflare.com/logs/nimbus2026/"},
    {"name": "DigiCert Yeti2025",      "url": "https://yeti2025.ct.digicert.com/log/"},
    {"name": "DigiCert Nessie2025",    "url": "https://nessie2025.ct.digicert.com/log/"},
    {"name": "DigiCert Yeti2026",      "url": "https://yeti2026.ct.digicert.com/log/"},
    {"name": "DigiCert Nessie2026",    "url": "https://nessie2026.ct.digicert.com/log/"},
    {"name": "Let's Encrypt Oak2025",  "url": "https://oak.ct.letsencrypt.org/2025/"},
    {"name": "Let's Encrypt Oak2026",  "url": "https://oak.ct.letsencrypt.org/2026/"},
    {"name": "Sectigo Sabre",          "url": "https://sabre.ct.comodo.com/"},
    {"name": "Sectigo Mammoth",        "url": "https://mammoth.ct.comodo.com/"},
    {"name": "TrustAsia Log2025",      "url": "https://ct.trustasia.com/log2025/"},
]

# ---------------------------------------------------------------------------
# Polling settings
# ---------------------------------------------------------------------------
CT_BATCH_SIZE = 256          # entries per API request
CT_REQUEST_DELAY = 0.2       # seconds between batch requests (be polite)
CT_MAX_ENTRIES_PER_RUN = 50_000   # per log per scan run (prevents runaway on first run)
CT_REQUEST_TIMEOUT = 30      # seconds
CT_MAX_WORKERS = 6           # parallel log pollers

# ---------------------------------------------------------------------------
# Probe settings
# ---------------------------------------------------------------------------
DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]   # always use external public DNS
PROBE_HTTP_TIMEOUT = 5       # seconds
PROBE_DNS_TIMEOUT = 5        # seconds
PROBE_MAX_WORKERS = 20       # parallel probe threads

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "generic_certs.db"
REPORTS_DIR = BASE_DIR / "reports_output"
