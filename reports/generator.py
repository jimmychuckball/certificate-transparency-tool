import csv
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
import re



def sanitize_filename(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9._-]', '_', name)

def export_domains_txt(domains, target_domain):
    """
    Export all discovered domains to a TXT file.
    """
    from pathlib import Path

    reports_dir = Path(REPORTS_DIR)
    reports_dir.mkdir(exist_ok=True)

    safe_name = sanitize_filename(target_domain)
    txt_path = reports_dir / f"{safe_name}_all_domains.txt"

    unique_domains = sorted(set(domains))

    with open(txt_path, "w", encoding="utf-8") as f:
        for domain in unique_domains:
            f.write(domain.strip() + "\n")

    print(f"[+] Exported {len(unique_domains)} domains to {txt_path}")



from config import REPORTS_DIR
from storage.database import get_exposed_nonprod, get_nonprod_domains, get_stats

logger = logging.getLogger(__name__)

Path(REPORTS_DIR).mkdir(exist_ok=True)

OFFBAND_FIELDS = ["domain", "env_class", "cert_issuer", "cert_not_after", "first_seen"]
RESULTS_FIELDS = ["domain", "probe_status", "probe_ip"]

EXPOSED_FIELDS = [
    "domain", "env_class", "probe_status", "probe_ip",
    "cert_issuer", "cert_not_after", "first_seen", "last_seen", "log_source",
]


def _domain_prefix(domain=None):
    if not domain:
        return ""
    safe = sanitize_filename(domain)
    return f"{safe}_"


def _timestamp():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def generate_exposed_csv(domain=None):
    """Write a CSV of all EXPOSED non-prod domains."""
    rows = get_exposed_nonprod()
    ts = _timestamp()
    path = Path(REPORTS_DIR) / f"{_domain_prefix(domain)}exposed_nonprod_{ts}.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=EXPOSED_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    logger.info("Exposed report → %s (%d rows)", path, len(rows))
    return path, len(rows)


def generate_full_nonprod_csv(domain=None):
    """Write a CSV of ALL non-prod domains with their probe status."""
    rows = get_nonprod_domains()
    ts = _timestamp()
    path = Path(REPORTS_DIR) / f"{_domain_prefix(domain)}all_nonprod_{ts}.csv"
    fields = EXPOSED_FIELDS + ["cert_cn", "cert_sha256"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    logger.info("Full non-prod report → %s (%d rows)", path, len(rows))
    return path, len(rows)


def export_probe_results():
    """
    Export probe results to a shareable CSV.
    Used on the off-band laptop to send results back to the corporate machine.
    """
    rows = get_nonprod_domains()
    ts = _timestamp()
    path = Path(REPORTS_DIR) / f"probe_results_{ts}.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=RESULTS_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    logger.info("Probe results export -> %s (%d rows)", path, len(rows))
    return path, len(rows)


def export_nonprod_for_offband():
    """
    Export all non-prod domains to a CSV the off-band laptop can bootstrap from.
    Includes env_class and cert metadata so the remote machine has full context.
    """
    rows = get_nonprod_domains()
    ts = _timestamp()
    path = Path(REPORTS_DIR) / f"offband_domains_{ts}.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OFFBAND_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    logger.info("Off-band export -> %s (%d non-prod domains)", path, len(rows))
    return path, len(rows)


def import_probe_results(csv_path):
    """
    Merge probe results from an off-band laptop CSV back into the local DB.
    The CSV must have columns: domain, probe_status, probe_ip
    Returns count of rows merged.
    """
    from storage.database import update_probe

    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Results file not found: {csv_path}")

    merged = 0
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get("domain", "").strip()
            status = row.get("probe_status", "").strip()
            ip = row.get("probe_ip", "").strip() or None
            if domain and status:
                update_probe(domain, status, ip)
                merged += 1

    logger.info("Imported %d probe results from %s", merged, path)
    return merged


def print_summary():
    """Print a concise status summary to stdout."""
    stats = get_stats()
    print("\n" + "=" * 60)
    print("  GENERIC DOMAIN CERT FINDER — CURRENT STATUS")
    print("=" * 60)
    print(f"  Total domains in DB : {stats['total']:,}")
    print()
    print("  By environment:")
    for row in stats["by_env"]:
        label = (row["env_class"] or "unknown").ljust(14)
        print(f"    {label} {row['cnt']:>6,}")
    print()
    print("  Non-prod probe status:")
    for row in stats["by_probe"]:
        label = (row["probe_status"] or "UNKNOWN").ljust(12)
        print(f"    {label} {row['cnt']:>6,}")
    print()
    print(f"  ** EXPOSED non-prod : {stats['exposed_nonprod']:,} **")
    print("=" * 60 + "\n")
