"""
Generic Certificate Monitor
-----------------------------
Usage:
  python main.py bootstrap [domains_file]   Import existing domain list + init CT log positions
  python main.py seed-domain                 Prompt for a domain and pull all historical certs from multiple CT/passive sources
  python main.py seed-domain example.com     Pull all historical certs for one domain from multiple CT/passive sources
  python main.py scan                        Poll CT logs for new certs
  python main.py probe [--force]             Probe non-prod domains for internet exposure
  python main.py report                      Generate CSV reports
  python main.py status                      Show DB summary
  python main.py run                         Full pipeline: scan + probe + report
"""

import argparse
import logging
import re
import sys
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



from config import DB_PATH, DOMAIN_SCOPE
from storage.database import init_db, upsert_domain, upsert_log, update_log_position
from filter.classifier import classify
from poller.ct_client import fetch_active_logs, poll_all_logs
from poller.seeder import seed_all
from probe.checker import probe_all_nonprod
from reports.generator import (
    generate_exposed_csv, generate_full_nonprod_csv, print_summary,
    export_nonprod_for_offband, export_probe_results, import_probe_results,
)

# Ensure UTF-8 output on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("cert_monitor.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)


_DOMAIN_RE = re.compile(r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)


def normalize_base_domain(value):
    """Normalize and validate a user-supplied base domain."""
    domain = (value or "").strip().lower()
    domain = domain.removeprefix("http://").removeprefix("https://")
    domain = domain.split("/", 1)[0].split(":", 1)[0]
    domain = domain.lstrip("*. ").strip(".")

    if not domain or not _DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid domain: {value!r}")
    return domain


def prompt_for_base_domain():
    """Ask the user which base domain to query."""
    while True:
        raw = input("Enter the base domain to pull certificates for, example example.com: ").strip()
        try:
            return normalize_base_domain(raw)
        except ValueError as exc:
            print(f"  {exc}. Try again.\n")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_bootstrap(domains_file=None):
    """
    1. Initialise the database.
    2. Register all CT logs and set their position to the current tree tip
       (so future scans only pick up NEW certs — no historical flood).
    3. Optionally import an existing domains file as a starting dataset.
    """
    logger.info("=== BOOTSTRAP ===")
    init_db()

    # Register CT logs and mark them at current tip
    logs = fetch_active_logs()
    logger.info("Registering %d CT logs and setting positions to current tip...", len(logs))

    import requests
    session = requests.Session()
    session.headers["User-Agent"] = "generic-cert-monitor/1.0"

    for log in logs:
        upsert_log(log["name"], log["url"])
        try:
            url = log["url"].rstrip("/") + "/ct/v1/get-sth"
            resp = session.get(url, timeout=15)
            resp.raise_for_status()
            tip = resp.json()["tree_size"]
            update_log_position(log["url"], tip)
            logger.info("  %s -> tip=%d", log["name"], tip)
        except Exception as exc:
            logger.warning("  %s → could not fetch tip: %s", log["name"], exc)

    # Import existing domains file if provided
    if domains_file:
        path = Path(domains_file)
        if not path.exists():
            logger.error("File not found: %s", domains_file)
            return

        logger.info("Importing domains from %s ...", path)
        imported = 0
        skipped = 0

        with open(path, encoding="utf-8") as f:
            for line in f:
                domain = line.strip().lower()
                if not domain or domain == "matching identities":
                    continue

                # Check it's in scope
                in_scope = False
                d = domain.lstrip("*.").lstrip(".")
                for scope in DOMAIN_SCOPE:
                    if d == scope or d.endswith("." + scope):
                        in_scope = True
                        break

                if not in_scope:
                    skipped += 1
                    continue

                env = classify(domain)
                is_new = upsert_domain(
                    domain=domain,
                    env_class=env,
                    cert_cn="",
                    cert_issuer="",
                    cert_not_after=None,
                    cert_sha256="",
                    log_source="bootstrap_import",
                )
                if is_new:
                    imported += 1

        logger.info("Imported %d domains (%d out-of-scope skipped)", imported, skipped)

    print_summary()
    logger.info("Bootstrap complete.")


def cmd_scan(domain=None):
    """Run a selected-domain multi-source CT/passive scan."""
    logger.info("=== SCAN ===")
    init_db()
    if domain:
        base_domain = normalize_base_domain(domain)
    else:
        base_domain = prompt_for_base_domain()
    total = seed_all([base_domain])
    logger.info("Scan complete -- %d new domains found for %s", total, base_domain)
    print_summary()


def cmd_probe(force=False):
    """Probe all non-prod domains for internet reachability."""
    logger.info("=== PROBE (force=%s) ===", force)
    init_db()
    exposed = probe_all_nonprod(force=force)
    logger.info("Probe complete -- %d EXPOSED non-prod domains", exposed)
    # Always export probe results so they can be copied back to the corporate machine
    results_path, count = export_probe_results()
    print_summary()
    print(f"  Probe results CSV -> {results_path}")
    print("  Copy this file to your corporate laptop and run:")
    print("    python main.py import-results <probe_results.csv>\n")


def cmd_report(domain=None):
    """Generate CSV reports."""
    logger.info("=== REPORT ===")
    init_db()
    base_domain = normalize_base_domain(domain) if domain else None
    exposed_path, exposed_count = generate_exposed_csv(base_domain)
    full_path, full_count = generate_full_nonprod_csv(base_domain)
    print_summary()
    print(f"  Exposed non-prod CSV : {exposed_path}  ({exposed_count} rows)")
    print(f"  Full non-prod CSV    : {full_path}  ({full_count} rows)")


def cmd_status():
    """Print current DB summary."""
    init_db()
    print_summary()


def cmd_seed(domains=None):
    """
    One-time historical backfill from multiple CT/passive sources for configured scope domains or a subset.
    Safe to re-run because upsert logic prevents duplicates.
    """
    logger.info("=== SEED FROM MULTI-SOURCE CT ===")
    init_db()
    if domains:
        normalized = [normalize_base_domain(d) for d in domains]
        logger.info("Seeding subset: %s", normalized)
        total = seed_all(normalized)
    else:
        from config import DOMAIN_SCOPE
        logger.info("Seeding all %d configured scope domains", len(DOMAIN_SCOPE))
        total = seed_all(None)
    print(f"\n  Seeding complete -- {total} new domains added")
    print_summary()


def cmd_seed_domain(domain=None):
    """Prompt for one base domain and fetch all known certificate names from multiple CT/passive sources."""
    logger.info("=== SEED SINGLE DOMAIN FROM MULTI-SOURCE CT ===")
    init_db()

    base_domain = normalize_base_domain(domain) if domain else prompt_for_base_domain()
    print(f"\n  Pulling historical certificates for: {base_domain}")
    total = seed_all([base_domain])
    print(f"\n  Seeding complete for {base_domain} -- {total} new domains added")
    print_summary()


def cmd_export_domains():
    """Export non-prod domains to a CSV for use on the off-band laptop."""
    logger.info("=== EXPORT DOMAINS ===")
    init_db()
    path, count = export_nonprod_for_offband()
    print(f"\n  Exported {count} non-prod domains -> {path}")
    print("  Copy this file to your off-band laptop and run:")
    print("    python main.py bootstrap <this_file.csv>")
    print("  Then probe from there with:")
    print("    python main.py probe")
    print("  Copy the resulting reports_output/probe_results_*.csv back here and run:")
    print("    python main.py import-results <probe_results.csv>\n")


def cmd_import_results(csv_path):
    """Merge off-band probe results back into the local DB."""
    logger.info("=== IMPORT RESULTS ===")
    init_db()
    try:
        merged = import_probe_results(csv_path)
        print(f"\n  Merged {merged} probe results from {csv_path}")
        print_summary()
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)


def cmd_run(force_probe=False, domain=None):
    """Full pipeline: selected-domain scan → probe → report."""
    logger.info("=== FULL PIPELINE RUN ===")
    init_db()
    if domain:
        base_domain = normalize_base_domain(domain)
    else:
        base_domain = prompt_for_base_domain()
    total = seed_all([base_domain])
    logger.info("Scan: %d new domains for %s", total, base_domain)
    exposed = probe_all_nonprod(force=force_probe)
    logger.info("Probe: %d EXPOSED", exposed)
    generate_exposed_csv(base_domain)
    generate_full_nonprod_csv(base_domain)
    print_summary()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generic Certificate Transparency Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # bootstrap
    p_boot = sub.add_parser("bootstrap", help="Init DB, register CT logs, optionally import domains file")
    p_boot.add_argument("domains_file", nargs="?", help="Path to existing domains .txt file")

    # scan
    p_scan = sub.add_parser("scan", help="Query all CT/passive sources for a domain")
    p_scan.add_argument("domain", nargs="?", help="Base domain to scan, example: example.com")

    # probe
    p_probe = sub.add_parser("probe", help="Probe non-prod domains for internet exposure")
    p_probe.add_argument("--force", action="store_true", help="Re-probe even recently checked domains")

    # report
    p_report = sub.add_parser("report", help="Generate CSV reports")
    p_report.add_argument("domain", nargs="?", help="Optional base domain used in output filenames")

    # status
    sub.add_parser("status", help="Show current DB summary")

    # run
    p_run = sub.add_parser("run", help="Full pipeline: scan + probe + report")
    p_run.add_argument("--force-probe", action="store_true")
    p_run.add_argument("domain", nargs="?", help="Base domain to scan, example: example.com")

    # seed
    p_seed = sub.add_parser(
        "seed",
        help="One-time historical backfill from multiple CT/passive sources for all configured scope domains or specific domains"
    )
    p_seed.add_argument(
        "domains", nargs="*",
        help="Specific base domains to seed, example: sprint.com mingeneric.com. "
             "Omit to seed all configured scope domains."
    )

    # seed-domain
    p_seed_domain = sub.add_parser(
        "seed-domain",
        help="Prompt for a base domain, then pull all historical certificate names from multiple CT/passive sources"
    )
    p_seed_domain.add_argument(
        "domain", nargs="?",
        help="Base domain to seed, example: example.com. Omit to be prompted."
    )

    # export-domains
    sub.add_parser("export-domains", help="Export non-prod domain list for off-band laptop")

    # import-results
    p_import = sub.add_parser("import-results", help="Merge probe results from off-band laptop CSV")
    p_import.add_argument("csv_path", help="Path to probe results CSV from off-band laptop")

    args = parser.parse_args()

    if args.command == "bootstrap":
        cmd_bootstrap(args.domains_file)
    elif args.command == "scan":
        cmd_scan(args.domain)
    elif args.command == "probe":
        cmd_probe(force=args.force)
    elif args.command == "report":
        cmd_report(args.domain)
    elif args.command == "status":
        cmd_status()
    elif args.command == "run":
        cmd_run(force_probe=args.force_probe, domain=args.domain)
    elif args.command == "seed":
        cmd_seed(args.domains or None)
    elif args.command == "seed-domain":
        cmd_seed_domain(args.domain)
    elif args.command == "export-domains":
        cmd_export_domains()
    elif args.command == "import-results":
        cmd_import_results(args.csv_path)


if __name__ == "__main__":
    main()
