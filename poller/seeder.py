"""
One-time historical seeding from multiple CT and passive DNS sources.

This replaces crt.sh-only seeding.
"""

from __future__ import annotations

import logging
from pathlib import Path
import re

from config import DOMAIN_SCOPE
from filter.classifier import classify
from storage.database import upsert_domain
from poller.ct_client import get_all_certificates, in_scope, normalize_domain

logger = logging.getLogger(__name__)


def sanitize_filename(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name)


def export_domains_txt(domains, target_domain):
    reports_dir = Path("reports_output")
    reports_dir.mkdir(exist_ok=True)

    safe_name = sanitize_filename(target_domain)
    txt_path = reports_dir / f"{safe_name}_all_domains.txt"

    unique_domains = sorted(set(normalize_domain(d) for d in domains if d))

    with open(txt_path, "w", encoding="utf-8") as f:
        for domain in unique_domains:
            f.write(domain + "\n")

    logger.info("[%s] TXT export -> %s (%d domains)", target_domain, txt_path, len(unique_domains))
    print(f"[+] Exported {len(unique_domains)} domains to {txt_path}")
    return txt_path, len(unique_domains)


def seed_domain(base_domain, session=None):
    """
    Query all configured sources for one base domain and upsert discovered names.
    Returns (new_domains, total_seen).
    """
    base_domain = normalize_domain(base_domain)
    logger.info("[%s] Querying all CT/passive sources...", base_domain)

    discovered = get_all_certificates(base_domain)

    if not discovered:
        logger.info("[%s] No domains found from configured sources", base_domain)
        export_domains_txt([], base_domain)
        return 0, 0

    new_count = 0
    seen = set()

    for domain in discovered:
        domain = normalize_domain(domain)
        if not domain or domain in seen:
            continue
        if not in_scope(domain, base_domain):
            continue

        seen.add(domain)

        is_new = upsert_domain(
            domain=domain,
            env_class=classify(domain),
            cert_cn="",
            cert_issuer="",
            cert_not_after=None,
            cert_sha256="",
            log_source="multi_source_ct",
        )

        if is_new:
            new_count += 1
            logger.info("  NEW [%s] %s", classify(domain), domain)

    export_domains_txt(seen, base_domain)

    logger.info("[%s] Done -- %d new domains (%d unique seen)", base_domain, new_count, len(seen))
    return new_count, len(seen)


def seed_all(domains=None):
    targets = domains if domains else DOMAIN_SCOPE

    total_new = 0
    for base_domain in targets:
        new, seen = seed_domain(base_domain)
        total_new += new

    logger.info("Seeding complete -- %d total new domains added", total_new)
    return total_new
