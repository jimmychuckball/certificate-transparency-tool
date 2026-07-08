"""
Multi-source certificate transparency and passive DNS collector.

This module intentionally keeps the old public function names used by main.py:
- fetch_active_logs()
- poll_all_logs()
- get_all_certificates()

seed-domain and seed use get_all_certificates() through poller.seeder.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import re
from typing import Callable, Iterable

import requests

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 25
MAX_WORKERS = 8

HEADERS = {
    "User-Agent": "GenericDomainCertFinder/3.0"
}

_DOMAIN_RE_TEMPLATE = r"(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+{domain}"


def normalize_domain(value: str) -> str:
    value = (value or "").strip().lower()
    value = value.strip(" ,;:'\"()[]{}<>")
    value = value.removeprefix("*.").strip(".")
    return value


def in_scope(candidate: str, base_domain: str) -> bool:
    candidate = normalize_domain(candidate)
    base_domain = normalize_domain(base_domain)
    return candidate == base_domain or candidate.endswith("." + base_domain)


def add_if_match(base_domain: str, candidate: str, discovered: set[str]) -> None:
    candidate = normalize_domain(candidate)
    if candidate and in_scope(candidate, base_domain):
        discovered.add(candidate)


def extract_domains_from_text(base_domain: str, text: str) -> set[str]:
    discovered: set[str] = set()
    pattern = re.compile(
        _DOMAIN_RE_TEMPLATE.format(domain=re.escape(base_domain)),
        re.IGNORECASE,
    )
    for match in pattern.findall(text or ""):
        add_if_match(base_domain, match, discovered)
    return discovered


def _get_json(url: str) -> object | None:
    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            logger.warning("HTTP %s from %s", resp.status_code, url.split("?")[0])
            return None
        return resp.json()
    except Exception as exc:
        logger.warning("JSON source failed %s: %s", url.split("?")[0], exc)
        return None


def _get_text(url: str) -> str:
    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            logger.warning("HTTP %s from %s", resp.status_code, url.split("?")[0])
            return ""
        return resp.text
    except Exception as exc:
        logger.warning("Text source failed %s: %s", url.split("?")[0], exc)
        return ""


def fetch_crtsh(base_domain: str) -> set[str]:
    discovered: set[str] = set()
    url = f"https://crt.sh/?q=%25.{base_domain}&output=json"
    data = _get_json(url)
    if not isinstance(data, list):
        return discovered

    for row in data:
        if not isinstance(row, dict):
            continue
        for field in ("name_value", "common_name"):
            value = row.get(field) or ""
            for item in str(value).splitlines():
                add_if_match(base_domain, item, discovered)

    return discovered


def fetch_certspotter(base_domain: str) -> set[str]:
    discovered: set[str] = set()
    url = (
        "https://api.certspotter.com/v1/issuances"
        f"?domain={base_domain}&include_subdomains=true&expand=dns_names"
    )
    data = _get_json(url)
    if not isinstance(data, list):
        return discovered

    for row in data:
        if not isinstance(row, dict):
            continue
        for name in row.get("dns_names", []) or []:
            add_if_match(base_domain, name, discovered)

    return discovered


def fetch_google_transparency(base_domain: str) -> set[str]:
    url = (
        "https://transparencyreport.google.com/transparencyreport/"
        "api/v3/httpsreport/ct/certsearch"
        f"?include_expired=true&include_subdomains=true&domain={base_domain}"
    )
    return extract_domains_from_text(base_domain, _get_text(url))


def fetch_cloudflare_radar(base_domain: str) -> set[str]:
    # Cloudflare does not expose a simple unauthenticated CT JSON API here,
    # so this scrapes public Radar page content as a best-effort source.
    url = f"https://radar.cloudflare.com/domains/domain/{base_domain}"
    return extract_domains_from_text(base_domain, _get_text(url))


def fetch_facebook_ct(base_domain: str) -> set[str]:
    url = f"https://developers.facebook.com/tools/ct/search/?query={base_domain}"
    return extract_domains_from_text(base_domain, _get_text(url))


def fetch_alienvault_otx(base_domain: str) -> set[str]:
    discovered: set[str] = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{base_domain}/passive_dns"
    data = _get_json(url)
    if not isinstance(data, dict):
        return discovered

    for row in data.get("passive_dns", []) or []:
        if isinstance(row, dict):
            add_if_match(base_domain, row.get("hostname", ""), discovered)

    return discovered


def fetch_hackertarget(base_domain: str) -> set[str]:
    discovered: set[str] = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={base_domain}"
    text = _get_text(url)
    for line in text.splitlines():
        host = line.split(",", 1)[0].strip()
        add_if_match(base_domain, host, discovered)
    return discovered


SOURCES: list[tuple[str, Callable[[str], set[str]]]] = [
    ("crt.sh", fetch_crtsh),
    ("CertSpotter", fetch_certspotter),
    ("Google Transparency Report", fetch_google_transparency),
    ("Cloudflare Radar", fetch_cloudflare_radar),
    ("Facebook CT Search", fetch_facebook_ct),
    ("AlienVault OTX Passive DNS", fetch_alienvault_otx),
    ("HackerTarget Passive DNS", fetch_hackertarget),
]


def get_all_certificates(base_domain: str) -> list[str]:
    """
    Query every configured source in parallel and return a deduplicated list
    of discovered in-scope domains.
    """
    base_domain = normalize_domain(base_domain)
    logger.info("[%s] Querying %d CT/passive sources...", base_domain, len(SOURCES))
    print(f"[+] Querying {len(SOURCES)} CT/passive sources for {base_domain}")

    all_domains: set[str] = set()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_name = {
            executor.submit(func, base_domain): name
            for name, func in SOURCES
        }

        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results = future.result() or set()
                logger.info("[%s] %s returned %d domains", base_domain, name, len(results))
                print(f"[+] {name}: {len(results)} domains")
                all_domains.update(results)
            except Exception as exc:
                logger.warning("[%s] %s failed: %s", base_domain, name, exc)
                print(f"[!] {name} failed: {exc}")

    logger.info("[%s] Total unique domains from all sources: %d", base_domain, len(all_domains))
    print(f"[+] Total unique domains discovered: {len(all_domains)}")
    return sorted(all_domains)


def fetch_active_logs():
    """
    Compatibility function for bootstrap. Returns metadata-like provider objects.
    These are not raw CT log endpoints anymore, but keeping this prevents old
    workflows from crashing.
    """
    return [{"name": name, "url": f"multisource://{name.lower().replace(' ', '_')}"} for name, _ in SOURCES]


def poll_all_logs(domain: str | None = None):
    """
    Compatibility function for scan/run. This codebase's historical scanner was
    log-position based. For the generic tool, use seed-domain for selected-domain
    collection. If a domain is supplied, return discovered count tuple.
    """
    if not domain:
        logger.info("poll_all_logs called without domain; no selected-domain scan performed")
        return 0, 0

    domains = get_all_certificates(domain)
    return len(domains), len(domains)


# Compatibility aliases used by earlier versions.
query_crtsh = get_all_certificates
fetch_all_certificates = get_all_certificates
