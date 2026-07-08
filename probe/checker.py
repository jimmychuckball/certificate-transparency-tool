import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
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



import dns.resolver
import requests
import urllib3

from config import DNS_SERVERS, PROBE_DNS_TIMEOUT, PROBE_HTTP_TIMEOUT, PROBE_MAX_WORKERS
from storage.database import get_nonprod_domains, update_probe

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


# Non-routable ranges beyond the standard RFC1918/loopback checks
_INTERNAL_NETS = [
    ipaddress.ip_network("100.64.0.0/10"),   # RFC 6598 - CGNAT / Generic internal
    ipaddress.ip_network("192.0.0.0/24"),    # RFC 6890 - IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),   # RFC 2544 - benchmarking
    ipaddress.ip_network("198.51.100.0/24"), # RFC 5737 - documentation
    ipaddress.ip_network("203.0.113.0/24"),  # RFC 5737 - documentation
    ipaddress.ip_network("240.0.0.0/4"),     # RFC 1112 - reserved
]


def _is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
        for net in _INTERNAL_NETS:
            if ip in net:
                return False
        return True
    except ValueError:
        return False


def _resolve(domain):
    """Resolve domain using public DNS. Returns list of IP strings."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = DNS_SERVERS
    resolver.timeout = PROBE_DNS_TIMEOUT
    resolver.lifetime = PROBE_DNS_TIMEOUT
    try:
        answers = resolver.resolve(domain, "A")
        return [str(r) for r in answers]
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except Exception:
        return []


def _http_reachable(domain):
    """Return True if the domain responds to HTTPS or HTTP."""
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}",
                timeout=PROBE_HTTP_TIMEOUT,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "generic-cert-monitor/1.0"},
            )
            if resp.status_code < 600:
                return True
        except Exception:
            pass
    return False


def probe_domain(domain):
    """
    Probe a single domain.

    Status values:
      EXPOSED   — resolves to a public IP AND responds over HTTP/S
      DNS_ONLY  — resolves to a public IP but no HTTP response
      PRIVATE   — resolves, but only to private/RFC1918 addresses
      DEAD      — no DNS resolution
      SKIPPED   — wildcard or otherwise un-probeable
    """
    if domain.startswith("*"):
        return "SKIPPED", None

    ips = _resolve(domain)
    if not ips:
        return "DEAD", None

    public_ips = [ip for ip in ips if _is_public_ip(ip)]

    if not public_ips:
        return "PRIVATE", ips[0]

    if _http_reachable(domain):
        return "EXPOSED", public_ips[0]

    return "DNS_ONLY", public_ips[0]


def probe_all_nonprod(force=False):
    """
    Probe every non-prod domain in the DB.
    If force=False, skip domains probed in the last 24 hours.
    Returns count of EXPOSED domains found.
    """
    from datetime import datetime, timezone, timedelta

    domains = get_nonprod_domains()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

    to_probe = []
    for row in domains:
        if not force and row.get("last_probed") and row["last_probed"] > cutoff:
            continue
        to_probe.append(row["domain"])

    logger.info("Probing %d non-prod domains...", len(to_probe))
    exposed = 0

    def _probe_and_save(domain):
        status, ip = probe_domain(domain)
        update_probe(domain, status, ip)
        return domain, status, ip

    with ThreadPoolExecutor(max_workers=PROBE_MAX_WORKERS) as pool:
        futures = {pool.submit(_probe_and_save, d): d for d in to_probe}
        for future in as_completed(futures):
            try:
                domain, status, ip = future.result()
                if status == "EXPOSED":
                    logger.warning("EXPOSED: %s (%s)", domain, ip)
                    exposed += 1
                else:
                    logger.debug("%s → %s", domain, status)
            except Exception as exc:
                logger.error("Probe error for %s: %s", futures[future], exc)

    logger.info("Probe complete — %d EXPOSED", exposed)
    return exposed
