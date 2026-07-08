import base64
import struct
import logging
from datetime import timezone
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



from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ExtensionOID

logger = logging.getLogger(__name__)


def _load_cert(der_bytes):
    try:
        return x509.load_der_x509_certificate(der_bytes, default_backend())
    except Exception:
        return None


def parse_entry(leaf_input_b64, extra_data_b64):
    """
    Decode a CT log entry into a dict with cert metadata.

    Handles both x509_entry (type 0) and precert_entry (type 1).
    Returns None if the entry cannot be parsed.
    """
    try:
        leaf = base64.b64decode(leaf_input_b64)
    except Exception:
        return None

    # MerkleTreeLeaf layout:
    #   version(1) + leaf_type(1) + timestamp(8) + entry_type(2) = 12 bytes header
    if len(leaf) < 12:
        return None

    entry_type = struct.unpack(">H", leaf[10:12])[0]
    pos = 12
    cert = None

    try:
        if entry_type == 0:  # x509_entry: cert is directly in leaf_input
            cert_len = struct.unpack(">I", b"\x00" + leaf[pos:pos + 3])[0]
            pos += 3
            cert = _load_cert(leaf[pos: pos + cert_len])

        elif entry_type == 1:  # precert_entry: full pre-cert lives in extra_data
            extra = base64.b64decode(extra_data_b64)
            # PrecertChainEntry: pre_certificate (3-byte len prefix) + chain
            pre_len = struct.unpack(">I", b"\x00" + extra[0:3])[0]
            cert = _load_cert(extra[3: 3 + pre_len])

    except Exception as exc:
        logger.debug("Entry parse error: %s", exc)
        return None

    if cert is None:
        return None

    return _extract(cert)


def _extract(cert):
    domains = set()

    # Common Name
    try:
        cn_list = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_list:
            domains.add(cn_list[0].value.lower().strip())
    except Exception:
        pass

    # Subject Alternative Names
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san.value.get_values_for_type(x509.DNSName):
            if name:
                domains.add(name.lower().strip())
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass

    # Issuer CN
    try:
        iss = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer = iss[0].value if iss else "Unknown"
    except Exception:
        issuer = "Unknown"

    # SHA-256 fingerprint
    try:
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    except Exception:
        fingerprint = ""

    # Validity period — handle both old (naive) and new (aware) cryptography versions
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:
        try:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        except Exception:
            not_after = None

    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = ""

    return {
        "domains": domains,
        "cn": cn,
        "issuer": issuer,
        "fingerprint": fingerprint,
        "not_after": not_after.isoformat() if not_after else None,
    }
