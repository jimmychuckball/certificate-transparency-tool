import sqlite3
import logging
from datetime import datetime, timezone
from contextlib import contextmanager
from config import DB_PATH
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



logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS ct_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    url         TEXT    NOT NULL UNIQUE,
    last_index  INTEGER DEFAULT 0,
    last_checked TEXT,
    is_active   INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS domains (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    domain        TEXT    NOT NULL UNIQUE,
    env_class     TEXT,
    first_seen    TEXT    NOT NULL,
    last_seen     TEXT    NOT NULL,
    cert_cn       TEXT,
    cert_issuer   TEXT,
    cert_not_after TEXT,
    cert_sha256   TEXT,
    log_source    TEXT,
    probe_status  TEXT    DEFAULT 'UNKNOWN',
    probe_ip      TEXT,
    last_probed   TEXT
);

CREATE TABLE IF NOT EXISTS scan_history (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type        TEXT NOT NULL,
    started_at       TEXT NOT NULL,
    completed_at     TEXT,
    domains_found    INTEGER DEFAULT 0,
    newly_exposed    INTEGER DEFAULT 0,
    notes            TEXT
);

CREATE INDEX IF NOT EXISTS idx_domains_env     ON domains(env_class);
CREATE INDEX IF NOT EXISTS idx_domains_probe   ON domains(probe_status);
CREATE INDEX IF NOT EXISTS idx_domains_domain  ON domains(domain);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)
    logger.info(f"Database initialised at {DB_PATH}")


# ---------------------------------------------------------------------------
# CT log table
# ---------------------------------------------------------------------------

def upsert_log(name, url):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO ct_logs (name, url) VALUES (?, ?) "
            "ON CONFLICT(url) DO UPDATE SET name=excluded.name, is_active=1",
            (name, url),
        )


def get_log_position(url):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT last_index FROM ct_logs WHERE url=?", (url,)
        ).fetchone()
        return row["last_index"] if row else 0


def update_log_position(url, index):
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.execute(
            "UPDATE ct_logs SET last_index=?, last_checked=? WHERE url=?",
            (index, now, url),
        )


def get_all_logs():
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM ct_logs WHERE is_active=1"
        ).fetchall()]


# ---------------------------------------------------------------------------
# Domain table
# ---------------------------------------------------------------------------

def upsert_domain(domain, env_class, cert_cn, cert_issuer,
                  cert_not_after, cert_sha256, log_source):
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM domains WHERE domain=?", (domain,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE domains SET last_seen=?, env_class=?, cert_cn=?, "
                "cert_issuer=?, cert_not_after=?, cert_sha256=?, log_source=? "
                "WHERE domain=?",
                (now, env_class, cert_cn, cert_issuer,
                 cert_not_after, cert_sha256, log_source, domain),
            )
            return False  # not new
        else:
            conn.execute(
                "INSERT INTO domains "
                "(domain, env_class, first_seen, last_seen, cert_cn, cert_issuer, "
                "cert_not_after, cert_sha256, log_source) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (domain, env_class, now, now, cert_cn, cert_issuer,
                 cert_not_after, cert_sha256, log_source),
            )
            return True  # new


def update_probe(domain, status, ip=None):
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.execute(
            "UPDATE domains SET probe_status=?, probe_ip=?, last_probed=? WHERE domain=?",
            (status, ip, now, domain),
        )


def get_nonprod_domains():
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM domains WHERE env_class != 'production' "
            "AND env_class IS NOT NULL "
            "ORDER BY env_class, domain"
        ).fetchall()]


def get_exposed_nonprod():
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM domains "
            "WHERE env_class != 'production' AND env_class IS NOT NULL "
            "AND probe_status = 'EXPOSED' "
            "ORDER BY env_class, domain"
        ).fetchall()]


def get_stats():
    with get_conn() as conn:
        total       = conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
        by_env      = conn.execute(
            "SELECT env_class, COUNT(*) as cnt FROM domains GROUP BY env_class ORDER BY cnt DESC"
        ).fetchall()
        by_probe    = conn.execute(
            "SELECT probe_status, COUNT(*) as cnt FROM domains "
            "WHERE env_class != 'production' GROUP BY probe_status"
        ).fetchall()
        exposed     = conn.execute(
            "SELECT COUNT(*) FROM domains WHERE env_class != 'production' AND probe_status='EXPOSED'"
        ).fetchone()[0]
    return {
        "total": total,
        "by_env": [dict(r) for r in by_env],
        "by_probe": [dict(r) for r in by_probe],
        "exposed_nonprod": exposed,
    }


# ---------------------------------------------------------------------------
# Scan history
# ---------------------------------------------------------------------------

def start_scan(scan_type):
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scan_history (scan_type, started_at) VALUES (?, ?)",
            (scan_type, now),
        )
        return cur.lastrowid


def finish_scan(scan_id, domains_found=0, newly_exposed=0, notes=""):
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.execute(
            "UPDATE scan_history SET completed_at=?, domains_found=?, "
            "newly_exposed=?, notes=? WHERE id=?",
            (now, domains_found, newly_exposed, notes, scan_id),
        )
