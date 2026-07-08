# Generic Domain Certificate Finder — Certificate Monitor

An security tool that discovers subdomains for a given base domain from public Certificate Transparency (CT) logs and passive DNS sources, classifies them by environment, and probes non-production domains to see whether they're reachable from the public internet.

The goal is to make it easy to find non-prod domains (dev, staging, QA, NPE, etc.) that should be behind VPN/zero-trust but are currently reachable externally — and to keep that list updated.

---

## Why This Exists

Public CT logs record every SSL/TLS certificate issued by trusted CAs, so every subdomain a certificate is issued for is publicly discoverable — including internal, non-production, and infrastructure hostnames.

This tool:

- Queries multiple CT/passive-DNS sources for a domain and merges the results into one deduplicated list
- Classifies each discovered domain as production or non-production (dev, staging, QA, NPE, UAT, etc.)
- Probes non-production domains to determine if they're reachable from the public internet
- Generates CSV/TXT reports for remediation — moving exposed non-prod domains behind VPN/zero-trust

It does **not** depend solely on [crt.sh](https://crt.sh) — it queries seven sources in parallel, so it keeps working when any single source is down or rate-limited.

---

## Domain Scope

`DOMAIN_SCOPE` in `config.py` lists the base domains considered "in scope" when importing a domain file via `bootstrap` (subdomains outside this list are skipped on import). It ships with a single placeholder entry:

```python
DOMAIN_SCOPE = [
    "generic.com",
]
```

Edit this list to add your own domains/brands. Note that `scan`, `seed-domain`, and `seed <domains...>` accept a domain directly on the command line and aren't restricted to `DOMAIN_SCOPE` — that list only matters for `bootstrap`'s file import and for the no-argument form of `seed`.

---

## How It Works

```
main.py <command>
  └─ poller/ct_client.py      Queries 7 CT/passive-DNS sources in parallel for one base domain
      └─ poller/seeder.py         Merges + dedupes results, writes a TXT export
          └─ filter/classifier.py     Classifies each domain: production vs non-prod
              └─ storage/database.py     Upserts into SQLite (generic_certs.db)
                  └─ probe/checker.py        DNS-resolves + HTTP(S) reachability check
                      └─ reports/generator.py    CSV/TXT reports to reports_output/
```

`scan`, `seed-domain`, and `seed` all re-query every source on each run (there's no incremental/position tracking) — duplicate results are simply ignored on upsert, so re-running is always safe.

---

## Project Structure

```
cert-monitor/
├── config.py              Domain scope, environment rules, probe/network settings
├── main.py                CLI entry point
├── run.bat                Windows interactive menu launcher
├── setup.bat              First-time setup (installs dependencies)
├── requirements.txt       Python dependencies
│
├── poller/
│   ├── ct_client.py       Queries CT/passive-DNS sources in parallel, merges results
│   ├── seeder.py          Orchestrates scope filtering, classification, DB upsert, TXT export
│   └── cert_parser.py     X.509/CT-log leaf entry decoder (not called by the current pipeline)
│
├── filter/
│   └── classifier.py      Regex-based prod vs non-prod classification
│
├── storage/
│   └── database.py        SQLite schema + queries (generic_certs.db)
│
├── probe/
│   └── checker.py         DNS resolution + HTTP(S) reachability checks
│
└── reports/
    └── generator.py       CSV/TXT report generation to reports_output/
```

---

## Requirements

- Python 3.9 or higher
- Windows (tested), should also run on macOS/Linux
- Internet access to reach the CT/passive-DNS source endpoints

---

## Setup

### First time on a new machine

1. Install Python 3.9+ from [python.org](https://www.python.org/downloads/) — tick **"Add Python to PATH"** during install
2. Clone or copy this repository
3. Double-click `setup.bat` — this installs all dependencies automatically

Or from a terminal:

```cmd
cd cert-monitor
pip install -r requirements.txt
```

### Initialize the database

```cmd
python main.py bootstrap [path\to\domains.txt]
```

Creates the SQLite database and tables. If a domains file is given (one domain per line), each entry is classified and imported, provided it matches (or is a subdomain of) something in `DOMAIN_SCOPE`. The argument is optional — omit it to start with an empty database and fill it in via `scan`/`seed`/`seed-domain`.

---

## Usage

### Windows menu launcher

Double-click `run.bat`. It first asks for a target domain, then shows a menu to find certificates, probe, report, run the full workflow, or check status for that domain.

### Command line

| Command | Description |
|---|---|
| `python main.py bootstrap [file]` | Initialize the DB, optionally import a domain list file |
| `python main.py scan [domain]` | Query all sources for one domain (prompts if omitted) |
| `python main.py seed-domain [domain]` | Same as `scan` — query all sources for one domain (prompts if omitted) |
| `python main.py seed [domains...]` | Query all sources for a list of domains, or every domain in `DOMAIN_SCOPE` if none given |
| `python main.py probe` | Check non-prod domains for internet exposure |
| `python main.py probe --force` | Re-probe all non-prod domains, ignoring the 24h cooldown |
| `python main.py report [domain]` | Generate CSV reports; `domain` is only used to prefix output filenames |
| `python main.py status` | Print a DB summary to the console |
| `python main.py run [domain]` | Full pipeline for one domain: query sources → probe → report |
| `python main.py run --force-probe [domain]` | Same, but ignores the probe cooldown |
| `python main.py export-domains` | Export non-prod domains to CSV for an off-band laptop |
| `python main.py import-results <file.csv>` | Merge off-band probe results back into the DB |

`scan`, `seed-domain`, and `run` all prompt interactively for a base domain (e.g. `example.com`) if you don't pass one on the command line.

---

## Two-Laptop Workflow (Recommended)

Running the probe from an **off-band laptop** (one not on your corporate network) gives the true external-attacker view of what's reachable. Probing from inside the corporate network can make internal-only domains look externally reachable, or mask NAT/firewall boundaries that would otherwise block them.

```
CORPORATE LAPTOP                        OFF-BAND LAPTOP
─────────────────────────────           ─────────────────────────────
1. python main.py seed-domain example.com
   (queries all sources, stores discovered domains)

2. python main.py export-domains
   → reports_output\offband_domains_*.csv

          ── copy file via USB or email ──►

                                        3. setup.bat  (first time only)

                                        4. python main.py bootstrap offband_domains_*.csv

                                        5. python main.py probe
                                           → reports_output\probe_results_*.csv

          ◄── copy file back ────────────

6. python main.py import-results probe_results_*.csv

7. python main.py report example.com
```

---

## Probe Status Reference

| Status | Meaning | Action |
|---|---|---|
| `EXPOSED` | Resolves to a public IP and responds over HTTP/S | **Needs remediation — move behind VPN/zero-trust** |
| `DNS_ONLY` | Resolves to a public IP but no HTTP response | Review — DNS record exists externally, service may be intermittent |
| `PRIVATE` | Resolves only to an RFC1918 or other non-routable range (e.g. CGNAT 100.64.0.0/10) | Already behind a network boundary — OK |
| `DEAD` | No DNS record found | Domain is not resolving — likely already decommissioned |
| `SKIPPED` | Wildcard domain (`*.example.com`) | Cannot probe directly — review manually |
| `UNKNOWN` | Not yet probed | Run `python main.py probe` |

Public DNS resolution uses `8.8.8.8` / `1.1.1.1` (`DNS_SERVERS` in `config.py`) so results reflect what the internet sees, not internal split-horizon DNS.

---

## Environment Classification

`filter/classifier.py` evaluates `ENV_RULES` from `config.py` in order and returns the first match; anything unmatched is classified `production`.

| Priority | Class | Patterns detected |
|---|---|---|
| 1 | `sandbox` | `sandbox` |
| 2 | `preprod` | `preprod`, `.pp.` (as a standalone label) |
| 3 | `training` | `training` |
| 4 | `uat` | `uat` |
| 5 | `qat` | `qat` (as a standalone label) |
| 6 | `perf` | `perf`, `plb`, `plab`, `prf` (as a standalone label) |
| 7 | `load` | `load` (as a standalone label) |
| 8 | `npe` | `npe` |
| 9 | `staging` | `stg`, `stage`, `staging` |
| 10 | `qlab` | `qlab` |
| 11 | `dev` | `dev` (as a standalone label) |
| 12 | `lab` | `lab` (as a standalone label) |
| 13 | `test` | `test`, `tst` (as a standalone label) |
| 14 | `beta` | `beta`, `alpha`, `preview` (as a standalone label) |
| — | `production` | anything not matching the above |

To add or adjust rules, edit `ENV_RULES` in `config.py` — order matters, since the first matching rule wins.

---

## Data Sources

`poller/ct_client.py` queries these sources in parallel for every `scan` / `seed` / `seed-domain` run:

- crt.sh
- CertSpotter
- Google Transparency Report
- Cloudflare Radar
- Facebook CT Search
- AlienVault OTX (passive DNS)
- HackerTarget (passive DNS)

Results from all sources are merged and deduplicated before classification and storage. If a source is unreachable or rate-limited, it's skipped (logged as a warning) and the run continues with whatever the other sources returned.

---

## Output Files

All reports are written to `reports_output\` (created automatically):

| File | Contents |
|---|---|
| `{domain}_all_domains.txt` | All domains discovered for `{domain}` across every source, deduplicated |
| `{domain}_exposed_nonprod_YYYYMMDD_HHMMSS.csv` | Non-prod domains with `EXPOSED` probe status |
| `{domain}_all_nonprod_YYYYMMDD_HHMMSS.csv` | All non-prod domains with probe status and cert metadata |
| `offband_domains_YYYYMMDD_HHMMSS.csv` | Export for bootstrapping the off-band laptop |
| `probe_results_YYYYMMDD_HHMMSS.csv` | Probe results for merging back into the corporate machine |

The `{domain}_` prefix is only added when a domain is passed to `report`/`run` (or implicitly via `seed-domain`/`scan`); `export-domains` and `import-results` files are not domain-prefixed.

The SQLite database lives at `generic_certs.db`, and logs are written to `cert_monitor.log`, both in the project directory.

---

## Notes

- `poller/cert_parser.py` decodes raw RFC 6962 CT log leaf entries (X.509/precert parsing) but isn't called anywhere in the current pipeline — `ct_client.py` queries source APIs over plain HTTP/JSON instead. It's kept for reference / potential future use.
- The `ct_logs` table and `bootstrap`'s log-registration step are vestigial holdovers from an earlier log-position-tracking design; they don't affect `scan`/`seed`/`seed-domain`, which always re-query every source fresh.
