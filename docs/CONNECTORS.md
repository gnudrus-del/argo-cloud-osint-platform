# Connectors

Argo registers 63 connectors by default: 46 key-free + 17 BYOK. A 64th
connector (`flowsint`) ships in the codebase but is **not registered** unless
`FLOWSINT_ENABLE=1` — see the note at the end of the key-free table.

Counts are derived from the live registry
(`build_default_registry().catalog()` in `osint_bot/connectors/__init__.py`),
not hand-counted — see `docs/CONTRIBUTING_MODULES.md` step 5 for keeping this
file in sync when a connector is added or removed.

## Key-free (46)

Work out of the box, no signup, no API key.

| Category | Connectors |
| --- | --- |
| DNS / certs | crt.sh, RDAP, DNS query, TLS cert, Wayback CDX, email security posture (SPF/DMARC/MTA-STS/DNSSEC) |
| Web fingerprint | Web fingerprint, Common Crawl, URL harvest, urlscan.io |
| Threat intel | PhishTank, OpenPhish, ThreatFox, Shodan InternetDB, Hudson Rock Cavalier (infostealer breach corpus) |
| Cloud exposure | Cloud bucket enumeration (S3/GCS/Azure — active, gated) |
| Geo / civic | Nominatim (OSM), Overpass (OSM), GDELT |
| Email OSINT | holehe (native + wrapper), Gravatar, Ignorant, EmailRep |
| IP / network | IPinfo |
| Username OSINT | Sherlock-lite, Maigret |
| Corporate | SEC Edgar, OpenCorporates |
| Recon (active, gated) | Content discovery, Port scan, Subdomain enum, DNStwist |
| Secrets scan | Secret scan (public repos) |
| Domain OSINT | theHarvester |
| Phone OSINT | phone_meta, phone_footprint |
| Social reverse | GHunt (Google), Toutatis (Instagram), socid-extractor, LinkedIn2Username, Telegram checker |
| Darkweb | Ahmia index |
| Threat intel bridge | MISP (`MISP_URL`/`MISP_KEY` are operator-configured env vars, not a BYOK-panel key — see below) |
| Aggregator | legit_scorer (native SION-like) |
| ASN | ASN lookup |

Some active-recon connectors (port scan, content discovery) require an in-scope case and produce audit events.

`emailrep`, `ipinfo` and `opencorporates` work key-free but also accept an
optional key for richer output — they're counted once here and listed again
under BYOK below.

**Not counted above — registers only when explicitly enabled**: `flowsint`,
an optional bridge to a separately-run FlowSINT stack
(`FLOWSINT_ENABLE=1` + `FLOWSINT_URL`/`FLOWSINT_USER`/`FLOWSINT_PASSWORD`).

MISP is grouped with the key-free connectors, not BYOK, because its
credentials (`MISP_URL`, `MISP_KEY`) are read from environment variables for
an operator-run instance rather than entered per-analyst in the BYOK key
panel — see `osint_bot/connectors/misp_client.py`.

**Maigret and Toutatis are "key-free" in the sense that neither needs a paid
API key or a BYOK-panel entry — but neither works purely out of the box
either**, unlike the rest of this table. Both require a one-time *server*
setup, done by whoever operates the instance, not by an individual analyst:

- **Maigret** needs `MAIGRET_PYTHON` (path to a Python venv with the
  `maigret` package installed) or `MAIGRET_CMD` (path to the `maigret`
  executable) set in the server's `.env`. Without it, every search returns
  `status="missing_key"` for this connector, indefinitely — `sherlock_lite`
  (genuinely zero-setup) is the fallback for username searches until it's
  configured. See `osint_bot/connectors/maigret.py`.
- **Toutatis** needs `TOUTATIS_SESSION` (an Instagram session cookie
  belonging to the operator's own account, used to query profile data) set
  in the server's `.env`. Same `missing_key` behaviour without it. See
  `osint_bot/connectors/toutatis.py`.

If you're evaluating Argo's out-of-the-box username/social coverage, the
connectors that genuinely need zero setup are `sherlock_lite` and (for a
person's name rather than a handle) `gdelt`/`wikipedia_search` — everything
else in the username/social-reverse rows above is either BYOK or needs this
kind of server-side configuration first.

## BYOK (17)

Optional. Fill only what you have; missing keys are silently skipped.

| Provider | Env var | Purpose |
| --- | --- | --- |
| Shodan | `SHODAN_API_KEY` | Passive host / service intelligence |
| VirusTotal | `VIRUSTOTAL_API_KEY` | File / URL / domain / IP intelligence |
| HIBP | `HIBP_API_KEY` | Breach exposure lookup |
| Hunter.io | `HUNTER_API_KEY` | Email finder / verifier |
| SecurityTrails | `SECURITYTRAILS_API_KEY` | Historical DNS |
| GreyNoise | `GREYNOISE_API_KEY` | Internet background noise labels |
| AlienVault OTX | `OTX_API_KEY` | Threat pulses |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IP abuse-report reputation |
| GitHub code search | `GITHUB_TOKEN` | Secret/credential leak search across public repos |
| LeakIX | `LEAKIX_API_KEY` | Exposed-service / leak search engine |
| Etherscan | `ETHERSCAN_API_KEY` | Ethereum blockchain queries |
| Companies House | `COMPANIES_HOUSE_API_KEY` | UK company registry |
| Brave Search | `BRAVE_SEARCH_API_KEY` | Web search API |
| Google PSE | `GOOGLE_PSE_API_KEY` | Programmable search engine |
| Influencers Club | `INFLUENCERS_CLUB_API_KEY` | Username → verified email |
| ContactOut | `CONTACTOUT_API_KEY` | LinkedIn/email → personal email/phone |
| Lusha | `LUSHA_API_KEY` | LinkedIn/email → professional email/phone |

## Anatomy of a connector

Every connector inherits from `BaseConnector` and exposes a `ConnectorSpec` metadata block:

```python
_SPEC = ConnectorSpec(
    name="example",
    label="Example — public data source",
    action_class=ACTION_PASSIVE,
    input_types=("domain", "ip"),
    output_categories=("dns_footprint",),
    required_key="",              # empty = no key
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=30, per_day=1000, burst=5),
    legal_note="Public DNS data. No personal data touched.",
    health_check_url="https://example.com/status",
)
```

Return a `ConnectorResult` with a list of `Finding` objects, each carrying evidence URLs, confidence and source reliability tags. See [`METHODOLOGY.md`](METHODOLOGY.md) for what those numbers should actually mean.

## Writing a new connector

1. Create `osint_bot/connectors/<name>.py`.
2. Subclass `BaseConnector`, set `spec = _SPEC`, implement `_fetch(context) -> ConnectorResult`.
3. Register it in `osint_bot/connectors/__init__.py`.
4. Add a unit test in `tests/`.
5. Document it here.

Full guide: [`docs/CONTRIBUTING_MODULES.md`](CONTRIBUTING_MODULES.md).
