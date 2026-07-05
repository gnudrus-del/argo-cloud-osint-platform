# Connectors

Argo ships 58 native connectors: 43 key-free + 15 BYOK.

## Key-free (43)

Work out of the box, no signup, no API key.

| Category | Connectors |
| --- | --- |
| DNS / certs | crt.sh, RDAP, DNS query, TLS cert, Wayback CDX |
| Web fingerprint | Web fingerprint, Common Crawl, URL harvest |
| Threat intel | PhishTank, OpenPhish, ThreatFox, Shodan InternetDB |
| Geo / civic | Nominatim (OSM), Overpass (OSM), GDELT |
| Email OSINT | holehe (native + wrapper), Gravatar, Ignorant |
| Username OSINT | Sherlock-lite, Maigret |
| Corporate | SEC Edgar |
| Recon (active, gated) | Content discovery, Port scan, Subdomain enum, DNStwist |
| Secrets scan | Secret scan (public repos) |
| Domain OSINT | theHarvester |
| Phone OSINT | phone_meta, phone_footprint |
| Social reverse | GHunt (Google), Toutatis (Instagram), socid-extractor, LinkedIn2Username, Telegram checker |
| Darkweb | Ahmia index |
| Aggregator | legit_scorer (native SION-like) |
| ASN | ASN lookup |

Some active-recon connectors (port scan, content discovery) require an in-scope case and produce audit events.

## BYOK (15)

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
| EmailRep | `EMAILREP_API_KEY` | Email reputation |
| IPinfo | `IPINFO_API_KEY` | IP geolocation + ASN |
| Etherscan | `ETHERSCAN_API_KEY` | Ethereum blockchain queries |
| OpenCorporates | `OPENCORPORATES_API_KEY` | Global company registry |
| Companies House | `COMPANIES_HOUSE_API_KEY` | UK company registry |
| Brave Search | `BRAVE_SEARCH_API_KEY` | Web search API |
| Google PSE | `GOOGLE_PSE_API_KEY` | Programmable search engine |
| Influencers Club | `INFLUENCERS_CLUB_API_KEY` | Username → verified email |
| Etherscan | `ETHERSCAN_API_KEY` | (see above) |
| MISP | `MISP_URL` + `MISP_KEY` | Bring your own MISP instance |

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

Return a `ConnectorResult` with a list of `Finding` objects, each carrying evidence URLs, confidence and source reliability tags.

## Writing a new connector

1. Create `osint_bot/connectors/<name>.py`.
2. Subclass `BaseConnector`, set `spec = _SPEC`, implement `_fetch(context) -> ConnectorResult`.
3. Register it in `osint_bot/connectors/__init__.py`.
4. Add a unit test in `tests/`.
5. Document it here.

Full guide: [`docs/CONTRIBUTING_MODULES.md`](CONTRIBUTING_MODULES.md).
