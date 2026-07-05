# Examples

Copy-paste recipes for the most common workflows. All examples use `example.com` as the safe public target.

## 1. Domain investigation (no keys)

```bash
argo-osint example.com --type domain --provider none \
    --max-pages 1 --output-dir reports/example --format both
```

Uses crt.sh, RDAP, DNS query, TLS cert, Wayback CDX, subdomain enumeration.

## 2. Domain investigation (BYOK providers)

```bash
export SHODAN_API_KEY=...
export VIRUSTOTAL_API_KEY=...
export SECURITYTRAILS_API_KEY=...
argo-osint example.com --type domain --provider all \
    --output-dir reports/example-full --format both
```

Adds Shodan (open ports), VT (file/URL reputation), historical DNS.

## 3. Company investigation

```bash
argo-osint "Acme Corp" --type company --provider all \
    --output-dir reports/acme --format both
```

Uses SEC Edgar, OpenCorporates (if `OPENCORPORATES_API_KEY` set), Companies House (UK), and web search.

## 4. Authorized email investigation

Requires a case with legal basis (`--case-id` links the query to a scope record).

```bash
argo-osint alice@example.com --type email --case-id CASE-2026-001 \
    --output-dir reports/case-001 --format both
```

Uses holehe (site enumeration for account existence), Gravatar, EmailRep (if BYOK), HIBP (if BYOK).

## 5. Authorized username investigation

```bash
argo-osint alice.example --type username --case-id CASE-2026-002 \
    --output-dir reports/case-002 --format both
```

Uses Maigret (~3000 sites), Sherlock-lite (subset, faster), Gravatar, GHunt (if configured).

## 6. IP address investigation

```bash
argo-osint 8.8.8.8 --type ip --provider all \
    --output-dir reports/ip --format both
```

Uses RDAP, ASN lookup, Shodan InternetDB, GreyNoise (if BYOK), OTX (if BYOK).

## 7. Web UI

```bash
export OSINT_WEB_TOKEN="pick-a-long-random-token"
python -m osint_bot.web --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>, sign up, open a case, run a query. Reports are downloadable from the case detail page.

## 8. Docker

```bash
export OSINT_WEB_TOKEN="pick-a-long-random-token"
docker compose up --build
```

Then browse <http://127.0.0.1:8000>.

## 9. Generate STIX 2.1 bundle

Once a case has findings:

```python
from osint_bot.stix_export import build_stix_bundle
import json

investigation = ...  # loaded from storage
bundle = build_stix_bundle(investigation)
print(json.dumps(bundle, indent=2))
```

Or via web UI: case detail → **Export** → **STIX 2.1**.

## 10. Generate MISP event

Same entry point; select **MISP** in the export dropdown. Result is a MISP core-format 2.4 event dict, ready to POST to your MISP instance.

## Redaction

By default, personal identifiers (emails, phone numbers) in exported reports are **partially redacted** unless the case explicitly requires disclosure and records the legal basis. This is a project-wide policy — see [`docs/RESPONSIBLE_USE.md`](RESPONSIBLE_USE.md).
