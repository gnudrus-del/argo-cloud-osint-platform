"""Backend message catalog for connector output (findings notes, remediation,
legal notes, error messages).

Design goals
------------
* **Safe by default.** ``t(key, lang)`` never raises: an unknown key returns
  the key itself, and an unknown language falls back to Italian (the project's
  original language). A connector that references a not-yet-added key degrades
  to showing the raw key rather than crashing a search.
* **Stateless.** Language is chosen per request and threaded through
  ``ConnectorContext.lang``; there is no global mutable locale.
* **No I/O.** The catalog is a plain in-memory dict — no file loading, no
  network, consistent with the platform's privacy posture.

Usage from a connector::

    from ..i18n import t
    notes=t("leakix.plugin", ctx.lang, plugin=plugin, host=host, port=port)

with the catalog entry::

    "leakix.plugin": {
        "it": "LeakIX: plugin '{plugin}' rilevato su {host}:{port}.",
        "en": "LeakIX: plugin '{plugin}' detected on {host}:{port}.",
    }
"""
from __future__ import annotations

DEFAULT_LANG = "it"
SUPPORTED_LANGS = ("it", "en")

# ---------------------------------------------------------------------------
# Catalog. Grouped by connector; keys are "<connector>.<slug>". Each entry maps
# a language code to a str.format template. Populated incrementally as
# connectors are migrated off hard-coded Italian strings.
# ---------------------------------------------------------------------------
CATALOG: dict[str, dict[str, str]] = {
    # -- shared / generic ---------------------------------------------------
    "generic.no_response": {
        "it": "{service} non risponde.",
        "en": "{service} is not responding.",
    },
    "generic.error": {
        "it": "Errore {service}: {error}",
        "en": "{service} error: {error}",
    },
    "generic.rate_limited": {
        "it": "{service}: limite di richieste raggiunto, riprova più tardi.",
        "en": "{service}: rate limit reached, try again later.",
    },
    "generic.no_key": {
        "it": "{service}: chiave API non configurata.",
        "en": "{service}: API key not configured.",
    },
    "generic.invalid_email": {
        "it": "Email non valida.",
        "en": "Invalid email.",
    },

    # -- gravatar -----------------------------------------------------------
    "gravatar.no_profile": {
        "it": "Nessun profilo Gravatar pubblico.",
        "en": "No public Gravatar profile.",
    },
    "gravatar.profile": {
        "it": "Profilo Gravatar pubblico associato a {email}.",
        "en": "Public Gravatar profile associated with {email}.",
    },
    "gravatar.username": {
        "it": "Username preferito dichiarato dall'utente su Gravatar.",
        "en": "Preferred username declared by the user on Gravatar.",
    },
    "gravatar.account": {
        "it": "Account {shortname} collegato al profilo Gravatar.",
        "en": "{shortname} account linked to the Gravatar profile.",
    },

    # -- leakix -------------------------------------------------------------
    "leakix.remediation_service": {
        "it": "Verificare l'esposizione del servizio e applicare patch o firewall rule.",
        "en": "Verify the service exposure and apply a patch or firewall rule.",
    },
    "leakix.plugin": {
        "it": "LeakIX: plugin '{plugin}' rilevato su {host}:{port}.",
        "en": "LeakIX: plugin '{plugin}' detected on {host}:{port}.",
    },
    "leakix.remediation_leak": {
        "it": "Chiudere immediatamente l'accesso non autorizzato. Investigare se ci sono stati accessi.",
        "en": "Immediately close the unauthorized access. Investigate whether any access occurred.",
    },
    "leakix.leak": {
        "it": "LeakIX: leak type '{leak_type}' su {host}:{port}.",
        "en": "LeakIX: leak type '{leak_type}' on {host}:{port}.",
    },

    # -- cloud_buckets --------------------------------------------------------
    "cloud_buckets.legal_note": {
        "it": "Attivo: sonda solo endpoint pubblici standard S3/GCS/Azure con HEAD/GET. Nessun bypass di autenticazione. Solo con scope autorizzato.",
        "en": "Active: probes only standard public S3/GCS/Azure endpoints with HEAD/GET. No authentication bypass. Only with authorized scope.",
    },
    "cloud_buckets.empty_target": {
        "it": "Target vuoto.",
        "en": "Empty target.",
    },
    "cloud_buckets.listable": {
        "it": "Bucket {provider} '{candidate}' esiste ed espone un listing pubblico del contenuto.",
        "en": "{provider} bucket '{candidate}' exists and exposes a public content listing.",
    },
    "cloud_buckets.exists": {
        "it": "Bucket {provider} '{candidate}' esiste ed e' raggiungibile pubblicamente (listing non confermato).",
        "en": "{provider} bucket '{candidate}' exists and is publicly reachable (listing not confirmed).",
    },
    "cloud_buckets.private": {
        "it": "Bucket {provider} '{candidate}' esiste ma risulta privato (403).",
        "en": "{provider} bucket '{candidate}' exists but appears private (403).",
    },

    # -- content_discovery --------------------------------------------------
    "content_discovery.legal_note": {
        "it": "Attivo: invia molte richieste HTTP al target. Solo con scope autorizzato.",
        "en": "Active: sends many HTTP requests to the target. Only with authorized scope.",
    },
    "content_discovery.target_empty": {
        "it": "Target vuoto.",
        "en": "Empty target.",
    },
    "content_discovery.path_reachable": {
        "it": "Path raggiungibile (HTTP {status}).",
        "en": "Path reachable (HTTP {status}).",
    },
    "content_discovery.hint_env": {
        "it": "possibile leak di segreti/ambiente",
        "en": "possible secrets/environment leak",
    },
    "content_discovery.hint_git": {
        "it": "repository Git esposto",
        "en": "exposed Git repository",
    },
    "content_discovery.hint_actuator_env": {
        "it": "Spring Actuator: possibile leak configurazione",
        "en": "Spring Actuator: possible configuration leak",
    },
    "content_discovery.hint_phpinfo": {
        "it": "phpinfo esposto",
        "en": "phpinfo exposed",
    },
    "content_discovery.hint_id_rsa": {
        "it": "chiave privata SSH esposta",
        "en": "SSH private key exposed",
    },
    "content_discovery.hint_dump_sql": {
        "it": "dump database esposto",
        "en": "database dump exposed",
    },

    # -- crt_sh -------------------------------------------------------------
    "crt_sh.detected": {
        "it": "Rilevato in Certificate Transparency logs. Cert emesso da CA {ca}.",
        "en": "Detected in Certificate Transparency logs. Cert issued by CA {ca}.",
    },

    # -- darkweb_scan -------------------------------------------------------
    "darkweb_scan.legal_note": {
        "it": "Interroga solo l'indice clear-web pubblico Ahmia. Nessun accesso diretto a Tor. Gated dal scope.",
        "en": "Queries only the public Ahmia clear-web index. No direct Tor access. Gated by scope.",
    },
    "darkweb_scan.keyword_short": {
        "it": "Keyword troppo corta.",
        "en": "Keyword too short.",
    },
    "darkweb_scan.onion_indexed": {
        "it": "Risorsa .onion indicizzata da Ahmia per '{query}'. Titolo: {title}. Verificare con OPSEC su Tor Browser.",
        "en": ".onion resource indexed by Ahmia for '{query}'. Title: {title}. Verify with OPSEC on Tor Browser.",
    },
    "darkweb_scan.why_linked": {
        "it": "Ahmia ha risposto con questo .onion per la query '{query}'",
        "en": "Ahmia returned this .onion for the query '{query}'",
    },

    # -- legit_scorer -------------------------------------------------------
    "legit_scorer.legal_note": {
        "it": "Solo aggregazione locale di segnali di altri connettori. Nessun invio proprio a servizi esterni.",
        "en": "Only local aggregation of signals from other connectors. No outbound calls to external services.",
    },
    "legit_scorer.target_empty": {
        "it": "Target vuoto.",
        "en": "Empty target.",
    },
    "legit_scorer.registry_uninit": {
        "it": "Registro non inizializzato.",
        "en": "Registry not initialized.",
    },

    # -- opencorporates -----------------------------------------------------
    "opencorporates.legal_note": {
        "it": "OpenCorporates aggrega registri imprese pubblici.",
        "en": "OpenCorporates aggregates public company registries.",
    },
    "opencorporates.company_record": {
        "it": "OpenCorporates: numero={number}, status={status}, creata={created}",
        "en": "OpenCorporates: number={number}, status={status}, incorporated={created}",
    },

    # -- openphish ----------------------------------------------------------
    "openphish.legal_note": {
        "it": "Feed pubblico OpenPhish. Solo verifiche difensive.",
        "en": "Public OpenPhish feed. Defensive checks only.",
    },
    "openphish.feed_unavailable": {
        "it": "OpenPhish: feed non scaricabile.",
        "en": "OpenPhish: feed not downloadable.",
    },
    "openphish.match": {
        "it": "URL presente nella feed pubblica OpenPhish.",
        "en": "URL present in the public OpenPhish feed.",
    },

    # -- otx ----------------------------------------------------------------
    "otx.legal_note": {
        "it": "OTX: pulse community open. Free per uso difensivo.",
        "en": "OTX: open community pulses. Free for defensive use.",
    },
    "otx.pulse_match": {
        "it": "Indicatore presente in pulse OTX (autore: {author}).",
        "en": "Indicator present in an OTX pulse (author: {author}).",
    },

    # -- overpass -----------------------------------------------------------
    "overpass.legal_note": {
        "it": "Dati geografici pubblici OpenStreetMap (ODbL). Nessun dato personale inviato.",
        "en": "Public OpenStreetMap geographic data (ODbL). No personal data sent.",
    },
    "overpass.invalid_target": {
        "it": "Target deve essere 'lat,lon' (opz. ',raggio_m').",
        "en": "Target must be 'lat,lon' (optionally ',radius_m').",
    },
    "overpass.unreachable": {
        "it": "Overpass API non raggiungibile o query fallita.",
        "en": "Overpass API unreachable or query failed.",
    },
    "overpass.feature": {
        "it": "Feature OSM entro {radius}m da {lat},{lon}.",
        "en": "OSM feature within {radius}m of {lat},{lon}.",
    },

    # -- secret_scan --------------------------------------------------------
    "secret_scan.legal_note": {
        "it": "Scarica contenuto pubblico e cerca pattern di segreti. Solo GET, nessuna modifica.",
        "en": "Downloads public content and looks for secret patterns. GET only, no modification.",
    },
    "secret_scan.empty_target": {
        "it": "Target vuoto.",
        "en": "Empty target.",
    },
    "secret_scan.pattern_found": {
        "it": "Pattern '{name}' trovato in {src_url}. Valore redatto. Verificare validità e revocare se reale.",
        "en": "Pattern '{name}' found in {src_url}. Value redacted. Verify validity and revoke if real.",
    },

    # -- securitytrails -----------------------------------------------------
    "securitytrails.legal_note": {
        "it": "SecurityTrails: lookup passivi su dati DNS storici. ToS standard.",
        "en": "SecurityTrails: passive lookups on historical DNS data. Standard ToS.",
    },
    "securitytrails.missing_key": {
        "it": "SecurityTrails richiede API key (BYOK).",
        "en": "SecurityTrails requires an API key (BYOK).",
    },
    "securitytrails.subdomain": {
        "it": "Sottodominio rilevato da SecurityTrails (DNS history).",
        "en": "Subdomain detected by SecurityTrails (DNS history).",
    },

    # -- sherlock_lite ------------------------------------------------------
    "sherlock_lite.legal_note": {
        "it": "Solo GET verso URL pubbliche. Nessun login o dato PII inviato.",
        "en": "GET requests to public URLs only. No login or PII sent.",
    },
    "sherlock_lite.invalid_username": {
        "it": "Username non valido.",
        "en": "Invalid username.",
    },
    "sherlock_lite.profile_found": {
        "it": "Profilo pubblico su {site} (detection {method} deterministica). Solo siti ad alta affidabilità: nessun falso positivo da 200 su SPA.",
        "en": "Public profile on {site} (deterministic {method} detection). High-reliability sites only: no false positives from 200 on SPAs.",
    },
    "sherlock_lite.why_linked": {
        "it": "L'username esatto '{username}' risolve a un profilo su {site}",
        "en": "The exact username '{username}' resolves to a profile on {site}",
    },

    # -- socid_extractor ----------------------------------------------------
    "socid_extractor.legal_note": {
        "it": "Un GET verso una URL pubblica di profilo. Estrae metadata già esposti dalla piattaforma.",
        "en": "A GET request to a public profile URL. Extracts metadata already exposed by the platform.",
    },
    "socid_extractor.not_installed": {
        "it": "Libreria 'socid-extractor' non installata (pip install socid-extractor).",
        "en": "Library 'socid-extractor' not installed (pip install socid-extractor).",
    },
    "socid_extractor.bad_target": {
        "it": "Target deve essere una URL di profilo (http/https).",
        "en": "Target must be a profile URL (http/https).",
    },
    "socid_extractor.parse_failed": {
        "it": "socid-extractor parsing fallito: {error}",
        "en": "socid-extractor parsing failed: {error}",
    },
    "socid_extractor.no_ids": {
        "it": "Nessun identificatore estratto dalla pagina.",
        "en": "No identifier extracted from the page.",
    },
    "socid_extractor.field_extracted": {
        "it": "Estratto da {url} via socid-extractor (campo '{key}').",
        "en": "Extracted from {url} via socid-extractor (field '{key}').",
    },

    # -- tls_cert -----------------------------------------------------------
    "tls_cert.legal_note": {
        "it": "Una connessione TCP al target:443 per leggere il cert pubblico. Passivo.",
        "en": "A TCP connection to target:443 to read the public certificate. Passive.",
    },
    "tls_cert.target_empty": {
        "it": "Target vuoto.",
        "en": "Empty target.",
    },
    "tls_cert.cert_unavailable": {
        "it": "Impossibile ottenere cert TLS da {host}:{port}.",
        "en": "Unable to obtain TLS cert from {host}:{port}.",
    },
    "tls_cert.san": {
        "it": "Subject Alt Name presente nel certificato di {host}:{port}",
        "en": "Subject Alt Name present in the certificate of {host}:{port}",
    },
    "tls_cert.issuer": {
        "it": "CA emittente del cert di {host}:{port}",
        "en": "Issuing CA of the cert for {host}:{port}",
    },
    "tls_cert.fingerprint": {
        "it": "SHA-256 del cert DER (identificatore univoco).",
        "en": "SHA-256 of the DER cert (unique identifier).",
    },

    # -- toutatis -----------------------------------------------------------
    "toutatis.legal_note": {
        "it": "Usa l'API IG con la sessione dell'investigatore. Restituisce dati parzialmente mascherati esposti da IG.",
        "en": "Uses the IG API with the investigator's session. Returns partially masked data exposed by IG.",
    },
    "toutatis.not_configured": {
        "it": "Toutatis non configurato (TOUTATIS_CMD/TOUTATIS_PYTHON).",
        "en": "Toutatis not configured (TOUTATIS_CMD/TOUTATIS_PYTHON).",
    },
    "toutatis.session_missing": {
        "it": "TOUTATIS_SESSION mancante (sessionid Instagram dell'investigatore).",
        "en": "TOUTATIS_SESSION missing (investigator's Instagram sessionid).",
    },
    "toutatis.invalid_username": {
        "it": "Username IG non valido.",
        "en": "Invalid IG username.",
    },
    "toutatis.timeout": {
        "it": "Toutatis timeout.",
        "en": "Toutatis timeout.",
    },
    "toutatis.exec_failed": {
        "it": "Esecuzione Toutatis fallita: {exc}",
        "en": "Toutatis execution failed: {exc}",
    },

    # -- wayback ------------------------------------------------------------
    "wayback.invalid_response": {
        "it": "Risposta CDX non valida.",
        "en": "Invalid CDX response.",
    },
    "wayback.remediation": {
        "it": "Verificare se l'URL è ancora accessibile. {desc}.",
        "en": "Verify whether the URL is still reachable. {desc}.",
    },
    "wayback.notes_url": {
        "it": "URL storicizzata da Wayback: {desc}.",
        "en": "URL archived by Wayback: {desc}.",
    },
    "wayback.snapshot_count": {
        "it": "Wayback Machine ha {count} snapshot per {domain} (200 OK, collassati per URL).",
        "en": "Wayback Machine has {count} snapshots for {domain} (200 OK, collapsed per URL).",
    },
    "wayback.desc_env": {
        "it": "File .env storicizzato da Wayback",
        "en": ".env file archived by Wayback",
    },
    "wayback.desc_git_config": {
        "it": "Git config storicizzato",
        "en": "Git config archived",
    },
    "wayback.desc_admin": {
        "it": "Path admin storicizzato",
        "en": "Admin path archived",
    },
    "wayback.desc_backup": {
        "it": "Backup path storicizzato",
        "en": "Backup path archived",
    },
    "wayback.desc_wp_admin": {
        "it": "WP admin storicizzato",
        "en": "WP admin archived",
    },
    "wayback.desc_phpinfo": {
        "it": "phpinfo storicizzato",
        "en": "phpinfo archived",
    },
    "wayback.desc_api": {
        "it": "API endpoint storicizzato",
        "en": "API endpoint archived",
    },
    "wayback.desc_swagger": {
        "it": "Swagger UI storicizzato",
        "en": "Swagger UI archived",
    },
    "wayback.desc_actuator": {
        "it": "Spring Actuator storicizzato",
        "en": "Spring Actuator archived",
    },
    "wayback.desc_password": {
        "it": "URL con 'password' in path/query",
        "en": "URL with 'password' in path/query",
    },
    "wayback.desc_token": {
        "it": "Token in query string storicizzato",
        "en": "Token in query string archived",
    },
    "wayback.desc_apikey": {
        "it": "API key in query string storicizzato",
        "en": "API key in query string archived",
    },

    # -- web_fingerprint ----------------------------------------------------
    "web_fingerprint.legal_note": {
        "it": "Un GET HTTPS al target. Passivo. No brute force.",
        "en": "A single HTTPS GET to the target. Passive. No brute force.",
    },
    "web_fingerprint.empty_target": {
        "it": "Target vuoto.",
        "en": "Empty target.",
    },
    "web_fingerprint.fetch_failed": {
        "it": "HTTP fetch fallita per {url}.",
        "en": "HTTP fetch failed for {url}.",
    },

    # -- abuseipdb ----------------------------------------------------------
    "abuseipdb.no_data": {"it": "AbuseIPDB non ha dati per l'IP.", "en": "AbuseIPDB has no data for the IP."},
    "abuseipdb.remediation_high_score": {"it": "Bloccare IP su firewall se score > 40. Investigare log per connessioni da/verso questo IP.", "en": "Block the IP at the firewall if the score is > 40. Investigate logs for connections to/from this IP."},
    "abuseipdb.remediation_tor": {"it": "IP è un nodo TOR. Considerare blocco selettivo o monitoraggio aumentato.", "en": "IP is a TOR node. Consider selective blocking or heightened monitoring."},
    "abuseipdb.report": {"it": "Report AbuseIPDB del {reported_at}: categorie {cats}.", "en": "AbuseIPDB report dated {reported_at}: categories {cats}."},
    "abuseipdb.score": {"it": "AbuseIPDB abuse score: {score}/100 ({reports} report).", "en": "AbuseIPDB abuse score: {score}/100 ({reports} reports)."},
    "abuseipdb.tor_note": {"it": "L'IP {ip} è un exit node TOR noto secondo AbuseIPDB.", "en": "IP {ip} is a known TOR exit node according to AbuseIPDB."},

    # -- asn_lookup ---------------------------------------------------------
    "asn_lookup.legal_note": {"it": "Servizio pubblico gratuito Team Cymru (DNS TXT). No PII.", "en": "Free public Team Cymru service (DNS TXT). No PII."},
    "asn_lookup.invalid_ip": {"it": "IP non valido o IPv6 (non supportato).", "en": "Invalid IP or IPv6 (not supported)."},
    "asn_lookup.empty_txt": {"it": "Team Cymru TXT vuoto (dig mancante o network fail).", "en": "Team Cymru TXT empty (dig missing or network failure)."},
    "asn_lookup.unparsable": {"it": "Risposta Team Cymru non parsabile: {origin_txt}", "en": "Unparsable Team Cymru response: {origin_txt}"},

    # -- common_crawl -------------------------------------------------------
    "common_crawl.legal_note": {"it": "Indice pubblico Common Crawl (Apache 2.0). No dati personali inviati.", "en": "Public Common Crawl index (Apache 2.0). No personal data submitted."},
    "common_crawl.invalid_target": {"it": "Target deve essere un dominio (no schema, no path).", "en": "Target must be a domain (no scheme, no path)."},
    "common_crawl.collinfo_failed": {"it": "Impossibile leggere collinfo.json da Common Crawl.", "en": "Unable to read collinfo.json from Common Crawl."},
    "common_crawl.archived_url": {"it": "URL indicizzata da Common Crawl {index}. HTTP {status}, MIME {mime}.", "en": "URL indexed by Common Crawl {index}. HTTP {status}, MIME {mime}."},

    # -- companies_house ----------------------------------------------------
    "companies_house.legal_note": {"it": "Companies House: registro ufficiale aziende UK.", "en": "Companies House: official UK companies register."},
    "companies_house.no_key": {"it": "Companies House richiede API key (free).", "en": "Companies House requires an API key (free)."},
    "companies_house.record_details": {"it": "Companies House: status={status}, creata={created}, address={address}", "en": "Companies House: status={status}, incorporated={created}, address={address}"},

    # -- dns_query ----------------------------------------------------------
    "dns_query.legal_note": {"it": "Query DNS pubbliche: nessuna informazione personale.", "en": "Public DNS queries: no personal information."},
    "dns_query.empty_target": {"it": "Target vuoto.", "en": "Empty target."},
    "dns_query.record_dig": {"it": "Record {rtype} per {target} via resolver di sistema.", "en": "{rtype} record for {target} via system resolver."},
    "dns_query.record_socket": {"it": "IP risolto per {target} (fallback socket).", "en": "IP resolved for {target} (socket fallback)."},

    # -- email_security -------------------------------------------------------
    "email_security.legal_note": {"it": "Interroga solo record DNS TXT pubblici del dominio (SPF/DMARC/MTA-STS/BIMI) e SOA per DNSSEC. Nessun contatto con server di posta o altri host del target.", "en": "Queries only the domain's public DNS TXT records (SPF/DMARC/MTA-STS/BIMI) and SOA for DNSSEC. No contact with mail servers or other target hosts."},
    "email_security.empty_target": {"it": "Target vuoto.", "en": "Empty target."},
    "email_security.dig_unavailable": {"it": "Impossibile eseguire i controlli: 'dig' non disponibile o irraggiungibile per ogni query effettuata.", "en": "Unable to run the checks: 'dig' is unavailable or unreachable for every query attempted."},
    "email_security.spf_missing": {"it": "Nessun record SPF per {domain}: chiunque può inviare email spacciandosi per questo dominio, senza che i server riceventi possano verificarlo via SPF.", "en": "No SPF record for {domain}: anyone can send email spoofing this domain, with receiving servers unable to verify it via SPF."},
    "email_security.spf_hardfail": {"it": "SPF di {domain} termina con '-all' (hardfail): i server riceventi sono istruiti a rifiutare la posta da IP non autorizzati. Postura corretta.", "en": "{domain}'s SPF ends with '-all' (hardfail): receiving servers are instructed to reject mail from unauthorized IPs. Correct posture."},
    "email_security.spf_softfail": {"it": "SPF di {domain} termina con '~all' (softfail): la posta da IP non autorizzati viene marcata sospetta ma spesso comunque recapitata. Protezione parziale.", "en": "{domain}'s SPF ends with '~all' (softfail): mail from unauthorized IPs is flagged as suspicious but often still delivered. Partial protection."},
    "email_security.spf_permissive": {"it": "SPF di {domain} è permissivo ('?all' o nessun qualificatore 'all' esplicito): offre poca o nessuna protezione anti-spoofing reale.", "en": "{domain}'s SPF is permissive ('?all' or no explicit 'all' qualifier): it offers little to no real anti-spoofing protection."},
    "email_security.saas_tenant": {"it": "L'SPF di {domain} include un provider SaaS noto ({provider}): indizio che la posta del dominio è ospitata lì.", "en": "{domain}'s SPF includes a known SaaS provider ({provider}): a sign the domain's mail is hosted there."},
    "email_security.dmarc_missing": {"it": "Nessun record DMARC per {domain}: manca la policy anti-spoofing, i domini possono essere impersonati liberamente nelle email.", "en": "No DMARC record for {domain}: no anti-spoofing policy in place, the domain can be freely impersonated in emails."},
    "email_security.dmarc_none": {"it": "DMARC di {domain} ha policy 'p=none': i fallimenti SPF/DKIM vengono solo monitorati, non bloccati. Lo spoofing resta fattibile.", "en": "{domain}'s DMARC has policy 'p=none': SPF/DKIM failures are only monitored, not blocked. Spoofing remains feasible."},
    "email_security.dmarc_quarantine": {"it": "DMARC di {domain} ha policy 'p=quarantine': la posta sospetta viene messa in quarantena (es. spam) invece di essere bloccata del tutto.", "en": "{domain}'s DMARC has policy 'p=quarantine': suspicious mail is quarantined (e.g. spam) instead of being blocked outright."},
    "email_security.dmarc_reject": {"it": "DMARC di {domain} ha policy 'p=reject': la posta che fallisce SPF/DKIM viene rifiutata. Postura corretta.", "en": "{domain}'s DMARC has policy 'p=reject': mail failing SPF/DKIM is rejected. Correct posture."},
    "email_security.dmarc_pct_note": {"it": " Nota: pct={pct}, quindi la policy si applica solo a una parte del traffico.", "en": " Note: pct={pct}, so the policy only applies to a portion of the traffic."},
    "email_security.mta_sts_missing": {"it": "Nessun record MTA-STS per {domain}: la posta in transito verso questo dominio non è protetta da un downgrade/MITM SMTP forzato. Gap di hardening minore.", "en": "No MTA-STS record for {domain}: mail in transit to this domain is not protected against a forced SMTP downgrade/MITM. Minor hardening gap."},
    "email_security.dnssec_not_enabled": {"it": "DNSSEC non risulta abilitato su {domain} (nessun RRSIG nella risposta SOA): le risposte DNS del dominio non sono firmate crittograficamente e sono in teoria falsificabili via cache poisoning.", "en": "DNSSEC does not appear to be enabled on {domain} (no RRSIG in the SOA response): the domain's DNS answers are not cryptographically signed and are in theory spoofable via cache poisoning."},
    "email_security.bimi_absent": {"it": "Nessun record BIMI per {domain} (informativo): il dominio non pubblica un logo aziendale verificato per i client email compatibili.", "en": "No BIMI record for {domain} (informational): the domain does not publish a verified brand logo for compatible email clients."},

    # -- dnstwist_native ----------------------------------------------------
    "dnstwist_native.legal_note": {"it": "Genera varianti del dominio e risolve i candidati. Nessun contatto col target.", "en": "Generates domain variants and resolves the candidates. No contact with the target."},
    "dnstwist_native.invalid_target": {"it": "Target deve essere un dominio.", "en": "Target must be a domain."},
    "dnstwist_native.no_permutations": {"it": "Impossibile generare permutazioni.", "en": "Unable to generate permutations."},
    "dnstwist_native.variant_registered": {"it": "Variante registrata di {domain} → {ip}. Possibile typosquat/phishing: verificare intestatario e uso.", "en": "Registered variant of {domain} → {ip}. Possible typosquat/phishing: verify the registrant and usage."},

    # -- emailrep -----------------------------------------------------------
    "emailrep.legal_note": {"it": "EmailRep.io: aggrega reputazione email da fonti pubbliche. Usabile solo con base giuridica (caso + autorizzazione).", "en": "EmailRep.io: aggregates email reputation from public sources. Use only with a legal basis (case + authorization)."},
    "emailrep.summary": {"it": "EmailRep: reputation={reputation}, suspicious={suspicious}, deliverable={deliverable}, profiles={profiles}", "en": "EmailRep: reputation={reputation}, suspicious={suspicious}, deliverable={deliverable}, profiles={profiles}"},

    # -- etherscan ----------------------------------------------------------
    "etherscan.legal_note": {"it": "Etherscan: dati pubblici on-chain Ethereum. Solo lettura.", "en": "Etherscan: public Ethereum on-chain data. Read-only."},
    "etherscan.invalid_address": {"it": "Etherscan: indirizzo ETH non valido (0x + 40 hex).", "en": "Etherscan: invalid ETH address (0x + 40 hex)."},
    "etherscan.missing_key": {"it": "Etherscan richiede API key (free).", "en": "Etherscan requires an API key (free)."},
    "etherscan.balance": {"it": "Etherscan: balance corrente = {eth} ETH ({wei} wei)", "en": "Etherscan: current balance = {eth} ETH ({wei} wei)"},
    "etherscan.has_tx": {"it": "Etherscan: wallet ha transazioni.", "en": "Etherscan: wallet has transactions."},
    "etherscan.no_tx": {"it": "Etherscan: wallet ha NESSUNA transazione.", "en": "Etherscan: wallet has NO transactions."},

    # -- flowsint -----------------------------------------------------------
    "flowsint.legal_note": {"it": "Interroga un'istanza FlowSINT privata configurata dall'operatore. Grafo di indagine locale.", "en": "Queries a private FlowSINT instance configured by the operator. Local investigation graph."},
    "flowsint.not_configured": {"it": "FlowSINT non configurato. Setta FLOWSINT_URL, FLOWSINT_USER, FLOWSINT_PASSWORD nel .env sulla VM.", "en": "FlowSINT not configured. Set FLOWSINT_URL, FLOWSINT_USER, FLOWSINT_PASSWORD in the .env file on the VM."},
    "flowsint.auth_failed": {"it": "Autenticazione FlowSINT fallita.", "en": "FlowSINT authentication failed."},
    "flowsint.investigation_failed": {"it": "Impossibile creare investigation su FlowSINT.", "en": "Unable to create an investigation on FlowSINT."},
    "flowsint.notes_with_relevant": {"it": "Investigation FlowSINT preconfigurata. Apri il link per esplorare il grafo con enricher graph-based. Rilevanti per {ttype}: {relevant}", "en": "Preconfigured FlowSINT investigation. Open the link to explore the graph with graph-based enrichers. Relevant for {ttype}: {relevant}"},
    "flowsint.no_relevant_enrichers": {"it": "Nessun enricher specifico per questo target_type.", "en": "No specific enricher for this target_type."},

    # -- gdelt --------------------------------------------------------------
    "gdelt.legal_note": {"it": "GDELT e' un dataset open su news/eventi. Uso libero per ricerca.", "en": "GDELT is an open dataset on news and events. Free for research use."},
    "gdelt.empty_query": {"it": "GDELT: query vuota.", "en": "GDELT: empty query."},
    "gdelt.article_note": {"it": "GDELT — fonte: {domain}, lingua: {language}", "en": "GDELT — source: {domain}, language: {language}"},

    # -- ghunt --------------------------------------------------------------
    "ghunt.legal_note": {"it": "Interroga API Google con le credenziali dell'investigatore. Solo dati pubblici del profilo.", "en": "Queries the Google APIs with the investigator's credentials. Public profile data only."},
    "ghunt.not_configured": {"it": "GHunt non configurato (GHUNT_CMD/GHUNT_PYTHON).", "en": "GHunt not configured (GHUNT_CMD/GHUNT_PYTHON)."},
    "ghunt.home_missing": {"it": "GHUNT_HOME non impostata: servono le cred (ghunt login).", "en": "GHUNT_HOME not set: credentials are required (ghunt login)."},
    "ghunt.creds_expired": {"it": "GHunt: credenziali mancanti/scadute (rifai ghunt login).", "en": "GHunt: credentials missing/expired (run ghunt login again)."},
    "ghunt.exec_failed": {"it": "Esecuzione GHunt fallita: {exc}", "en": "GHunt execution failed: {exc}"},
    "ghunt.timeout": {"it": "GHunt timeout.", "en": "GHunt timeout."},
    "ghunt.no_data": {"it": "GHunt: nessun dato pubblico associato all'email.", "en": "GHunt: no public data associated with the email."},

    # -- github_search ------------------------------------------------------
    "github_search.remediation_secret": {"it": "Revocare immediatamente qualsiasi credenziale esposta nel file {file_path}. Rimuovere il file dalla cronologia git (BFG Repo Cleaner). Aggiungere .gitignore per prevenire future esposizioni.", "en": "Immediately revoke any credentials exposed in the file {file_path}. Remove the file from git history (BFG Repo Cleaner). Add a .gitignore rule to prevent future exposures."},
    "github_search.pattern_found": {"it": "Pattern '{keyword}' trovato in repository pubblico correlato a '{target}'.", "en": "Pattern '{keyword}' found in a public repository related to '{target}'."},
    "github_search.repo_mentions": {"it": "{count} repository pubblici GitHub menzionano '{target}' in README/descrizione.", "en": "{count} public GitHub repositories mention '{target}' in README or description."},

    # -- google_pse ---------------------------------------------------------
    "google_pse.legal_note": {"it": "Google PSE: API ufficiale. ToS Google.", "en": "Google PSE: official API. Subject to Google Terms of Service."},
    "google_pse.missing_key_format": {"it": "Google PSE richiede 'API_KEY|CX_ID'.", "en": "Google PSE requires 'API_KEY|CX_ID'."},
    "google_pse.snippet": {"it": "Google PSE: {snippet}", "en": "Google PSE: {snippet}"},

    # -- greynoise ----------------------------------------------------------
    "greynoise.legal_note": {"it": "GreyNoise: contesto su scanner Internet. Solo IP, no PII.", "en": "GreyNoise: context on Internet scanners. IP only, no PII."},
    "greynoise.needs_key": {"it": "GreyNoise richiede API key (BYOK).", "en": "GreyNoise requires an API key (BYOK)."},
    "greynoise.classification": {"it": "GreyNoise: classification={classification}, name={name}", "en": "GreyNoise: classification={classification}, name={name}"},

    # -- hibp ---------------------------------------------------------------
    "hibp.unsupported_target": {"it": "HIBP: tipo target non supportato (usa email o domain).", "en": "HIBP: unsupported target type (use email or domain)."},
    "hibp.no_response_or_invalid_key": {"it": "HIBP: nessuna risposta o API key non valida.", "en": "HIBP: no response or invalid API key."},
    "hibp.breach_notes": {"it": "Email '{t}' trovata nel breach '{title}' ({date}). Dati esposti: {pw_exposed}.", "en": "Email '{t}' found in the '{title}' breach ({date}). Data exposed: {pw_exposed}."},
    "hibp.breach_remediation": {"it": "Cambiare la password usata su {title}. Se riutilizzata altrove, cambiarla ovunque. Abilitare MFA.", "en": "Change the password used on {title}. If reused elsewhere, change it everywhere. Enable MFA."},
    "hibp.domain_notes": {"it": "HIBP: {count} account del dominio '{t}' presenti in breach. Severità basata su conteggio.", "en": "HIBP: {count} accounts of domain '{t}' present in breaches. Severity based on count."},
    "hibp.domain_remediation": {"it": "Forzare il reset password per i {count} account compromessi. Notificare gli utenti secondo GDPR.", "en": "Force a password reset for the {count} compromised accounts. Notify users under GDPR."},

    # -- holehe -------------------------------------------------------------
    "holehe.legal_note": {"it": "Esegue holehe in locale su endpoint pubblici. Nessuna email inviata; solo check di registrazione.", "en": "Runs holehe locally against public endpoints. No email is sent; registration checks only."},
    "holehe.not_configured": {"it": "holehe non configurato. Setta HOLEHE_CMD (o HOLEHE_PYTHON) nel .env. Fallback: holehe_native.", "en": "holehe not configured. Set HOLEHE_CMD (or HOLEHE_PYTHON) in the .env file. Fallback: holehe_native."},
    "holehe.timeout": {"it": "holehe timeout.", "en": "holehe timeout."},
    "holehe.execution_failed": {"it": "Esecuzione holehe fallita: {exc}", "en": "holehe execution failed: {exc}"},
    "holehe.evidence_title_registered": {"it": "holehe ha marcato '{email}' come usata su {d}", "en": "holehe marked '{email}' as used on {d}"},
    "holehe.registered_notes": {"it": "holehe: l'email risulta REGISTRATA su {d} (rilevato via endpoint pubblico). Possibili FP/rate-limit.", "en": "holehe: the email is REGISTERED on {d} (detected via public endpoint). Possible FPs / rate-limit."},
    "holehe.registered_why_linked": {"it": "holehe ha marcato '{email}' come usata su {d}", "en": "holehe marked '{email}' as used on {d}"},
    "holehe.recovery_hint_email_notes": {"it": "holehe: hint di recupero email mascherato esposto da {domain} per {email}.", "en": "holehe: masked email recovery hint exposed by {domain} for {email}."},
    "holehe.recovery_hint_phone_notes": {"it": "holehe: hint di recupero telefono mascherato esposto da {domain} per {email}.", "en": "holehe: masked phone recovery hint exposed by {domain} for {email}."},
    "holehe.recovery_why_linked": {"it": "{domain} espone un dato di recupero collegato a {email}", "en": "{domain} exposes a recovery hint linked to {email}"},

    # -- holehe_native ------------------------------------------------------
    "holehe_native.legal_note": {"it": "Controlli passivi su email (Gravatar, MX, disposable). Nessun invio di posta.", "en": "Passive email checks (Gravatar, MX, disposable). No mail is sent."},
    "holehe_native.disposable": {"it": "Dominio email 'usa e getta': bassa affidabilità dell'identità.", "en": "Disposable email domain: low identity reliability."},
    "holehe_native.domain_valid": {"it": "Il dominio risolve: l'email è plausibilmente recapitabile.", "en": "The domain resolves: the email is plausibly deliverable."},
    "holehe_native.gravatar_profile": {"it": "Profilo Gravatar pubblico ({url}).", "en": "Public Gravatar profile ({url})."},
    "holehe_native.gravatar_account": {"it": "Account {shortname} collegato via Gravatar.", "en": "Account {shortname} linked via Gravatar."},
    "holehe_native.gmail_canonical": {"it": "Forma canonica Gmail (dot-trick/plus rimossi): stessa casella.", "en": "Canonical Gmail form (dot-trick/plus removed): same mailbox."},

    # -- hudsonrock -----------------------------------------------------------
    "hudsonrock.legal_note": {"it": "Interroga l'API pubblica gratuita di Hudson Rock Cavalier (corpus di log infostealer aggregati). Il tier gratuito non restituisce mai credenziali in chiaro: solo conteggi aggregati e URL di esempio parzialmente redatti.", "en": "Queries Hudson Rock Cavalier's free public API (aggregated infostealer log corpus). The free tier never returns plaintext credentials: only aggregate counts and partially redacted sample URLs."},
    "hudsonrock.empty_target": {"it": "Target vuoto.", "en": "Empty target."},
    "hudsonrock.no_corpus_hits": {"it": "Nessuna voce nel corpus breach Hudson Rock per questo target (non prova assenza di rischio).", "en": "No entries in the Hudson Rock breach corpus for this target (does not prove absence of risk)."},
    "hudsonrock.domain_summary": {"it": "Corpus infostealer: {employees} dipendenti, {users} utenti, {third_parties} terze parti coinvolti. Famiglie stealer: {families}. Esempi URL dipendenti: {sample_urls}.", "en": "Infostealer corpus: {employees} employees, {users} users, {third_parties} third parties involved. Stealer families: {families}. Sample employee URLs: {sample_urls}."},
    "hudsonrock.email_summary": {"it": "Email trovata in log infostealer. Famiglie stealer: {families}.", "en": "Email found in infostealer logs. Stealer families: {families}."},

    # -- hunter -------------------------------------------------------------
    "hunter.legal_note": {"it": "Hunter.io Domain Search — solo per domini di propria competenza o con autorizzazione scritta.", "en": "Hunter.io Domain Search — only for domains you own or have written authorization for."},
    "hunter.email_found": {"it": "Email trovata da Hunter.io: {first} {last} — {position}.", "en": "Email found by Hunter.io: {first} {last} — {position}."},
    "hunter.email_pattern": {"it": "Formato email predominante per {t}: {pattern}. Usabile per generare indirizzi target.", "en": "Predominant email format for {t}: {pattern}. Can be used to generate target addresses."},
    "hunter.email_remediation": {"it": "Trattare come PII. Non usare per phishing. Informare l'interessato se richiesto da DSAR.", "en": "Treat as PII. Do not use for phishing. Inform the data subject if required by a DSAR."},
    "hunter.org_name": {"it": "Nome organizzazione da Hunter.io: {org}.", "en": "Organization name from Hunter.io: {org}."},

    # -- ignorant -----------------------------------------------------------
    "ignorant.legal_note": {"it": "Esegue ignorant in locale su endpoint pubblici. Nessun SMS inviato; solo check di registrazione.", "en": "Runs ignorant locally against public endpoints. No SMS is sent; registration checks only."},
    "ignorant.not_configured": {"it": "ignorant non configurato. Setta IGNORANT_CMD (o IGNORANT_PYTHON) nel .env.", "en": "ignorant not configured. Set IGNORANT_CMD (or IGNORANT_PYTHON) in the .env file."},
    "ignorant.invalid_number": {"it": "Numero non valido (serve formato internazionale, es. +39...).", "en": "Invalid phone number (international format required, e.g. +39...)."},
    "ignorant.timeout": {"it": "ignorant timeout.", "en": "ignorant timeout."},
    "ignorant.execution_failed": {"it": "Esecuzione ignorant fallita: {exc}", "en": "ignorant execution failed: {exc}"},
    "ignorant.registered_on": {"it": "ignorant ha marcato il numero come usato su {d}", "en": "ignorant marked the number as used on {d}"},
    "ignorant.why_linked": {"it": "ignorant ha marcato il numero come usato su {d}", "en": "ignorant marked the number as used on {d}"},

    # -- ipinfo -------------------------------------------------------------
    "ipinfo.legal_note": {"it": "IPinfo: geolocation IP pubblica. Niente PII di utenti.", "en": "IPinfo: public IP geolocation. No user PII."},
    "ipinfo.finding": {"it": "IPinfo: {key}={value}", "en": "IPinfo: {key}={value}"},

    # -- linkedin2username --------------------------------------------------
    "linkedin2username.legal_note": {"it": "Naviga LinkedIn come utente autenticato dell'investigatore. Solo profili pubblici della company.", "en": "Browses LinkedIn as the investigator's authenticated user. Public company profiles only."},
    "linkedin2username.not_configured": {"it": "linkedin2username non configurato (LINKEDIN2U_PYTHON/SCRIPT).", "en": "linkedin2username not configured (LINKEDIN2U_PYTHON/SCRIPT)."},
    "linkedin2username.missing_credentials": {"it": "Credenziali LinkedIn mancanti (LINKEDIN_USER/LINKEDIN_PASS).", "en": "LinkedIn credentials missing (LINKEDIN_USER/LINKEDIN_PASS)."},
    "linkedin2username.invalid_company": {"it": "Nome azienda non valido (max 60 char alfanumerici).", "en": "Invalid company name (max 60 alphanumeric characters)."},
    "linkedin2username.invalid_domain": {"it": "Dominio non valido.", "en": "Invalid domain."},
    "linkedin2username.timeout": {"it": "linkedin2username timeout.", "en": "linkedin2username timeout."},
    "linkedin2username.login_failed": {"it": "Login LinkedIn fallito o account bloccato (challenge?).", "en": "LinkedIn login failed or account locked (challenge?)."},
    "linkedin2username.execution_failed": {"it": "Esecuzione linkedin2username fallita: {exc}", "en": "linkedin2username execution failed: {exc}"},
    "linkedin2username.candidate": {"it": "Username candidato per {company} (probabile). Da confermare con maigret/holehe.", "en": "Candidate username for {company} (likely). To be confirmed with maigret/holehe."},

    # -- maigret ------------------------------------------------------------
    "maigret.legal_note": {"it": "Esegue Maigret in locale su URL pubbliche. Nessun login. Solo profili 'Claimed'.", "en": "Runs Maigret locally against public URLs. No login. 'Claimed' profiles only."},
    "maigret.not_configured": {"it": "Maigret non configurato. Setta MAIGRET_PYTHON (o MAIGRET_CMD) nel .env. Fallback: sherlock_lite.", "en": "Maigret not configured. Set MAIGRET_PYTHON (or MAIGRET_CMD) in the .env file. Fallback: sherlock_lite."},
    "maigret.invalid_username": {"it": "Username non valido.", "en": "Invalid username."},
    "maigret.exec_failed": {"it": "Esecuzione Maigret fallita: {error}", "en": "Maigret execution failed: {error}"},
    "maigret.profile_confirmed": {"it": "Profilo confermato da Maigret su {site} (detection per-sito).{tag_note}", "en": "Profile confirmed by Maigret on {site} (per-site detection).{tag_note}"},
    "maigret.tag_suffix": {"it": " Tag: {tags}.", "en": " Tags: {tags}."},
    "maigret.why_linked": {"it": "Maigret ha marcato '{username}' come Claimed su {site}", "en": "Maigret marked '{username}' as Claimed on {site}"},

    # -- misp ---------------------------------------------------------------
    "misp.legal_note": {"it": "Interroga un MISP privato configurato dall'operatore. Nessun dato lascia il perimetro.", "en": "Queries a private MISP instance configured by the operator. No data leaves the perimeter."},
    "misp.not_configured": {"it": "MISP non configurato. Setta MISP_URL e MISP_KEY nel .env sulla VM.", "en": "MISP not configured. Set MISP_URL and MISP_KEY in the .env file on the VM."},
    "misp.empty_target": {"it": "Target vuoto.", "en": "Empty target."},
    "misp.unreachable_or_auth": {"it": "MISP non raggiungibile o autenticazione fallita.", "en": "MISP unreachable or authentication failed."},
    "misp.attribute": {"it": "Attributo MISP [{category}]. {comment} {to_ids}", "en": "MISP attribute [{category}]. {comment} {to_ids}"},
    "misp.no_attributes": {"it": "Nessun attributo MISP per il target.", "en": "No MISP attributes for the target."},

    # -- nominatim ----------------------------------------------------------
    "nominatim.legal_note": {"it": "Nominatim free tier richiede User-Agent identificativo e ~1 req/s. Rispetta le linee guida OSM.", "en": "The free Nominatim tier requires an identifying User-Agent and ~1 req/s. Follow the OSM usage guidelines."},
    "nominatim.empty_query": {"it": "Nominatim: query vuota.", "en": "Nominatim: empty query."},
    "nominatim.result": {"it": "Nominatim (OSM): {display_name}", "en": "Nominatim (OSM): {display_name}"},

    # -- phishtank ----------------------------------------------------------
    "phishtank.legal_note": {"it": "PhishTank: DB pubblico di URL di phishing (community-verified).", "en": "PhishTank: public database of phishing URLs (community-verified)."},
    "phishtank.match_found": {"it": "URL corrisponde a segnalazione PhishTank verificata (id {id}).", "en": "URL matches a verified PhishTank submission (id {id})."},

    # -- phone_footprint ----------------------------------------------------
    "phone_footprint.legal_note": {"it": "Deriva OSINT pivots da un numero. Nessuna API BYOK, solo euristiche locali.", "en": "Derives OSINT pivots from a phone number. No BYOK API, only local heuristics."},
    "phone_footprint.empty_number": {"it": "Numero vuoto.", "en": "Empty phone number."},
    "phone_footprint.invalid_no_footprint": {"it": "Numero non valido: nessun footprint derivabile.", "en": "Invalid number: no footprint can be derived."},
    "phone_footprint.module_missing": {"it": "phonenumbers non installato (pip install phonenumbers).", "en": "phonenumbers not installed (pip install phonenumbers)."},
    "phone_footprint.parse_failed": {"it": "Parsing numero fallito: {exc}", "en": "Phone number parsing failed: {exc}"},
    "phone_footprint.pivot": {"it": "Pivot phone footprint: {pivot}", "en": "Phone footprint pivot: {pivot}"},

    # -- phone_meta ---------------------------------------------------------
    "phone_meta.legal_note": {"it": "Metadata locali su numero (nazione, tipo, carrier). Nessuna chiamata verso servizi esterni.", "en": "Local metadata for a phone number (country, type, carrier). No calls to external services."},
    "phone_meta.empty_number": {"it": "Numero vuoto.", "en": "Empty phone number."},
    "phone_meta.invalid_syntax": {"it": "Sintassi numero non valida (usa E.164, es. +39...).", "en": "Invalid phone syntax (use E.164, e.g. +39...)."},
    "phone_meta.module_missing": {"it": "phonenumbers non installato (pip install phonenumbers).", "en": "phonenumbers not installed (pip install phonenumbers)."},
    "phone_meta.parse_failed": {"it": "Parsing numero fallito: {exc}", "en": "Phone number parsing failed: {exc}"},
    "phone_meta.type_inferred": {"it": "Tipo linea dedotto: {type}.", "en": "Line type inferred: {type}."},
    "phone_meta.carrier_historic": {"it": "Carrier storico (potrebbe essere portato): {carrier}.", "en": "Historic carrier (may have been ported): {carrier}."},

    # -- port_scan ----------------------------------------------------------
    "port_scan.legal_note": {"it": "Scan attivo TCP: richiede scope autorizzato del caso.", "en": "Active TCP scan: requires the case's authorized scope."},
    "port_scan.empty_target": {"it": "Target vuoto.", "en": "Empty target."},
    "port_scan.resolve_failed": {"it": "Impossibile risolvere {target}.", "en": "Unable to resolve {target}."},
    "port_scan.port_open": {"it": "Porta TCP aperta su {host}: {port}.", "en": "Open TCP port on {host}: {port}."},
    "port_scan.banner": {"it": "Banner rilevato su {host}:{port}: {banner}", "en": "Banner detected on {host}:{port}: {banner}"},
    "port_scan.risky": {"it": "Porta {port} tipicamente ad alto rischio: verificare esposizione.", "en": "Port {port} is typically high-risk: verify exposure."},

    # -- rdap ---------------------------------------------------------------
    "rdap.invalid_domain": {"it": "Target non è un dominio valido.", "en": "Target is not a valid domain."},
    "rdap.unavailable": {"it": "RDAP non disponibile per '{target}'.", "en": "RDAP not available for '{target}'."},
    "rdap.registrar": {"it": "Registrar ufficiale dal registro RDAP.", "en": "Official registrar from the RDAP registry."},
    "rdap.created": {"it": "Data di registrazione del dominio.", "en": "Domain registration date."},
    "rdap.expiry": {"it": "Data di scadenza del dominio.", "en": "Domain expiration date."},
    "rdap.nameserver": {"it": "Nameserver dal registro RDAP.", "en": "Nameserver from the RDAP registry."},
    "rdap.status": {"it": "Stato del dominio: {s}.", "en": "Domain status: {s}."},

    # -- sec_edgar ----------------------------------------------------------
    "sec_edgar.legal_note": {"it": "SEC EDGAR: documenti pubblici SEC. User-Agent identificativo richiesto.", "en": "SEC EDGAR: public SEC filings. Identifying User-Agent required."},

    # -- shodan -------------------------------------------------------------
    "shodan.invalid_ip": {"it": "IP non valido: {ip}", "en": "Invalid IP: {ip}"},
    "shodan.resolve_failed": {"it": "Impossibile risolvere '{target}' in IP per query Shodan.", "en": "Unable to resolve '{target}' to an IP for the Shodan query."},
    "shodan.no_data": {"it": "Shodan non ha dati per {ip}.", "en": "Shodan has no data for {ip}."},
    "shodan.open_port": {"it": "Porta aperta rilevata da Shodan: {svc_label}.", "en": "Open port detected by Shodan: {svc_label}."},
    "shodan.hostname": {"it": "Hostname associato all'IP {ip} da Shodan.", "en": "Hostname associated with IP {ip} by Shodan."},
    "shodan.os": {"it": "Sistema operativo rilevato da Shodan su {ip}.", "en": "Operating system detected by Shodan on {ip}."},
    "shodan.cpe": {"it": "Tecnologia rilevata via Shodan su {ip}:{port}.", "en": "Technology detected via Shodan on {ip}:{port}."},
    "shodan.vuln": {"it": "Vulnerabilità segnalata da Shodan su {ip}:{port} — verificare manualmente.", "en": "Vulnerability reported by Shodan on {ip}:{port} — verify manually."},

    # -- shodan_internetdb --------------------------------------------------
    "shodan_internetdb.legal_note": {"it": "Endpoint pubblico gratuito Shodan InternetDB. Solo dati già indicizzati, nessuna scansione attiva.", "en": "Free public Shodan InternetDB endpoint. Indexed data only, no active scanning."},
    "shodan_internetdb.invalid_ip": {"it": "Target non è un IP valido.", "en": "Target is not a valid IP."},
    "shodan_internetdb.not_in_db": {"it": "InternetDB non ha dati indicizzati per {ip}.", "en": "InternetDB has no indexed data for {ip}."},
    "shodan_internetdb.open_port": {"it": "Porta osservata da Shodan su {ip} (indicizzata, non scan live).", "en": "Port observed by Shodan on {ip} (indexed, not a live scan)."},
    "shodan_internetdb.cpe": {"it": "CPE (software/versione) inferito da Shodan.", "en": "CPE (software/version) inferred by Shodan."},
    "shodan_internetdb.vuln": {"it": "CVE potenziale associato a {ip} da Shodan. Verificare versione reale.", "en": "Potential CVE associated with {ip} by Shodan. Verify the actual version."},

    # -- ripe_stat ------------------------------------------------------------
    "ripe_stat.legal_note": {"it": "API pubblica gratuita RIPE NCC (Regional Internet Registry). Solo dati di routing/allocazione già pubblicati, nessuna scansione attiva.", "en": "Free public RIPE NCC (Regional Internet Registry) API. Only already-published routing/allocation data, no active scanning."},
    "ripe_stat.invalid_ip": {"it": "Target non è un IP valido.", "en": "Target is not a valid IP."},
    "ripe_stat.prefix_note": {"it": "Prefisso di rete che annuncia {ip} secondo RIPEstat.", "en": "Network prefix announcing {ip} per RIPEstat."},
    "ripe_stat.asn_note": {"it": "Sistema autonomo (ASN) responsabile del routing di questo IP.", "en": "Autonomous system (ASN) responsible for routing this IP."},
    "ripe_stat.abuse_note": {"it": "Contatto abuse ufficiale registrato per questo netblock — canale legittimo per segnalazioni.", "en": "Official abuse contact registered for this netblock — legitimate reporting channel."},

    # -- hackertarget -----------------------------------------------------
    "hackertarget.legal_note": {"it": "Endpoint gratuito HackerTarget (rate-limitato). Correlazione infrastrutturale passiva, nessuna scansione del target.", "en": "Free HackerTarget endpoint (rate-limited). Passive infrastructure correlation, no scanning of the target."},
    "hackertarget.invalid_ip": {"it": "Target non è un IP valido.", "en": "Target is not a valid IP."},
    "hackertarget.no_hosts": {"it": "Nessun altro dominio noto sullo stesso IP {ip} (o rate limit API esaurito).", "en": "No other known domains on the same IP {ip} (or API rate limit exhausted)."},
    "hackertarget.cohosted_note": {"it": "Dominio che risolve sullo stesso IP {ip} — possibile stesso operatore/hosting condiviso, verificare.", "en": "Domain resolving to the same IP {ip} — possible same operator/shared hosting, verify."},

    # -- wikipedia_search -----------------------------------------------------
    "wikipedia_search.legal_note": {"it": "API pubblica Wikipedia (REST search), nessuna chiave. Wikipedia non è fonte primaria: usare come contesto iniziale, verificare le fonti citate in nota.", "en": "Public Wikipedia REST search API, no key. Wikipedia is not a primary source: use as initial context, verify the sources cited in its references."},
    "wikipedia_search.empty_target": {"it": "Target vuoto.", "en": "Empty target."},
    "wikipedia_search.no_match": {"it": "Nessuna voce Wikipedia trovata per '{query}'.", "en": "No Wikipedia article found for '{query}'."},
    "wikipedia_search.article_note": {"it": "Voce Wikipedia ({lang}) — verificare le fonti primarie citate nella pagina.", "en": "Wikipedia article ({lang}) — verify the primary sources cited on the page."},

    # -- subdomain_enum -----------------------------------------------------
    "subdomain_enum.legal_note": {"it": "Fonti passive (CT logs) + risoluzione DNS di prefissi comuni. Nessuno scan attivo del target.", "en": "Passive sources (CT logs) + DNS resolution of common prefixes. No active scanning of the target."},
    "subdomain_enum.invalid_domain": {"it": "Target deve essere un dominio.", "en": "Target must be a domain."},
    "subdomain_enum.active_sub": {"it": "Sottodominio attivo → {resolved_host}. Fonte: {source}.", "en": "Active subdomain → {resolved_host}. Source: {source}."},
    "subdomain_enum.historic_sub": {"it": "Sottodominio in CT log ma non risolve ora (storico/dismesso).", "en": "Subdomain in CT logs but does not resolve now (historic/dismissed)."},

    # -- telegram_checker ---------------------------------------------------
    "telegram_checker.legal_note": {"it": "Usa l'API Telegram con le credenziali dell'investigatore. Solo dati pubblici del profilo.", "en": "Uses the Telegram API with the investigator's credentials. Public profile data only."},
    "telegram_checker.not_configured": {"it": "telegram-checker non configurato (TELEGRAM_CMD).", "en": "telegram-checker not configured (TELEGRAM_CMD)."},
    "telegram_checker.missing_credentials": {"it": "Credenziali Telegram mancanti (TELEGRAM_API_ID, TELEGRAM_API_HASH, TELEGRAM_PHONE).", "en": "Telegram credentials missing (TELEGRAM_API_ID, TELEGRAM_API_HASH, TELEGRAM_PHONE)."},
    "telegram_checker.invalid_number": {"it": "Numero non valido (usa E.164, es. +39...).", "en": "Invalid phone number (use E.164, e.g. +39...)."},
    "telegram_checker.timeout": {"it": "telegram-checker timeout.", "en": "telegram-checker timeout."},
    "telegram_checker.exec_failed": {"it": "Esecuzione telegram-checker fallita: {exc}", "en": "telegram-checker execution failed: {exc}"},

    # -- theharvester -------------------------------------------------------
    "theharvester.legal_note": {"it": "Raccolta passiva da fonti pubbliche (CT logs, motori, DNS aggregatori). Nessun contatto diretto col target.", "en": "Passive collection from public sources (CT logs, search engines, DNS aggregators). No direct contact with the target."},
    "theharvester.not_configured": {"it": "theHarvester non configurato. Setta THEHARVESTER_CMD (o THEHARVESTER_PYTHON) nel .env.", "en": "theHarvester not configured. Set THEHARVESTER_CMD (or THEHARVESTER_PYTHON) in the .env file."},
    "theharvester.invalid_domain": {"it": "Target deve essere un dominio valido.", "en": "Target must be a valid domain."},
    "theharvester.exec_failed": {"it": "Esecuzione theHarvester fallita: {reason}", "en": "theHarvester execution failed: {reason}"},
    "theharvester.email_public": {"it": "Email raccolta da fonti pubbliche per il dominio {domain}", "en": "Email collected from public sources for domain {domain}"},
    "theharvester.email_why": {"it": "Email raccolta da fonti pubbliche per il dominio {domain}", "en": "Email collected from public sources for domain {domain}"},
    "theharvester.host_note": {"it": "Host/sottodominio di {domain} (theHarvester).", "en": "Host/subdomain of {domain} (theHarvester)."},
    "theharvester.ip_note": {"it": "IP associato a {domain} (theHarvester).", "en": "IP associated with {domain} (theHarvester)."},

    # -- threatfox ----------------------------------------------------------
    "threatfox.legal_note": {"it": "Feed IOC community abuse.ch (CC0). Consultazione passiva di reputation nota.", "en": "abuse.ch community IOC feed (CC0). Passive lookup of known reputation."},
    "threatfox.empty_target": {"it": "Target vuoto.", "en": "Empty target."},
    "threatfox.ioc_found": {"it": "IOC ThreatFox: {ioc_type}. Tag: {tags}.", "en": "ThreatFox IOC: {ioc_type}. Tags: {tags}."},
    "threatfox.no_ioc": {"it": "Nessun IOC ThreatFox per questo target (non prova assenza di rischio).", "en": "No ThreatFox IOC for this target (does not prove absence of risk)."},

    # -- url_harvest --------------------------------------------------------
    "url_harvest.legal_note": {"it": "Solo archivi pubblici (Wayback CDX, Common Crawl). Nessun contatto col target.", "en": "Public archives only (Wayback CDX, Common Crawl). No contact with the target."},
    "url_harvest.invalid_target": {"it": "Target deve essere un dominio o URL.", "en": "Target must be a domain or URL."},
    "url_harvest.interesting_endpoint": {"it": "Endpoint potenzialmente interessante (parametri/api/file sensibili).", "en": "Potentially interesting endpoint (parameters/api/sensitive files)."},
    "url_harvest.archived_url": {"it": "URL storica indicizzata da Wayback.", "en": "Historical URL indexed by Wayback."},

    # -- urlscan ------------------------------------------------------------
    "urlscan.domain_observed": {"it": "Dominio osservato in scansione urlscan.io del {date}.", "en": "Domain observed in a urlscan.io scan on {date}."},
    "urlscan.ip_observed": {"it": "IP osservato in scansione urlscan.io del {date}.", "en": "IP observed in a urlscan.io scan on {date}."},
    "urlscan.malicious_notes": {"it": "urlscan.io ha classificato la scansione come malevola.", "en": "urlscan.io classified the scan as malicious."},
    "urlscan.malicious_remediation": {"it": "Bloccare l'URL/dominio e investigare eventuali connessioni.", "en": "Block the URL/domain and investigate any related connections."},

    # -- virustotal ---------------------------------------------------------
    "virustotal.no_response_or_limit": {"it": "VirusTotal: nessuna risposta o rate-limit raggiunto.", "en": "VirusTotal: no response or rate limit reached."},
    "virustotal.detection_notes": {"it": "{malicious}/{total} motori antivirus considerano il target malevolo.", "en": "{malicious}/{total} antivirus engines flag the target as malicious."},
    "virustotal.detection_remediation": {"it": "Bloccare il target su firewall/EDR. Investigare eventuali connessioni.", "en": "Block the target on firewall/EDR. Investigate any related connections."},
    "virustotal.reputation_notes": {"it": "VirusTotal reputation score: {reputation}.", "en": "VirusTotal reputation score: {reputation}."},
    "virustotal.category_notes": {"it": "Categoria VirusTotal ({vendor}): {category}.", "en": "VirusTotal category ({vendor}): {category}."},

    # (generic.no_key / generic.error / generic.no_response already defined
    # at the top of this catalog; the connector code shares those single
    # authoritative entries.)

    # -- brave_search_api ---------------------------------------------------
    "brave_search_api.legal_note": {"it": "Brave Search API: BYOK richiesto. ToS Brave applicabile.", "en": "Brave Search API: BYOK required. Brave Terms of Service apply."},
    "brave_search_api.missing_key": {"it": "Brave Search richiede API key (BYOK).", "en": "Brave Search requires an API key (BYOK)."},
    "brave_search_api.result_note": {"it": "Brave Search: {description}", "en": "Brave Search: {description}"},

    # -- influencers_club ---------------------------------------------------
    "influencers_club.legal_note": {"it": "Servizio SaaS a pagamento (influencers.club). Restituisce email di creator/business associate a un username. BYOK dell'analista.", "en": "Paid SaaS service (influencers.club). Returns emails of creators/businesses associated with a username. Analyst's BYOK."},
    "influencers_club.missing_key": {"it": "INFLUENCERS_CLUB_API_KEY non configurata.", "en": "INFLUENCERS_CLUB_API_KEY not configured."},
    "influencers_club.invalid_username": {"it": "Username non valido.", "en": "Invalid username."},
    "influencers_club.auth_or_quota": {"it": "Chiave Influencers Club non valida o quota esaurita.", "en": "Influencers Club key invalid or quota exhausted."},
    "influencers_club.rate_limit": {"it": "Rate limit Influencers Club.", "en": "Influencers Club rate limit."},
    "influencers_club.unreachable": {"it": "Influencers Club non raggiungibile.", "en": "Influencers Club unreachable."},
    "influencers_club.no_match": {"it": "Nessun match per @{username}.", "en": "No match for @{username}."},
    "influencers_club.email_public": {"it": "Email pubblica di @{username} (Influencers Club).", "en": "Public email of @{username} (Influencers Club)."},
    "influencers_club.email_why": {"it": "Influencers Club ha collegato @{username} all'email", "en": "Influencers Club linked @{username} to the email"},
    "influencers_club.field_note": {"it": "Campo '{field}' da Influencers Club per @{username}.", "en": "Field '{field}' from Influencers Club for @{username}."},

    # -- contactout -----------------------------------------------------
    "contactout.legal_note": {"it": "Servizio SaaS a pagamento (ContactOut). Restituisce email/telefoni personali associati a un profilo LinkedIn o a un indirizzo email. BYOK dell'analista.", "en": "Paid SaaS service (ContactOut). Returns personal emails/phones associated with a LinkedIn profile or an email address. Analyst's BYOK."},
    "contactout.missing_key": {"it": "CONTACTOUT_API_KEY non configurata.", "en": "CONTACTOUT_API_KEY not configured."},
    "contactout.empty_target": {"it": "Target vuoto.", "en": "Empty target."},
    "contactout.invalid_target": {"it": "Target non valido: serve un URL profilo LinkedIn o un indirizzo email.", "en": "Invalid target: needs a LinkedIn profile URL or an email address."},
    "contactout.auth_or_quota": {"it": "Chiave ContactOut non valida o quota esaurita.", "en": "ContactOut key invalid or quota exhausted."},
    "contactout.rate_limit": {"it": "Rate limit ContactOut.", "en": "ContactOut rate limit."},
    "contactout.unreachable": {"it": "ContactOut non raggiungibile.", "en": "ContactOut unreachable."},
    "contactout.no_match": {"it": "Nessun match per {target}.", "en": "No match for {target}."},
    "contactout.email_remediation": {"it": "Valutare l'esposizione dell'email personale/professionale su servizi di terze parti.", "en": "Assess exposure of the personal/professional email on third-party services."},
    "contactout.email_found": {"it": "Email trovata da ContactOut per {target}.", "en": "Email found by ContactOut for {target}."},
    "contactout.phone_found": {"it": "Telefono trovato da ContactOut per {target}.", "en": "Phone found by ContactOut for {target}."},
    "contactout.name_found": {"it": "Nome dal profilo (ContactOut).", "en": "Name from profile (ContactOut)."},

    # -- lusha ------------------------------------------------------------
    "lusha.legal_note": {"it": "Servizio SaaS a pagamento (Lusha). Restituisce email/telefoni professionali associati a un profilo LinkedIn o a un indirizzo email. BYOK dell'analista.", "en": "Paid SaaS service (Lusha). Returns professional emails/phones associated with a LinkedIn profile or an email address. Analyst's BYOK."},
    "lusha.missing_key": {"it": "LUSHA_API_KEY non configurata.", "en": "LUSHA_API_KEY not configured."},
    "lusha.empty_target": {"it": "Target vuoto.", "en": "Empty target."},
    "lusha.invalid_target": {"it": "Target non valido: serve un URL profilo LinkedIn o un indirizzo email.", "en": "Invalid target: needs a LinkedIn profile URL or an email address."},
    "lusha.auth_or_quota": {"it": "Chiave Lusha non valida o quota esaurita.", "en": "Lusha key invalid or quota exhausted."},
    "lusha.rate_limit": {"it": "Rate limit Lusha.", "en": "Lusha rate limit."},
    "lusha.unreachable": {"it": "Lusha non raggiungibile.", "en": "Lusha unreachable."},
    "lusha.no_match": {"it": "Nessun match per {target}.", "en": "No match for {target}."},
    "lusha.email_remediation": {"it": "Valutare l'esposizione dell'email personale/professionale su servizi di terze parti.", "en": "Assess exposure of the personal/professional email on third-party services."},
    "lusha.email_found": {"it": "Email trovata da Lusha per {target}.", "en": "Email found by Lusha for {target}."},
    "lusha.phone_found": {"it": "Telefono trovato da Lusha per {target}.", "en": "Phone found by Lusha for {target}."},
    "lusha.name_found": {"it": "Nome dal profilo (Lusha).", "en": "Name from profile (Lusha)."},

    # -- ai_agents (LLM, opt-in) ----------------------------------------
    "ai_agents.disclaimer": {"it": "Generato da AI — non verificato. Verifica ogni citazione contro la tabella evidenze.", "en": "AI-generated — unverified. Verify every citation against the evidence table."},
    "ai_agents.not_enabled": {"it": "Arricchimento AI non abilitato per questo caso.", "en": "AI enrichment is not enabled for this case."},
    "ai_agents.no_key": {"it": "Nessuna chiave AI configurata (Anthropic/OpenAI/endpoint locale).", "en": "No AI key configured (Anthropic/OpenAI/local endpoint)."},
    "ai_agents.triage_fallback_rationale": {"it": "(fallback: nessuna valutazione AI ricevuta)", "en": "(fallback: no AI assessment received)"},
    "ai_agents.hallucinated_dropped": {"it": "{n} elementi scartati: l'AI ha citato ID non esistenti.", "en": "{n} items dropped: the AI referenced non-existent IDs."},
    "ai_agents.narrative_failed": {"it": "Generazione narrativa fallita: {error}", "en": "Narrative generation failed: {error}"},
    "ai_agents.truncated_note": {"it": "Nota: {sent} finding su {total} inviati (troncato per dimensione).", "en": "Note: {sent} of {total} findings sent (truncated for size)."},
}


def t(key: str, lang: str = DEFAULT_LANG, /, **params: object) -> str:
    """Resolve ``key`` for ``lang`` and interpolate ``params``.

    Falls back Italian → raw key, and never raises on a missing param
    (a formatting error yields the un-interpolated template).
    """
    if lang not in SUPPORTED_LANGS:
        lang = DEFAULT_LANG
    entry = CATALOG.get(key)
    if not entry:
        return key
    template = entry.get(lang) or entry.get(DEFAULT_LANG) or key
    if not params:
        return template
    try:
        return template.format(**params)
    except (KeyError, IndexError, ValueError):
        return template


def has(key: str) -> bool:
    """True if ``key`` exists in the catalog (used by tests/CI checks)."""
    return key in CATALOG
