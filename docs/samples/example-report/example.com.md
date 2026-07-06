# Rapporto investigativo OSINT - example.com

**Tipo obiettivo:** `domain`  
**Generato:** `2026-07-06T13:29:26+00:00`

## Sintesi discorsiva

La ricerca su **example.com** ha prodotto **4 evidenze organizzate**. Le aree piu rilevanti sono: copertura web, domini e sottodomini, presenza web, piano HUMINT etico. Sono state acquisite 1 pagine pubbliche e 54 fonti/risultati iniziali. Il quadro va letto come una mappa investigativa: utile per orientare verifiche, non come attribuzione definitiva.

## Copertura della ricerca

La raccolta ha usato questi provider o seed: **bing_dork, censys_link, duckduckgo_dork, google_dork, hunter_link, intelx_link, seed, shodan_link, wayback_link, yandex_dork**. Sono state preparate **15 query** e sono state lette **1 pagine**. Non risulta configurata una API di ricerca web: per copertura ampia imposta `BING_SEARCH_API_KEY` o un provider equivalente.

## Query e dork utilizzati

- `example.com`
- `"example.com"`
- `site:example.com`
- `example.com security.txt`
- `example.com privacy policy`
- `example.com filetype:pdf`
- `"example.com"`
- `site:example.com`
- `site:example.com filetype:pdf`
- `site:example.com filetype:xls OR filetype:xlsx`
- `site:example.com intitle:index.of`
- `site:example.com inurl:admin OR inurl:login`
- `site:example.com intext:"api_key" OR intext:"token" OR intext:"secret"`
- `site:github.com "example.com"`
- `site:crt.sh "example.com"`

## Cosa emerge

### Copertura web

Sono state raccolte 1 evidenze nella categoria copertura web.

- **1 pagine lette, 0 non disponibili** — grado **B2** — confidenza alta (`0.80`).
  Copertura web basata su fonti pubbliche e URL seed/API.
  Fonte: [Example Domain](https://example.com/).

### Domini e sottodomini

Sono state raccolte 1 evidenze nella categoria domini e sottodomini.

- **example.com** — grado **B2** — confidenza media (`0.55`).
  Dominio o sottodominio rilevato da fonti pubbliche.
  Fonte: [https://example.com/](https://example.com/).

### Presenza web

Sono state raccolte 1 evidenze nella categoria presenza web.

- **example.com** — grado **B2** — confidenza media (`0.55`).
  1 evidenze raccolte su questo host.
  Fonte: [Example Domain](https://example.com/).

### Piano humint etico

Sono state raccolte 1 evidenze nella categoria piano HUMINT etico.

- **consent_based_open_questions** — grado **F6** — confidenza alta (`0.80`).
  Usare per interviste consensuali o analisi di fonti pubbliche, non per elicitazione ingannevole.

## Entita e relazioni

### Entita normalizzate

- **example.com** (`domain`) grado `B2` confidenza `0.90` - fonti: 12
- **iana.org** (`domain`) grado `F6` confidenza `0.50` - fonti: 1
- **https://example.com** (`url`) grado `F6` confidenza `0.45` - fonti: 2
- **https://example.com/.well-known/security.txt** (`url`) grado `F6` confidenza `0.45` - fonti: 1
- **https://example.com/about** (`url`) grado `F6` confidenza `0.45` - fonti: 1
- **https://example.com/about-us** (`url`) grado `F6` confidenza `0.45` - fonti: 1
- **https://example.com/careers** (`url`) grado `F6` confidenza `0.45` - fonti: 1
- **https://example.com/contact** (`url`) grado `F6` confidenza `0.45` - fonti: 1
- **https://example.com/privacy** (`url`) grado `F6` confidenza `0.45` - fonti: 1
- **https://example.com/robots.txt** (`url`) grado `F6` confidenza `0.45` - fonti: 1
- **https://example.com/sitemap.xml** (`url`) grado `F6` confidenza `0.45` - fonti: 1
- **https://example.com/terms** (`url`) grado `F6` confidenza `0.45` - fonti: 1
- **https://iana.org/domains/example** (`url`) grado `F6` confidenza `0.45` - fonti: 1
- **https://www.example.com** (`url`) grado `F6` confidenza `0.45` - fonti: 1
- Altre 54 entita tecniche o di dettaglio nella versione JSON.

### Relazioni principali

- **example.com** -> **https://example.com** (`observed_page`, `0.50`); fonte: https://example.com/
- **example.com** -> **https://example.com** (`searched_or_seeded`, `0.35`); fonte: https://example.com/
- **example.com** -> **https://example.com/.well-known/security.txt** (`searched_or_seeded`, `0.35`); fonte: https://example.com/.well-known/security.txt
- **example.com** -> **https://example.com/about** (`searched_or_seeded`, `0.35`); fonte: https://example.com/about
- **example.com** -> **https://example.com/about-us** (`searched_or_seeded`, `0.35`); fonte: https://example.com/about-us
- **example.com** -> **https://example.com/careers** (`searched_or_seeded`, `0.35`); fonte: https://example.com/careers
- **example.com** -> **https://example.com/contact** (`searched_or_seeded`, `0.35`); fonte: https://example.com/contact
- **example.com** -> **https://example.com/privacy** (`searched_or_seeded`, `0.35`); fonte: https://example.com/privacy
- **example.com** -> **https://example.com/robots.txt** (`searched_or_seeded`, `0.35`); fonte: https://example.com/robots.txt
- **example.com** -> **https://example.com/sitemap.xml** (`searched_or_seeded`, `0.35`); fonte: https://example.com/sitemap.xml
- **example.com** -> **https://example.com/terms** (`searched_or_seeded`, `0.35`); fonte: https://example.com/terms
- **example.com** -> **https://www.example.com** (`searched_or_seeded`, `0.35`); fonte: https://www.example.com/
- **https://example.com** -> **https://iana.org/domains/example** (`links_to`, `0.35`); fonte: https://example.com/
- **https://example.com** -> **example.com** (`hosted_on`, `0.50`); fonte: https://example.com/
- **https://example.com/.well-known/security.txt** -> **example.com** (`hosted_on`, `0.50`); fonte: https://example.com/.well-known/security.txt
- **https://example.com/about** -> **example.com** (`hosted_on`, `0.50`); fonte: https://example.com/about
- **https://example.com/about-us** -> **example.com** (`hosted_on`, `0.50`); fonte: https://example.com/about-us
- **https://example.com/careers** -> **example.com** (`hosted_on`, `0.50`); fonte: https://example.com/careers
- **https://example.com/contact** -> **example.com** (`hosted_on`, `0.50`); fonte: https://example.com/contact
- **https://example.com/privacy** -> **example.com** (`hosted_on`, `0.50`); fonte: https://example.com/privacy
- **https://example.com/robots.txt** -> **example.com** (`hosted_on`, `0.50`); fonte: https://example.com/robots.txt
- **https://example.com/sitemap.xml** -> **example.com** (`hosted_on`, `0.50`); fonte: https://example.com/sitemap.xml
- **https://example.com/terms** -> **example.com** (`hosted_on`, `0.50`); fonte: https://example.com/terms
- **https://iana.org/domains/example** -> **iana.org** (`hosted_on`, `0.50`); fonte: https://iana.org/domains/example
- **https://www.example.com** -> **example.com** (`hosted_on`, `0.50`); fonte: https://www.example.com/
- Altre 86 relazioni tecniche o di dettaglio nella versione JSON.

## Fascicolo finale: fatti, inferenze e ipotesi

### Fatti osservati

- Fatto osservato: **1 pagine lette, 0 non disponibili** nella categoria **copertura web**. Fonte primaria: [Example Domain](https://example.com/).
- Fatto osservato: **example.com** nella categoria **domini e sottodomini**. Fonte primaria: [https://example.com/](https://example.com/).
- Fatto osservato: **example.com** nella categoria **presenza web**. Fonte primaria: [Example Domain](https://example.com/).
- Fatto osservato: **consent_based_open_questions** nella categoria **piano HUMINT etico**. Fonte primaria: output agente.

### Inferenze

- Inferenza: la **copertura web** descrive l'ampiezza e i limiti della raccolta; non prova da sola presenza, attribuzione o esposizione.
- Inferenza: le evidenze di **domini e sottodomini** indicano una presenza web mappabile e utile per ricostruire il perimetro pubblico.
- Inferenza: le evidenze di **presenza web** indicano una presenza web mappabile e utile per ricostruire il perimetro pubblico.

### Ipotesi operative

- Ipotesi operativa: il quadro e sottocampionato; configurare `BING_SEARCH_API_KEY` o aggiungere seed affidabili prima di trarre conclusioni.
- Ipotesi operativa: per asset autorizzati, la priorita e confrontare sito ufficiale, sottodomini, archivi e superfici OPSEC pubbliche.

## Checklist di verifica manuale

- Per ogni fonte: aprire il link, annotare autore/data/titolo, salvare eventuale snapshot e segnare se conferma o smentisce il fatto collegato.
- Verifica fonte: [https://example.com/](https://example.com/).
- Verifica fonte: [Example Domain](https://example.com/).
- Verifica fonte: [Example Domain](https://example.com/).

## Valutazione operativa

Il profilo e utile come base di ricognizione. La prossima fase dovrebbe aumentare copertura fonti e qualita delle citazioni.

## Prossimi passi consigliati

- Configurare `BING_SEARCH_API_KEY` per ricerche web ampie e ripetibili.
- Verificare manualmente le evidenze piu importanti aprendo le fonti citate.
- Aggiungere URL seed affidabili quando il motore di ricerca non restituisce risultati.
- Separare fatti osservati, inferenze e ipotesi operative nel fascicolo finale.
- Per red-team autorizzato, abilitare network scan solo su asset propri o con permesso scritto.

## Fonti principali

- [example.com - home](https://example.com/) - `seed` - Fonte seed automatica generata dal planner per arricchire la raccolta iniziale.
- [example.com - home](https://www.example.com/) - `seed` - Fonte seed automatica generata dal planner per arricchire la raccolta iniziale.
- [example.com - about](https://example.com/about) - `seed` - Fonte seed automatica generata dal planner per arricchire la raccolta iniziale.
- [example.com - about-us](https://example.com/about-us) - `seed` - Fonte seed automatica generata dal planner per arricchire la raccolta iniziale.
- [example.com - contact](https://example.com/contact) - `seed` - Fonte seed automatica generata dal planner per arricchire la raccolta iniziale.
- [example.com - privacy](https://example.com/privacy) - `seed` - Fonte seed automatica generata dal planner per arricchire la raccolta iniziale.
- [example.com - terms](https://example.com/terms) - `seed` - Fonte seed automatica generata dal planner per arricchire la raccolta iniziale.
- [example.com - careers](https://example.com/careers) - `seed` - Fonte seed automatica generata dal planner per arricchire la raccolta iniziale.
- [example.com - robots.txt](https://example.com/robots.txt) - `seed` - Fonte seed automatica generata dal planner per arricchire la raccolta iniziale.
- [example.com - sitemap.xml](https://example.com/sitemap.xml) - `seed` - Fonte seed automatica generata dal planner per arricchire la raccolta iniziale.
- [example.com - .well-known/security.txt](https://example.com/.well-known/security.txt) - `seed` - Fonte seed automatica generata dal planner per arricchire la raccolta iniziale.
- [Certificate Transparency per example.com](https://crt.sh/?q=%25.example.com) - `seed` - Fonte seed automatica generata dal planner per arricchire la raccolta iniziale.
- [URLScan per example.com](https://urlscan.io/search/#domain:example.com) - `seed` - Fonte seed automatica generata dal planner per arricchire la raccolta iniziale.
- [google dork: "example.com"](https://www.google.com/search?q=%22example.com%22) - `google_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [bing dork: "example.com"](https://www.bing.com/search?q=%22example.com%22) - `bing_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [duckduckgo dork: "example.com"](https://duckduckgo.com/?q=%22example.com%22) - `duckduckgo_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [yandex dork: "example.com"](https://yandex.com/search/?text=%22example.com%22) - `yandex_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [google dork: site:example.com](https://www.google.com/search?q=site%3Aexample.com) - `google_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [bing dork: site:example.com](https://www.bing.com/search?q=site%3Aexample.com) - `bing_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [duckduckgo dork: site:example.com](https://duckduckgo.com/?q=site%3Aexample.com) - `duckduckgo_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [yandex dork: site:example.com](https://yandex.com/search/?text=site%3Aexample.com) - `yandex_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [google dork: site:example.com filetype:pdf](https://www.google.com/search?q=site%3Aexample.com+filetype%3Apdf) - `google_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [bing dork: site:example.com filetype:pdf](https://www.bing.com/search?q=site%3Aexample.com+filetype%3Apdf) - `bing_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [duckduckgo dork: site:example.com filetype:pdf](https://duckduckgo.com/?q=site%3Aexample.com+filetype%3Apdf) - `duckduckgo_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [yandex dork: site:example.com filetype:pdf](https://yandex.com/search/?text=site%3Aexample.com+filetype%3Apdf) - `yandex_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [google dork: site:example.com filetype:xls OR filetype:xlsx](https://www.google.com/search?q=site%3Aexample.com+filetype%3Axls+OR+filetype%3Axlsx) - `google_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [bing dork: site:example.com filetype:xls OR filetype:xlsx](https://www.bing.com/search?q=site%3Aexample.com+filetype%3Axls+OR+filetype%3Axlsx) - `bing_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [duckduckgo dork: site:example.com filetype:xls OR filetype:xlsx](https://duckduckgo.com/?q=site%3Aexample.com+filetype%3Axls+OR+filetype%3Axlsx) - `duckduckgo_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [yandex dork: site:example.com filetype:xls OR filetype:xlsx](https://yandex.com/search/?text=site%3Aexample.com+filetype%3Axls+OR+filetype%3Axlsx) - `yandex_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.
- [google dork: site:example.com intitle:index.of](https://www.google.com/search?q=site%3Aexample.com+intitle%3Aindex.of) - `google_dork` - Dork generato automaticamente; aprire manualmente e verificare le fonti risultanti.

## Pagine analizzate

- [Example Domain](https://example.com/) - acquisita

## Stato agenti

- **Pianificatore**: Piano investigativo generato con guardrail difensivi. (`ok`)
  - web: raccogliere fonti pubbliche citabili
  - correlation: separare evidenze osservate da inferenze
  - review: verificare omonimie, attribuzione e attualita
  - network: enumerare solo asset propri o autorizzati
- **Raccolta web**: Copertura web sintetizzata. (`ok`)
- **Strumenti esterni**: Integrazioni esterne eseguite o annotate secondo policy. (`skipped`)
  - Nessun tool esterno selezionato. Usa --external-tool con tool installati localmente.
- **OPSEC**: 0 segnali OPSEC pubblici rilevati. (`ok`)
  - OPSEC: privilegiare remediation difensiva, rotazione segreti e riduzione esposizione.
  - Non eseguire download o accessi a risorse che non sono chiaramente pubbliche e autorizzate.
- **Crypto**: 0 address crypto candidati rilevati. (`ok`)
- **Media**: 0 evidenze media/metadati. (`ok`)
  - Nessun file media locale o riferimento media pubblico analizzato.
- **Geolocalizzazione**: 0 segnali geografici pubblici rilevati. (`ok`)
- **SOCMINT**: 0 riferimenti social pubblici. (`ok`)
  - SOCMINT limitata a contenuti pubblici, citabili e verificabili.
  - Non raccogliere follower, contatti privati, dati di minori o contenuti dietro login.
- **Telefono**: Target non telefonico. (`skipped`)
- **HUMINT**: Piano HUMINT etico generato. (`ok`)
  - HUMINT supportato solo come preparazione etica: obiettivo, consenso, domande aperte, verifica incrociata.
  - Niente pretesti, pressione psicologica, impersonificazione o raccolta di dati personali non necessari.
  - Separare dichiarazioni dirette, inferenze dell'analista e fonti documentali.
- **reverse_account**: Target non email/telefono. (`skipped`)
- **red_team**: Red team richiede --confirm-authorization e target di propria competenza. (`skipped`)

## Affidabilità delle evidenze (Admiralty)

Su **4** evidenze: **3** gold (A1–B2), **0** solide (B3–C2), **0** candidate da verificare (C3–D4), **1** deboli o non valutabili.

Distribuzione per grado:
- `B2` — 3 evidenza/e
- `F6` — 1 evidenza/e

Il grado segue lo standard Admiralty/NATO (STANAG 2511): la prima lettera è l'affidabilità della fonte (A=completamente affidabile, F=non valutabile), il numero è la credibilità dell'informazione (1=confermata, 6=non valutabile).

## Cosa abbiamo eseguito

La pipeline ha completato l'agente Raccolta web con 1 evidenza e l'agente HUMINT con 1 evidenza.
**Pianificatore** — Piano investigativo generato con guardrail difensivi.
**Raccolta web** — Copertura web sintetizzata.
**Strumenti esterni** — Integrazioni esterne eseguite o annotate secondo policy.
**OPSEC** — 0 segnali OPSEC pubblici rilevati.
**Crypto** — 0 address crypto candidati rilevati.
**Media** — 0 evidenze media/metadati.
**Geolocalizzazione** — 0 segnali geografici pubblici rilevati.
**SOCMINT** — 0 riferimenti social pubblici.
**Telefono** — Target non telefonico.
**HUMINT** — Piano HUMINT etico generato.
**Reverse-account** — Target non email/telefono.
**Red team** — Red team richiede --confirm-authorization e target di propria competenza.
Sono stati saltati: Strumenti esterni, Telefono, Reverse-account e Red team — verificare le opzioni `--confirm-authorization`, `--allow-darkweb` o l'idoneità del target.

## Nota metodologica

Questo report separa dati osservati e inferenze. Le evidenze vanno verificate manualmente prima di usarle
in un contesto operativo, legale o investigativo. Per target personali o identificatori individuali applicare
minimizzazione, autorizzazione esplicita e controllo delle omonimie.
