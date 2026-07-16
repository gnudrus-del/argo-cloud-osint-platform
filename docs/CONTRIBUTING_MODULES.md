# Guida per contribuire nuovi moduli OSINT

Questa guida descrive il contratto minimo per aggiungere un modulo senza modificare il core della pipeline. Un modulo deve essere isolato, avere input tipizzato, restituire JSON normalizzato e rispettare i guardrail legali/OPSEC.

## Regola di base

Un nuovo tool non deve chiamare direttamente la UI, il report o il job runner. Deve esporre un plugin registrabile e lasciare al core il compito di orchestrare, tracciare e compilare il report.

## Contratto plugin

Il plugin riceve un `PluginContext`:

```python
PluginContext(
    target="example.com",
    target_type="domain",
    confirm_authorization=True,
    include_contact=False,
    allow_network_scan=False,
    timeout=30,
    source_route="standard",
)
```

Il plugin restituisce un `PluginResult`:

```python
PluginResult(
    plugin="example_plugin",
    status="ok",
    started_at=started,
    finished_at=time.time(),
    findings=[...],
    output={"raw": "..."},
    error="",
    warnings=[],
)
```

Status consigliati:

- `ok`: modulo eseguito e completato.
- `skipped`: modulo bloccato da guardrail, autorizzazione mancante o target non compatibile.
- `missing`: tool non installato o API key assente.
- `timeout`: esecuzione oltre il tempo massimo.
- `error`: errore tecnico non previsto.
- `manual_setup`: tool presente ma non configurato.

## Output normalizzato

Ogni dato utile deve diventare un `Finding` con:

- `kind`: tipo stabile, per esempio `external_sherlock_profile`, `contact_email`, `related_domain`.
- `value`: valore normalizzato.
- `confidence`: numero tra `0.0` e `1.0`.
- `evidence`: URL, titolo e breve citazione verificabile.
- `notes`: chiarimento operativo, soprattutto quando serve verifica manuale.

Non trasformare dork, ipotesi o semplici query in fatti. Il report separa fatti osservati, inferenze e ipotesi operative: il plugin deve fornire evidenze, non conclusioni non supportate.

Per come assegnare `confidence`, `source_reliability`/`info_credibility` (grado Admiralty/NATO) e `severity` in modo coerente con gli altri 63 connettori — non "a sensazione" — vedi [`METHODOLOGY.md`](METHODOLOGY.md).

## Guardrail obbligatori

- Le azioni passive devono essere default.
- Network scan, dark/deep web, login-gated e qualunque azione attiva devono richiedere autorizzazione esplicita lato server.
- Non estrarre o inferire dati privati non pubblici, come email o telefono di registrazione di social.
- Non registrare API key, cookie, token, credenziali o dati personali dell'analista nei log.
- Redigere email e telefono quando `include_contact` e falso.
- Se il modulo fallisce, restituire errore strutturato e lasciare proseguire la pipeline.

## Esempio minimo

```python
import time

from osint_bot.models import Evidence, Finding
from osint_bot.plugins import PluginContext, PluginRegistry, PluginResult


class ExamplePlugin:
    name = "example_plugin"
    passive = True
    gated = False

    def run(self, context: PluginContext) -> PluginResult:
        started = time.time()
        if context.target_type not in {"domain", "company"}:
            return PluginResult(
                plugin=self.name,
                status="skipped",
                started_at=started,
                finished_at=time.time(),
                error="Target non compatibile con il modulo.",
            )

        finding = Finding(
            kind="related_domain",
            value=context.target,
            confidence=0.5,
            evidence=[Evidence(url=f"https://{context.target}", title=context.target)],
            notes="Evidenza pubblica da verificare manualmente.",
        )
        return PluginResult(
            plugin=self.name,
            status="ok",
            started_at=started,
            finished_at=time.time(),
            findings=[finding],
        )


registry = PluginRegistry()
registry.register(ExamplePlugin())
```

## Test richiesti

Per ogni modulo nuovo aggiungere almeno:

- test di successo con output normalizzato;
- test di target non compatibile o autorizzazione mancante;
- test di timeout/errore o tool mancante;
- test che nessun dato sensibile finisca in output quando non autorizzato.

Comandi:

```powershell
python -m unittest discover -s tests
python -m compileall osint_bot
```

## Documentazione modulo

Ogni modulo deve dichiarare:

- fonti interrogate;
- tipo di OSINT: passivo, attivo/gated, login-gated;
- API key richieste;
- limiti noti e falsi positivi comuni;
- campi `Finding` prodotti;
- indicazioni di verifica manuale.

