"""Test offline (nessuna rete, nessuna chiamata reale a ``dig``) per il
connector ``email_security``: mocka la funzione interna che invoca il
subprocess ``dig`` (stesso approccio isolato usato per ``dns_query._dig``)
cosi' da validare la logica di parsing/severity in modo deterministico su
qualunque macchina, anche senza ``dig`` installato."""
import unittest
from unittest.mock import patch

from osint_bot.connector import ConnectorContext
from osint_bot.connectors import build_default_registry, email_security


def _dig_map(records: dict[str, list[str]]):
    """Costruisce un side_effect per ``email_security._dig`` che risponde in
    base al nome interrogato (target/_dmarc.target/_mta-sts.target/...)."""
    def _fn(name, rtype, timeout):
        return records.get(name, [])
    return _fn


class EmailSecurityConnectorTests(unittest.TestCase):
    def setUp(self):
        self.reg = build_default_registry()
        self.conns = getattr(self.reg, "_connectors", {})
        self.domain = "example.com"

    def _fetch(self, target, ttype="domain"):
        ctx = ConnectorContext(target=target, target_type=ttype, timeout=5, case_id="T")
        return self.conns["email_security"]._fetch(ctx)

    # ------------------------------------------------------------------
    # Registrazione + input validation
    # ------------------------------------------------------------------
    def test_registered_in_default_registry(self):
        self.assertIn("email_security", self.conns)

    def test_empty_target_is_error(self):
        res = self._fetch("")
        self.assertEqual(res.status, "error")

    def test_dig_totally_unavailable_is_error(self):
        with patch.object(email_security, "_dig", return_value=None), \
             patch.object(email_security, "_dig_dnssec_soa", return_value=None):
            res = self._fetch(self.domain)
        self.assertEqual(res.status, "error")

    # ------------------------------------------------------------------
    # Scenario (a): nessun record TXT ovunque -> finding "missing" per
    # SPF/DMARC/MTA-STS, status comunque "ok" (non e' un errore, e' una
    # postura reale e osservabile).
    # ------------------------------------------------------------------
    def test_no_records_anywhere_yields_missing_findings(self):
        side_effect = _dig_map({})  # tutte le query TXT ritornano []
        with patch.object(email_security, "_dig", side_effect=side_effect), \
             patch.object(email_security, "_dig_dnssec_soa", return_value=None):
            res = self._fetch(self.domain)

        self.assertEqual(res.status, "ok")
        kinds = {f.kind for f in res.findings}
        self.assertIn("spf_missing", kinds)
        self.assertIn("dmarc_missing", kinds)
        self.assertIn("mta_sts_missing", kinds)
        # Nessun finding "hardfail/reject" inventato quando i record non ci sono.
        self.assertNotIn("spf_hardfail", kinds)
        self.assertNotIn("dmarc_policy_reject", kinds)

    # ------------------------------------------------------------------
    # Scenario (b): SPF -all (hardfail) + DMARC p=reject -> nessun finding
    # negativo per SPF/DMARC; al massimo MTA-STS/DNSSEC mancanti.
    # ------------------------------------------------------------------
    def test_hardfail_spf_and_reject_dmarc_are_clean(self):
        records = {
            self.domain: ['"v=spf1 include:_spf.google.com -all"'],
            f"_dmarc.{self.domain}": ['"v=DMARC1; p=reject; pct=100"'],
        }
        with patch.object(email_security, "_dig", side_effect=_dig_map(records)), \
             patch.object(email_security, "_dig_dnssec_soa", return_value=None):
            res = self._fetch(self.domain)

        self.assertEqual(res.status, "ok")
        kinds = {f.kind for f in res.findings}
        self.assertIn("spf_hardfail", kinds)
        self.assertIn("dmarc_policy_reject", kinds)
        self.assertNotIn("spf_missing", kinds)
        self.assertNotIn("spf_permissive", kinds)
        self.assertNotIn("spf_softfail", kinds)
        self.assertNotIn("dmarc_missing", kinds)
        self.assertNotIn("dmarc_policy_none", kinds)
        self.assertNotIn("dmarc_policy_quarantine", kinds)
        # MTA-STS non configurato in questo scenario -> restano findings di gap minore.
        self.assertIn("mta_sts_missing", kinds)
        # SaaS tenant riconosciuto dall'include Google.
        saas_findings = [f for f in res.findings if f.kind == "saas_tenant_inferred"]
        self.assertTrue(any(f.value == "Google Workspace" for f in saas_findings))

    # ------------------------------------------------------------------
    # Scenario (c): SPF ?all (permissivo) + DMARC p=none -> finding MEDIUM
    # per entrambi.
    # ------------------------------------------------------------------
    def test_permissive_spf_and_none_dmarc_are_medium_findings(self):
        records = {
            self.domain: ['"v=spf1 include:spf.example.net ?all"'],
            f"_dmarc.{self.domain}": ['"v=DMARC1; p=none"'],
        }
        with patch.object(email_security, "_dig", side_effect=_dig_map(records)), \
             patch.object(email_security, "_dig_dnssec_soa", return_value=None):
            res = self._fetch(self.domain)

        self.assertEqual(res.status, "ok")
        by_kind = {f.kind: f for f in res.findings}
        self.assertIn("spf_permissive", by_kind)
        self.assertEqual(by_kind["spf_permissive"].severity, "medium")
        self.assertIn("dmarc_policy_none", by_kind)
        self.assertEqual(by_kind["dmarc_policy_none"].severity, "medium")

    # ------------------------------------------------------------------
    # DNSSEC: RRSIG presente -> nessun finding negativo; assente -> LOW.
    # ------------------------------------------------------------------
    def test_dnssec_rrsig_present_no_finding(self):
        with patch.object(email_security, "_dig", side_effect=_dig_map({})), \
             patch.object(email_security, "_dig_dnssec_soa",
                           return_value="example.com. 3600 IN RRSIG SOA 8 2 ..."):
            res = self._fetch(self.domain)
        kinds = {f.kind for f in res.findings}
        self.assertNotIn("dnssec_not_enabled", kinds)

    def test_dnssec_rrsig_absent_yields_low_finding(self):
        with patch.object(email_security, "_dig", side_effect=_dig_map({})), \
             patch.object(email_security, "_dig_dnssec_soa",
                           return_value="example.com. 3600 IN SOA ns1.example.com. ..."):
            res = self._fetch(self.domain)
        by_kind = {f.kind: f for f in res.findings}
        self.assertIn("dnssec_not_enabled", by_kind)
        self.assertEqual(by_kind["dnssec_not_enabled"].severity, "low")

    def test_dnssec_skipped_gracefully_when_dig_missing(self):
        # _dig_dnssec_soa ritorna None quando dig non e' installato: nessun
        # finding, ne' positivo ne' negativo, e il connettore non fallisce.
        with patch.object(email_security, "_dig", side_effect=_dig_map({})), \
             patch.object(email_security, "_dig_dnssec_soa", return_value=None):
            res = self._fetch(self.domain)
        self.assertEqual(res.status, "ok")
        kinds = {f.kind for f in res.findings}
        self.assertNotIn("dnssec_not_enabled", kinds)


class EmailSecurityParsingTests(unittest.TestCase):
    """Unit test diretti sulle funzioni pure di parsing (nessun subprocess)."""

    def test_find_spf_record(self):
        recs = ["some other txt", "v=spf1 -all", "v=DKIM1; k=rsa"]
        self.assertEqual(email_security.find_spf_record(recs), "v=spf1 -all")
        self.assertIsNone(email_security.find_spf_record(["nope"]))

    def test_find_dmarc_record(self):
        recs = ["v=DMARC1; p=reject", "irrelevant"]
        self.assertEqual(email_security.find_dmarc_record(recs), "v=DMARC1; p=reject")
        self.assertIsNone(email_security.find_dmarc_record(["nope"]))

    def test_parse_spf_all_qualifier_hardfail(self):
        self.assertEqual(email_security.parse_spf_all_qualifier("v=spf1 -all"), "-")

    def test_parse_spf_all_qualifier_softfail(self):
        self.assertEqual(email_security.parse_spf_all_qualifier("v=spf1 include:x ~all"), "~")

    def test_parse_spf_all_qualifier_neutral(self):
        self.assertEqual(email_security.parse_spf_all_qualifier("v=spf1 ?all"), "?")

    def test_parse_spf_all_qualifier_default_plus(self):
        self.assertEqual(email_security.parse_spf_all_qualifier("v=spf1 all"), "+")

    def test_parse_spf_all_qualifier_absent(self):
        self.assertEqual(email_security.parse_spf_all_qualifier("v=spf1 include:_spf.google.com"), "")

    def test_parse_dmarc_tag_p(self):
        self.assertEqual(email_security.parse_dmarc_tag("v=DMARC1; p=quarantine; pct=50", "p"), "quarantine")

    def test_parse_dmarc_tag_pct(self):
        self.assertEqual(email_security.parse_dmarc_tag("v=DMARC1; p=none; pct=25", "pct"), "25")

    def test_parse_dmarc_tag_missing(self):
        self.assertIsNone(email_security.parse_dmarc_tag("v=DMARC1; p=reject", "pct"))

    def test_detect_saas_from_spf_google(self):
        saas = email_security.detect_saas_from_spf("v=spf1 include:_spf.google.com ~all")
        self.assertIn("Google Workspace", saas)

    def test_detect_saas_from_spf_microsoft(self):
        saas = email_security.detect_saas_from_spf("v=spf1 include:spf.protection.outlook.com -all")
        self.assertIn("Microsoft 365", saas)

    def test_detect_saas_from_spf_none(self):
        self.assertEqual(email_security.detect_saas_from_spf("v=spf1 include:mail.acme.com -all"), [])

    def test_clean_txt_strips_quotes_and_joins_split_strings(self):
        raw = ['"v=DMARC1; p=reject; rua=mailto:agg@" "example.com"']
        cleaned = email_security._clean_txt(raw)
        self.assertEqual(cleaned, ["v=DMARC1; p=reject; rua=mailto:agg@example.com"])


if __name__ == "__main__":
    unittest.main()
