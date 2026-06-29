"""Tests for target_classifier.py — classification + normalization."""
from __future__ import annotations

import pytest

from osint_bot.target_classifier import (
    T_BTC, T_CIDR, T_COMPANY, T_DOMAIN, T_EMAIL, T_ETH, T_FILE_HASH,
    T_HANDLE, T_IP, T_PERSON, T_PHONE, T_SUBDOMAIN, T_URL, T_UNKNOWN,
    classify_target, suggest_external_tools, suggest_modules,
)


class TestEmptyAndWhitespace:
    def test_empty(self):
        spec = classify_target("")
        assert spec.type == T_UNKNOWN
        assert spec.confidence == 0.0

    def test_whitespace_only(self):
        spec = classify_target("   \t\n")
        assert spec.type == T_UNKNOWN


class TestEmail:
    def test_standard(self):
        spec = classify_target("alice@example.com")
        assert spec.type == T_EMAIL
        assert spec.value == "alice@example.com"
        assert spec.confidence >= 0.9
        assert spec.attributes["local"] == "alice"
        assert spec.attributes["domain"] == "example.com"

    def test_uppercase_normalized(self):
        spec = classify_target("ALICE@Example.COM")
        assert spec.type == T_EMAIL
        assert spec.value == "alice@example.com"

    def test_with_plus_alias(self):
        spec = classify_target("alice+tag@example.com")
        assert spec.type == T_EMAIL

    def test_invalid_no_at(self):
        spec = classify_target("aliceexample.com")
        assert spec.type != T_EMAIL


class TestDomain:
    def test_apex(self):
        spec = classify_target("example.com")
        assert spec.type == T_DOMAIN
        assert spec.value == "example.com"
        assert spec.attributes["apex"] == "example.com"

    def test_subdomain_detected(self):
        spec = classify_target("api.example.com")
        assert spec.type == T_SUBDOMAIN
        assert spec.attributes["apex"] == "example.com"

    def test_lowercased(self):
        spec = classify_target("API.Example.COM")
        assert spec.value == "api.example.com"

    def test_trailing_dot_stripped(self):
        spec = classify_target("example.com.")
        assert spec.type == T_DOMAIN
        assert spec.value == "example.com"

    def test_single_label_rejected(self):
        spec = classify_target("localhost")
        # No dot → not a domain. Falls through to handle (short) or unknown.
        assert spec.type != T_DOMAIN

    def test_tld_only(self):
        spec = classify_target(".com")
        assert spec.type != T_DOMAIN


class TestIPAndCIDR:
    def test_ipv4(self):
        spec = classify_target("192.168.1.1")
        assert spec.type == T_IP
        assert spec.attributes["private"] is True

    def test_ipv4_public(self):
        spec = classify_target("8.8.8.8")
        assert spec.type == T_IP
        assert spec.attributes["private"] is False

    def test_ipv4_invalid(self):
        spec = classify_target("999.0.0.1")
        assert spec.type != T_IP

    def test_cidr_v4(self):
        spec = classify_target("10.0.0.0/24")
        assert spec.type == T_CIDR
        assert spec.attributes["num_addresses"] == 256

    def test_cidr_invalid(self):
        spec = classify_target("256.0.0.0/8")
        assert spec.type != T_CIDR


class TestURL:
    def test_http(self):
        spec = classify_target("http://example.com/path?q=1")
        assert spec.type == T_URL
        assert spec.attributes["host"] == "example.com"

    def test_https_with_port(self):
        spec = classify_target("https://example.com:8443/")
        assert spec.type == T_URL

    def test_partial_no_scheme_falls_through(self):
        spec = classify_target("example.com/path")
        # Without scheme, our URL regex requires http(s)://, so this becomes
        # a domain (since the regex DOMAIN_RE will not match "example.com/path")
        assert spec.type != T_URL


class TestCrypto:
    def test_eth_address(self):
        spec = classify_target("0x" + "a" * 40)
        assert spec.type == T_ETH
        assert spec.value == ("0x" + "a" * 40).lower()

    def test_eth_invalid_length(self):
        spec = classify_target("0x" + "a" * 39)
        assert spec.type != T_ETH

    def test_btc_legacy(self):
        spec = classify_target("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert spec.type == T_BTC

    def test_btc_bech32(self):
        spec = classify_target("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
        assert spec.type == T_BTC
        assert spec.attributes["bech32"] is True


class TestHandle:
    def test_with_at(self):
        spec = classify_target("@alice")
        assert spec.type == T_HANDLE
        assert spec.value == "alice"

    def test_short_with_at(self):
        spec = classify_target("@abc")
        assert spec.type == T_HANDLE
        assert spec.value == "abc"

    def test_at_with_dots_underscores(self):
        spec = classify_target("@alice.bob_2024")
        assert spec.type == T_HANDLE

    def test_bare_lowconf(self):
        spec = classify_target("alicebob")
        assert spec.type == T_HANDLE
        assert spec.confidence < 0.7  # ambiguous


class TestPhone:
    def test_e164(self):
        spec = classify_target("+393331234567")
        assert spec.type == T_PHONE
        assert spec.attributes["e164"] == "+393331234567"

    def test_formatted_no_plus(self):
        spec = classify_target("+39 333 1234567")
        assert spec.type == T_PHONE

    def test_with_brackets(self):
        spec = classify_target("(415) 555-0172")
        # No country code but has separators → low confidence
        assert spec.type == T_PHONE
        assert spec.confidence < 0.8

    def test_too_short(self):
        spec = classify_target("12345")
        assert spec.type != T_PHONE


class TestFileHash:
    def test_md5(self):
        spec = classify_target("d41d8cd98f00b204e9800998ecf8427e")
        assert spec.type == T_FILE_HASH
        assert spec.attributes["algorithm"] == "md5"

    def test_sha256(self):
        spec = classify_target("a" * 64)
        assert spec.type == T_FILE_HASH
        assert spec.attributes["algorithm"] == "sha256"

    def test_sha1(self):
        spec = classify_target("a" * 40)
        # Could collide with ETH which is 40 hex but with 0x prefix.
        assert spec.type == T_FILE_HASH

    def test_invalid_length(self):
        spec = classify_target("abc123")
        assert spec.type != T_FILE_HASH


class TestPersonAndCompany:
    def test_full_name(self):
        spec = classify_target("Mario Rossi")
        assert spec.type == T_PERSON

    def test_single_word_falls_to_handle_or_company(self):
        spec = classify_target("Acme")
        # Single word → not a person (no space). Becomes handle or company.
        assert spec.type in {T_HANDLE, T_COMPANY}


class TestHint:
    def test_hint_matching_value(self):
        spec = classify_target("example.com", hint="domain")
        assert spec.type == T_DOMAIN

    def test_hint_overrides_when_no_validator(self):
        spec = classify_target("Acme Spa", hint="company")
        assert spec.type == T_COMPANY

    def test_hint_with_invalid_value_warns(self):
        spec = classify_target("notanip", hint="ip")
        # Hinted as IP but invalid → returns IP type with warning, low conf.
        assert spec.type == T_IP
        assert spec.warnings
        assert spec.confidence < 0.5


class TestSuggestModules:
    def test_domain_modules(self):
        spec = classify_target("example.com")
        mods = suggest_modules(spec)
        assert "company_domain" in mods
        assert "opsec" in mods

    def test_email_modules(self):
        spec = classify_target("a@b.com")
        mods = suggest_modules(spec)
        assert "phone_email" in mods
        assert "socmint" in mods

    def test_unknown_falls_back(self):
        spec = classify_target("")
        mods = suggest_modules(spec)
        assert mods  # not empty


class TestSuggestTools:
    def test_domain_authorized_no_active(self):
        spec = classify_target("example.com")
        tools = suggest_external_tools(spec, authorized=True, allow_active=False)
        assert "amass" in tools
        assert "subfinder" in tools
        assert "nuclei" not in tools

    def test_domain_authorized_with_active(self):
        spec = classify_target("example.com")
        tools = suggest_external_tools(spec, authorized=True, allow_active=True)
        # Active tools aren't in _TOOLS_BY_TYPE[T_DOMAIN] by default, must use extra
        tools = suggest_external_tools(
            spec, authorized=True, allow_active=True, extra=["nuclei", "nmap"],
        )
        assert "nuclei" in tools
        assert "nmap" in tools

    def test_handle_pii_blocked_without_auth(self):
        spec = classify_target("@alice")
        tools = suggest_external_tools(spec, authorized=False, allow_active=False)
        assert "sherlock" not in tools
        assert "maigret" not in tools

    def test_handle_pii_ok_with_auth(self):
        spec = classify_target("@alice")
        tools = suggest_external_tools(spec, authorized=True, allow_active=False)
        assert "sherlock" in tools

    def test_extra_dedupe(self):
        spec = classify_target("example.com")
        tools = suggest_external_tools(
            spec, authorized=True, allow_active=False, extra=["amass", "amass"],
        )
        assert tools.count("amass") == 1


class TestRationale:
    def test_every_result_has_rationale(self):
        for raw in [
            "example.com", "a@b.com", "8.8.8.8", "@alice", "+39 333 1234567",
            "0x" + "a" * 40, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        ]:
            spec = classify_target(raw)
            assert spec.rationale, f"missing rationale for {raw}"
            assert len(spec.rationale) > 10
