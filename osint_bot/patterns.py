"""Centralized regex patterns shared across modules.

Single source of truth for EMAIL / PHONE / DOMAIN / IP / URL / HANDLE /
BTC / ETH patterns. Anything that needs to match an identifier should
import from here; do not redefine the same regex in another module — they
will drift.
"""

from __future__ import annotations

import re


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)

URL_RE = re.compile(r"\bhttps?://[^\s<>()]+", re.IGNORECASE)

# Stricter phone: requires explicit "+" prefix to mark intent, otherwise we
# generate false positives over every long digit run (timestamps, IDs).
# Use only for entity extraction over arbitrary text. The orchestrator uses
# a looser variant when parsing user-supplied commands; that variant lives
# alongside this one as PHONE_LOOSE_RE.
PHONE_RE = re.compile(r"\+\d{1,3}[\s.\-]?(?:\(?\d{1,4}\)?[\s.\-]?){1,5}\d{2,4}")
PHONE_LOOSE_RE = re.compile(r"(?:\+\d{1,3}[\s.\-]?)?(?:\(?\d{2,4}\)?[\s.\-]?){2,5}\d{3,4}")

# Loose IP shape — callers MUST validate the match with ipaddress.ip_address
# before treating it as a real IP (regex alone accepts 999.0.0.1).
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

HANDLE_RE = re.compile(r"(?<!\w)@([A-Za-z0-9_.-]{3,32})")

DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
