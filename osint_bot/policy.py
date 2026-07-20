"""Centralised policy gate for every connector call.

Every ``BaseConnector.run()`` invocation passes through :func:`check_policy`
*before* the API-key check, the cache lookup, the rate-limiter or the actual
``_fetch``.  This makes Rules-of-Engagement and case-scope enforcement a
property of the *SDK*, not of each individual connector — a new connector
gets the enforcement for free and cannot forget to call it.

Enforcement rules
-----------------

The gate takes a :class:`~osint_bot.connector.ConnectorContext` and a
:class:`~osint_bot.connector.ConnectorSpec` and decides whether the call is
allowed.  The result is a ``(allowed: bool, reason: str)`` tuple; the SDK
turns a denial into a ``ConnectorResult(status="policy_denied", error=...)``
so the orchestrator can still show the outcome to the analyst.

The rules, in order:

1. **Active / gated action classes always require a case.**  ``ACTIVE_GATED``,
   ``PII_GATED`` and ``DARKWEB_GATED`` connectors cannot run outside a case
   with a valid, non-revoked Rules of Engagement (RoE) — no ambient
   authority, no anonymous scans.

2. **Case scope is enforced when a case is provided.**  If the caller
   supplies ``context.case_id`` the target must fall inside the case's
   ``allowed_targets`` list.  Passive connectors on out-of-scope targets are
   rejected too: the case-scope covenant is symmetric.

3. **Purely passive calls without a case are still allowed** for backward
   compatibility with CLI use and smoke tests.  The rationale is documented
   in :doc:`../docs/THREAT_MODEL` §3 (single-tenant analyst assumption); the
   case-based flow is the one that fires the audit chain in production.

The gate is deliberately conservative: if the storage layer cannot be
reached, or the case row cannot be loaded, the decision defaults to
``deny`` for gated actions and ``allow`` for passive actions — this fails
closed on the actions that carry real-world risk.
"""
from __future__ import annotations

import ipaddress
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - import cycle guard
    from .connector import ConnectorContext, ConnectorSpec

# Import kept lazy inside functions to avoid circular imports at module load.


# Action classes that always require a case + active RoE.
_GATED_ACTIONS = {"active-gated", "pii-gated", "darkweb-gated"}


def _target_in_scope(target: str, allowed: list[str]) -> bool:
    """Case-insensitive membership check with a lenient subdomain match.

    ``example.com`` in ``allowed`` matches ``sub.example.com`` too — this
    reflects how analysts think of "domain scope" (the whole tree)
    without forcing the analyst to list every subdomain explicitly.
    ``*.example.com`` gets the same apex+subtree coverage — accepted as a
    distinct, more explicit spelling since ``scope.parse_entry()``/the
    case-scope UI already validate and store it as its own entry kind.

    CIDR entries (``10.0.0.0/24``) match any IPv4/IPv6 address they
    contain, via real ``ipaddress`` containment rather than string
    comparison — previously excluded entirely (the ``/`` disqualified
    them from every branch below), so a case scoped to a whole authorised
    network denied every single IP in it.

    For IPv4 / IPv6 / emails / handles we do a strict case-insensitive
    equality check.
    """
    if not allowed:
        return False
    needle = (target or "").strip().lower()
    if not needle:
        return False
    for entry in allowed:
        item = (entry or "").strip().lower()
        if not item:
            continue
        if "/" in item:
            try:
                network = ipaddress.ip_network(item, strict=False)
                ip = ipaddress.ip_address(needle)
            except ValueError:
                continue
            if ip in network:
                return True
            continue
        if item.startswith("*."):
            item = item[2:]
        if needle == item:
            return True
        # Domain-tree match (only when the allowed entry looks like a domain)
        if "." in item and "@" not in item:
            if needle.endswith("." + item):
                return True
    return False


def _load_case(case_id: str) -> dict | None:
    """Return the case row for ``case_id`` or ``None`` if unavailable.

    Delegates to the process-wide Storage singleton exposed by
    :mod:`osint_bot.web.get_storage`. Imports are kept lazy inside the
    function to avoid a top-level import cycle between ``web`` →
    ``connector`` → ``policy`` → ``web``.

    Any exception is swallowed and treated as "storage unavailable" so
    the caller can apply the fail-closed default for gated actions.
    """
    try:
        from .web import get_storage  # local, lazy — breaks the cycle
        return get_storage().get_case(case_id)
    except Exception:
        return None


def _load_active_roe(case_id: str) -> dict | None:
    """Return the *active* RoE row for ``case_id`` or ``None``.

    A RoE is active when it has ``valid_from <= now <= valid_to`` and no
    ``revoked_at``. If storage exposes an ``get_active_roe`` helper it is
    used; otherwise the function looks the case up and inspects its
    embedded RoE fields.
    """
    try:
        from .web import get_storage  # local, lazy

        stor = get_storage()
        loader = getattr(stor, "get_active_roe", None)
        if loader is not None:
            return loader(case_id)
        # Fallback: read the case row and check whether it has an
        # embedded scope. This keeps the check useful even when the RoE
        # subsystem is not fully wired.
        case = _load_case(case_id)
        if not case:
            return None
        # A "case with scope" is treated as its own RoE for the purpose
        # of this check.
        allowed = _parse_scope(case)
        if allowed:
            return {"allowed_targets": allowed, "source": "case"}
    except Exception:
        pass
    return None


def _parse_scope(case: dict) -> list[str]:
    """Extract the ``allowed_targets`` list from a case row.

    The column stores JSON — return an empty list if it is missing or
    unparseable rather than raising, so the caller can decide the policy
    outcome based on the *presence* of a scope rather than the shape of
    the parse error.
    """
    raw = case.get("allowed_targets") or "[]"
    if isinstance(raw, list):
        return [str(x) for x in raw]
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            return []
        if isinstance(parsed, list):
            return [str(x) for x in parsed]
    return []


def check_policy(context: ConnectorContext,
                 spec: ConnectorSpec) -> tuple[bool, str]:
    """Decide whether ``context`` is allowed to reach ``spec``'s ``_fetch``.

    Returns ``(True, "")`` when the call is allowed; ``(False, reason)``
    when it must be blocked. The ``reason`` string is surfaced to the
    analyst via the ``ConnectorResult.error`` field and, when the
    orchestrator opts in, written to the SHA-256 audit chain.
    """
    is_gated = spec.action_class in _GATED_ACTIONS

    # 1. Gated actions always need a case.
    if is_gated and not context.case_id:
        return False, (
            f"Connector '{spec.name}' has action_class '{spec.action_class}' "
            f"and requires an in-scope case. Run this query inside a case "
            f"with a valid Rules of Engagement."
        )

    if not context.case_id:
        # Passive, no case → allow (single-tenant analyst assumption).
        return True, ""

    # 2. A case_id was supplied → load it and enforce scope.
    case = _load_case(context.case_id)
    if case is None:
        # Storage unavailable / unknown case.
        if is_gated:
            return False, (
                f"Case '{context.case_id}' not found. Gated connector "
                f"'{spec.name}' refuses to run without a verifiable case."
            )
        return True, ""

    # A case with status revoked / closed cannot host new queries.
    status = str(case.get("status", "")).lower()
    if status in {"revoked", "closed", "archived"}:
        return False, (
            f"Case '{context.case_id}' is '{status}'. New queries are not "
            f"accepted; open a new case."
        )

    # 3. Scope check.
    allowed = _parse_scope(case)
    if not allowed:
        # A case without an explicit scope is permissive for passive
        # calls (typical of exploratory triage) but never permissive for
        # gated calls.
        if is_gated:
            return False, (
                f"Case '{context.case_id}' has no allowed_targets set. Gated "
                f"connector '{spec.name}' refuses to run against an empty "
                f"scope."
            )
        return True, ""

    if not _target_in_scope(context.target, allowed):
        return False, (
            f"Target '{context.target}' is not in the allowed_targets of "
            f"case '{context.case_id}'. Update the case scope explicitly if "
            f"the target belongs to the investigation."
        )

    # 4. Gated actions additionally require an active RoE.
    if is_gated:
        roe = _load_active_roe(context.case_id)
        if not roe:
            return False, (
                f"Case '{context.case_id}' has no active Rules of Engagement. "
                f"Gated connector '{spec.name}' refuses to run without a "
                f"signed, non-revoked RoE."
            )
        allowed_classes = roe.get("allowed_classes") or []
        if isinstance(allowed_classes, str):
            try:
                allowed_classes = json.loads(allowed_classes)
            except (TypeError, ValueError):
                allowed_classes = []
        if allowed_classes and spec.action_class not in allowed_classes:
            return False, (
                f"Case '{context.case_id}' RoE does not authorise action "
                f"class '{spec.action_class}'. Connector '{spec.name}' "
                f"blocked."
            )

        # 5. RoE time window. safety.authorize_action (the gate used by
        # external tools) already enforces valid_from/valid_to via the same
        # _within_window helper — this path served every native connector
        # without it, so an expired-but-not-revoked RoE kept silently
        # authorising gated connectors past its mandate.
        from datetime import datetime, timezone

        from .safety import _within_window
        now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if not _within_window(roe, now_iso):
            return False, (
                f"Case '{context.case_id}' RoE is outside its time window "
                f"(valid_from/valid_to). Connector '{spec.name}' blocked."
            )

        # 6. Four-eyes. Mirrors safety.authorize_action's equivalent check:
        # a RoE that requires a second signature for active/darkweb-gated
        # actions must have one before those classes may run.
        if roe.get("requires_second_signature") and spec.action_class in {"active-gated", "darkweb-gated"}:
            if not roe.get("second_signed_at"):
                return False, (
                    f"Case '{context.case_id}' RoE requires a second "
                    f"signature (4-eyes) for '{spec.action_class}' actions. "
                    f"Connector '{spec.name}' blocked pending co-signature."
                )

    return True, ""


__all__ = ["check_policy"]
