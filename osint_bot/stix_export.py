"""Export di un'investigation Argo verso STIX 2.1 e MISP event.

Due formati standard di threat-intelligence, richiesti per interoperabilita'
con SIEM/TIP (OpenCTI, MISP, Anomali, ThreatConnect) e per deliverable
"court-ready" condivisibili.

Design:
  * **ID deterministici**: gli STIX id usano UUIDv5 su un namespace fisso Argo
    + il valore dell'entita'. Rieseguire l'export sullo stesso caso produce lo
    stesso bundle (riproducibilita' forense, diffing tra run).
  * **Zero dipendenze**: costruisco i dict a mano secondo la spec STIX 2.1 e il
    formato MISP core; niente ``stix2``/``pymisp`` per non appesantire il bundle.
  * **Input** = il dict ``Investigation.to_dict()`` gia' salvato come
    ``<target>.json`` dal report classico (target, target_type, generated_at,
    findings[], entities[], relationships[]).

Riferimenti: STIX 2.1 (OASIS), MISP core format 2.4.
"""
from __future__ import annotations

import uuid
from typing import Any

# Namespace UUIDv5 dedicato ad Argo (fisso, costante nel tempo: garantisce
# ID STIX/MISP deterministici e riproducibili tra run diverse dello stesso caso).
_ARGO_NS = uuid.UUID("6f1a1e02-3a5b-5c7d-9e2f-a1b2c3d4f5b7")

# Identity SDO che rappresenta la piattaforma come "creatore" degli oggetti.
_ARGO_IDENTITY_ID = "identity--" + str(uuid.uuid5(_ARGO_NS, "argo-osint-platform"))


# ---------------------------------------------------------------------------
# Mapping entita' Argo -> tipo STIX (SCO observable o SDO)
# ---------------------------------------------------------------------------
# value_key indica la proprieta' STIX che contiene il valore osservato.
_STIX_SCO_MAP: dict[str, tuple[str, str]] = {
    "domain": ("domain-name", "value"),
    "hostname": ("domain-name", "value"),
    "ip": ("ipv4-addr", "value"),
    "ipv4": ("ipv4-addr", "value"),
    "ipv6": ("ipv6-addr", "value"),
    "email": ("email-addr", "value"),
    "url": ("url", "value"),
    "handle": ("user-account", "account_login"),
    "username": ("user-account", "account_login"),
    "file_hash": ("file", "hashes"),
    "md5": ("file", "hashes"),
    "sha256": ("file", "hashes"),
    "mac": ("mac-addr", "value"),
}

# Entita' che diventano Identity SDO (persone/organizzazioni).
_STIX_IDENTITY_CLASS: dict[str, str] = {
    "person": "individual",
    "individual": "individual",
    "company": "organization",
    "org": "organization",
    "organization": "organization",
}


def _sco_id(stix_type: str, value: str) -> str:
    return f"{stix_type}--" + str(uuid.uuid5(_ARGO_NS, f"{stix_type}:{value.lower()}"))


def _ipv4_or_v6(value: str) -> str:
    return "ipv6-addr" if ":" in value else "ipv4-addr"


def _entity_to_stix(entity: dict) -> dict | None:
    """Converte una entita' Argo in un oggetto STIX 2.1 (SCO o Identity SDO)."""
    etype = (entity.get("type") or "").lower()
    value = str(entity.get("value") or entity.get("display_value") or "").strip()
    if not value:
        return None

    # Persone / organizzazioni -> Identity SDO
    if etype in _STIX_IDENTITY_CLASS:
        oid = "identity--" + str(uuid.uuid5(_ARGO_NS, f"identity:{etype}:{value.lower()}"))
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": oid,
            "created_by_ref": _ARGO_IDENTITY_ID,
            "name": value,
            "identity_class": _STIX_IDENTITY_CLASS[etype],
        }

    # Observable (SCO)
    if etype in _STIX_SCO_MAP:
        stix_type, value_key = _STIX_SCO_MAP[etype]
        if stix_type in ("ipv4-addr", "ipv6-addr"):
            stix_type = _ipv4_or_v6(value)
        oid = _sco_id(stix_type, value)
        obj: dict[str, Any] = {"type": stix_type, "spec_version": "2.1", "id": oid}
        if stix_type == "file":
            # hashes richiede un dict; deduco l'algoritmo dalla lunghezza hex.
            algo = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}.get(len(value), "SHA-256")
            obj["hashes"] = {algo: value}
        else:
            obj[value_key] = value
        return obj

    # Fallback: custom observable x-osint-entity (mantiene tracciabilita').
    oid = "x-osint-entity--" + str(uuid.uuid5(_ARGO_NS, f"x:{etype}:{value.lower()}"))
    return {
        "type": "x-osint-entity",
        "spec_version": "2.1",
        "id": oid,
        "x_entity_type": etype or "unknown",
        "value": value,
    }


def _finding_to_note(finding: dict, subject_refs: list[str]) -> dict | None:
    """Un finding diventa un Note SDO agganciato agli observable pertinenti."""
    kind = finding.get("kind") or "finding"
    value = str(finding.get("value") or "").strip()
    if not value:
        return None
    conf = finding.get("confidence")
    grade = f"{finding.get('source_reliability', 'F')}{finding.get('info_credibility', 6)}"
    content_bits = [f"[{kind}] {value}", f"Admiralty {grade}"]
    if isinstance(conf, (int, float)):
        content_bits.append(f"confidence {round(float(conf), 2)}")
    if finding.get("notes"):
        content_bits.append(str(finding["notes"]))
    why = finding.get("why_linked") or []
    if why:
        content_bits.append("why_linked: " + "; ".join(map(str, why)))
    gaps = finding.get("gaps") or []
    if gaps:
        content_bits.append("gaps: " + "; ".join(map(str, gaps)))
    content = " | ".join(content_bits)
    nid = "note--" + str(uuid.uuid5(_ARGO_NS, f"note:{kind}:{value.lower()}"))
    note: dict[str, Any] = {
        "type": "note",
        "spec_version": "2.1",
        "id": nid,
        "created_by_ref": _ARGO_IDENTITY_ID,
        "abstract": kind,
        "content": content,
    }
    if subject_refs:
        note["object_refs"] = subject_refs
    return note


def _confidence_to_stix(conf: Any) -> int:
    """STIX confidence e' 0..100. Argo usa 0..1 float."""
    try:
        c = float(conf)
    except (TypeError, ValueError):
        return 0
    return max(0, min(100, round(c * 100)))


def investigation_to_stix_bundle(inv: dict, *, generated_at: str = "") -> dict:
    """Costruisce un bundle STIX 2.1 completo da un investigation dict.

    Struttura: [identity Argo] + [SCO/Identity per ogni entita'] +
    [relationship per ogni relazione] + [note per ogni finding] +
    [report che raggruppa tutto].
    """
    ts = generated_at or inv.get("generated_at") or "1970-01-01T00:00:00Z"
    if not ts.endswith("Z") and "+" not in ts:
        ts = ts + "Z"

    objects: list[dict] = []
    # 1. Identity della piattaforma
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": _ARGO_IDENTITY_ID,
        "name": "Argo OSINT",
        "identity_class": "system",
        "description": "Piattaforma OSINT privacy-by-design (autogenerato).",
    })

    # 2. Entita' -> observable/identity, con mappa value->stix_id per i ref.
    value_to_id: dict[str, str] = {}
    id_to_id: dict[str, str] = {}  # entity["id"] Argo -> stix id
    for entity in inv.get("entities") or []:
        obj = _entity_to_stix(entity)
        if not obj:
            continue
        objects.append(obj)
        val = str(entity.get("value") or "").lower()
        if val:
            value_to_id[val] = obj["id"]
        if entity.get("id"):
            id_to_id[str(entity["id"])] = obj["id"]

    # 3. Relationship SRO
    for rel in inv.get("relationships") or []:
        src = id_to_id.get(str(rel.get("source"))) or value_to_id.get(str(rel.get("source")).lower())
        tgt = id_to_id.get(str(rel.get("target"))) or value_to_id.get(str(rel.get("target")).lower())
        if not src or not tgt:
            continue
        rkind = (rel.get("kind") or "related-to").replace("_", "-")
        rid = "relationship--" + str(uuid.uuid5(_ARGO_NS, f"rel:{src}:{rkind}:{tgt}"))
        sro = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": rid,
            "created_by_ref": _ARGO_IDENTITY_ID,
            "relationship_type": rkind,
            "source_ref": src,
            "target_ref": tgt,
            "confidence": _confidence_to_stix(rel.get("confidence")),
        }
        objects.append(sro)

    # 4. Findings -> Note (agganciate al target quando risolvibile).
    target_val = str(inv.get("target") or "").lower()
    target_ref = value_to_id.get(target_val)
    for finding in inv.get("findings") or []:
        # aggancio la nota all'observable il cui valore compare nel finding.
        refs: list[str] = []
        fval = str(finding.get("value") or "").lower()
        if fval in value_to_id:
            refs.append(value_to_id[fval])
        elif target_ref:
            refs.append(target_ref)
        note = _finding_to_note(finding, refs)
        if note:
            objects.append(note)

    # 5. Report SDO che raggruppa tutti gli object_refs
    report_id = "report--" + str(uuid.uuid5(_ARGO_NS, f"report:{target_val}:{ts}"))
    objects.append({
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created_by_ref": _ARGO_IDENTITY_ID,
        "name": f"Argo OSINT — {inv.get('target') or 'investigation'}",
        "published": ts,
        "report_types": ["threat-report", "observed-data"],
        "object_refs": [o["id"] for o in objects if o["id"] != report_id] or [_ARGO_IDENTITY_ID],
    })

    bundle_id = "bundle--" + str(uuid.uuid5(_ARGO_NS, f"bundle:{target_val}:{ts}"))
    return {"type": "bundle", "id": bundle_id, "objects": objects}


# ---------------------------------------------------------------------------
# MISP event
# ---------------------------------------------------------------------------
# Mapping entita' -> (misp_type, misp_category)
_MISP_ATTR_MAP: dict[str, tuple[str, str]] = {
    "domain": ("domain", "Network activity"),
    "hostname": ("hostname", "Network activity"),
    "ip": ("ip-dst", "Network activity"),
    "ipv4": ("ip-dst", "Network activity"),
    "ipv6": ("ip-dst", "Network activity"),
    "email": ("email-src", "Payload delivery"),
    "url": ("url", "Network activity"),
    "handle": ("github-username", "Social network"),
    "username": ("github-username", "Social network"),
    "md5": ("md5", "Payload delivery"),
    "sha256": ("sha256", "Payload delivery"),
    "file_hash": ("sha256", "Payload delivery"),
    "phone": ("phone-number", "Other"),
    "crypto": ("btc", "Financial fraud"),
    "person": ("target-user", "Attribution"),
    "company": ("target-org", "Attribution"),
    "org": ("target-org", "Attribution"),
}


def investigation_to_misp_event(inv: dict, *, generated_at: str = "") -> dict:
    """Costruisce un MISP core-format event da un investigation dict."""
    ts = generated_at or inv.get("generated_at") or "1970-01-01T00:00:00"
    date = ts[:10]
    uuid_seed = str(uuid.uuid5(_ARGO_NS, f"misp:{str(inv.get('target') or '').lower()}:{ts}"))

    attributes: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def _add(mtype: str, category: str, value: str, comment: str = "", to_ids: bool = False):
        key = (mtype, value.lower())
        if not value or key in seen:
            return
        seen.add(key)
        attributes.append({
            "uuid": str(uuid.uuid5(_ARGO_NS, f"attr:{mtype}:{value.lower()}")),
            "type": mtype,
            "category": category,
            "value": value,
            "to_ids": to_ids,
            "comment": comment[:255],
        })

    for entity in inv.get("entities") or []:
        etype = (entity.get("type") or "").lower()
        value = str(entity.get("value") or "").strip()
        if etype in _MISP_ATTR_MAP and value:
            mtype, category = _MISP_ATTR_MAP[etype]
            # crypto: distinguo ETH da BTC dal prefisso 0x
            if etype == "crypto" and value.lower().startswith("0x"):
                mtype = "eth"
            _add(mtype, category, value, comment=f"entity:{etype} conf={entity.get('confidence')}")

    # Findings che portano un IOC utile (url/ip/domain/email nel value).
    for finding in inv.get("findings") or []:
        fkind = (finding.get("kind") or "").lower()
        fval = str(finding.get("value") or "").strip()
        if not fval:
            continue
        grade = f"{finding.get('source_reliability', 'F')}{finding.get('info_credibility', 6)}"
        comment = f"{fkind} · Admiralty {grade}"
        if fval.startswith(("http://", "https://")):
            _add("url", "Network activity", fval, comment=comment)
        elif fkind.startswith("dns_") or fkind == "asn_prefix":
            _add("domain", "Network activity", fval, comment=comment)
        elif fkind in ("tls_fingerprint_sha256",):
            _add("x509-fingerprint-sha256", "Network activity", fval, comment=comment)

    event = {
        "Event": {
            "uuid": uuid_seed,
            "info": f"Argo OSINT — {inv.get('target') or 'investigation'}",
            "date": date,
            "threat_level_id": "4",   # 4 = undefined
            "analysis": "1",          # 1 = ongoing
            "distribution": "0",      # 0 = your org only (privacy-by-default)
            "published": False,
            "Attribute": attributes,
            "Tag": [
                {"name": "tlp:amber"},
                {"name": "source:argo-osint"},
                {"name": f'osint:target-type="{inv.get("target_type") or "unknown"}"'},
            ],
        }
    }
    return event
