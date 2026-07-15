"""CLI di verifica indipendente per i sigilli dei report (Ed25519 + RFC3161).

    argo-verify-report <seal.json> [--pubkey <base64>] [--save-tsa-token <path>]

*seal.json* è l'export prodotto da ``GET /api/jobs/<id>/seal`` (scaricabile
dall'analista dal pannello "Sigillo" della UI, o via API/curl). Verifica:

1. La firma Ed25519 di ``manifest_hash``, contro la chiave pubblica embedded
   nel seal (o quella passata esplicitamente con ``--pubkey``, per chi vuole
   controllare un ``seal.json`` contro una copia della chiave ottenuta prima
   e per altra via — l'unico modo per non fidarsi ciecamente di un file che
   potrebbe essere stato sostituito insieme alla sua stessa chiave pubblica
   embedded).
2. Se presente un token RFC3161 (``tsa_token_der_b64``), stampa lo stato e il
   ``gen_time`` dichiarati e (con ``--save-tsa-token``) lo salva su disco con
   le istruzioni per verificarlo con strumenti standard (``openssl``).

Non-goal esplicito: questo comando NON riverifica l'hash dei singoli file di
evidenza/report contro ``manifest_hash`` — richiederebbe l'export dell'intera
lista artifact (fuori scope v1) — e NON verifica la catena di certificati
della TSA (vedi ``docs/THREAT_MODEL.md``): verifica solo che la firma sul
manifest_hash dichiarato sia autentica.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from . import report_signing


def verify_seal(seal: dict, *, pubkey_b64_override: str = "") -> tuple[bool, list[str]]:
    """Verifica un dict di sigillo (stessa forma di GET /api/jobs/<id>/seal).

    Ritorna ``(ok, righe)`` — ``ok`` è True solo se la firma Ed25519 verifica;
    ``righe`` è un report leggibile da stampare.
    """
    lines: list[str] = []
    pubkey_b64 = pubkey_b64_override or seal.get("signing_pubkey_b64", "")
    manifest_hash = seal.get("manifest_hash", "")
    signature_b64 = seal.get("signature_b64", "")
    if not (pubkey_b64 and manifest_hash and signature_b64):
        return False, ["Sigillo incompleto: mancano manifest_hash, signature_b64 o la chiave pubblica."]

    sig_ok = report_signing.verify_signature(manifest_hash, signature_b64, pubkey_b64)
    lines.append(f"Firma Ed25519: {'VALIDA' if sig_ok else 'NON VALIDA'}")
    lines.append(f"  manifest_hash:  {manifest_hash}")
    lines.append(f"  fingerprint:    {seal.get('signing_pubkey_fingerprint', '')}")
    lines.append(f"  sigillato il:   {seal.get('sealed_at', '')}")
    lines.append(f"  sigillato da:   {seal.get('sealed_by', '')}")
    lines.append(f"  artifact count: {seal.get('artifact_count', '')}")
    if pubkey_b64_override:
        lines.append("  (verificato contro la chiave pubblica fornita con --pubkey, non quella embedded nel file)")

    tsa_token_b64 = seal.get("tsa_token_der_b64", "")
    if tsa_token_b64:
        lines.append("")
        lines.append(f"Timestamp RFC3161: {seal.get('tsa_status', '')}")
        lines.append(f"  gen_time dichiarato: {seal.get('tsa_gen_time', '')}")
        lines.append(f"  TSA:                 {seal.get('tsa_url_host', '')}")
        lines.append("  Argo non verifica la catena di certificati della TSA (vedi docs/THREAT_MODEL.md).")
        lines.append("  Verifica indipendente: salva il token (--save-tsa-token) e usa")
        lines.append("  `openssl ts -reply -in token.der -text`.")
    else:
        lines.append("")
        lines.append("Nessun timestamp RFC3161 associato a questo sigillo (solo firma locale).")

    lines.append("")
    lines.append("NOTA: questo comando verifica solo l'autenticità della firma sul")
    lines.append("manifest_hash dichiarato — non riverifica l'hash dei singoli file di")
    lines.append("evidenza/report contro il manifest (richiede l'export completo della")
    lines.append("lista artifact, non incluso in questo export).")
    return sig_ok, lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="argo-verify-report",
        description=(
            "Verifica indipendente della firma Ed25519 (e dell'eventuale "
            "timestamp RFC3161) di un sigillo di report Argo."
        ),
    )
    parser.add_argument("seal_json", help="Path al file JSON del sigillo (export di GET /api/jobs/<id>/seal).")
    parser.add_argument("--pubkey", default="",
                        help="Chiave pubblica Ed25519 (base64) da usare al posto di quella embedded nel file.")
    parser.add_argument("--save-tsa-token", default="", metavar="PATH",
                        help="Se il sigillo ha un token RFC3161, lo salva (DER) in questo path.")
    args = parser.parse_args(argv)

    try:
        seal = json.loads(Path(args.seal_json).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Impossibile leggere {args.seal_json}: {exc}", file=sys.stderr)
        return 2

    ok, lines = verify_seal(seal, pubkey_b64_override=args.pubkey)
    print("\n".join(lines))

    if args.save_tsa_token and seal.get("tsa_token_der_b64"):
        out_path = Path(args.save_tsa_token)
        out_path.write_bytes(base64.b64decode(seal["tsa_token_der_b64"]))
        print(f"\nToken RFC3161 salvato in {out_path}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
