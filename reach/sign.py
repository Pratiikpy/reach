"""EIP-191 signing of a research report — the same provable-receipt moat as Aletheia.

The signature covers a canonical hash of {question, answer, sources, tee_verified, time}.
Any caller can recover the signer offline; change one field and the signature breaks.
"""
from __future__ import annotations
import hashlib
import json
import os

from eth_account import Account
from eth_account.messages import encode_defunct


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign_report(payload: dict, private_key: str | None = None) -> dict | None:
    pk = (private_key or os.environ.get("REACH_SIGNER_KEY") or os.environ.get("ATTEST_PRIVATE_KEY")
          or os.environ.get("EVM_WALLET_PRIVATE_KEY"))
    if not pk:
        return None
    if not pk.startswith("0x"):
        pk = "0x" + pk
    body = _canonical(payload)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    acct = Account.from_key(pk)
    sig = acct.sign_message(encode_defunct(text=digest))
    return {
        "signer": acct.address,
        "message_sha256": digest,
        "signature": sig.signature.hex(),
        "scheme": "EIP-191/personal_sign over sha256(canonical_json)",
    }


def _signer_key() -> str | None:
    pk = (os.environ.get("REACH_SIGNER_KEY") or os.environ.get("ATTEST_PRIVATE_KEY")
          or os.environ.get("EVM_WALLET_PRIVATE_KEY"))
    if not pk:
        return None
    return pk if pk.startswith("0x") else "0x" + pk


def signer_address() -> str | None:
    """The address Reach signs with. Published so a consumer has a trust anchor to compare against —
    a signature is only evidence of origin if you already know whose key to expect."""
    pk = _signer_key()
    if not pk:
        return None
    try:
        return Account.from_key(pk).address
    except Exception:  # noqa: BLE001
        return None


def verify_report(signer: str, message_sha256: str, signature: str) -> bool:
    """True when `signature` really was produced over `message_sha256` by `signer`.

    This is an INTEGRITY check, not an attribution one: `signer` is supplied by the caller, so a
    report signed with an attacker's own key and naming the attacker's own address passes. Use
    verify_report_full() to establish that Reach issued the report."""
    try:
        rec = Account.recover_message(encode_defunct(text=message_sha256), signature=signature)
        return rec.lower() == signer.lower()
    except Exception:  # noqa: BLE001
        return False


def recover_signer(message_sha256: str, signature: str) -> str | None:
    try:
        return Account.recover_message(encode_defunct(text=message_sha256), signature=signature)
    except Exception:  # noqa: BLE001
        return None


def verify_report_full(
    *,
    message_sha256: str,
    signature: str,
    signer: str | None = None,
    payload: dict | None = None,
    expected_signer: str | None = None,
) -> dict:
    """Full verification: signature integrity, digest-matches-payload, and issuer attribution.

    Three independent things can be wrong with a signed report and the old endpoint checked only the
    first, then reported a bare `valid: true`:

      1. the signature does not match the digest        -> forged or corrupted signature
      2. the digest does not match the payload          -> the report body was edited after signing,
                                                           and checking the signature alone will
                                                           never notice, because the signature only
                                                           ever covered the digest
      3. the signer is not Reach                        -> cryptographically perfect, issued by
                                                           somebody else entirely
    """
    recovered = recover_signer(message_sha256, signature)
    signature_valid = recovered is not None and (
        signer is None or recovered.lower() == signer.lower()
    )

    digest_matches_payload = None
    if payload is not None:
        digest_matches_payload = (
            hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest() == (message_sha256 or "").lower()
        )

    anchor = (expected_signer or signer_address() or "").lower() or None
    attributed = None
    if anchor and recovered:
        attributed = recovered.lower() == anchor

    if not signature_valid:
        verdict = "INVALID_SIGNATURE"
    elif digest_matches_payload is False:
        verdict = "PAYLOAD_ALTERED_AFTER_SIGNING"
    elif attributed is False:
        verdict = "VALID_SIGNATURE_UNKNOWN_ISSUER"
    elif attributed is True:
        verdict = "VALID"
    else:
        verdict = "VALID_UNATTRIBUTED"

    return {
        "valid": bool(signature_valid) and digest_matches_payload is not False,
        "signature_valid": bool(signature_valid),
        "recovered_signer": recovered,
        "claimed_signer": signer,
        "expected_signer": anchor,
        "attributed": attributed,
        "digest_matches_payload": digest_matches_payload,
        "verdict": verdict,
        "scheme": "EIP-191/personal_sign over sha256(canonical_json)",
        "note": "A valid signature proves integrity, not origin. Pass the original payload to also "
                "prove the report body was not edited after signing.",
    }
