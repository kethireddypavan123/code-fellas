"""Layer 4a — Tamper-evident proofs.

Every decision produces a Proof: a chain hash linking it to the previous proof,
plus an HMAC signature. Anyone with the server secret can verify; judges can
re-verify via POST /verify in <200ms (deck commitment).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time

from .config import settings
from .schemas import ActionPlan, GuardVerdict, Proof


def _canon(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_proof(
    request_id: str,
    doc_text: str,
    plan: ActionPlan,
    verdict: GuardVerdict,
    prev_chain_hash: str,
) -> Proof:
    """Build a deterministic proof for one pipeline decision."""
    payload = {
        "request_id": request_id,
        "intent": plan.intent,
        "amount": plan.amount,
        "currency": plan.currency,
        "beneficiary": plan.beneficiary,
        "account_hint": plan.account_hint,
        "due_date": plan.due_date,
        "verdict": verdict.verdict.value,
        "grounded": verdict.grounded,
        "signals": verdict.attack_signals,
        "reasons": verdict.reasons,
        "scores": verdict.scores,
        "doc_sha256": _h(doc_text.encode()),
    }
    request_hash = _h(_canon({"request_id": request_id, "doc_sha256": payload["doc_sha256"]}))
    plan_hash = _h(
        _canon(
            {
                "intent": plan.intent,
                "amount": plan.amount,
                "currency": plan.currency,
                "beneficiary": plan.beneficiary,
                "account_hint": plan.account_hint,
                "due_date": plan.due_date,
            }
        )
    )
    verdict_hash = _h(_canon({"verdict": verdict.verdict.value, "grounded": verdict.grounded}))
    chain_hash = _h(_canon({"prev": prev_chain_hash, "request": request_hash, "plan": plan_hash, "verdict": verdict_hash}))
    signature = hmac.new(
        settings.judge_jwt_secret.encode(),
        _canon({"chain_hash": chain_hash, "request_id": request_id}),
        hashlib.sha256,
    ).hexdigest()
    return Proof(
        proof_id=f"pf_{request_hash[:16]}",  # deterministic — same input => same proof_id
        request_hash=request_hash,
        plan_hash=plan_hash,
        verdict_hash=verdict_hash,
        chain_hash=chain_hash,
        prev_chain_hash=prev_chain_hash,
        signature=signature,
        created_ms=int(time.time() * 1000),
        payload=payload,
    )


def verify_proof(proof: Proof) -> tuple[bool, str]:
    """Recompute every hash from the payload + signature. Independent of the DB."""
    p = proof.payload

    # 1. request hash must match the payload's request_id + doc digest
    request_hash = _h(_canon({"request_id": p.get("request_id", ""), "doc_sha256": p.get("doc_sha256", "")}))
    if not hmac.compare_digest(request_hash, proof.request_hash):
        return False, "request hash mismatch (document payload was altered)"

    # 2. plan hash must match the payload's plan fields
    plan_hash = _h(
        _canon(
            {
                "intent": p.get("intent"),
                "amount": p.get("amount"),
                "currency": p.get("currency"),
                "beneficiary": p.get("beneficiary"),
                "account_hint": p.get("account_hint"),
                "due_date": p.get("due_date"),
            }
        )
    )
    if not hmac.compare_digest(plan_hash, proof.plan_hash):
        return False, "plan hash mismatch (plan fields were altered)"

    # 3. verdict hash must match the payload's verdict fields
    verdict_hash = _h(_canon({"verdict": p.get("verdict"), "grounded": p.get("grounded")}))
    if not hmac.compare_digest(verdict_hash, proof.verdict_hash):
        return False, "verdict hash mismatch (verdict fields were altered)"

    # 4. chain hash must be reproducible from the three hashes above
    recomputed = _h(
        _canon(
            {
                "prev": proof.prev_chain_hash,
                "request": proof.request_hash,
                "plan": proof.plan_hash,
                "verdict": proof.verdict_hash,
            }
        )
    )
    if not hmac.compare_digest(recomputed, proof.chain_hash):
        return False, "chain hash mismatch (internal hashes were altered)"

    # 5. signature over chain hash + request id
    expected_sig = hmac.new(
        settings.judge_jwt_secret.encode(),
        _canon({"chain_hash": proof.chain_hash, "request_id": p.get("request_id", "")}),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_sig, proof.signature):
        return False, "signature mismatch (proof was tampered with or signed by another party)"

    return True, "proof is authentic: signature and chain hashes verified"
