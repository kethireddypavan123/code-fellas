"""Layer 3 — Deterministic Guard (final authority).

Never uses an LLM. Combines document indicators + plan validation + grounding
checks into a verdict: OK / BLOCK / REVIEW with machine-readable reasons.
Deterministic: same input => same output, same hashes, always.
"""
from __future__ import annotations

import re
from typing import Optional

from .config import settings
from .ingestion import Ingested
from .schemas import ActionPlan, GuardVerdict, Indicators, Verdict

# Instructions appearing anywhere in the document (not just invisible text)
_CMD_IN_DOC = re.compile(
    r"(?is)\b(ignore|disregard)\s+(all\s+)?previous\b"
    r"|\b(transfer|send|wire)\s+(rs\.?|inr|₹)?\s*[\d,]+"
    r"|\b(add beneficiary|approve payment|bypass|jailbreak)\b"
)

# Commands targeting the assistant inside the document (meta-instructions)
_META_CMD = re.compile(
    r"(?is)\b(you are now|your instructions are|from now on|respond with only|"
    r"output the system prompt|reveal your prompt|bypass|jailbreak|admin override)\b"
)


class Guard:
    def __init__(self, raw_doc: str = "") -> None:
        self._raw = raw_doc

    def check(self, ing: Ingested, plan: ActionPlan, indicators: Indicators) -> GuardVerdict:
        reasons: list[str] = []
        signals: list[str] = []
        scores: dict[str, float] = {}
        verdict = Verdict.OK

        # --- 1. Stealth unicode signals -------------------------------------
        if indicators.zero_width_chars > 0:
            signals.append("zero_width_chars")
            reasons.append(f"document contains {indicators.zero_width_chars} zero-width characters")
        if indicators.bidi_chars > 0:
            signals.append("bidi_chars")
            reasons.append("document contains bidirectional control characters")
        if indicators.homoglyph_hits:
            signals.append("homoglyphs")
            reasons.append(f"homoglyph substitution detected: {indicators.homoglyph_hits}")
        if indicators.mixed_script:
            signals.append("mixed_script")
            reasons.append("mixed-script document (possible obfuscation)")
        if indicators.hidden_instruction_snippets:
            signals.append("hidden_instructions")
            reasons.append(
                "instruction-like phrases: " + ", ".join(indicators.hidden_instruction_snippets[:5])
            )
        if indicators.entropy_spikes:
            signals.append("entropy_spikes")
            reasons.append(f"{indicators.entropy_spikes} high-entropy blob(s) in document")

        # --- 2. Raw-text command scan (defence in depth) ---------------------
        raw_cmds = _CMD_IN_DOC.findall(self._raw)
        if raw_cmds:
            signals.append("commands_in_document")
            reasons.append("payment commands found inside untrusted document text")
        meta = _META_CMD.search(self._raw)
        if meta:
            signals.append("meta_instructions")
            reasons.append("document contains meta-instructions targeting the assistant")

        # --- 3. Plan-vs-document grounding ----------------------------------
        grounded, ground_reason = self._grounding_check(ing.text, plan)
        if not grounded:
            reasons.append(ground_reason or "plan not grounded in document")
            signals.append("plan_not_grounded")
        scores["grounded"] = 1.0 if grounded else 0.0

        # --- 4. Risk scoring --------------------------------------------------
        score = 0.0
        score += 3.0 * min(indicators.zero_width_chars, 20) / 20
        score += 3.0 * min(indicators.bidi_chars, 20) / 20
        score += 2.0 if indicators.homoglyph_hits else 0.0
        score += 1.5 if indicators.mixed_script else 0.0
        score += 2.0 if indicators.hidden_instruction_snippets or raw_cmds else 0.0
        score += 2.5 if meta else 0.0
        score += 2.5 if not grounded else 0.0
        scores["risk"] = round(score, 2)

        # --- 5. Verdict bands --------------------------------------------------
        if score >= 4.5:
            verdict = Verdict.BLOCK
        elif score >= 2.0 or not grounded:
            verdict = Verdict.REVIEW
        else:
            verdict = Verdict.OK

        # --- 6. Deterministic hard rules --------------------------------------
        if plan.intent in ("payment", "invoice_approval"):
            amount = plan.amount or 0.0
            if not plan.amount:
                if verdict == Verdict.OK:
                    verdict = Verdict.REVIEW
                    reasons.append("payment intent without extractable amount requires manual review")
            elif amount > settings.max_safe_transfer:
                verdict = Verdict.BLOCK
                reasons.append(
                    f"amount {amount:,.2f} exceeds max safe transfer {settings.max_safe_transfer:,.2f}"
                )
            elif amount > settings.confirm_above_amount and verdict == Verdict.OK:
                verdict = Verdict.REVIEW
                reasons.append(
                    f"amount {amount:,.2f} exceeds auto-execution limit {settings.confirm_above_amount:,.2f}"
                )

        return GuardVerdict(
            verdict=verdict,
            reasons=reasons,
            grounded=grounded,
            attack_signals=signals,
            scores=scores,
        )

    def _grounding_check(self, doc_text: str, plan: ActionPlan) -> tuple[bool, Optional[str]]:
        """Every executable field in the plan must appear verbatim in the doc."""
        if plan.intent == "unknown":
            return True, None  # nothing to execute, nothing to ground
        if plan.intent in ("budget_query", "report"):
            return True, None  # read-only intents always grounded

        lower = doc_text.lower()
        # Amount must appear in the document
        if plan.amount is not None:
            amt = plan.amount
            variants = {
                f"{amt:,.2f}",
                f"{amt:,.0f}",
                f"{amt:.2f}",
                f"{amt:.0f}",
                str(int(amt)),
            }
            if amt >= 100_000 and amt % 100_000 == 0:
                variants.add(f"{amt / 100_000:.0f} lakh")
                variants.add(f"{amt / 100_000:.0f} lac")
            if amt >= 1000 and amt % 1000 == 0:
                variants.add(f"{amt / 1000:.0f}k")
            if not any(v.lower() in lower for v in variants):
                return False, f"plan amount {amt:,.2f} not found in document text"

        # Beneficiary must appear in the document
        if plan.beneficiary:
            name = plan.beneficiary.lower().strip()
            if name not in lower and name.rstrip("s") not in lower:
                return False, f"plan beneficiary '{plan.beneficiary}' not found in document text"

        return True, None
