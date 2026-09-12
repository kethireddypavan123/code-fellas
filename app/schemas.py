"""Pydantic schemas shared by every layer.

State ownership follows the R1 deck: each layer owns its state, the guard's
verdict is final authority, the executor is idempotent with a rollback window.
"""
from __future__ import annotations

import time
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    OK = "OK"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


class DocIn(BaseModel):
    """Layer 1 input: raw document from any channel."""

    channel: Literal["pdf", "email", "invoice", "memo"] = "memo"
    text: str = Field(min_length=1, max_length=200_000)
    source: str = Field(default="unknown", max_length=256)
    request_id: Optional[str] = Field(default=None, max_length=128)


class Indicators(BaseModel):
    """Layer 1 output: deterministic document indicators."""

    zero_width_chars: int = 0
    bidi_chars: int = 0
    homoglyph_hits: list[str] = Field(default_factory=list)
    mixed_script: bool = False
    invisible_word_count: int = 0
    hidden_instruction_snippets: list[str] = Field(default_factory=list)
    entropy_spikes: int = 0
    clean_text: str = ""


class ActionPlan(BaseModel):
    """Layer 2 output: structured plan extracted from the document."""

    intent: Literal["payment", "invoice_approval", "budget_query", "report", "unknown"]
    amount: Optional[float] = None
    currency: str = "INR"
    beneficiary: Optional[str] = None
    account_hint: Optional[str] = None
    due_date: Optional[str] = None
    confidence: float = 0.0
    source_model: str = "deterministic-fallback"


class GuardVerdict(BaseModel):
    """Layer 3 output: final authority on whether the plan may execute."""

    verdict: Verdict
    reasons: list[str] = Field(default_factory=list)
    grounded: bool = False
    attack_signals: list[str] = Field(default_factory=list)
    scores: dict[str, float] = Field(default_factory=dict)


class Proof(BaseModel):
    """Layer 4 artifact: tamper-evident, independently verifiable."""

    proof_id: str
    request_hash: str
    plan_hash: str
    verdict_hash: str
    chain_hash: str
    prev_chain_hash: str
    signature: str
    created_ms: int
    payload: dict[str, Any]


class ProcessResponse(BaseModel):
    """End-to-end API response."""

    request_id: str
    verdict: Verdict
    reasons: list[str]
    plan: Optional[ActionPlan]
    proof: Optional[Proof]
    execution: Optional[dict[str, Any]]
    review_url: Optional[str] = None
    timing_ms: dict[str, float]
    degraded: bool = False
    warnings: list[str] = Field(default_factory=list)


class VerifyRequest(BaseModel):
    proof_id: str
    proof: Proof


class ReviewDecision(BaseModel):
    decision: Literal["approve", "reject"]
    reviewer: str = "judge"


def now_ms() -> int:
    return int(time.time() * 1000)
