"""Layer 1 — Ingestion.

Parses raw document text into normalized text plus deterministic indicators.
This layer never decides — it only describes. Uses pure standard library so it
works with zero dependencies (real PDF parsing can be swapped in later; the
API contract stays the same).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import indicators as ind
from .config import settings
from .schemas import DocIn, Indicators

# Pattern used by attackers to mark content "system-only"
_SYSTEM_MARKER = re.compile(r"(?is)(system|internal)[-_ ]?only|<!--.*?-->|\[.*?system.*?\]")


@dataclass
class Ingested:
    doc: DocIn
    indicators: Indicators
    text: str  # normalized, sanitized text


def _normalize_whitespace(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def ingest(doc: DocIn) -> Ingested:
    """Parse raw text; flag stealth unicode but keep clean copy for analysis."""
    raw = doc.text
    res: Indicators = ind.scan(
        raw,
        entropy_threshold=settings.high_entropy_threshold,
        entropy_min_len=settings.high_entropy_min_len,
    )

    # Flag "system-only" style sections in the indicators too
    if _SYSTEM_MARKER.search(raw) and "system-only section" not in res.hidden_instruction_snippets:
        res.hidden_instruction_snippets.append("system-only section")

    text = _normalize_whitespace(res.clean_text)
    return Ingested(doc=doc, indicators=res, text=text)
