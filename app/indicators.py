"""Deterministic text indicators — no ML, no network, pure functions.

These power Layer 1 (ingestion descriptions) and are re-used by the guard as
independent attack signals (defence in depth: ingestion sees raw bytes, the
guard re-checks the cleaned text and the plan).
"""
from __future__ import annotations

import math
import unicodedata
from collections import Counter
from typing import List

from .schemas import Indicators

# Zero-width / invisible formatting characters
ZERO_WIDTH = {
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero width no-break space (BOM smuggling)
}

# Bidirectional control characters (text direction attacks)
BIDI = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}

# Homoglyph pairs: cyrillic/greek letters that look like ASCII
HOMOGLYPHS = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u0501": "d", "\u03bf": "o", "\u03b1": "a",
    "\u03b5": "e", "\u03c1": "p", "\u03d2": "y",
}

# Common attacker phrasing (case-insensitive)
INJECTION_PHRASES = [
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "disregard all previous",
    "system prompt",
    "you are now",
    "new instructions",
    "override",
    "developer mode",
    "jailbreak",
    "transfer rs",
    "transfer inr",
    "transfer all",
    "send all funds",
    "move the funds",
    "approve payment to",
    "wire to account",
    "add beneficiary",
    "bypass",
    "do not inform",
    "don't tell the user",
    "hide this from",
    "admin override",
    "urgent transfer",
    "secret transfer",
]

SCRIPT_RANGES = [
    (0x0400, 0x04FF),  # cyrillic
    (0x0370, 0x03FF),  # greek
    (0x0600, 0x06FF),  # arabic
    (0x0900, 0x097F),  # devanagari
    (0x4E00, 0x9FFF),  # cjk
]


def _is_non_ascii_letter(ch: str) -> bool:
    cp = ord(ch)
    return ch.isalpha() and any(lo <= cp <= hi for lo, hi in SCRIPT_RANGES)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def scan(text: str, entropy_threshold: float = 4.2, entropy_min_len: int = 28) -> Indicators:
    """Return deterministic indicators for a raw document text."""
    zw = sum(text.count(c) for c in ZERO_WIDTH)
    bidi = sum(text.count(c) for c in BIDI)
    homo = [c for c in text if c in HOMOGLYPHS]

    scripts = {ch for ch in text if _is_non_ascii_letter(ch)}
    mixed = len(scripts) >= 2

    # Tokens that are invisible after stripping zero-width chars but have content
    invisible_words = 0
    hidden_snippets: List[str] = []
    normalized = text
    for c in ZERO_WIDTH | BIDI:
        normalized = normalized.replace(c, "")

    lowered = normalized.lower()
    for phrase in INJECTION_PHRASES:
        if phrase in lowered:
            hidden_snippets.append(phrase)

    # Entropy spikes on long token runs (obfuscated payloads / base64 blobs)
    spikes = 0
    for token in normalized.split():
        stripped = token.strip(".,;:()[]{}'\"")
        if len(stripped) >= entropy_min_len and shannon_entropy(stripped) >= entropy_threshold:
            spikes += 1

    return Indicators(
        zero_width_chars=zw,
        bidi_chars=bidi,
        homoglyph_hits=sorted({HOMOGLYPHS[c] for c in homo}),
        mixed_script=mixed,
        invisible_word_count=invisible_words,
        hidden_instruction_snippets=hidden_snippets[:10],
        entropy_spikes=spikes,
        clean_text=unicodedata.normalize("NFKC", normalized),
    )
