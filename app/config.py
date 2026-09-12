"""Central configuration for the Guarded AI Financial Assistant.

All budgets mirror the Round 1 deck commitments (slide 8):
  p95 end-to-end < 4s, proof < 3s, verify < 200ms, over-refusal <= ~5%.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _bool_env(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    app_name: str = "Guarded AI Financial Assistant"
    version: str = "1.0.0-fs2605"

    # --- Gemini (hosted LLM allowed for FS-2605) ------------------------------
    gemini_api_key: str = field(default_factory=lambda: os.environ.get("GEMINI_API_KEY", ""))
    gemini_endpoint: str = field(
        default_factory=lambda: os.environ.get(
            "GEMINI_ENDPOINT",
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
        )
    )
    llm_timeout_s: float = float(os.environ.get("LLM_TIMEOUT_S", "1.8"))

    # --- Service --------------------------------------------------------------
    db_path: str = field(default_factory=lambda: os.environ.get("DB_PATH", "data/ledger.db"))
    host: str = os.environ.get("HOST", "0.0.0.0")
    port: int = int(os.environ.get("PORT", "8000"))

    # --- Latency budgets (seconds) --------------------------------------------
    analyze_budget_s: float = 2.0
    guard_budget_s: float = 1.0
    execute_budget_s: float = 1.0
    proof_budget_s: float = 3.0
    verify_budget_ms: float = 200.0

    # --- Guard thresholds ------------------------------------------------------
    stealth_zxw_threshold: int = int(os.environ.get("STEALTH_ZXW_THRESHOLD", "4"))
    stealth_token_ratio: float = float(os.environ.get("STEALTH_TOKEN_RATIO", "0.30"))
    high_entropy_threshold: float = float(os.environ.get("HIGH_ENTROPY_THRESHOLD", "4.2"))
    high_entropy_min_len: int = int(os.environ.get("HIGH_ENTROPY_MIN_LEN", "28"))
    max_safe_transfer: float = float(os.environ.get("MAX_SAFE_TRANSFER", "25000.0"))
    confirm_above_amount: float = float(os.environ.get("CONFIRM_ABOVE_AMOUNT", "2000.0"))

    # --- Demo / bench ----------------------------------------------------------
    judge_jwt_secret: str = field(
        default_factory=lambda: os.environ.get("JUDGE_JWT_SECRET", "demo-only-not-a-secret-for-judges")
    )


settings = Settings()

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)
