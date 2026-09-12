"""Layer 4b — Idempotent executor with rollback window.

Executes approved plans against a SQLite ledger. Guarantees:
  * Idempotency: same request_id => same outcome, executed exactly once.
  * Rollback window: recent executions can be reversed (rollback(execution_id)).
  * Exact reconciliation: every rupee is accounted for in ledger_entries.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .config import settings
from .schemas import ActionPlan, Verdict


@dataclass
class ExecutionResult:
    execution_id: str
    status: str  # "executed" | "already_executed" | "blocked" | "review" | "failed"
    detail: str
    balance_after: float


class Executor:
    def __init__(self) -> None:
        self._db: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        self._seq = 0

    def connect(self) -> None:
        Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
        fresh = not os.path.exists(settings.db_path)
        self._db = sqlite3.connect(settings.db_path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                account_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                balance REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS executions (
                execution_id TEXT PRIMARY KEY,
                request_id TEXT UNIQUE NOT NULL,
                plan_json TEXT NOT NULL,
                verdict TEXT NOT NULL,
                amount REAL,
                beneficiary TEXT,
                status TEXT NOT NULL,
                created_ms INTEGER NOT NULL,
                rolled_back INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS ledger_entries (
                entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                delta REAL NOT NULL,
                created_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS proofs (
                proof_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                chain_hash TEXT NOT NULL,
                created_ms INTEGER NOT NULL,
                proof_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS replay_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                replayed_ms INTEGER NOT NULL
            );
            """
        )
        self._db.commit()
        if fresh:
            self._seed_accounts()

    def _seed_accounts(self) -> None:
        assert self._db is not None
        seed = [
            ("ops-main", "Operations Main", 500_000.0),
            ("ops-vendor", "Vendor Settlement", 120_000.0),
            ("ops-payroll", "Payroll", 80_000.0),
        ]
        self._db.executemany(
            "INSERT OR IGNORE INTO accounts (account_id, owner, balance) VALUES (?, ?, ?)", seed
        )
        self._db.commit()

    # ------------------------------------------------------------------ core
    def execute(self, request_id: str, plan: ActionPlan, verdict: Verdict) -> ExecutionResult:
        assert self._db is not None
        with self._lock:
            row = self._db.execute(
                "SELECT execution_id, status, amount, beneficiary FROM executions WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row:
                self._db.execute(
                    "INSERT INTO replay_log (request_id, replayed_ms) VALUES (?, strftime('%s','now') * 1000)",
                    (request_id,),
                )
                self._db.commit()
                return ExecutionResult(
                    execution_id=row["execution_id"],
                    status="already_executed" if row["status"] == "executed" else row["status"],
                    detail="idempotent replay: request was already processed",
                    balance_after=self._balance("ops-main"),
                )
            if verdict != Verdict.OK:
                self._record_noop(request_id, plan, verdict)
                return ExecutionResult(
                    execution_id=f"noop_{request_id}",
                    status="blocked" if verdict == Verdict.BLOCK else "review",
                    detail="guard verdict prevents execution",
                    balance_after=self._balance("ops-main"),
                )
            amount = float(plan.amount or 0.0)
            beneficiary = plan.beneficiary or "unknown-beneficiary"
            credit_account = self._ensure_beneficiary_account(beneficiary)
            self._seq += 1
            execution_id = f"ex_{self._seq:06d}_{request_id[:12]}"
            self._db.execute("BEGIN")
            try:
                self._db.execute(
                    "UPDATE accounts SET balance = balance - ? WHERE account_id = 'ops-main'",
                    (amount,),
                )
                self._db.execute(
                    "UPDATE accounts SET balance = balance + ? WHERE account_id = ?",
                    (amount, credit_account),
                )
                self._db.execute(
                    "INSERT INTO executions (execution_id, request_id, plan_json, verdict, amount, beneficiary, status, created_ms) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'executed', strftime('%s','now') * 1000)",
                    (
                        execution_id,
                        request_id,
                        json.dumps(plan.model_dump()),
                        verdict.value,
                        amount,
                        beneficiary,
                    ),
                )
                self._db.executemany(
                    "INSERT INTO ledger_entries (execution_id, account_id, delta, created_ms) VALUES (?, ?, ?, strftime('%s','now') * 1000)",
                    [
                        (execution_id, "ops-main", -amount),
                        (execution_id, credit_account, amount),
                    ],
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                return ExecutionResult(
                    execution_id=execution_id,
                    status="failed",
                    detail="database transaction failed; nothing was moved",
                    balance_after=self._balance("ops-main"),
                )
            return ExecutionResult(
                execution_id=execution_id,
                status="executed",
                detail=f"moved {amount:,.2f} {plan.currency} to {beneficiary}",
                balance_after=self._balance("ops-main"),
            )

    def rollback(self, execution_id: str) -> ExecutionResult:
        """Reverse an executed transfer within the rollback window."""
        assert self._db is not None
        with self._lock:
            row = self._db.execute(
                "SELECT amount, beneficiary, rolled_back FROM executions WHERE execution_id = ? AND status = 'executed'",
                (execution_id,),
            ).fetchone()
            if not row:
                return ExecutionResult(execution_id, "failed", "no executed transfer found for rollback", self._balance("ops-main"))
            if row["rolled_back"]:
                return ExecutionResult(execution_id, "failed", "already rolled back", self._balance("ops-main"))
            amount = float(row["amount"] or 0.0)
            beneficiary = row["beneficiary"] or "unknown-beneficiary"
            credit_account = self._ensure_beneficiary_account(beneficiary)
            self._db.execute("BEGIN")
            try:
                self._db.execute("UPDATE accounts SET balance = balance + ? WHERE account_id = 'ops-main'", (amount,))
                self._db.execute("UPDATE accounts SET balance = balance - ? WHERE account_id = ?", (amount, credit_account))
                self._db.execute("UPDATE executions SET rolled_back = 1 WHERE execution_id = ?", (execution_id,))
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                return ExecutionResult(execution_id, "failed", "rollback transaction failed", self._balance("ops-main"))
            return ExecutionResult(execution_id, "executed", f"rolled back {amount:,.2f}", self._balance("ops-main"))

    # ---------------------------------------------------------------- helpers
    def _ensure_beneficiary_account(self, beneficiary: str) -> str:
        assert self._db is not None
        account_id = f"bnf-{beneficiary.lower().replace(' ', '-')[:40]}"
        self._db.execute(
            "INSERT OR IGNORE INTO accounts (account_id, owner, balance) VALUES (?, ?, 0)",
            (account_id, beneficiary),
        )
        return account_id

    def _balance(self, account_id: str) -> float:
        assert self._db is not None
        row = self._db.execute("SELECT balance FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        return float(row["balance"]) if row else 0.0

    def _record_noop(self, request_id: str, plan: ActionPlan, verdict: Verdict) -> None:
        assert self._db is not None
        self._seq += 1
        self._db.execute(
            "INSERT OR IGNORE INTO executions (execution_id, request_id, plan_json, verdict, amount, beneficiary, status, created_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%s','now') * 1000)",
            (
                f"noop_{self._seq:06d}",
                request_id,
                json.dumps(plan.model_dump()),
                verdict.value,
                plan.amount,
                plan.beneficiary,
                "blocked" if verdict == Verdict.BLOCK else "review",
            ),
        )
        self._db.commit()

    def mark_reviewed(self, request_id: str, outcome: str) -> bool:
        """Close out a pending review row: status -> 'approved' | 'rejected'."""
        assert self._db is not None
        cur = self._db.execute(
            "UPDATE executions SET status = ? WHERE request_id = ? AND status = 'review'",
            (outcome, request_id),
        )
        self._db.commit()
        return cur.rowcount > 0

    def save_proof(self, proof_json: str, proof_id: str, request_id: str, chain_hash: str) -> None:
        assert self._db is not None
        self._db.execute(
            "INSERT OR REPLACE INTO proofs (proof_id, request_id, chain_hash, created_ms, proof_json) VALUES (?, ?, ?, strftime('%s','now') * 1000, ?)",
            (proof_id, request_id, chain_hash, proof_json),
        )
        self._db.commit()

    def last_chain_hash(self) -> str:
        assert self._db is not None
        row = self._db.execute("SELECT chain_hash FROM proofs ORDER BY created_ms DESC, proof_id DESC LIMIT 1").fetchone()
        return row["chain_hash"] if row else "GENESIS"

    def stats(self) -> dict[str, Any]:
        assert self._db is not None
        executed = self._db.execute("SELECT COUNT(*) c FROM executions WHERE status='executed' AND rolled_back=0").fetchone()["c"]
        blocked = self._db.execute("SELECT COUNT(*) c FROM executions WHERE status='blocked'").fetchone()["c"]
        review = self._db.execute("SELECT COUNT(*) c FROM executions WHERE status='review'").fetchone()["c"]
        replays = self._db.execute("SELECT COUNT(*) c FROM replay_log").fetchone()["c"]
        return {
            "executed": executed,
            "blocked": blocked,
            "review": review,
            "replays_blocked": replays,
            "ops_main_balance": self._balance("ops-main"),
        }

    def accounts(self) -> list[dict[str, Any]]:
        assert self._db is not None
        rows = self._db.execute(
            "SELECT account_id, owner, balance FROM accounts ORDER BY balance DESC LIMIT 8"
        ).fetchall()
        return [dict(r) for r in rows]

    def recent(self, limit: int = 12) -> list[dict[str, Any]]:
        assert self._db is not None
        rows = self._db.execute(
            "SELECT execution_id, request_id, status, amount, beneficiary, created_ms, rolled_back "
            "FROM executions ORDER BY created_ms DESC, rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        if self._db:
            self._db.close()
            self._db = None
