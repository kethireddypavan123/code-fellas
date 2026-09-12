"""FS-2605 — Injection-Resistant Financial Assistant.

FastAPI service wiring the four layers:
  1. Ingestion      — normalize + indicator extraction (pure, deterministic)
  2. Analyzer       — Gemini 2.0 Flash with deterministic fallback
  3. Guard          — final authority, never an LLM, deterministic verdicts
  4. Proof/Executor — hash-chained proofs + idempotent SQLite ledger

Run: uvicorn app.main:app --reload   (see README for the 3-command flow)
"""
from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from .analyzer import Analyzer
from .config import settings
from .executor import Executor
from .guard import Guard
from .ingestion import ingest
from .metrics import (
    ATTACK_SIGNAL_COUNT,
    EXECUTIONS,
    LLM_FALLBACK,
    PIPELINE_LATENCY,
    PROCESS_COUNT,
    SERVICE_UP,
    VERIFY_LATENCY,
)
from .proofs import make_proof, verify_proof
from .schemas import DocIn, ProcessResponse, ReviewDecision, Verdict, VerifyRequest

analyzer = Analyzer()
executor = Executor()
_review_queue: dict[str, dict[str, Any]] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    await analyzer.start()
    executor.connect()
    SERVICE_UP.set(1)
    yield
    SERVICE_UP.set(0)
    await analyzer.stop()
    executor.close()


app = FastAPI(title=settings.app_name, version=settings.version, lifespan=lifespan)


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.version,
        "degraded_llm": not bool(settings.gemini_api_key),
        "uptime_checks": "deterministic guard online",
    }


@app.get("/metrics")
def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/process", response_model=ProcessResponse)
async def process(doc: DocIn) -> ProcessResponse:
    """End-to-end pipeline: ingest → analyze → guard → proof → execute."""
    t0 = time.perf_counter()
    request_id = doc.request_id or f"req_{uuid.uuid4().hex[:12]}"

    # Layer 1 — ingestion (raw preserved for defence-in-depth scans)
    ing = ingest(doc)

    # Layer 2 — analyzer (LLM with deterministic fallback)
    plan, degraded = await analyzer.analyze(ing.text)
    if degraded:
        LLM_FALLBACK.inc()

    # Layer 3 — guard (deterministic, final authority)
    guard = Guard(raw_doc=doc.text)
    verdict = guard.check(ing, plan, ing.indicators)
    for s in verdict.attack_signals:
        ATTACK_SIGNAL_COUNT.labels(signal=s).inc()

    # Layer 4a — proof (hash-chained, HMAC-signed)
    prev = executor.last_chain_hash()
    proof = make_proof(request_id, doc.text, plan, verdict, prev)
    executor.save_proof(
        proof.model_dump_json(), proof.proof_id, request_id, proof.chain_hash
    )

    # Layer 4b — execution (idempotent, rollback window)
    execution: dict[str, Any]
    review_url: Optional[str] = None
    if verdict.verdict == Verdict.REVIEW:
        review_url = f"/review/{request_id}"
        _review_queue[request_id] = {
            "plan": plan.model_dump(),
            "verdict": verdict.model_dump(),
            "proof_id": proof.proof_id,
            "received_ms": int(time.time() * 1000),
        }
        res = executor.execute(request_id, plan, Verdict.REVIEW)
        execution = {"status": res.status, "detail": res.detail, "execution_id": res.execution_id}
    else:
        res = executor.execute(request_id, plan, verdict.verdict)
        execution = {"status": res.status, "detail": res.detail, "execution_id": res.execution_id}
    EXECUTIONS.labels(status=execution["status"]).inc()

    total_ms = (time.perf_counter() - t0) * 1000
    PIPELINE_LATENCY.observe(total_ms / 1000)
    PROCESS_COUNT.labels(verdict=verdict.verdict.value, degraded=str(degraded)).inc()

    return ProcessResponse(
        request_id=request_id,
        verdict=verdict.verdict,
        reasons=verdict.reasons,
        plan=plan,
        proof=proof,
        execution=execution,
        review_url=review_url,
        timing_ms={
            "total": round(total_ms, 2),
            "analyze_budget_s": settings.analyze_budget_s,
            "end_to_end_budget_s": 4.0,
        },
        degraded=degraded,
        warnings=["LLM unavailable — deterministic fallback used"] if degraded else [],
    )


@app.post("/verify")
def verify(req: VerifyRequest) -> dict[str, Any]:
    """Independently recompute the proof. Budget: <200ms."""
    t0 = time.perf_counter()
    ok, detail = verify_proof(req.proof)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    VERIFY_LATENCY.observe(elapsed_ms / 1000)
    return {
        "proof_id": req.proof.proof_id,
        "valid": ok,
        "detail": detail,
        "elapsed_ms": round(elapsed_ms, 2),
        "budget_ms": settings.verify_budget_ms,
    }


@app.get("/review/{request_id}")
def get_review(request_id: str) -> dict[str, Any]:
    item = _review_queue.get(request_id)
    if not item:
        raise HTTPException(status_code=404, detail="no pending review for this request_id")
    return {"request_id": request_id, **item}


@app.post("/review/{request_id}")
def decide_review(request_id: str, decision: ReviewDecision) -> dict[str, Any]:
    item = _review_queue.pop(request_id, None)
    if not item:
        raise HTTPException(status_code=404, detail="no pending review for this request_id")
    if decision.decision == "approve":
        from .schemas import ActionPlan

        plan = ActionPlan(**item["plan"])
        res = executor.execute(request_id, plan, Verdict.OK)
        EXECUTIONS.labels(status=res.status).inc()
        return {"request_id": request_id, "decision": "approved", "execution": {
            "status": res.status, "detail": res.detail, "execution_id": res.execution_id
        }}
    res = executor.execute(request_id, ActionPlan(intent="unknown"), Verdict.BLOCK)
    return {"request_id": request_id, "decision": "rejected", "execution": {
        "status": res.status, "detail": res.detail
    }}


@app.post("/rollback/{execution_id}")
def rollback(execution_id: str) -> dict[str, Any]:
    res = executor.rollback(execution_id)
    return {"execution_id": execution_id, "status": res.status, "detail": res.detail}


@app.get("/stats")
def stats() -> dict[str, Any]:
    return {"executor": executor.stats(), "pending_reviews": len(_review_queue)}
