# FS-2605 — Injection-Resistant Financial Assistant

**Team Code Fellas** · FinTech Sprint '26 · VIT AP

An AI financial assistant that **cannot be talked into moving money**: every
document is analyzed by an LLM, but a **deterministic guard is the final
authority** — and every decision ships with a **tamper-evident, verifiable proof**.

## Architecture (mirrors the R1 deck)

```
Document ──► [1] Ingestion ──► [2] Analyzer (Gemini 2.0 Flash + deterministic fallback)
                                       │
                                       ▼
                       [3] Deterministic Guard  ◄── final authority, never an LLM
                        │ grounded?  │ risk bands  │ hard policy rules
                                       ▼
              [4a] Proof (hash chain + HMAC)   [4b] Executor (SQLite, idempotent, rollback)
```

## Run in 3 commands

```bash
pip install -r requirements.txt
python -m bench.run_bench            # deterministic attack bench (no API key needed)
uvicorn app.main:app --port 8000     # live service
```

Optional: `export GEMINI_API_KEY=...` enables the hosted LLM in Layer 2.
Without it, the service runs fully deterministic (responses flagged `degraded: true`).

## API

| Endpoint | Method | Purpose |
|---|---|---|
| `/process` | POST | Full pipeline: ingest → analyze → guard → proof → execute |
| `/verify` | POST | Independently verify a proof (<200ms budget) |
| `/review/{request_id}` | GET/POST | Human-in-the-loop queue for REVIEW verdicts |
| `/rollback/{execution_id}` | POST | Reverse a recent execution |
| `/healthz` | GET | Liveness + degraded flag |
| `/metrics` | GET | Prometheus metrics |

## Committed metrics (verifiable — see bench)

| Metric | Commitment | Where proven |
|---|---|---|
| Attack detection | > 95% | `python -m bench.run_bench` summary |
| Determinism | 100% same input → same verdict | `tests/test_pipeline.py::test_determinism_same_input_same_verdict` |
| Proof verify | < 200ms | `/verify` elapsed_ms in tests |
| Over-refusal | ≤ 5% | bench benign cases |
| p95 latency | < 4s | bench + `/process timing_ms` |

## Where This Breaks (mandatory slide mirror)

- The guard's phrase list is finite — novel paraphrases of injection may land REVIEW, not BLOCK (by design: fail-closed).
- Grounding is lexical; a paraphrased amount ("eight thousand" vs "8k") can mis-ground → REVIEW.
- HMAC verification requires the server secret; key rotation invalidates old proofs.
- LLM unavailable ⇒ reduced extraction accuracy (fallback), never reduced safety.
- Single-node SQLite — no horizontal scaling; a production executor needs a real ledger with 2PC.

## Repo rules compliance

- `AI_LEDGER.md` maintained at repo root.
- Deterministic outputs: same request → same verdict, same proof hashes (proof_id is derived, not random).
- No secrets in repo: set `GEMINI_API_KEY` via environment only.
- ≥3 domain metrics exposed at `/metrics`.
