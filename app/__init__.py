"""FS-2605 — Injection-Resistant Financial Assistant (Team Code Fellas).

Layer map:
    ingestion  -> Layer 1: normalize + deterministic indicators
    analyzer   -> Layer 2: Gemini 2.0 Flash with deterministic fallback
    guard      -> Layer 3: deterministic final authority (never an LLM)
    proofs     -> Layer 4a: hash-chained, HMAC-signed tamper-evident proofs
    executor   -> Layer 4b: idempotent SQLite ledger with rollback window
    metrics    -> Prometheus counters/histograms exposed at /metrics
    main       -> FastAPI service wiring it all together
"""
