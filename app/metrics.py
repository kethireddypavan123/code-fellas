"""Prometheus metrics — exposed at /metrics (contest requirement)."""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

PROCESS_COUNT = Counter(
    "guard_process_total",
    "Documents processed by verdict",
    ["verdict", "degraded"],
)
ATTACK_SIGNAL_COUNT = Counter(
    "guard_attack_signal_total",
    "Attack signals raised by name",
    ["signal"],
)
PIPELINE_LATENCY = Histogram(
    "guard_pipeline_latency_seconds",
    "End-to-end pipeline latency",
    buckets=(0.1, 0.25, 0.5, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0, 10.0),
)
VERIFY_LATENCY = Histogram(
    "guard_verify_latency_seconds",
    "Proof verification latency",
    buckets=(0.01, 0.025, 0.05, 0.1, 0.2, 0.5),
)
LLM_FALLBACK = Counter(
    "guard_llm_fallback_total",
    "Times the deterministic fallback replaced the LLM",
)
EXECUTIONS = Counter(
    "guard_execution_total",
    "Executions by status",
    ["status"],
)
SERVICE_UP = Gauge("guard_service_up", "1 when service is healthy")
