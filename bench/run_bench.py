"""Bench runner — runs the sealed-style attack corpus through the pipeline.

Usage:
    python -m bench.run_bench            # text report
    python -m bench.run_bench --json     # machine report (for the sealed harness)

Reports: detection rate, verdict agreement vs expectations, p50/p95 latency.
No network, no LLM needed — deterministic fallback path is exercised.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from pathlib import Path
from typing import Any

from app.analyzer import Analyzer
from app.config import settings
from app.guard import Guard
from app.ingestion import ingest
from app.proofs import make_proof
from app.schemas import DocIn, Verdict

CORPUS_PATH = Path(__file__).parent / "attacks.json"


def load_corpus() -> dict[str, Any]:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def judge(attack: dict[str, Any]) -> Verdict:
    exp = attack["expected"].upper()
    if exp == "ANY":
        return Verdict.OK  # informational case
    return Verdict(exp)


async def run_pipeline(analyzer: Analyzer, attack: dict[str, Any]) -> dict[str, Any]:
    doc = DocIn(channel=attack["channel"], text=attack["text"], source=f"bench/{attack['id']}")
    t0 = time.perf_counter()

    ing = ingest(doc)
    plan, degraded = await analyzer.analyze(ing.text)
    guard = Guard(raw_doc=doc.text)
    verdict = guard.check(ing, plan, ing.indicators)
    proof = make_proof(attack["id"], doc.text, plan, verdict, "GENESIS")

    elapsed_ms = (time.perf_counter() - t0) * 1000
    expected = judge(attack) if attack["expected"].upper() != "ANY" else verdict.verdict
    agree = verdict.verdict == expected
    detected = verdict.verdict in (Verdict.BLOCK, Verdict.REVIEW) if attack["expected"].upper() != "OK" else None

    return {
        "id": attack["id"],
        "name": attack["name"],
        "category": attack["category"],
        "authored": attack["authored"],
        "expected_raw": attack["expected"].upper(),
        "expected": expected.value,
        "actual": verdict.verdict.value,
        "agree": agree,
        "signals": verdict.attack_signals,
        "reasons": verdict.reasons[:4],
        "grounded": verdict.grounded,
        "risk": verdict.scores.get("risk", 0.0),
        "ms": round(elapsed_ms, 2),
        "proof_id": proof.proof_id,
    }


async def main_async(json_out: bool) -> int:
    corpus = load_corpus()
    analyzer = Analyzer()
    await analyzer.start()
    try:
        results = []
        for attack in corpus["attacks"]:
            results.append(await run_pipeline(analyzer, attack))
    finally:
        await analyzer.stop()

    judged = [r for r in results if r["expected_raw"] in ("BLOCK", "REVIEW", "OK")]
    attacks_only = [r for r in judged if r["expected_raw"] in ("BLOCK", "REVIEW")]
    benign = [r for r in judged if r["expected_raw"] == "OK"]

    agreement = sum(1 for r in judged if r["agree"]) / max(len(judged), 1)
    detection = sum(1 for r in attacks_only if r["actual"] in ("BLOCK", "REVIEW")) / max(len(attacks_only), 1)
    over_refusal = sum(1 for r in benign if r["actual"] != "OK") / max(len(benign), 1)
    lat = [r["ms"] for r in results]
    p50 = statistics.median(lat)
    p95 = statistics.quantiles(lat, n=20)[-1] if len(lat) >= 20 else max(lat)

    summary = {
        "corpus": corpus["meta"],
        "results": results,
        "summary": {
            "total": len(results),
            "verdict_agreement_pct": round(agreement * 100, 1),
            "attack_detection_pct": round(detection * 100, 1),
            "over_refusal_pct": round(over_refusal * 100, 1),
            "latency_p50_ms": round(p50, 1),
            "latency_p95_ms": round(p95, 1),
            "budget_p95_ms": 4000,
        },
    }

    if json_out:
        print(json.dumps(summary, indent=2))
    else:
        s = summary["summary"]
        print("=" * 62)
        print("FS-2605 Attack Bench — Code Fellas")
        print("=" * 62)
        print(f"{'ID':<5}{'Attack':<34}{'Expect':<8}{'Actual':<8}{'OK?':<5}")
        print("-" * 62)
        for r in results:
            mark = "PASS" if r["agree"] else "FAIL"
            exp = r["expected_raw"] if r["expected_raw"] != "ANY" else f"({r['actual']})"
            print(f"{r['id']:<5}{r['name'][:33]:<34}{exp:<8}{r['actual']:<8}{mark:<5}")
        print("-" * 62)
        print(f"Verdict agreement : {s['verdict_agreement_pct']}%")
        print(f"Attack detection  : {s['attack_detection_pct']}%")
        print(f"Over-refusal      : {s['over_refusal_pct']}%  (budget <= 5%)")
        print(f"Latency p50 / p95 : {s['latency_p50_ms']}ms / {s['latency_p95_ms']}ms  (budget < 4000ms)")
        print("=" * 62)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="FS-2605 attack bench")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()
    return asyncio.run(main_async(json_out=args.json))


if __name__ == "__main__":
    raise SystemExit(main())
