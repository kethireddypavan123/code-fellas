# AI Ledger — Code Fellas (FS-2605)

Per contest rules, this file records **when and how AI tools were used**, what was
produced by humans, and what was verified. Updated continuously during the sprint.

## Tooling
| Tool | Used for |
|---|---|
| Codebuff (Buffy agent) | Scaffolding, code generation, refactoring, test writing, bench design |
| Gemini 2.0 Flash (in-app) | Runtime document analysis (hosted LLM — permitted for FS-2605 only) |

## Log
| Time (H+) | Author | Action | Verified by |
|---|---|---|---|
| 0:00 | Team | Architecture, threat model, slide commitments | whole team |
| 0:30 | Team + Codebuff | Scaffold: config, schemas, requirements | code review |
| 1:00 | Team + Codebuff | Layer 1 ingestion + indicators (stealth unicode) | unit tests |
| 1:30 | Team + Codebuff | Layer 2 analyzer (Gemini + deterministic fallback) | unit tests |
| 2:00 | Team + Codebuff | Layer 3 deterministic guard + grounding check | unit tests + determinism test |
| 2:30 | Team | **R1 submission: interface contract + sample data + AI_LEDGER.md** | — |
| 3:00 | Team + Codebuff | Layer 4 proofs (hash chain + HMAC) + idempotent executor | tamper test |
| 3:30 | Team + Codebuff | FastAPI service (/healthz /metrics /process /verify /review) | API tests |
| 4:00 | Team + Codebuff | Attack corpus (22 attacks, 16 authored) + bench runner | bench run |
| 4:30 | Team + Codebuff | Test suite (unit + API), README, 3-command run | pytest |
| — | Team | *Sealed harness adaptation (H+8 change) — filled during event* | — |
| — | Team | *R3 video + final deck — filled during event* | — |

## Human vs AI authorship policy
- All **attack narratives, threat modelling, and slide claims** are human-authored.
- AI-assisted code is **reviewed line-by-line by the team** before commit.
- Every committed metric in the deck is **reproducible from the bench output**
  (`python -m bench.run_bench`).
- No AI generated any part of the security-critical guard logic without human review.

## Runtime LLM usage (transparency)
- Gemini 2.0 Flash is used **only** in Layer 2 (analysis), never in the guard
  (Layer 3), which is deterministic and is the sole execution authority.
- When the LLM is unavailable or slow, the pipeline **degrades to a deterministic
  fallback** and every response is flagged `degraded: true`.
