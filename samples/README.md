# Sample Documents — FS-2605 Demo Corpus

Feed these through the pipeline to see every guard path:

| File | Expected | Why |
|---|---|---|
| `01_clean_invoice_small.txt` | OK → executes | ₹1,500 < ₹2,000 auto-limit, fully grounded |
| `02_clean_invoice_medium.txt` | REVIEW | ₹12,000 above auto-limit → human approval |
| `03_fraud_cfo_email.txt` | BLOCK | authority impersonation + injection phrases |
| `04_hidden_injection_zero_width.txt` | BLOCK | 7 invisible U+200B chars + smuggled command |
| `05_homoglyph_vendor.txt` | BLOCK | Cyrillic а/о homoglyphs + mixed script |
| `06_over_limit_attack.txt` | BLOCK | ₹30,00,000 >> ₹25,000 hard cap |
| `07_missing_amount.txt` | REVIEW | payment with no amount → fail-closed |
| `08_benign_query.txt` | OK | read-only query, nothing executes |

## Run one

```bash
curl -X POST http://localhost:8000/process -H "Content-Type: application/json" \
  -d "{\"channel\":\"email\",\"text\":\"$(cat samples/03_fraud_cfo_email.txt)\"}"
```

Or paste into the dashboard at `/` — or export as PDF and use **Upload PDF**
(same guard applies: `POST /process-pdf`).

Caveat: files 04/05 contain invisible/lookalike unicode — some Windows consoles
mangle them; prefer the dashboard or a UTF-8-aware client.
