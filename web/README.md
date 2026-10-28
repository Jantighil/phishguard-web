# PhishGuard

Explainable phishing detection for **links** and **e-mails**, as a web app. Based on the paper *An Improved Model for Deep Dive Phishing Detection*: a boosting ensemble (character-n-gram model + lexical features -> LightGBM) that explains every verdict.

![CI](../../actions/workflows/ci.yml/badge.svg)

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000                        # open http://localhost:8000
```
Docker: `docker build -t phishguard . && docker run -p 8000:8000 phishguard`
Tests: `pip install -r requirements-dev.txt && python -m pytest -q`

Settings (environment variables): `ENABLE_CRAWL=1` (turn on live page inspection, off by default), `RATE_LIMIT_PER_MIN=30`.

## What the user sees: a detailed, educational verdict
1. **Verdict** (PHISHING / SUSPICIOUS / LIKELY LEGITIMATE), risk percentage, and a borderline warning for uncertain scores.
2. **Verdict explained**: plain-language paragraphs saying *why*, naming the real owner of the address and what the model weighed (including signals that leaned the other way).
3. **Your input with warning signs marked** (exact characters in a link; influential words in an e-mail).
4. **Anatomy of the address** (links): protocol, sub-domain, **registered domain = the real owner**, port, path, query, each with a one-line lesson.
5. **Warning signs found**, ranked HIGH / MEDIUM / LOW. Each card shows *what we saw* (exact text), *what it is*, *why attackers use it* and *how to spot it yourself*. E-mail tactics: urgency, threats, credential requests, reward bait, generic greeting, payment pressure, suspicious links.
6. **Checks that came out clean**, **what we cannot verify** (domain ownership/age, e-mail headers, hacked genuine sites ...), **what to do now**, and **double-check it yourself**.
7. **Analyst details** (collapsed): all scores, thresholds, model versions, TreeSHAP signals with weights, raw findings, suggested follow-up, and a copyable plain-text report.

Every sentence is generated from facts found in the input (matched text, parsed address parts, crawler observations); the rule layer can only *raise* a verdict: a link with a strong rule hit (look-alike brand, raw IP, hidden `@`, brand inside another domain) is never shown as LIKELY LEGITIMATE, even if the model score is low (this happened in testing with `g00gle.com`).

## API
| Endpoint | Body | Notes |
|---|---|---|
| `POST /api/analyze/url` | `{"url": "...", "crawl": false}` | http/https only, <= 2048 chars |
| `POST /api/analyze/email` | `{"text": "..."}` | 20 - 50,000 chars |
| `GET /api/health`, `GET /api/about` | | status; measured metrics and limits |

Interactive docs at `/api/docs`. Errors are clean JSON (`422` bad input, `429` rate-limited), never stack traces.

## Security
- Strict CSP, `X-Frame-Options: DENY`, `nosniff`; the UI renders all text with `textContent` (no `innerHTML`), so pasted HTML/JS cannot execute.
- Per-IP rate limit (in-memory; behind a reverse proxy, also rate-limit there).
- Crawler: off by default; blocks private / loopback / link-local addresses on every redirect hop (SSRF guard), 5 redirects, 2 MB, 8 s, no JavaScript executed. Before enabling it publicly, run it in a network-restricted container.

## Model performance (held-out test, split by host)
| | Accuracy | Precision | Recall | False-alarm rate | AUC |
|---|---|---|---|---|---|
| Links (n = 64,635) | 94.7% | 96.0% | 91.2% | 2.8% | 0.985 |
| E-mails (n = 8,637) | 98.3% | 98.2% | 97.9% | 1.4% | 0.998 |
| Page model (n = 19,777) | 96.4% | 96.6% | 95.2% | 2.6% | 0.995 |

Full numbers and baselines: `metrics/`.

## Honest limitations
- **No classifier is "without mistakes".** These figures are on research datasets; real-world accuracy is lower. Treat the verdict as triage, not as a security guarantee.
- **Source bias.** The data mixes sources with different habits (e.g. one source's legitimate URLs are all bare domains). A leave-one-source-out test dropped accuracy to 38 - 84% on an unseen source. Adding more diverse legitimate URLs is the most valuable improvement.
- **E-mail data** mixes corpora (Enron-style business mail as the legitimate class), so 98% overstates performance on modern inboxes. The word highlights reflect those corpora, not universal truths.
- **Page model** was trained on one dataset's page features and the crawler recomputes them approximately; the 60/40 score fusion is a fixed heuristic. Static crawling cannot see content built by JavaScript.
- Hacked legitimate domains hosting phishing pages, and brand-new attacks, can be missed. IPv6 links are not supported.

## Layout
```
app/            FastAPI service + static UI (index.html, app.js, style.css)
phishguard/     features, inference, rule indicators (explain.py), educational reports (educate.py), crawler
models/         trained models (url / email / page)  - pinned library versions, see requirements.txt
metrics/        evaluation results
training/       data prep + training scripts (run from the repo root: python training/make_raw.py data.csv, then prep, train_url, train_email, train_page)
tests/          43 tests (API, validation, SSRF, report honesty, rule override, XSS guard)
finetune_transformer.py   GPU stage from the paper (DistilBERT/BERT/RoBERTa) - untested starter script
```
Retraining needs `pip install -r requirements-train.txt` and the 500k dataset (not included).

## License
MIT.
