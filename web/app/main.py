"""PhishGuard web service (FastAPI). Run: uvicorn app.main:app"""
import json, os, re, threading, time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS
from phishguard.educate import build_email_report, build_url_report
from phishguard.explain import FLOOR_KINDS, SEVERITY, URG, merge_spans, phrase_spans, url_anatomy, url_indicators
from phishguard.predict import PhishGuard

ROOT = Path(__file__).resolve().parent.parent
ENABLE_CRAWL = os.getenv('ENABLE_CRAWL', '0') == '1'
RATE_LIMIT = int(os.getenv('RATE_LIMIT_PER_MIN', '30'))
MAX_URL, MAX_EMAIL = 2048, 50_000
VERSION = '1.0.0'
DISCLAIMER = ('PhishGuard is a machine-learning triage aid, not a guarantee. It can be wrong in both directions. '
              'When in doubt, do not enter credentials; open the organisation\'s official site by typing its address yourself.')

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.g = PhishGuard(str(ROOT / 'models')); yield

app = FastAPI(title='PhishGuard', version=VERSION, lifespan=lifespan, docs_url='/api/docs', redoc_url=None, openapi_url='/api/openapi.json')
_hits, _lock = defaultdict(deque), threading.Lock()

@app.middleware('http')
async def guard(request: Request, call_next):
    if request.url.path.startswith('/api/') and request.method == 'POST':
        ip, now = (request.client.host if request.client else 'unknown'), time.time()
        with _lock:
            q = _hits[ip]
            while q and now - q[0] > 60: q.popleft()
            if len(q) >= RATE_LIMIT:
                return JSONResponse({'detail': 'Too many requests - please wait a minute and try again.'}, status_code=429, headers={'Retry-After': '60'})
            q.append(now)
    resp = await call_next(request)
    resp.headers.update({'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        'Cache-Control': 'no-store' if request.url.path.startswith('/api/') else 'public, max-age=300'})
    return resp

class UrlRequest(BaseModel):
    url: str
    crawl: bool = False

class EmailRequest(BaseModel):
    text: str

def clean_url(raw: str) -> str:
    u = raw.strip()
    if not u: raise HTTPException(422, 'Please enter a web address.')
    if len(u) > MAX_URL: raise HTTPException(422, f'That address is too long (limit {MAX_URL} characters).')
    if re.search(r'\s', u) or re.search(r'[\x00-\x1f\x7f]', u): raise HTTPException(422, 'The address must not contain spaces or control characters.')
    m = re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]*):(//)?', u)
    if m and m.group(1).lower() not in ('http', 'https') and m.group(2): raise HTTPException(422, 'Only http:// and https:// addresses can be analysed.')
    try: host = urlsplit(u if re.match(r'^https?://', u, re.I) else '//' + u).hostname
    except ValueError: host = None
    if host and ':' in host: raise HTTPException(422, 'Links that use an IPv6 address are not supported.')
    if not host or ('.' not in host and host != 'localhost'): raise HTTPException(422, "That does not look like a web address (e.g. https://example.com/page).")
    return u

def summary(verdict, risk):
    pct = round(risk * 100, 1)
    return {'PHISHING': f'The model rates this {pct}% likely to be phishing. Do not open it or enter any information.',
            'SUSPICIOUS': f'The model rates this {pct}% likely to be phishing - the evidence is mixed. Treat it with caution and verify it another way.',
            'LIKELY LEGITIMATE': f'The model rates this only {pct}% likely to be phishing, but no tool can prove a link is safe.'}[verdict]

@app.get('/api/health')
def health(): return {'status': 'ok', 'version': VERSION, 'crawl_enabled': ENABLE_CRAWL}

@app.get('/api/about')
def about():
    m = json.loads((ROOT / 'metrics' / 'url_metrics.json').read_text()); e = json.loads((ROOT / 'metrics' / 'email_metrics.json').read_text())
    s = m['test']['STACKED ENSEMBLE (char-LR + lexical + LightGBM)']; es = e['test']['STACKED ENSEMBLE (TF-IDF LR + cues + LightGBM)']
    return {'version': VERSION, 'crawl_enabled': ENABLE_CRAWL, 'url_test': {k: round(s[k], 4) for k in ('accuracy', 'precision', 'recall', 'f1', 'fpr', 'auc')},
            'email_test': {k: round(es[k], 4) for k in ('accuracy', 'precision', 'recall', 'f1', 'fpr', 'auc')}, 'disclaimer': DISCLAIMER,
            'limitations': ['Trained on public research datasets; real-world accuracy is lower, especially for sources unlike the training data.',
                            'Legitimate sites with unusual-looking addresses can be flagged; phishing on a hacked legitimate domain can be missed.',
                            'Reasons describe what the model used, not proof of intent.']}

def analyst_block(g, extra):
    return dict(model_versions=[g.url['version'], g.email['version'], g.page['version']], decision_threshold_url=g.url['threshold'], **extra)

@app.post('/api/analyze/url')
def analyze_url(req: UrlRequest):
    u = clean_url(req.url); g = app.state.g
    try: r = g.analyze_url(u, crawl=req.crawl and ENABLE_CRAWL, allow_private=False)
    except Exception: raise HTTPException(500, 'The analysis failed unexpectedly for this input.')
    ind = url_indicators(u); anatomy = url_anatomy(u); verdict, override = r['verdict'], None
    floor = [i for i in ind if i['kind'] in FLOOR_KINDS]
    if verdict == 'LIKELY LEGITIMATE' and floor:     # strong rule hit: never present such a link as likely legitimate
        verdict = 'SUSPICIOUS'
        override = (f"The model's own score is low ({round(r['risk'] * 100, 1)}%), but the link contains a strong warning sign "
                    f"(\"{u[floor[0]['start']:floor[0]['end']]}\": {floor[0]['label'].lower()}), so we raised the verdict to SUSPICIOUS.")
    page = dict(requested=req.crawl, enabled=ENABLE_CRAWL, checked=r['page_checked'], score=r.get('page_score'), reasons=r.get('page_reasons', []),
                info=r.get('crawl_info'), error=r.get('crawl_error'), features=r.get('page_features'))
    if req.crawl and not ENABLE_CRAWL: page['error'] = 'Live page checking is turned off on this server.'
    report = build_url_report(u, verdict, r['risk'], ind, r['reasons'], page, override, anatomy)
    summ = override or summary(verdict, r['risk'])
    follow = [f"Block or sandbox the registered domain {anatomy['owner']} (and the full host {anatomy['host']}) if the verdict is confirmed.",
              'Search mail/proxy/DNS logs for other users who visited it.', 'Cross-check the URL in independent sources (blocklists, URL scanners) before acting: this tool uses only the link text'
              + (' and a static page fetch.' if page['checked'] else '.')]
    return dict(type='url', input=u, verdict=verdict, model_verdict=r['verdict'], risk=r['risk'], summary=summ, borderline=0.3 <= r['risk'] < 0.85,
                report=report, model_reasons=r['reasons'], indicators=[dict(i, severity=SEVERITY[i['kind']]) for i in ind], page=page, url_score=r['url_score'],
                analyst=analyst_block(g, dict(normalized_input=r['normalized'], url_model_score=r['url_score'], page_model_score=page['score'],
                    fusion='logit-average 0.6 link / 0.4 page (fixed heuristic)' if page['checked'] else 'link model only', rule_override=bool(override), follow_up=follow)),
                disclaimer=DISCLAIMER)

@app.post('/api/analyze/email')
def analyze_email(req: EmailRequest):
    t = req.text.strip()
    if len(t) < 20: raise HTTPException(422, 'Please paste the full e-mail text (at least a few sentences).')
    if len(t) > MAX_EMAIL: raise HTTPException(422, f'That e-mail is too long (limit {MAX_EMAIL} characters).')
    g = app.state.g
    try: r = g.score_email(t)
    except Exception: raise HTTPException(500, 'The analysis failed unexpectedly for this input.')
    # order matters: known phishing cues (risk) win over a model 'safe' word on the same text; filler words are never marked 'safe'
    safe = [x['term'] for x in r['terms'] if x['direction'] == 'safe' and not set(x['term'].split()) <= ENGLISH_STOP_WORDS]
    spans = (phrase_spans(t, [x['term'] for x in r['terms'] if x['direction'] == 'risk'], 'risk') + phrase_spans(t, URG, 'risk') + phrase_spans(t, safe, 'safe'))
    links = []
    for m in list(re.finditer(r'https?://[^\s"\'<>)\]]+', t))[:5]:
        lu = m.group(0).rstrip('.,;')
        try:
            lr = g.score_url(lu); inds = [dict(kind=i['kind'], label=i['label'], severity=SEVERITY[i['kind']]) for i in url_indicators(lu)]
            links.append(dict(url=lu, risk=round(lr['p'], 4), indicators=inds))
        except Exception: pass
    report = build_email_report(t, r['verdict'], r['p'], r['explain'], links)
    return dict(type='email', verdict=r['verdict'], risk=round(r['p'], 4), summary=summary(r['verdict'], r['p']), borderline=0.3 <= r['p'] < 0.85,
                report=report, model_reasons=r['explain'], terms=r['terms'], spans=merge_spans(spans), links=links, text=t,
                analyst=analyst_block(g, dict(email_model_score=round(r['p'], 4), influential_terms=r['terms'], follow_up=['Obtain the full headers and check SPF/DKIM/DMARC results for the sender domain.', 'Detonate attachments and links only in a sandbox.', 'Check whether other recipients got the same message.'])),
                disclaimer=DISCLAIMER)

STATIC = ROOT / 'app' / 'static'
app.mount('/static', StaticFiles(directory=STATIC), name='static')
@app.api_route('/', methods=['GET', 'HEAD'], include_in_schema=False)
def index(): return FileResponse(STATIC / 'index.html')
