import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from fastapi.testclient import TestClient
from app import main
from phishguard.explain import url_indicators, merge_spans

@pytest.fixture(scope='module')
def client():
    with TestClient(main.app) as c: yield c

@pytest.fixture(autouse=True)
def reset_rate():
    main._hits.clear()

PHISH = 'http://paypa1-secure-login.verify-account.xyz/signin.php?id=88213'

def test_health_and_index(client):
    assert client.get('/api/health').json()['status'] == 'ok'
    r = client.get('/'); assert r.status_code == 200 and 'PhishGuard' in r.text
    assert "default-src 'self'" in r.headers['content-security-policy']
    for f in ('app.js', 'style.css'): assert client.get(f'/static/{f}').status_code == 200

def test_about_has_metrics(client):
    a = client.get('/api/about').json(); assert 0.9 < a['url_test']['accuracy'] < 1 and a['limitations']

def test_phishing_url_flagged_with_truthful_reasons(client):
    d = client.post('/api/analyze/url', json={'url': PHISH}).json()
    assert d['verdict'] == 'PHISHING' and d['risk'] > .85
    kinds = {i['kind'] for i in d['indicators']}; assert {'lookalike', 'keyword', 'tld'} <= kinds
    for i in d['indicators']: assert d['input'][i['start']:i['end']]            # spans always point at real text
    assert all({'direction', 'effect', 'impact', 'reason'} <= set(r) for r in d['model_reasons'])
    bait = [r for r in d['model_reasons'] if 'keyword' in r['reason']]
    assert all('Contains 0 keyword' not in r['reason'] for r in bait)                     # never claims 'no bait words' when present

def test_legit_url_not_flagged(client):
    d = client.post('/api/analyze/url', json={'url': 'https://github.com/anthropics'}).json()
    assert d['verdict'] == 'LIKELY LEGITIMATE' and d['indicators'] == []

def test_scheme_optional_and_whitespace_trimmed(client):
    d = client.post('/api/analyze/url', json={'url': '  github.com/anthropics  '}).json(); assert d['input'] == 'github.com/anthropics'

@pytest.mark.parametrize('bad', ['', '   ', 'not a url', 'javascript://x', 'ftp://example.com/a', 'localhostonly', 'http://', 'a' * 3000, 'http://exa mple.com', 'http://x.com/\x00'])
def test_bad_url_rejected_cleanly(client, bad):
    r = client.post('/api/analyze/url', json={'url': bad}); assert r.status_code == 422 and isinstance(r.json()['detail'], (str, list))

def test_ipv6_rejected_with_clear_message(client):
    r = client.post('/api/analyze/url', json={'url': 'http://[::1]:80/x.php'}); assert r.status_code == 422 and 'IPv6' in r.json()['detail']

def test_missing_field_and_wrong_type(client):
    assert client.post('/api/analyze/url', json={}).status_code == 422
    assert client.post('/api/analyze/url', json={'url': 123}).status_code == 422

def test_unicode_and_odd_but_valid_urls_do_not_crash(client):
    for u in ['https://m\u00fcnchen.de/stra\u00dfe', 'http://xn--pple-43d.com/login', 'https://user@good.com@evil.xyz/', 'https://a.b.c.d.e.f.example.com/%41%42']:
        r = client.post('/api/analyze/url', json={'url': u}); assert r.status_code == 200, (u, r.text)
        for i in r.json()['indicators']: assert i['start'] < i['end'] <= len(u)

def test_crawl_disabled_by_default_and_ssrf_blocked(client, monkeypatch):
    d = client.post('/api/analyze/url', json={'url': 'https://github.com', 'crawl': True}).json()
    assert d['page']['checked'] is False and 'turned off' in d['page']['error']
    monkeypatch.setattr(main, 'ENABLE_CRAWL', True)
    d = client.post('/api/analyze/url', json={'url': 'http://127.0.0.1:8000/x.html', 'crawl': True}).json()
    assert d['page']['checked'] is False and 'blocked' in d['page']['error']
    d = client.post('/api/analyze/url', json={'url': 'http://169.254.169.254/latest/meta-data', 'crawl': True}).json()
    assert 'blocked' in d['page']['error']

def test_email_phishing_and_spans(client):
    t = 'URGENT: Your account has been suspended! Verify your password immediately at http://secure-login.example.xyz/verify or it will be closed.'
    d = client.post('/api/analyze/email', json={'text': t}).json()
    assert d['verdict'] == 'PHISHING' and d['links'] and d['model_reasons']
    for s in d['spans']: assert 0 <= s['start'] < s['end'] <= len(d['text'])
    sp = sorted(d['spans'], key=lambda s: s['start']); assert all(a['end'] <= b['start'] for a, b in zip(sp, sp[1:]))   # no overlaps

def test_email_normal_and_validation(client):
    d = client.post('/api/analyze/email', json={'text': 'Hi Tom, attached is the Q3 gas schedule we discussed. Thanks, Mary'}).status_code
    assert d == 200
    assert client.post('/api/analyze/email', json={'text': 'hi'}).status_code == 422
    assert client.post('/api/analyze/email', json={'text': 'x' * 60000}).status_code == 422

def test_html_in_input_is_returned_as_data_only(client):
    d = client.post('/api/analyze/url', json={'url': 'http://evil.xyz/<script>alert(1)</script>'}).json()
    assert d['input'].startswith('http://evil.xyz/<script>')          # JSON data; the UI renders it with textContent only
    js = open(os.path.join(main.STATIC, 'app.js')).read(); assert 'innerHTML' not in js and 'eval(' not in js

def test_rate_limit(client, monkeypatch):
    monkeypatch.setattr(main, 'RATE_LIMIT', 3)
    codes = [client.post('/api/analyze/url', json={'url': 'https://github.com'}).status_code for _ in range(5)]
    assert codes[:3] == [200] * 3 and codes[3:] == [429, 429]

def test_indicator_edge_cases():
    assert url_indicators('https://www.amazonaws.com/x') == [] and url_indicators('https://paypal.com/signin')[0]['kind'] == 'keyword'
    assert any(i['kind'] == 'brand' for i in url_indicators('https://paypal.com.evil-site.top/'))
    assert merge_spans([dict(start=0, end=5), dict(start=3, end=8), dict(start=8, end=9)]) == [dict(start=0, end=5), dict(start=8, end=9)]

def test_known_phishing_cue_never_marked_safe(client):
    t = 'URGENT: Your account has been suspended! Verify your password immediately at http://secure-login.example.xyz/verify or it will be closed.'
    d = client.post('/api/analyze/email', json={'text': t}).json()
    for s in d['spans']:
        if d['text'][s['start']:s['end']].lower() in ('password', 'verify', 'urgent', 'suspended', 'immediately'): assert s['direction'] == 'risk'
        if s['direction'] == 'safe': assert d['text'][s['start']:s['end']].lower() not in ('has', 'at', 'will', 'or', 'it', 'be')

# ---------------- detailed (educational) report ----------------
def _url(client, u): return client.post('/api/analyze/url', json={'url': u}).json()

def test_report_url_structure_and_anatomy(client):
    d = _url(client, 'http://paypal.com.evil-site.top:8080/login?id=1'); r = d['report']
    assert d['verdict'] == 'PHISHING' and r['anatomy']['owner'] == 'evil-site.top' and r['anatomy']['subdomain'] == 'paypal.com'
    parts = {p['part']: p['text'] for p in r['anatomy']['parts']}
    assert parts['Registered domain (the real owner)'] == 'evil-site.top' and parts['Port'] == ':8080' and parts['Query'] == '?id=1'
    assert 'evil-site.top' in r['verdict_explained'][0]
    for key in ('findings', 'clean_checks', 'cannot_verify', 'actions', 'verify_yourself', 'text'): assert r[key]

def test_every_piece_of_evidence_is_real_text_from_the_input(client):
    for u in ['http://paypa1-secure-login.verify-account.xyz/signin.php?id=88213', 'http://185.23.44.9:8080/update.exe', 'https://paypal.com.evil-site.top/login']:
        r = _url(client, u)['report']; low = u.lower()
        for f in r['findings']:
            for e in f['evidence']: assert e.strip('".').lower() in low, (u, f['id'], e)
            assert f['what'] and f['why'] and f['spot']

def test_clean_checks_never_contradict_findings(client):
    r = _url(client, 'http://185.23.44.9:8080/update.exe')['report']; ids = {f['id'] for f in r['findings']}
    assert {'ip-host', 'port', 'file-ext'} <= ids
    assert not any('raw IP' in c for c in r['clean_checks']) and not any('program or archive' in c for c in r['clean_checks'])

@pytest.mark.parametrize('u', ['https://paypa1.com', 'https://g00gle.com/search', 'http://185.199.108.153/', 'https://paypal.com.account-help.org/', 'https://secure.example.com@evil.xyz/'])
def test_strong_rule_hit_is_never_rated_likely_legitimate(client, u):
    d = _url(client, u); assert d['verdict'] in ('SUSPICIOUS', 'PHISHING'), d['verdict']
    if d['model_verdict'] == 'LIKELY LEGITIMATE': assert d['summary'].startswith("The model's own score is low") and d['analyst']['rule_override']

@pytest.mark.parametrize('u', ['https://outlook.live.com/mail', 'https://support.microsoft.com/en-us', 'https://www.amazon.co.uk/gp/css', 'https://accounts.google.com/signin', 'https://en.wikipedia.org/wiki/Phishing', 'https://login.microsoftonline.com/'])
def test_genuine_sites_get_no_high_severity_flags(client, u):
    d = _url(client, u); assert not [i for i in d['indicators'] if i['severity'] == 'high'], (u, d['indicators'])

def test_legit_report_is_balanced_and_not_overclaiming(client):
    r = _url(client, 'https://github.com/anthropics')['report']; txt = ' '.join(r['verdict_explained'])
    assert 'No strong warning signs' in txt and r['clean_checks'] and any('Who owns the domain' in c for c in r['cannot_verify'])
    assert 'safe' not in r['headline'].lower() and any('HTTPS' in v for v in r['verify_yourself'])

def test_email_report_evidence_and_checks(client):
    t = 'Dear customer, URGENT: your account is suspended! Send your password and OTP now. Verify here http://185.23.44.9/login or lose access.'
    d = client.post('/api/analyze/email', json={'text': t}).json(); r = d['report']; ids = {f['id'] for f in r['findings']}
    assert d['verdict'] == 'PHISHING' and {'credentials', 'urgency', 'threat', 'generic', 'suspicious-links'} <= ids
    for f in r['findings']:
        if f['id'] != 'shouting' and f['id'] != 'suspicious-links':
            for e in f['evidence']: assert e.lower() in t.lower()
    assert not any('No urgency' in c for c in r['clean_checks']) and not any('passwords' in c for c in r['clean_checks'])
    assert any('sender' in c.lower() for c in r['cannot_verify'])

def test_benign_email_has_no_credential_finding(client):
    t = 'Hi Tom, attached is the Q3 gas schedule we discussed. Please let me know if the numbers look right. Thanks, Mary'
    r = client.post('/api/analyze/email', json={'text': t}).json()['report']
    assert 'credentials' not in {f['id'] for f in r['findings']} and any('No request for passwords' in c for c in r['clean_checks'])

def test_analyst_block_present(client):
    a = _url(client, 'https://github.com')['analyst']; assert a['model_versions'] and 'follow_up' in a and a['normalized_input'] == 'github.com'
