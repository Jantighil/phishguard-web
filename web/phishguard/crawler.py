"""Safe, static (no JavaScript execution) page crawler that extracts page-content features.
Safeguards: http(s) only, SSRF guard (blocks private/loopback/link-local IPs), per-hop redirect validation,
size + time limits, never saves or executes anything."""
import ipaddress, re, socket
from urllib.parse import urljoin, urlsplit
import requests
from bs4 import BeautifulSoup

UA = 'PhishGuard-Research-Crawler/1.0 (+security-research; no JS execution)'
MAX_BYTES, TIMEOUT, MAX_REDIRECTS = 2_000_000, 8, 5
PAGE_FEATURES = ['HasTitle', 'HasFavicon', 'HasDescription', 'HasCopyrightInfo', 'HasSocialNet', 'HasSubmitButton',
                 'HasHiddenFields', 'HasPasswordField', 'HasExternalFormSubmit', 'IsResponsive', 'NoOfiFrame',
                 'NoOfJS', 'NoOfCSS', 'NoOfImage', 'NoOfExternalRef', 'NoOfSelfRef', 'NoOfEmptyRef', 'NoOfPopup',
                 'LineOfCode', 'LargestLineLength', 'Bank', 'Pay', 'Crypto']
SOCIAL = ('facebook.com', 'twitter.com', 'x.com', 'instagram.com', 'linkedin.com', 'youtube.com', 'tiktok.com')

class UnsafeURL(Exception): pass

def _check_host(host: str, allow_private: bool):
    if allow_private: return
    try: infos = socket.getaddrinfo(host, None)
    except socket.gaierror: raise UnsafeURL('dns-failure')
    for i in infos:
        ip = ipaddress.ip_address(i[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise UnsafeURL(f'blocked non-public address {ip}')

def fetch(url: str, allow_private=False):
    if not re.match(r'^[a-z]+://', url): url = 'http://' + url
    chain, cur = [], url
    s = requests.Session(); s.headers['User-Agent'] = UA
    for _ in range(MAX_REDIRECTS + 1):
        sp = urlsplit(cur)
        if sp.scheme not in ('http', 'https') or not sp.hostname: raise UnsafeURL('scheme')
        _check_host(sp.hostname, allow_private); chain.append(cur)
        r = s.get(cur, timeout=TIMEOUT, allow_redirects=False, stream=True)
        if r.status_code in (301, 302, 303, 307, 308) and 'Location' in r.headers:
            cur = urljoin(cur, r.headers['Location']); r.close(); continue
        body = b''
        for ch in r.iter_content(65536):
            body += ch
            if len(body) > MAX_BYTES: break
        enc = r.encoding or 'utf-8'
        return dict(final_url=cur, status=r.status_code, redirects=len(chain) - 1, chain=chain,
                    html=body.decode(enc, errors='replace'), content_type=r.headers.get('Content-Type', ''))
    raise UnsafeURL('too-many-redirects')

def page_features(html: str, page_url: str) -> dict:
    soup = BeautifulSoup(html, 'html.parser'); host = (urlsplit(page_url).hostname or '').lower()
    base = '.'.join(host.split('.')[-2:])
    def internal(h):
        if not h: return True
        hh = (urlsplit(urljoin(page_url, h)).hostname or '').lower(); return hh.endswith(base)
    links = [a.get('href', '') for a in soup.find_all('a')]
    forms = soup.find_all('form'); text = soup.get_text(' ', strip=True).lower(); lines = html.split('\n')
    ext_refs = sum(1 for h in links if h and not h.startswith(('#', 'javascript', 'mailto:')) and not internal(h))
    meta = lambda n: soup.find('meta', attrs={'name': re.compile(f'^{n}$', re.I)})
    return {
        'HasTitle': int(bool(soup.title and soup.title.get_text(strip=True))),
        'HasFavicon': int(bool(soup.find('link', rel=lambda v: v and 'icon' in ' '.join(v).lower()))),
        'HasDescription': int(bool(meta('description'))),
        'HasCopyrightInfo': int('©' in html or 'copyright' in text or '&copy;' in html),
        'HasSocialNet': int(any(d in h for h in links for d in SOCIAL)),
        'HasSubmitButton': int(bool(soup.find(['button', 'input'], attrs={'type': 'submit'}))),
        'HasHiddenFields': int(bool(soup.find('input', attrs={'type': 'hidden'}))),
        'HasPasswordField': int(bool(soup.find('input', attrs={'type': 'password'}))),
        'HasExternalFormSubmit': int(any(f.get('action') and not internal(f.get('action')) for f in forms)),
        'IsResponsive': int(bool(meta('viewport'))),
        'NoOfiFrame': len(soup.find_all('iframe')),
        'NoOfJS': len(soup.find_all('script')),
        'NoOfCSS': len(soup.find_all('link', rel=lambda v: v and 'stylesheet' in ' '.join(v).lower())),
        'NoOfImage': len(soup.find_all('img')),
        'NoOfExternalRef': ext_refs,
        'NoOfSelfRef': sum(1 for h in links if h and internal(h) and not h.startswith(('#', 'javascript'))),
        'NoOfEmptyRef': sum(1 for h in links if h in ('', '#', 'javascript:void(0)', 'javascript:;')),
        'NoOfPopup': len(re.findall(r'window\.open\(', html)),
        'LineOfCode': len(lines), 'LargestLineLength': max((len(l) for l in lines), default=0),
        'Bank': int(any(k in text for k in ('bank', 'account number', 'routing'))),
        'Pay': int(any(k in text for k in ('payment', 'paypal', 'credit card', 'card number'))),
        'Crypto': int(any(k in text for k in ('bitcoin', 'crypto', 'wallet', 'ethereum'))),
    }

def crawl(url: str, allow_private=False) -> dict:
    """Returns dict(ok, features, info) or dict(ok=False, error)."""
    try: r = fetch(url, allow_private)
    except UnsafeURL as e: return dict(ok=False, error=f'blocked: {e}')
    except requests.RequestException as e: return dict(ok=False, error=f'unreachable: {type(e).__name__}')
    if 'html' not in r['content_type'].lower() and '<html' not in r['html'][:2000].lower():
        return dict(ok=False, error=f"not an HTML page ({r['content_type']})", info={k: r[k] for k in ('final_url', 'status', 'redirects')})
    f = page_features(r['html'], r['final_url'])
    return dict(ok=True, features=f, info=dict(final_url=r['final_url'], status=r['status'], redirects=r['redirects'],
                host_changed=(urlsplit(url if '://' in url else 'http://' + url).hostname != urlsplit(r['final_url']).hostname)))
