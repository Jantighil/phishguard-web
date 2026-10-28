"""Lexical URL features (scheme/www-independent) used by the boosting ensemble."""
import re, math
from collections import Counter
from urllib.parse import urlsplit
import numpy as np, pandas as pd

KEYWORDS = ['login','signin','secure','account','verify','update','bank','paypal','confirm','password',
            'webscr','ebay','amazon','apple','microsoft','support','wallet','billing','invoice','free','bonus']
SHORTENERS = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','rebrand.ly','cutt.ly','s.free.fr','shorturl.at'}
SUSP_EXT = ('.exe','.scr','.zip','.rar','.apk','.js','.bat','.msi','.sh','.cmd','.jar')
IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
TOP_TLDS = ['com','org','net','edu','gov','uk','de','ru','cn','br','in','io','info','xyz','top','co','app','dev','site','online','ng','fr','nl','jp','it','es','au','ca','ly','cc','me','tk','ml','ga','cf','gq','icu','club','live','page','link','ipfs']
TLD_IDX = {t: i + 1 for i, t in enumerate(TOP_TLDS)}

def _entropy(s: str) -> float:
    if not s: return 0.0
    c = Counter(s); n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())

def url_features(norm: str) -> dict:
    """`norm` is scheme-less, www-less (see prep.normalize_url)."""
    s = norm
    try: p = urlsplit('//' + s)
    except ValueError: p = urlsplit('//invalid')
    host = (p.hostname or '').lower(); path = p.path or ''; query = p.query or ''
    labels = host.split('.') if host else ['']
    tld = labels[-1]; sld = labels[-2] if len(labels) > 1 else ''
    L = max(len(s), 1)
    digits = sum(ch.isdigit() for ch in s); letters = sum(ch.isalpha() for ch in s)
    tokens = re.split(r'[^a-zA-Z0-9]+', s); tokens = [t for t in tokens if t]
    low = s.lower()
    return {
        'len': len(s), 'host_len': len(host), 'path_len': len(path), 'query_len': len(query),
        'n_labels': len(labels), 'n_subdomains': max(len(labels) - 2, 0), 'tld_len': len(tld), 'sld_len': len(sld),
        'tld_id': TLD_IDX.get(tld, 0),
        'is_ip': int(bool(IP_RE.match(host))), 'has_port': int(p.port is not None if _safe_port(p) else 0),
        'dots': s.count('.'), 'hyphens': s.count('-'), 'underscores': s.count('_'), 'at': int('@' in s),
        'pct': s.count('%'), 'qmarks': s.count('?'), 'amps': s.count('&'), 'eqs': s.count('='),
        'slashes': s.count('/'), 'path_depth': path.count('/'), 'dslash_in_path': int('//' in path),
        'digits': digits, 'digit_ratio': digits / L, 'letter_ratio': letters / L,
        'special_ratio': (L - digits - letters) / L, 'upper_ratio': sum(ch.isupper() for ch in s) / L,
        'host_digits': sum(ch.isdigit() for ch in host), 'host_hyphens': host.count('-'),
        'host_entropy': _entropy(host), 'path_entropy': _entropy(path), 'url_entropy': _entropy(s),
        'longest_token': max((len(t) for t in tokens), default=0), 'n_tokens': len(tokens),
        'avg_token': float(np.mean([len(t) for t in tokens])) if tokens else 0.0,
        'punycode': int('xn--' in host), 'shortener': int(host in SHORTENERS),
        'susp_ext': int(path.lower().endswith(SUSP_EXT)), 'has_ext_php': int('.php' in low),
        'kw_count': sum(low.count(k) for k in KEYWORDS), 'kw_in_host': sum(k in host for k in KEYWORDS),
        'brand_in_path_not_host': int(any(k in path.lower() and k not in host for k in ('paypal','apple','amazon','microsoft','ebay','bank'))),
        'long_hex': int(bool(re.search(r'[0-9a-f]{16,}', low))), 'has_fragment': int('#' in s),
        'tld_in_path': int(bool(re.search(r'\.(com|net|org)/', path.lower()))),
    }

def _safe_port(p):
    try: p.port; return True
    except ValueError: return False

def featurize(norms) -> pd.DataFrame:
    return pd.DataFrame([url_features(x) for x in norms]).astype('float32')
