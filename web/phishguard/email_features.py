import re
URG = ['urgent','immediately','verify','suspend','expire','click here','confirm','password','account','limited time',
       'act now','security alert','winner','congratulations','prize','free','bank','invoice','payment','unusual activity','login','update']
URL_RE = re.compile(r'https?://[^\s"\'<>]+|<\|URL\|>', re.I)
def email_features(t: str) -> dict:
    low = t.lower(); n = max(len(t), 1); urls = URL_RE.findall(t)
    return {'len': len(t), 'n_words': len(t.split()), 'n_urls': len(urls),
            'n_ip_urls': sum(bool(re.match(r'https?://\d+\.\d+\.\d+\.\d+', u)) for u in urls),
            'n_at_urls': sum('@' in u for u in urls), 'html': int(bool(re.search(r'<(html|body|a |table|img)', low))),
            'upper_ratio': sum(c.isupper() for c in t) / n, 'digit_ratio': sum(c.isdigit() for c in t) / n,
            'excl': t.count('!'), 'dollar': t.count('$'), 'urg_hits': sum(low.count(k) for k in URG),
            'has_form': int('<form' in low), 'has_attach_word': int('attach' in low),
            'subject_len': len(t.split('\n', 1)[0]), 'subject_upper': sum(c.isupper() for c in t.split('\n', 1)[0]) / max(len(t.split('\n', 1)[0]), 1)}

ARTIFACT = re.compile(r'\[[A-Z_ ]{2,30}\]|<\|URL\|>|\b(email_separator|simbol|emoji|financial_info)\b', re.I)
def clean_text(t: str) -> str:
    """Remove corpus-specific anonymisation / normalisation placeholders that leak the source (and label)."""
    return re.sub(r'\s+', ' ', ARTIFACT.sub(' ', t)).strip()
