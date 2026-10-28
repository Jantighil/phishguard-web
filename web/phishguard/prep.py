"""Step 1 - clean, de-duplicate, remove source artifacts, and split (grouped by host)."""
import re, zlib, pandas as pd, numpy as np

SCHEME = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')
WWW = re.compile(r'^www\d*\.', re.I)

def normalize_url(u: str) -> str:
    """Strip scheme + leading 'www.' (both leak the label in this dataset), lowercase host,
    drop a lone trailing slash."""
    u = SCHEME.sub('', str(u).strip())
    host, sep, rest = u.partition('/')
    host = WWW.sub('', host.lower())
    out = host + sep + rest
    return out[:-1] if out.endswith('/') and rest == '' else out

def host_of(n: str) -> str:
    h = n.split('/', 1)[0].split('?', 1)[0].split('#', 1)[0]
    return h.rsplit('@', 1)[-1].split(':', 1)[0]

def split_by_host(hosts: pd.Series) -> pd.Series:
    b = hosts.map(lambda h: zlib.crc32(h.encode()) % 100)
    return pd.Series(np.where(b < 15, 'test', np.where(b < 25, 'val', 'train')), index=hosts.index)

if __name__ == '__main__':
    raw = pd.read_parquet('raw.parquet')
    # ---------------- URLs ----------------
    u = raw[raw.content_type == 'url'][['source_id', 'url', 'binary_label']].copy()
    n0 = len(u)
    u['norm'] = u.url.map(normalize_url)
    u['key'] = u.norm.str.lower()
    lab = u.groupby('key').binary_label.nunique()
    conflicts = lab[lab > 1].index
    u = u[~u.key.isin(conflicts)].drop_duplicates('key')
    u['host'] = u.norm.map(host_of)
    u['split'] = split_by_host(u.host)
    print(f'URLs: {n0} -> {len(u)} after de-dup ({len(conflicts)} conflicting keys dropped)')
    print(pd.crosstab(u.split, u.binary_label))
    print(pd.crosstab(u.source_id, u.binary_label))
    u[['source_id', 'norm', 'host', 'binary_label', 'split']].to_parquet('urls_clean.parquet')
    # ---------------- Emails ----------------
    e = raw[raw.content_type == 'email'][['source_id', 'email_subject', 'email_body', 'email_urls', 'binary_label']].copy()
    e['email_subject'] = e.email_subject.fillna(''); e['email_body'] = e.email_body.fillna('')
    e['text'] = (e.email_subject + ' \n ' + e.email_body).str.strip()
    e = e[e.text.str.len() > 5]
    e['key'] = e.text.str.lower().str.replace(r'\s+', ' ', regex=True)
    lab = e.groupby('key').binary_label.nunique()
    e = e[~e.key.isin(lab[lab > 1].index)].drop_duplicates('key').reset_index(drop=True)
    e['split'] = np.random.RandomState(42).choice(['train', 'val', 'test'], len(e), p=[.75, .10, .15])
    print(f'Emails after de-dup: {len(e)}'); print(pd.crosstab(e.split, e.binary_label))
    e[['text', 'binary_label', 'split']].to_parquet('emails_clean.parquet')
