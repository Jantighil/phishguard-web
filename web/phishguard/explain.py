"""Rule-based, human-checkable indicators (character spans) for URLs and emails.
These are separate from the model's SHAP reasons: they point at the exact text that looks risky."""
import re

BRANDS = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'netflix', 'instagram', 'whatsapp', 'linkedin',
          'dhl', 'fedex', 'chase', 'wellsfargo', 'bankofamerica', 'binance', 'coinbase', 'dropbox', 'office365', 'outlook']
KEYWORDS = ['login', 'signin', 'secure', 'account', 'verify', 'update', 'confirm', 'password', 'webscr', 'billing', 'invoice', 'wallet', 'bonus']
RISKY_TLDS = {'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'club', 'live', 'link', 'site', 'online', 'cc'}
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at'}
RISKY_EXT = ('.exe', '.scr', '.apk', '.bat', '.msi', '.cmd', '.jar', '.zip', '.rar')
LEET = str.maketrans('01345$@', 'oleass' + 'a')
SECOND_LEVEL = {'co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'sch', 'mil', 'or', 'ne', 'go', 'nic'}
OWN = {'paypal': {'paypal'}, 'google': {'google', 'youtube', 'goo', 'gstatic', 'googleapis', 'googleusercontent'},
       'microsoft': {'microsoft', 'live', 'office', 'office365', 'microsoftonline', 'windows', 'azure', 'bing', 'skype', 'xbox'},
       'apple': {'apple', 'icloud'}, 'amazon': {'amazon', 'amzn'}, 'facebook': {'facebook', 'fb', 'meta', 'instagram', 'whatsapp'},
       'instagram': {'instagram', 'facebook', 'meta'}, 'whatsapp': {'whatsapp', 'facebook', 'meta'}, 'netflix': {'netflix', 'nflxso'},
       'chase': {'chase', 'jpmorgan'}, 'office365': {'office', 'office365', 'microsoft', 'microsoftonline'},
       'outlook': {'outlook', 'live', 'office', 'microsoft', 'office365', 'microsoftonline', 'hotmail'}}
SEVERITY = {'at-sign': 'high', 'ip-host': 'high', 'lookalike': 'high', 'brand': 'high', 'punycode': 'medium', 'shortener': 'medium',
            'tld': 'medium', 'port': 'medium', 'random-id': 'medium', 'subdomains': 'medium', 'file-ext': 'medium', 'keyword': 'low'}
FLOOR_KINDS = {'at-sign', 'ip-host', 'lookalike', 'brand'}   # strong rule hits: a link containing one is never rated LIKELY LEGITIMATE
URG = ['urgent', 'immediately', 'verify your', 'suspended', 'expire', 'click here', 'confirm your', 'security alert',
       'act now', 'limited time', 'unusual activity', 'winner', 'congratulations', 'password']

def _reg_sld(host: str) -> str:
    p = host.split('.')
    if len(p) >= 3 and p[-2] in SECOND_LEVEL and len(p[-1]) == 2: return p[-3]
    return p[-2] if len(p) >= 2 else host

def url_indicators(url: str) -> list:
    """Spans refer to the string exactly as submitted (after .strip())."""
    out = []; s = url
    m = re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', s); hs = m.end() if m else 0
    he = len(s)
    for ch in '/?#':
        i = s.find(ch, hs)
        if i != -1: he = min(he, i)
    auth = s[hs:he]; host_start = hs + (auth.rfind('@') + 1 if '@' in auth else 0)
    hostport = s[host_start:he]; host = re.sub(r':\d+$', '', hostport).lower()
    def add(a, b, kind, label, detail): out.append(dict(start=a, end=b, kind=kind, label=label, detail=detail))
    if '@' in auth:
        i = hs + auth.rfind('@'); add(i, i + 1, 'at-sign', "'@' in the address", "Everything before '@' is ignored by the browser, which can hide the real destination.")
    if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host):
        add(host_start, host_start + len(host), 'ip-host', 'IP address instead of a domain name', 'Legitimate services rarely ask you to log in on a bare IP address.')
    pm = re.search(r':\d+$', hostport)
    if pm: add(host_start + pm.start(), host_start + pm.end(), 'port', 'Unusual port number', 'Normal websites use the default web ports and do not show a port.')
    if 'xn--' in host:
        i = s.lower().find('xn--', host_start); add(i, he, 'punycode', 'Punycode (look-alike characters)', 'Internationalised domains can imitate well-known names.')
    if host in SHORTENERS: add(host_start, host_start + len(host), 'shortener', 'Link shortener', 'The real destination is hidden behind the short link.')
    tld = host.rsplit('.', 1)[-1] if '.' in host else ''
    if tld in RISKY_TLDS and not re.fullmatch(r'[\d.]+', host):
        add(host_start + len(host) - len(tld), host_start + len(host), 'tld', f'.{tld} domain ending', 'This ending appears frequently in phishing reports (it is not proof by itself).')
    # brand look-alikes and brand names inside someone else's domain
    sld = _reg_sld(host); pos = host_start
    for label in host.split('.'):
        for tok in re.split(r'-', label):
            t0 = host_start + host.find(tok, pos - host_start) if tok else pos
            norm = tok.translate(LEET)
            for b in BRANDS:
                if tok == b and sld not in OWN.get(b, {b}): add(t0, t0 + len(tok), 'brand', f'Brand name "{b}" in a domain that is not {b}\'s own',
                                              'Attackers place a trusted brand in the subdomain or domain to look genuine.')
                elif tok != b and norm == b: add(t0, t0 + len(tok), 'lookalike', f'Look-alike spelling of "{b}"', 'Digits or symbols replace letters to imitate a trusted brand.')
            pos = t0 + len(tok) + 1
    for k in KEYWORDS:
        for m2 in re.finditer(k, s[host_start:], re.I):
            a = host_start + m2.start(); add(a, a + len(k), 'keyword', f'Bait word "{k}"', 'Words like login/verify/secure are used to create trust or urgency.')
    for m2 in re.finditer(r'[0-9a-fA-F]{16,}', s[he:]):
        add(he + m2.start(), he + m2.end(), 'random-id', 'Long random-looking identifier', 'Auto-generated paths are typical of throw-away phishing pages.')
    path = re.split(r'[?#]', s[he:], 1)[0].lower()
    for e in RISKY_EXT:
        if path.endswith(e): add(he + len(path) - len(e), he + len(path), 'file-ext', f'Risky file type {e}', 'Links that download programs or archives are a common malware route.')
    n_sub = max(len(host.split('.')) - 2, 0)
    if n_sub >= 3 and he > host_start: add(host_start, host_start + len(host), 'subdomains', f'{n_sub} sub-domain levels', 'Long chains of sub-domains are used to bury the real domain.')
    # de-duplicate identical spans, keep order
    seen, res = set(), []
    for d in sorted(out, key=lambda d: (d['start'], d['end'])):
        k = (d['start'], d['end'], d['kind'])
        if k not in seen: seen.add(k); res.append(d)
    return res

def phrase_spans(text: str, phrases, direction: str) -> list:
    out = []
    for p in phrases:
        words = [re.escape(w) for w in p.split()]
        if not words: continue
        for m in re.finditer(r'(?<!\w)' + r'\W+'.join(words) + r'(?!\w)', text, re.I):
            out.append(dict(start=m.start(), end=m.end(), direction=direction, term=p))
    return out

def merge_spans(spans: list) -> list:
    """Remove overlaps (earlier/longer wins) so the UI can render without nesting."""
    res, last = [], -1
    for sp in sorted(spans, key=lambda d: (d['start'], -(d['end'] - d['start']))):
        if sp['start'] >= last: res.append(sp); last = sp['end']
    return res


def registered_domain(host: str):
    """(subdomain, registered domain) - approximate: handles two-part endings like .com.ng / .co.uk, not the full public-suffix list."""
    p = host.split('.')
    if re.fullmatch(r'[\d.]+', host) or len(p) < 2: return '', host
    n = 3 if len(p) >= 3 and p[-2] in SECOND_LEVEL and len(p[-1]) == 2 else 2
    return '.'.join(p[:-n]), '.'.join(p[-n:])

def url_anatomy(url: str) -> dict:
    s = url; m = re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]*)://', s); scheme = m.group(1).lower() if m else ''
    rest = s[m.end():] if m else s; he = len(rest)
    for ch in '/?#':
        i = rest.find(ch)
        if i != -1: he = min(he, i)
    auth, tail = rest[:he], rest[he:]; user = auth[:auth.rfind('@')] if '@' in auth else ''
    hostport = auth[auth.rfind('@') + 1:]; pm = re.search(r':(\d+)$', hostport); port = pm.group(1) if pm else ''
    host = (hostport[:pm.start()] if pm else hostport).lower(); sub, reg = registered_domain(host)
    path = re.split(r'[?#]', tail, 1)[0]; q = re.search(r'\?([^#]*)', tail); frag = re.search(r'#(.*)$', tail)
    parts = []
    if scheme: parts.append(dict(part='Protocol', text=scheme + '://', note=('Encrypts the connection, which protects data in transit. It does NOT show the site is trustworthy: many phishing sites also use HTTPS.' if scheme == 'https' else 'Not encrypted: anything typed can be read on the way. Real login pages should use https.')))
    else: parts.append(dict(part='Protocol', text='(not given)', note='No http:// or https:// was typed, so the protocol could not be checked.'))
    if user: parts.append(dict(part='Username part', text=user + '@', note="Browsers ignore this and connect to what follows the last '@'. It is not the destination."))
    if sub: parts.append(dict(part='Sub-domain', text=sub, note='Freely chosen by whoever owns the domain; it says nothing about who that is.'))
    kind = 'IP address' if re.fullmatch(r'[\d.]+', host) else 'Registered domain (the real owner)'
    parts.append(dict(part=kind, text=reg, note=('The server is addressed by number, so there is no registered name to check.' if kind == 'IP address' else 'Read the host from right to left: this name plus its ending identifies who controls the site. Everything to its left is chosen by that owner.'), owner=True))
    if port: parts.append(dict(part='Port', text=':' + port, note='A non-default network port; public sites normally hide this.'))
    if path and path != '/': parts.append(dict(part='Path', text=path, note='Which page on that site; it can be anything and proves nothing about the owner.'))
    if q: parts.append(dict(part='Query', text='?' + q.group(1), note='Extra data sent to the page (tracking, session or victim identifiers).'))
    if frag and frag.group(1): parts.append(dict(part='Fragment', text='#' + frag.group(1), note='A position inside the page; never sent to the server.'))
    return dict(parts=parts, owner=reg, subdomain=sub, host=host)

LESSONS = {
 'at-sign': ("Hidden '@' in the address", "A web address can carry a 'name@' prefix before the real host.", "Attackers put a trusted-looking name before the '@' so the link appears to belong to a known site; the browser ignores that part and goes to what follows the last '@'.", "Look at what comes right after the last '@': that is where the link really goes."),
 'ip-host': ('Raw IP address instead of a domain name', 'The address uses numbers (like 185.23.44.9) rather than a name (like example.com).', 'Organisations almost always use a registered domain name for public services. Attackers use bare IPs to avoid registering (and being traced through) a domain, and to host pages on compromised servers. Exceptions exist, such as home routers and internal tools.', 'Be wary of any sign-in or payment page whose address starts with numbers.'),
 'port': ('Unusual network port', 'A number after a colon (like :8080) selects a non-standard port.', 'Public websites normally use the default ports and do not show them. Quick-setup phishing kits and malware are often served from non-standard ports; developers also use them legitimately.', 'A port number in the address of a page that asks you to sign in is unusual.'),
 'punycode': ('Punycode (encoded look-alike name)', "Names starting 'xn--' are the encoded form of non-English characters.", "Letters from other alphabets can look identical to Latin ones (for example Cyrillic 'a'), letting attackers register a name that looks exactly like a real brand. Many genuine sites in other languages use punycode too.", "Type the organisation's address yourself instead of following the link."),
 'shortener': ('Shortened link', 'A link-shortening service forwards to a destination you cannot see.', "Attackers use short links to conceal the real address and to slip past filters that look for known bad domains.", "Use the shortener's preview option, or ask the sender for the full address."),
 'tld': ('Domain ending often seen in phishing reports', 'The part after the final dot decides the domain type (here shown as the ending).', 'Some endings are cheap or free to register in bulk, so they appear disproportionately in abuse reports. Plenty of legitimate sites use them too, so this is a weak signal on its own.', 'Established organisations usually use well-known endings (such as .com, .org or a country ending). Treat an unusual ending as a reason to look closer.'),
 'brand': ("Trusted brand name inside someone else's domain", "A well-known brand name appears in the address, but the domain that actually owns the address is a different one.", "The owner of an address is the name just before its ending (read right to left). Attackers put a famous brand in the sub-domain or inside the domain, so the start of the link looks familiar while the real owner is unrelated.", 'Find the ending, then step one name to the left: that is the owner. If it is not the brand, it is not the brand.'),
 'lookalike': ('Look-alike spelling of a brand', 'Digits or symbols replace letters, for example 1 for l or 0 for o.', "At a glance 'paypa1' reads as 'paypal'. This 'typosquatting' relies on people skimming instead of reading.", 'Read the name letter by letter, especially for banks, e-mail and payment services.'),
 'keyword': ('Bait words (login, verify, secure ...)', 'Words suggesting security or urgency appear in the address.', 'They are added to make a fake page feel official. Real sites use the same words (a genuine /login page exists), so on their own they prove nothing; they matter when the domain itself is unfamiliar.', 'Judge the domain first; treat the keywords as supporting evidence only.'),
 'random-id': ('Long random-looking identifier', 'A long string of hexadecimal-looking characters sits in the path.', 'Phishing kits often generate a unique address per victim or campaign so lists of known bad links do not match. Legitimate services also use long IDs (sessions, documents), so it is only a hint.', 'Harmless alone; suspicious when combined with an unfamiliar domain.'),
 'file-ext': ('Link to a program or archive', 'The address ends in a file type that can run code or hide it (.exe, .apk, .zip ...).', 'Executables and archives can install malware; attackers disguise them as invoices, updates or documents.', "Download software only from the publisher's official site, never from a link in a message."),
 'subdomains': ('Many sub-domain levels', 'The address has a long chain of dot-separated names before the main domain.', 'A long chain pushes the real owner out of view, so the visible beginning looks like a trusted name.', 'Read the host from right to left: only the last two names (three for endings like .co.uk) identify the owner.'),
 'page-external-form': ('Form sends data to a different website', "A form on the page submits to an address on another domain than the page itself.", 'A fake sign-in page can look perfect while forwarding everything you type to the attacker.', 'Genuine sign-in pages normally submit to the same organisation. Check the address bar before typing anything.'),
 'page-password': ('Page asks for a password', 'The page contains a password field.', 'Normal for real sign-in pages, so it is not suspicious by itself. It matters when you arrived through an unexpected message or the domain is unfamiliar.', 'Reach sign-in pages by typing the address or using a bookmark, not through message links.'),
 'page-iframe': ('Embedded frames', 'The page embeds content from elsewhere inside itself.', 'Frames can load content from other sites, sometimes invisibly, to overlay fake forms or load malicious code. Legitimate sites use them for videos, maps and payments.', 'Weak evidence alone; look at what else is wrong.'),
 'redirect-host': ('Link redirected to a different website', 'The address you submitted ended up on a different domain.', 'Redirects hide the true destination. Legitimate tracking and login flows also redirect, so check where it ended up.', 'Compare the final address with the one you expected.'),
 'urgency': ('Urgency or pressure', 'The message tries to make you act quickly.', 'Pressure stops you from thinking and checking. Genuine organisations give reasonable time and do not usually threaten immediate consequences through links in unsolicited messages.', "Pause. Contact the organisation through its official website or app, not through the message."),
 'threat': ('Threat of losing access or penalty', 'The message says something will be suspended, closed or reported.', 'Fear is a powerful lever: it pushes people to click before verifying. Real providers rarely lock an account without prior notice in your account area.', "Log in by typing the official address yourself and look for notices there."),
 'credentials': ('Asks for passwords, codes or personal details', 'The message asks you to confirm or send secrets or identity details.', 'Banks and major services generally state that they never ask for your password, PIN or one-time code by e-mail. Whoever obtains these can take over your account.', 'Never send or type these because a message asked. Contact the provider through an official channel.'),
 'reward': ('Reward or prize bait', 'The message promises a prize, gift or windfall.', "Unexpected rewards are used to lure people into 'claiming' them by entering details or paying a fee.", "If you did not enter a competition, you did not win one."),
 'generic': ('Generic greeting', "The message addresses a group ('Dear customer') rather than you by name.", 'Mass mailings do not know your name. Organisations that hold your account usually address you personally, though not always.', 'A weak sign by itself; combine it with the other findings.'),
 'payment': ('Pressure to pay or transfer', 'The message asks for a transfer, gift cards or crypto.', 'Irreversible payment methods are preferred by fraudsters because money cannot be recalled.', 'Confirm any payment request by phone using a number you already trust.'),
 'shouting': ('Excessive capitals or exclamation marks', 'The text is written in an alarmed style.', 'Alarming formatting adds pressure. It is a weak signal: some genuine marketing also does this.', 'Treat as supporting evidence only.'),
 'suspicious-links': ('Suspicious link inside the message', 'One or more links in the message show warning signs when analysed.', 'The visible text of a link can differ from where it goes. Phishing e-mails exist to get you to open a link like this.', 'Do not click. Open the organisation\'s site by typing its address.'),
}
EMAIL_SEV = {'credentials': 'high', 'suspicious-links': 'high', 'urgency': 'medium', 'threat': 'medium', 'reward': 'medium', 'payment': 'medium', 'generic': 'low', 'shouting': 'low'}
TACTICS = {
 'urgency': ['urgent', 'immediately', 'within 24 hours', 'within 48 hours', 'act now', 'expires', 'expire', 'limited time', 'final notice', 'last warning', 'as soon as possible'],
 'threat': ['suspended', 'locked', 'closed', 'terminated', 'deactivated', 'legal action', 'will be blocked', 'unauthorized', 'unusual activity', 'security alert', 'permanently'],
 'credentials': ['password', 'pin', 'otp', 'one-time', 'verification code', 'bvn', 'card number', 'cvv', 'security answer', 'login details', 'verify your account', 'confirm your identity', 'update your details', 'update your information'],
 'reward': ['congratulations', 'winner', 'you have won', 'prize', 'lottery', 'inheritance', 'claim your', 'free gift', 'you have been selected'],
 'generic': ['dear customer', 'dear user', 'dear client', 'dear member', 'dear account holder', 'valued customer', 'dear sir/madam', 'dear sir or madam'],
 'payment': ['wire transfer', 'gift card', 'gift cards', 'bitcoin', 'send payment', 'bank transfer', 'western union'],
}
def email_tactics(text: str) -> dict:
    """kind -> list of matched snippets (exact text from the e-mail)."""
    out = {}
    for k, ph in TACTICS.items():
        hits = phrase_spans(text, ph, 'risk')
        if hits: out[k] = sorted({text[h['start']:h['end']] for h in hits}, key=str.lower)
    letters = [c for c in text if c.isalpha()]
    if (len(letters) > 40 and sum(c.isupper() for c in letters) / len(letters) > 0.3) or text.count('!') >= 3:
        out['shouting'] = [f"{text.count('!')} exclamation mark(s); {round(100 * sum(c.isupper() for c in letters) / max(len(letters), 1))}% capital letters"]
    return out
