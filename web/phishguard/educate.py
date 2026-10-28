"""Builds the detailed, educational verdict. Every sentence is generated from facts found in the input
(matched text, parsed address parts, crawler observations, model contributions): nothing is asserted that was not observed."""
from phishguard.explain import LESSONS, SEVERITY, EMAIL_SEV, url_anatomy, email_tactics

ORDER = {'high': 0, 'medium': 1, 'low': 2}

def _join(xs):
    xs = list(xs); return xs[0] if len(xs) == 1 else ', '.join(xs[:-1]) + ' and ' + xs[-1] if xs else ''

def _finding(kind, sev, evidence):
    t, what, why, spot = LESSONS[kind]
    return dict(id=kind, severity=sev, title=t, evidence=evidence[:6], what=what, why=why, spot=spot)

def _model_view(verdict, risk, reasons):
    pct = round(risk * 100, 1); up = [r for r in reasons if r['direction'] == 'risk']; down = [r for r in reasons if r['direction'] == 'safe']
    s = f"The machine-learning model, working from the text of the input alone, scored it {pct}% likely to be phishing."
    if up: s += f" Its strongest push toward phishing: {up[0]['reason'].rstrip('.')} ({up[0]['impact']} influence)."
    if down and abs(down[0]['weight']) >= 0.3: s += f" It leaned the other way on: {down[0]['reason'].rstrip('.')} ({down[0]['impact']} influence)."
    return s

def _actions(verdict, kind):
    if verdict == 'PHISHING':
        a = [f"Do not {'open the link' if kind == 'url' else 'click any link, open attachments or reply'}.", 'Do not enter passwords, one-time codes or card details.',
             'If you already did: change that password now (and anywhere you reused it), turn on two-factor authentication, and call the real organisation using a number from its official website or your card.',
             "Report it to the organisation being imitated and to your e-mail provider; reportphishing@apwg.org also accepts reports.", 'Delete the message and warn others who may have received it.']
    elif verdict == 'SUSPICIOUS':
        a = ['Do not enter credentials or payment details until you have verified it another way.', "Open the organisation's site by typing the address or using a bookmark, not through this " + ('link.' if kind == 'url' else 'message.'),
             'Contact the sender through a channel you already trust to confirm they sent it.']
    else:
        a = ['No strong warning signs were found, but keep the usual habits: if you reached a page through an unexpected message, type the address yourself before signing in.', 'Be alert to anything that asks for passwords or codes you did not expect to give.']
    return a

def build_url_report(u, verdict, risk, ind, reasons, page, override, anatomy, link_facts=None):
    by = {}
    for i in ind: by.setdefault(i['kind'], []).append(u[i['start']:i['end']])
    f = []
    for k, ev in by.items():
        if k == 'keyword': ev = [f'"{x}"' for x in dict.fromkeys(e.lower() for e in ev)]
        elif k == 'tld': ev = ['.' + ev[0].lstrip('.')]
        elif k == 'subdomains': ev = [anatomy['host']]
        f.append(_finding(k, SEVERITY[k], list(dict.fromkeys(ev))))
    feats = page.get('features') or {}; info = page.get('info') or {}
    if page.get('checked'):
        if feats.get('HasExternalFormSubmit'): f.append(_finding('page-external-form', 'high', ['a form submits to another domain']))
        if feats.get('HasPasswordField'): f.append(_finding('page-password', 'low', ['password field present']))
        if feats.get('NoOfiFrame'): f.append(_finding('page-iframe', 'low', [f"{int(feats['NoOfiFrame'])} embedded frame(s)"]))
        if info.get('host_changed'): f.append(_finding('redirect-host', 'medium', [info.get('final_url', '')]))
    f.sort(key=lambda x: ORDER[x['severity']])
    hi = [x['title'] for x in f if x['severity'] == 'high']; me = [x['title'] for x in f if x['severity'] == 'medium']; lo = [x['title'] for x in f if x['severity'] == 'low']
    owner = anatomy['owner']; paras = []
    if override: paras.append(override)
    if verdict == 'PHISHING':
        if hi or me: paras.append(f"We classified this link as phishing because it shows {_join([t.lower() for t in hi + me])}. The address belongs to {owner}, so check whether that is really who you expect.")
        else: paras.append(f"No single rule-based warning sign stands out, but the overall shape of the address (its character patterns, structure and randomness) closely matches phishing links the model learned from. The address belongs to {owner}.")
    elif verdict == 'SUSPICIOUS':
        paras.append("The evidence is mixed" + (f": the link shows {_join([t.lower() for t in hi + me])}" if hi or me else ': no strong rule-based sign, but the model sees some phishing-like patterns') + f". The address belongs to {owner}. Treat it as unverified until you confirm it independently.")
    else:
        paras.append(f"No strong warning signs were found. The address belongs to {owner}, and it does not use the usual tricks (look-alike spelling, raw IP address, hidden '@', or a famous brand inside someone else's domain)." + (f" Minor flags ({_join([t.lower() for t in lo + me])}) are common on genuine sites and do not change the picture on their own." if lo or me else ''))
    paras.append(_model_view(verdict, risk, reasons))
    if page.get('checked'): paras.append(f"We also fetched the page (static check, no scripts run); the page-content model scored it {round(page['score'] * 100, 1)}% likely phishing, and the final risk combines both scores.")
    passed = []
    if 'lookalike' not in by and 'brand' not in by: passed.append('No look-alike spelling of a well-known brand and no famous brand name inside an unrelated domain')
    if 'ip-host' not in by: passed.append('The address uses a domain name, not a raw IP address')
    if 'at-sign' not in by: passed.append("No hidden '@' disguising the destination")
    if 'punycode' not in by: passed.append('No encoded look-alike (punycode) characters')
    if 'shortener' not in by: passed.append('Not a link-shortening service')
    if 'tld' not in by: passed.append('The domain ending is not on our watch-list of endings often seen in phishing reports')
    if 'keyword' not in by: passed.append('No bait words such as login, verify or secure in the address')
    if 'file-ext' not in by: passed.append('The link does not point to a program or archive file')
    if 'random-id' not in by: passed.append('No long random-looking identifier')
    if 'subdomains' not in by and 'port' not in by: passed.append('Ordinary structure: no long sub-domain chain or unusual port')
    if page.get('checked') and not feats.get('HasExternalFormSubmit'): passed.append('No form on the page sends data to a different website')
    cannot = ['Who owns the domain, how old it is, and whether it appears on blocklists: we only analyse the link text' + ('' if page.get('checked') else ' (and did not fetch the page)') + '.',
              'Whether a genuine site has been hacked to host a phishing page.', 'Content created by JavaScript after the page loads.' if page.get('checked') else 'What the page actually asks you for.']
    verify = [f"Read the host from right to left: the real owner is {owner}" + (f", and '{anatomy['subdomain']}' in front of it is only a label the owner chose." if anatomy['subdomain'] else '.'),
              'Hover over (or long-press) a link to see where it really goes before you click.', 'Compare the spelling with the real organisation, letter by letter.',
              "Search for the organisation yourself and compare its address with this one.", 'Never trust padlock/HTTPS alone: it shows the connection is encrypted, not who is on the other end.']
    rep = dict(headline=f"{verdict}: {owner}", verdict_explained=paras, anatomy=anatomy, findings=f, clean_checks=passed, cannot_verify=cannot,
               actions=_actions(verdict, 'url'), verify_yourself=verify)
    rep['text'] = report_text(rep, u); return rep

def build_email_report(text, verdict, risk, reasons, links):
    tac = email_tactics(text); f = []
    for k, ev in tac.items(): f.append(_finding(k, EMAIL_SEV[k], ev))
    bad_links = [l for l in links if l['risk'] >= 0.5 or any(i['severity'] == 'high' for i in l['indicators'])]
    if bad_links:
        ev = [l['url'] + (' (' + ', '.join(sorted({i['label'] for i in l['indicators']})[:2]) + ')' if l['indicators'] else f" ({round(l['risk'] * 100)}% risk)") for l in bad_links]
        f.append(_finding('suspicious-links', 'high', ev))
    f.sort(key=lambda x: ORDER[x['severity']]); hi = [x['title'].lower() for x in f if x['severity'] == 'high']; me = [x['title'].lower() for x in f if x['severity'] == 'medium']
    paras = []
    if verdict == 'PHISHING':
        paras.append("We classified this e-mail as phishing because " + (f"it shows {_join(hi + me)}." if hi or me else "its wording and style closely match phishing and spam e-mails the model learned from, even though no single classic tactic was detected."))
    elif verdict == 'SUSPICIOUS': paras.append("The evidence is mixed" + (f": the e-mail shows {_join(hi + me)}." if hi or me else ": the wording resembles some phishing e-mails, but no classic tactic was detected.") + " Verify it before acting on it.")
    else: paras.append("We found no classic phishing tactics in this e-mail's text" + (f", apart from minor signs ({_join([x['title'].lower() for x in f])}) that are common in genuine mail." if f else '.'))
    paras.append(_model_view(verdict, risk, reasons))
    clean = []
    for k, label in [('urgency', 'No urgency or pressure language'), ('threat', 'No threats of suspension or penalty'), ('credentials', 'No request for passwords, codes or personal details'),
                     ('reward', 'No prize or reward bait'), ('generic', 'Not a generic "Dear customer" greeting'), ('payment', 'No pressure to pay by transfer, gift card or crypto')]:
        if k not in tac: clean.append(label)
    if links and not bad_links: clean.append('The links found in the e-mail did not look suspicious on their own')
    cannot = ['Who really sent it: we only see the pasted text, not the sender address or the e-mail headers (SPF/DKIM/DMARC results).', "Where each link really leads if it was hidden behind link text, and the contents of any attachments.",
              'Whether an account was hijacked: phishing from a genuine hacked mailbox can read as perfectly normal.']
    verify = ["Check the sender's full address, not just the display name.", 'Hover over links to see the real destination.', 'Contact the organisation through its official website or app, not through this message.', 'Be careful with unexpected attachments, even from known senders.']
    rep = dict(headline=verdict + ': e-mail analysis', verdict_explained=paras, findings=f, clean_checks=clean, cannot_verify=cannot, actions=_actions(verdict, 'email'), verify_yourself=verify)
    rep['text'] = report_text(rep, text[:300] + ('...' if len(text) > 300 else '')); return rep

def report_text(r, subject):
    L = ['PHISHGUARD REPORT', '=' * 17, f'Input: {subject}', f"Verdict: {r['headline']}", '']
    L += r['verdict_explained'] + ['']
    if r.get('anatomy'): L += ['Anatomy of the address:'] + [f"  - {p['part']}: {p['text']}  ({p['note']})" for p in r['anatomy']['parts']] + ['']
    if r['findings']:
        L.append('Warning signs found:')
        for x in r['findings']: L += [f"  [{x['severity'].upper()}] {x['title']}", f"    Seen: {'; '.join(x['evidence'])}", f"    Why attackers do this: {x['why']}", f"    How to spot it: {x['spot']}"]
        L.append('')
    if r['clean_checks']: L += ['Checks that came out clean:'] + [f'  + {c}' for c in r['clean_checks']] + ['']
    L += ['What we cannot verify:'] + [f'  ? {c}' for c in r['cannot_verify']] + ['', 'What to do now:'] + [f'  * {c}' for c in r['actions']] + ['', 'Double-check it yourself:'] + [f'  * {c}' for c in r['verify_yourself']]
    L += ['', 'PhishGuard is a machine-learning triage aid, not a guarantee; it can be wrong in both directions.']
    return '\n'.join(L)
