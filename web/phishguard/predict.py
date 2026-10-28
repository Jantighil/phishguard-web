"""PhishGuard inference: URL / email / live-page analysis.
Every model reason states (a) the OBSERVED value of a feature, which is always true of the input, and
(b) the model's EFFECT (TreeSHAP contribution), so a reason can never claim something the input does not show."""
import os, sys, joblib, numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from phishguard.prep import normalize_url
from phishguard.features import featurize
from phishguard.email_features import email_features, clean_text

_n = lambda v: f'{int(round(v))}'
FACTS = {  # feature -> function(value, ctx) -> observed fact
 'char_score': lambda v, c: f'Character-pattern score {v:+.1f} (positive = resembles phishing URLs, negative = resembles legitimate ones)',
 'host_digits': lambda v, c: f'The domain name contains {_n(v)} digit(s)',
 'is_ip': lambda v, c: 'The host is a raw IP address' if v else 'The host is a normal domain name, not an IP address',
 'tld_id': lambda v, c: f"The domain ending is .{c.get('tld', '?')}",
 'longest_token': lambda v, c: f'The longest unbroken text chunk is {_n(v)} characters',
 'path_len': lambda v, c: f'The path after the domain is {_n(v)} characters long',
 'query_len': lambda v, c: f'The query string is {_n(v)} characters long',
 'dots': lambda v, c: f'The address contains {_n(v)} dot(s)',
 'n_subdomains': lambda v, c: f'The address has {_n(v)} sub-domain level(s)',
 'host_entropy': lambda v, c: f'Domain randomness (entropy) is {v:.2f} (higher = more random-looking)',
 'url_entropy': lambda v, c: f'Whole-URL randomness (entropy) is {v:.2f}',
 'path_entropy': lambda v, c: f'Path randomness (entropy) is {v:.2f}',
 'host_hyphens': lambda v, c: f'The domain contains {_n(v)} hyphen(s)',
 'hyphens': lambda v, c: f'The address contains {_n(v)} hyphen(s)',
 'susp_ext': lambda v, c: 'The link ends in an executable/archive file type' if v else 'The link does not end in an executable/archive file type',
 'kw_count': lambda v, c: f'Contains {_n(v)} keyword(s) from our bait list (login, verify, bank, brand names ...)',
 'kw_in_host': lambda v, c: f'{_n(v)} bait-list keyword(s) appear inside the domain name',
 'at': lambda v, c: "Contains an '@' symbol" if v else "No '@' symbol",
 'has_port': lambda v, c: 'Specifies a network port' if v else 'Specifies no network port',
 'shortener': lambda v, c: 'Is a known link-shortener' if v else 'Is not a known link-shortener',
 'punycode': lambda v, c: 'Domain uses punycode (xn--)' if v else 'Domain does not use punycode',
 'brand_in_path_not_host': lambda v, c: 'A well-known brand name appears in the path but not in the domain' if v else 'No brand name hidden in the path',
 'long_hex': lambda v, c: 'Contains a long hexadecimal-looking identifier' if v else 'No long hexadecimal identifier',
 'len': lambda v, c: f'The address is {_n(v)} characters long',
 'digits': lambda v, c: f'The address contains {_n(v)} digit(s)',
 'digit_ratio': lambda v, c: f'{v:.0%} of the address characters are digits',
 'pct': lambda v, c: f'{_n(v)} percent-encoded character(s)',
 'path_depth': lambda v, c: f'The path has {_n(v)} folder level(s)',
 'has_ext_php': lambda v, c: 'Points at a .php script' if v else 'Does not point at a .php script',
 'n_labels': lambda v, c: f'The domain has {_n(v)} dot-separated part(s)',
 'sld_len': lambda v, c: f'The main domain word is {_n(v)} characters long',
 'host_len': lambda v, c: f'The domain is {_n(v)} characters long',
 # e-mail
 'text_score': lambda v, c: f'Wording score {v:+.1f} (positive = similar to phishing/spam e-mails in training data)',
 'n_urls': lambda v, c: f'The e-mail contains {_n(v)} link(s)',
 'n_ip_urls': lambda v, c: f'{_n(v)} link(s) point to a raw IP address',
 'urg_hits': lambda v, c: f'{_n(v)} urgency / account-security phrase(s) found',
 'html': lambda v, c: 'The body is HTML-formatted' if v else 'The body is plain text',
 'upper_ratio': lambda v, c: f'{v:.0%} of the characters are capital letters',
 'excl': lambda v, c: f'{_n(v)} exclamation mark(s)', 'dollar': lambda v, c: f'{_n(v)} dollar sign(s)',
 'n_words': lambda v, c: f'The e-mail has {_n(v)} words',
 'has_form': lambda v, c: 'Contains an embedded form' if v else 'Contains no embedded form',
 # live page
 'PAGE:HasPasswordField': lambda v, c: 'The page asks for a password' if v else 'The page has no password field',
 'PAGE:HasExternalFormSubmit': lambda v, c: 'A form on the page sends data to a DIFFERENT website' if v else 'No form sends data to a different website',
 'PAGE:HasHiddenFields': lambda v, c: 'The page has hidden form fields' if v else 'The page has no hidden form fields',
 'PAGE:HasSubmitButton': lambda v, c: 'The page has a submit button' if v else 'The page has no submit button',
 'PAGE:NoOfiFrame': lambda v, c: f'The page embeds {_n(v)} iframe(s)',
 'PAGE:HasTitle': lambda v, c: 'The page has a title' if v else 'The page has no title',
 'PAGE:HasFavicon': lambda v, c: 'The page has a site icon' if v else 'The page has no site icon',
 'PAGE:HasCopyrightInfo': lambda v, c: 'The page shows a copyright notice' if v else 'The page shows no copyright notice',
 'PAGE:HasSocialNet': lambda v, c: 'The page links to social networks' if v else 'The page has no social-network links',
 'PAGE:HasDescription': lambda v, c: 'The page has a meta description' if v else 'The page has no meta description',
 'PAGE:IsResponsive': lambda v, c: 'The page is mobile-responsive' if v else 'The page is not mobile-responsive',
 'PAGE:NoOfPopup': lambda v, c: f'The page opens {_n(v)} pop-up window(s)',
 'PAGE:Bank': lambda v, c: 'The page text mentions banking terms' if v else 'No banking terms on the page',
 'PAGE:Pay': lambda v, c: 'The page text mentions payment terms' if v else 'No payment terms on the page',
 'PAGE:Crypto': lambda v, c: 'The page text mentions crypto terms' if v else 'No crypto terms on the page',
}
def _logit(p): p = np.clip(p, 1e-6, 1 - 1e-6); return np.log(p / (1 - p))
def _sig(z): return 1 / (1 + np.exp(-z))
def _verdict(p, thr):
    return 'PHISHING' if p >= max(thr, .85) else 'SUSPICIOUS' if p >= .5 else 'LIKELY LEGITIMATE'

class PhishGuard:
    def __init__(self, model_dir=None):
        d = model_dir or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'models')
        self.url = joblib.load(f'{d}/url_model.joblib'); self.email = joblib.load(f'{d}/email_model.joblib')
        self.page = joblib.load(f'{d}/page_model.joblib')

    @staticmethod
    def _impact(w):
        a = abs(w); return 'strong' if a >= 1.0 else 'moderate' if a >= 0.3 else 'slight'

    def _explain(self, booster, X, prefix='', k=6, ctx=None):
        c = booster.predict(X, pred_contrib=True)[0][:-1]; names = list(X.columns); out = []
        for i in np.argsort(-np.abs(c)):
            if len(out) >= k or abs(c[i]) < 0.05: break
            key = prefix + names[i]; v = float(X.iloc[0][names[i]])
            fn = FACTS.get(key); fact = fn(v, ctx or {}) if fn else f'{names[i].replace("_", " ")} = {v:g}'
            out.append(dict(direction='risk' if c[i] > 0 else 'safe', effect='raises risk' if c[i] > 0 else 'lowers risk',
                            impact=self._impact(c[i]), weight=round(float(c[i]), 2), reason=fact))
        return out

    def score_url(self, url):
        n = normalize_url(url); X = featurize([n])
        cs = self.url['sgd'].decision_function(self.url['tf'].transform(self.url['hv'].transform([n])))
        X['char_score'] = cs.astype('float32'); X = X[self.url['columns']]
        p = float(self.url['booster'].predict(X)[0])
        host = n.split('/', 1)[0].split('?', 1)[0].rsplit('@', 1)[-1].split(':', 1)[0]
        return dict(p=p, normalized=n, explain=self._explain(self.url['booster'], X, ctx=dict(tld=host.rsplit('.', 1)[-1])))

    def score_email(self, text):
        X = pd.DataFrame([email_features(text)]).astype('float32'); clean = clean_text(text)
        v = self.email['tfidf'].transform([clean]); s = self.email['lr'].decision_function(v)
        X['text_score'] = s.astype('float32'); X = X[self.email['columns']]
        p = float(self.email['booster'].predict(X)[0])
        coef = self.email['lr'].coef_[0]; names = self.email['tfidf'].get_feature_names_out(); v = v.tocoo()
        contrib = sorted(((float(coef[j] * d), names[j]) for j, d in zip(v.col, v.data)), key=lambda t: -abs(t[0]))[:10]
        terms = [dict(term=t, weight=round(w, 3), direction='risk' if w > 0 else 'safe') for w, t in contrib if abs(w) > 0.02]
        return dict(p=p, verdict=_verdict(p, .5), explain=self._explain(self.email['booster'], X), terms=terms)

    def analyze_url(self, url, crawl=False, allow_private=False):
        r = self.score_url(url); p = r['p']
        res = dict(url=url, normalized=r['normalized'], url_score=round(p, 4), reasons=r['explain'], page_checked=False)
        if crawl:
            from phishguard.crawler import crawl as do_crawl
            c = do_crawl(url, allow_private)
            if c['ok']:
                F = pd.DataFrame([c['features']])[self.page['columns']].astype('float32')
                pp = float(self.page['booster'].predict(F)[0])
                p = float(_sig(.6 * _logit(r['p']) + .4 * _logit(pp)))   # heuristic fusion weights (not trained)
                res.update(page_checked=True, page_score=round(pp, 4), crawl_info=c['info'], page_features=c['features'], page_reasons=self._explain(self.page['booster'], F, 'PAGE:'))
            else: res['crawl_error'] = c['error']
        res['risk'] = round(p, 4); res['verdict'] = _verdict(p, self.url['threshold']); return res
