(() => {
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
  const status = $('status'), result = $('result');

  // ---- tabs
  const tabs = { url: [$('tab-url'), $('panel-url')], email: [$('tab-email'), $('panel-email')] };
  Object.entries(tabs).forEach(([k, [t]]) => t.addEventListener('click', () => {
    Object.entries(tabs).forEach(([k2, [t2, p2]]) => { t2.setAttribute('aria-selected', String(k2 === k)); p2.classList.toggle('hidden', k2 !== k); });
    result.classList.add('hidden'); status.textContent = ''; status.className = '';
  }));

  // ---- render helpers (all user/server text goes through textContent: no HTML injection)
  function highlighted(text, spans, cls, title) {
    const box = el('div', 'mono'); let pos = 0;
    for (const s of spans.slice().sort((a, b) => a.start - b.start)) {
      if (s.start < pos || s.end > text.length || s.start >= s.end) continue;
      box.append(document.createTextNode(text.slice(pos, s.start)));
      const m = el('mark', cls(s), text.slice(s.start, s.end)); m.title = title(s); box.append(m); pos = s.end;
    }
    box.append(document.createTextNode(text.slice(pos))); return box;
  }
  function section(title, ...kids) { const s = el('section', 'res'); s.append(el('h2', null, title), ...kids); return s; }
  function reasonList(items) {
    const ul = el('ul', 'list');
    for (const r of items) {
      const li = el('li'), pill = el('span', 'pill ' + r.direction, (r.direction === 'risk' ? '\u25B2 ' : '\u25BC ') + r.effect);
      const d = el('div'); d.append(el('div', null, r.reason), el('div', 'sub', r.impact + ' influence (model weight ' + (r.weight > 0 ? '+' : '') + r.weight + ')'));
      li.append(pill, d); ul.append(li);
    }
    return ul;
  }
  function header(d) {
    const s = el('section', 'res v-' + d.verdict.split(' ')[0]); s.append(el('span', 'badge', d.verdict));
    const pct = Math.round(d.risk * 1000) / 10, m = el('div', 'meter'), bar = el('div'); bar.style.width = Math.max(pct, 1) + '%'; m.append(bar);
    m.setAttribute('role', 'img'); m.setAttribute('aria-label', 'Phishing risk ' + pct + ' percent');
    const sc = el('div', 'scale'); sc.append(el('span', null, '0% safe'), el('span', null, pct + '% risk'), el('span', null, '100% phishing'));
    s.append(m, sc, el('p', 'sum', d.summary));
    if (d.borderline) s.append(el('div', 'note', 'This is a borderline result. Verify through an official channel before trusting it.'));
    return s;
  }
  const pctOf = (x) => Math.round(x * 1000) / 10;
  const ul = (items, mark) => { const u = el('ul', 'plain'); items.forEach((t) => u.append(el('li', null, (mark ? mark + ' ' : '') + t))); return u; };
  const kv = (rows) => { const t = el('table', 'kv'); rows.forEach(([k, v]) => { const r = el('tr'); r.append(el('th', null, k), el('td', null, String(v))); t.append(r); }); return t; };
  const SEV = { high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };

  function findingCard(f) {
    const c = el('div', 'finding sev-' + f.severity), h = el('div', 'fh'); h.append(el('span', 'sev', SEV[f.severity]), el('strong', null, f.title)); c.append(h);
    const ev = el('p', 'ev'); ev.append(el('span', 'lbl', 'What we saw: ')); f.evidence.forEach((e) => ev.append(el('code', null, e)));
    c.append(ev);
    [['What it is', f.what], ['Why attackers use it', f.why], ['How to spot it yourself', f.spot]].forEach(([l, t]) => { const p = el('p'); p.append(el('span', 'lbl', l + ': '), document.createTextNode(t)); c.append(p); });
    return c;
  }
  function anatomyTable(a) {
    const t = el('table', 'anat');
    a.parts.forEach((p) => { const r = el('tr', p.owner ? 'owner' : ''); const td = el('td'); td.append(el('code', null, p.text)); r.append(el('th', null, p.part), td, el('td', 'sub', p.note)); t.append(r); });
    const w = el('div', 'scroll'); w.append(t); return w;
  }
  function analystBlock(d, extraTables) {
    const det = el('details', 'analyst'); det.append(el('summary', null, 'Analyst details (scores, model signals, raw findings, plain-text report)'));
    const A = d.analyst, rows = [['Model versions', A.model_versions.join(', ')], ['Decision threshold (link model)', A.decision_threshold_url]];
    if (d.type === 'url') rows.unshift(['Normalised input (scheme and www removed)', A.normalized_input], ['Link model score', A.url_model_score], ['Page model score', A.page_model_score === null ? 'not fetched' : A.page_model_score], ['Score fusion', A.fusion], ['Rule override applied', A.rule_override ? 'yes' : 'no'], ['Model verdict before rules', d.model_verdict]);
    else rows.unshift(['E-mail model score', A.email_model_score]);
    det.append(kv(rows));
    det.append(el('h3', null, 'Model signals (TreeSHAP, log-odds)'));
    const t = el('table', 'kv'); d.model_reasons.concat(d.page ? d.page.reasons : []).forEach((r) => { const tr = el('tr'); tr.append(el('th', null, (r.weight > 0 ? '+' : '') + r.weight), el('td', null, r.effect + ' (' + r.impact + '): ' + r.reason)); t.append(tr); });
    det.append(t);
    if (extraTables) extraTables.forEach((x) => det.append(x));
    det.append(el('h3', null, 'Suggested analyst follow-up')); det.append(ul(A.follow_up, '\u2022'));
    det.append(el('h3', null, 'Plain-text report')); det.append(el('pre', 'mono', d.report.text));
    return det;
  }
  function copyButton(d) {
    const b = el('button', 'secondary', 'Copy report as text'); b.type = 'button';
    b.addEventListener('click', async () => { try { await navigator.clipboard.writeText(d.report.text); b.textContent = 'Copied \u2713'; } catch (_) { b.textContent = 'Copy not available: open Analyst details and select the text'; } setTimeout(() => { b.textContent = 'Copy report as text'; }, 3000); });
    return b;
  }
  function reportSections(d) {
    const r = d.report, out = [];
    out.push(section('Verdict explained', ...r.verdict_explained.map((t) => el('p', null, t))));
    return { out, r };
  }
  function tail(d) {
    const r = d.report, out = [];
    out.push(section(r.findings.length ? 'Warning signs found (' + r.findings.length + ')' : 'Warning signs found',
      ...(r.findings.length ? r.findings.map(findingCard) : [el('p', null, 'None of the warning signs we look for were found in this ' + (d.type === 'url' ? 'link.' : 'e-mail.'))])));
    if (r.clean_checks.length) out.push(section('Checks that came out clean', ul(r.clean_checks, '\u2713')));
    out.push(section('What we cannot verify', ul(r.cannot_verify, '?')));
    out.push(section('What to do now', ul(r.actions, '\u2022')), section('Double-check it yourself', ul(r.verify_yourself, '\u2022')));
    const bar = el('div', 'bar'); bar.append(copyButton(d)); out.push(bar);
    return out;
  }

  function renderUrl(d) {
    result.replaceChildren(header(d)); const { out } = reportSections(d); result.append(...out);
    if (d.indicators.length) result.append(section('Your link with the warning signs marked', highlighted(d.input, d.indicators, () => 'risk', (s) => s.label)));
    result.append(section('Anatomy of this address', anatomyTable(d.report.anatomy)), ...tail(d));
    const pg = [];
    if (d.page.checked) { const info = d.page.info || {}; pg.push(el('h3', null, 'Page inspection'), kv([['Page model score', pctOf(d.page.score) + '%'], ['Final URL', info.final_url], ['Redirects', info.redirects], ['HTTP status', info.status]])); }
    else if (d.page.requested && d.page.error) pg.push(el('h3', null, 'Page inspection'), el('p', null, 'Not performed: ' + d.page.error));
    result.append(analystBlock(d, pg), el('p', 'disc', d.disclaimer)); result.classList.remove('hidden');
  }
  function renderEmail(d) {
    result.replaceChildren(header(d)); const { out } = reportSections(d); result.append(...out);
    result.append(section('Your e-mail with the influential words marked', highlighted(d.text, d.spans, (s) => s.direction, (s) => (s.direction === 'risk' ? 'Looks like phishing wording: ' : 'Looks like normal wording: ') + s.term),
      el('p', 'sub', 'Yellow = phishing-style wording (rule cues and model words). Green = wording typical of normal mail. Single words are weak evidence on their own.')));
    result.append(...tail(d));
    const lk = [];
    if (d.links.length) { lk.push(el('h3', null, 'Links found in the e-mail')); const t = el('table', 'kv'); d.links.forEach((l) => { const r = el('tr'); r.append(el('th', null, pctOf(l.risk) + '% risk'), el('td', null, l.url + (l.indicators.length ? '  [' + l.indicators.map((i) => i.label).join('; ') + ']' : ''))); t.append(r); }); lk.push(t); }
    result.append(analystBlock(d, lk), el('p', 'disc', d.disclaimer)); result.classList.remove('hidden');
  }

  async function post(path, body) {
    const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    let data = null; try { data = await r.json(); } catch (_) {}
    if (!r.ok) throw new Error(typeof (data && data.detail) === 'string' ? data.detail : r.status === 422 ? 'Please check your input and try again.' : 'Something went wrong (' + r.status + '). Please try again.');
    return data;
  }
  function wire(form, run) {
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault(); const btn = form.querySelector('button[type=submit]'); btn.disabled = true;
      status.className = ''; status.textContent = 'Analysing...'; result.classList.add('hidden');
      try { await run(); status.textContent = ''; } catch (e) { status.className = 'err'; status.textContent = e.message || 'Network error - is the server running?'; } finally { btn.disabled = false; }
    });
  }
  wire($('form-url'), async () => renderUrl(await post('/api/analyze/url', { url: $('url').value, crawl: $('crawl').checked })));
  wire($('form-email'), async () => renderEmail(await post('/api/analyze/email', { text: $('email').value })));

  fetch('/api/about').then((r) => r.json()).then((a) => {
    if (a.crawl_enabled) $('crawl-wrap').classList.remove('hidden');
    const box = $('about'), p = (x) => (x * 100).toFixed(1) + '%';
    const t = el('table'); [['', 'Links', 'E-mails'], ['Accuracy', p(a.url_test.accuracy), p(a.email_test.accuracy)], ['False-alarm rate', p(a.url_test.fpr), p(a.email_test.fpr)], ['Recall (phishing caught)', p(a.url_test.recall), p(a.email_test.recall)]]
      .forEach((row, i) => { const tr = el('tr'); row.forEach((c) => tr.append(el(i ? 'td' : 'th', null, c))); t.append(tr); });
    const ul = el('ul'); a.limitations.forEach((x) => ul.append(el('li', null, x)));
    box.replaceChildren(el('p', null, 'Measured on held-out test data (hosts never seen in training):'), t, el('p', null, 'Limits:'), ul, el('p', 'sub', 'Version ' + a.version));
  }).catch(() => { $('about').textContent = 'Model information is unavailable.'; });
})();
