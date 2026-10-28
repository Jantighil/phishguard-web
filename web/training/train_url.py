"""URL model: char-n-gram TF-IDF (SGD) + 45 lexical features -> LightGBM stacked boosting ensemble."""
import os, sys, time, json, joblib, numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sklearn.feature_extraction.text import HashingVectorizer, TfidfTransformer
from sklearn.linear_model import SGDClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
                             confusion_matrix, precision_recall_curve)
import lightgbm as lgb
from phishguard.features import featurize

T0 = time.time()
def log(*a): print(f'[{time.time()-T0:6.0f}s]', *a, flush=True)

def metrics(y, p, thr=0.5):
    yh = (p >= thr).astype(int); tn, fp, fn, tp = confusion_matrix(y, yh).ravel()
    return dict(accuracy=accuracy_score(y, yh), precision=precision_score(y, yh), recall=recall_score(y, yh),
                f1=f1_score(y, yh), fpr=fp / (fp + tn), fnr=fn / (fn + tp), auc=roc_auc_score(y, p),
                tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp), thr=float(thr))

df = pd.read_parquet('urls_clean.parquet').reset_index(drop=True)
log('rows', len(df)); X_lex = featurize(df.norm); y = df.binary_label.values
log('lexical features done', X_lex.shape)
tr, va, te = [np.where(df.split == s)[0] for s in ('train', 'val', 'test')]

hv = HashingVectorizer(analyzer='char', ngram_range=(3, 5), n_features=2 ** 20, alternate_sign=False,
                       norm=None, lowercase=True, dtype=np.float32)
H = hv.transform(df.norm); log('hashing done', H.shape, H.nnz)
tf = TfidfTransformer(sublinear_tf=True).fit(H[tr]); Xc = tf.transform(H).astype(np.float32); del H
log('tfidf done')

def new_sgd(): return SGDClassifier(loss='log_loss', alpha=2e-6, max_iter=15, tol=None, random_state=42)
# out-of-fold char-model scores for the training rows (so the booster never sees leaked scores)
oof = np.zeros(len(df), dtype=np.float32)
for k, (a, b) in enumerate(StratifiedKFold(4, shuffle=True, random_state=42).split(tr, y[tr])):
    m = new_sgd().fit(Xc[tr[a]], y[tr[a]]); oof[tr[b]] = m.decision_function(Xc[tr[b]]); log('oof fold', k)
sgd = new_sgd().fit(Xc[tr], y[tr])
for idx in (va, te): oof[idx] = sgd.decision_function(Xc[idx])
log('char SGD fitted')

results = {}
p_char = 1 / (1 + np.exp(-oof))
results['Char-TFIDF + Logistic (SGD)'] = metrics(y[te], p_char[te])
nb = MultinomialNB(alpha=0.05).fit(Xc[tr], y[tr]); results['Char-TFIDF + Naive Bayes'] = metrics(y[te], nb.predict_proba(Xc[te])[:, 1])
log('NB done')

Xs = X_lex.copy(); Xs['char_score'] = oof
P = dict(objective='binary', learning_rate=0.05, num_leaves=127, min_child_samples=40, feature_fraction=0.8,
         bagging_fraction=0.8, bagging_freq=1, lambda_l2=1.0, verbose=-1, num_threads=1, seed=42)
def fit_lgb(X):
    d_tr = lgb.Dataset(X.iloc[tr], y[tr]); d_va = lgb.Dataset(X.iloc[va], y[va])
    return lgb.train(P, d_tr, 1200, valid_sets=[d_va], callbacks=[lgb.early_stopping(40, verbose=False)])
b_lex = fit_lgb(X_lex); results['Lexical features + LightGBM'] = metrics(y[te], b_lex.predict(X_lex.iloc[te])); log('lex lgb', b_lex.best_iteration)
rf = RandomForestClassifier(80, max_depth=22, min_samples_leaf=3, n_jobs=1, random_state=42).fit(X_lex.iloc[tr], y[tr])
results['Lexical features + Random Forest'] = metrics(y[te], rf.predict_proba(X_lex.iloc[te])[:, 1]); log('rf done')
b_st = fit_lgb(Xs); p_st = b_st.predict(Xs); log('stacked lgb', b_st.best_iteration)
results['STACKED ENSEMBLE (char-LR + lexical + LightGBM)'] = metrics(y[te], p_st[te])

# decision threshold: highest recall subject to FPR<=1% on validation
pr = np.sort(np.unique(np.round(p_st[va], 4))); best = 0.5
for t in pr:
    m = metrics(y[va], p_st[va], t)
    if m['fpr'] <= 0.01: best = t; break
results['STACKED @ FPR<=1% threshold'] = metrics(y[te], p_st[te], best)
log('threshold', best)

per_source = {}
for s in df.source_id.unique():
    ix = te[df.source_id.values[te] == s]
    if len(set(y[ix])) > 1: per_source[s] = metrics(y[ix], p_st[ix], 0.5)
    else: per_source[s] = dict(n=len(ix), only_class=int(y[ix][0]), accuracy=float(((p_st[ix] >= .5) == y[ix]).mean()))

# leave-one-source-out: how well does it generalise to a source it never saw?
loso = {}
for s in ['uci_phiusiil_2024', 'mendeley_kaitholikkal_full_2024']:
    trn = np.where((df.source_id != s) & (df.split != 'test'))[0]; tst = np.where(df.source_id == s)[0]
    b = lgb.train({**P, 'num_leaves': 63}, lgb.Dataset(X_lex.iloc[trn], y[trn]), 300)
    loso[s] = metrics(y[tst], b.predict(X_lex.iloc[tst])); log('LOSO', s)

imp = pd.Series(b_st.feature_importance('gain'), index=Xs.columns).sort_values(ascending=False)
joblib.dump(dict(hv=hv, tf=tf, sgd=sgd, booster=b_st, columns=list(Xs.columns), threshold=float(best),
                 version='phishguard-url-1.0'), 'url_model.joblib', compress=3)
json.dump(dict(test=results, per_source_test=per_source, leave_one_source_out_lexical_only=loso,
               top_features=imp.head(15).round(1).to_dict(), n_train=len(tr), n_val=len(va), n_test=len(te)),
          open('url_metrics.json', 'w'), indent=1, default=float)
log('saved'); print(pd.DataFrame(results).T[['accuracy','precision','recall','f1','fpr','fnr','auc']].round(4).to_string())
