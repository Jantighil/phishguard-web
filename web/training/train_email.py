"""Email model: word TF-IDF logistic + handcrafted cues -> LightGBM stacked ensemble."""
import os, re, sys, time, json, joblib, numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import lightgbm as lgb
from phishguard.email_features import email_features, clean_text

T0 = time.time()
def log(*a): print(f'[{time.time()-T0:5.0f}s]', *a, flush=True)
def metrics(y, p, thr=0.5):
    yh = (p >= thr).astype(int); tn, fp, fn, tp = confusion_matrix(y, yh).ravel()
    return dict(accuracy=accuracy_score(y, yh), precision=precision_score(y, yh), recall=recall_score(y, yh),
                f1=f1_score(y, yh), fpr=fp / (fp + tn), fnr=fn / (fn + tp), auc=roc_auc_score(y, p))

df = pd.read_parquet('emails_clean.parquet'); y = df.binary_label.values
tr, va, te = [np.where(df.split == s)[0] for s in ('train', 'val', 'test')]
clean = df.text.map(clean_text)
X_h = pd.DataFrame([email_features(t) for t in df.text]).astype('float32'); log('handcrafted', X_h.shape)
tfv = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=300000, sublinear_tf=True, strip_accents='unicode', dtype=np.float32)
Xw = tfv.fit_transform(clean[tr]); Xw_all = tfv.transform(clean); log('tfidf', Xw_all.shape)
mk = lambda: LogisticRegression(C=8, max_iter=300, solver='liblinear')
oof = np.zeros(len(df), dtype=np.float32)
for k, (a, b) in enumerate(StratifiedKFold(4, shuffle=True, random_state=42).split(tr, y[tr])):
    oof[tr[b]] = mk().fit(Xw_all[tr[a]], y[tr[a]]).decision_function(Xw_all[tr[b]])
lr = mk().fit(Xw_all[tr], y[tr])
for i in (va, te): oof[i] = lr.decision_function(Xw_all[i])
res = {'Word-TFIDF + Logistic Regression': metrics(y[te], 1 / (1 + np.exp(-oof[te])))}
Xs = X_h.copy(); Xs['text_score'] = oof
P = dict(objective='binary', learning_rate=0.05, num_leaves=63, min_child_samples=30, feature_fraction=0.8,
         bagging_fraction=0.8, bagging_freq=1, lambda_l2=1.0, verbose=-1, num_threads=1, seed=42)
fit = lambda X: lgb.train(P, lgb.Dataset(X.iloc[tr], y[tr]), 800, valid_sets=[lgb.Dataset(X.iloc[va], y[va])],
                          callbacks=[lgb.early_stopping(40, verbose=False)])
b0 = fit(X_h); res['Handcrafted cues + LightGBM'] = metrics(y[te], b0.predict(X_h.iloc[te]))
b = fit(Xs); res['STACKED ENSEMBLE (TF-IDF LR + cues + LightGBM)'] = metrics(y[te], b.predict(Xs.iloc[te]))
imp = pd.Series(b.feature_importance('gain'), index=Xs.columns).sort_values(ascending=False)
terms = np.array(tfv.get_feature_names_out()); coef = lr.coef_[0]
top = dict(phishing=terms[np.argsort(-coef)[:15]].tolist(), legit=terms[np.argsort(coef)[:15]].tolist())
joblib.dump(dict(tfidf=tfv, lr=lr, booster=b, columns=list(Xs.columns), version='phishguard-email-1.0'), 'email_model.joblib', compress=3)
json.dump(dict(test=res, top_features=imp.head(12).round(1).to_dict(), top_terms=top, n_train=len(tr), n_test=len(te)),
          open('email_metrics.json', 'w'), indent=1, default=float)
print(pd.DataFrame(res).T.round(4).to_string()); log('saved')
