"""Page-content model trained on the PhiUSIIL rows (the only source with page-level features),
restricted to the features the crawler can reproduce."""
import os, sys, json, time, joblib, numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import lightgbm as lgb
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from phishguard.prep import normalize_url, host_of, split_by_host
from phishguard.crawler import PAGE_FEATURES
# behavioural cues only: size/volume counts (LineOfCode, NoOfExternalRef, NoOfImage...) mostly measure 'big rich site' in this corpus
USE = ['HasTitle','HasFavicon','HasDescription','HasCopyrightInfo','HasSocialNet','HasSubmitButton','HasHiddenFields','HasPasswordField','HasExternalFormSubmit','IsResponsive','NoOfiFrame','NoOfPopup','Bank','Pay','Crypto']
raw = pd.read_parquet('raw.parquet'); r = raw[raw.source_id == 'uci_phiusiil_2024'].copy()
F = pd.DataFrame([json.loads(s) for s in r.source_features_json]).reindex(columns=USE).apply(pd.to_numeric, errors='coerce')
F.index = r.index; y = r.binary_label.values
split = split_by_host(r.url.map(lambda u: host_of(normalize_url(u))))
tr, va, te = [np.where(split.values == s)[0] for s in ('train', 'val', 'test')]
P = dict(objective='binary', learning_rate=0.05, num_leaves=15, min_child_samples=50, feature_fraction=0.8, bagging_fraction=0.8,
         bagging_freq=1, lambda_l2=5.0, verbose=-1, num_threads=1, seed=42)
b = lgb.train(P, lgb.Dataset(F.iloc[tr], y[tr]), 600, valid_sets=[lgb.Dataset(F.iloc[va], y[va])], callbacks=[lgb.early_stopping(30, verbose=False)])
p = b.predict(F.iloc[te]); yh = (p >= .5).astype(int); tn, fp, fn, tp = confusion_matrix(y[te], yh).ravel()
m = dict(accuracy=accuracy_score(y[te], yh), precision=precision_score(y[te], yh), recall=recall_score(y[te], yh),
         f1=f1_score(y[te], yh), fpr=fp / (fp + tn), fnr=fn / (fn + tp), auc=roc_auc_score(y[te], p), n_test=len(te))
imp = pd.Series(b.feature_importance('gain'), index=USE).sort_values(ascending=False)
joblib.dump(dict(booster=b, columns=USE, version='phishguard-page-1.0'), 'page_model.joblib', compress=3)
json.dump(dict(test=m, top_features=imp.head(10).round(1).to_dict()), open('page_metrics.json', 'w'), indent=1, default=float)
print(json.dumps(m, indent=1, default=float)); print(imp.head(10))
