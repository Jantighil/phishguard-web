"""GPU stage from the paper: fine-tune DistilBERT / BERT / RoBERTa on the cleaned URLs (run in Colab, T4 GPU).
NOT executed in the package build environment (no GPU) - treat as a starting point and check the first epoch.
Usage:  python finetune_transformer.py --model distilbert-base-uncased --n_train 150000 --data urls_clean.parquet
(urls_clean.parquet is produced by phishguard/prep.py)"""
import argparse, numpy as np, pandas as pd, torch
from datasets import Dataset
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score
from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments, DataCollatorWithPadding
ap = argparse.ArgumentParser(); ap.add_argument('--model', default='distilbert-base-uncased'); ap.add_argument('--data', default='urls_clean.parquet')
ap.add_argument('--n_train', type=int, default=150000); ap.add_argument('--epochs', type=int, default=2); ap.add_argument('--out', default='transformer_out')
a = ap.parse_args()
df = pd.read_parquet(a.data).rename(columns={'norm': 'text', 'binary_label': 'label'})
tr = df[df.split == 'train'].groupby('label', group_keys=False).apply(lambda g: g.sample(min(len(g), a.n_train // 2), random_state=42))
va, te = df[df.split == 'val'].sample(20000, random_state=1), df[df.split == 'test']      # test stays FULL size
tok = AutoTokenizer.from_pretrained(a.model)
enc = lambda d: Dataset.from_pandas(d[['text', 'label']].reset_index(drop=True)).map(lambda b: tok(b['text'], truncation=True, max_length=64), batched=True)
def cm(p):
    lg, y = p; pr = torch.softmax(torch.tensor(lg), -1)[:, 1].numpy(); yh = (pr >= .5).astype(int)
    P, R, F, _ = precision_recall_fscore_support(y, yh, average='binary')
    return dict(accuracy=accuracy_score(y, yh), precision=P, recall=R, f1=F, auc=roc_auc_score(y, pr))
m = AutoModelForSequenceClassification.from_pretrained(a.model, num_labels=2)
args = TrainingArguments(a.out, per_device_train_batch_size=64, per_device_eval_batch_size=256, learning_rate=3e-5, num_train_epochs=a.epochs,
                         fp16=torch.cuda.is_available(), eval_strategy='epoch', save_strategy='epoch', load_best_model_at_end=True, metric_for_best_model='f1', report_to='none', seed=42)
t = Trainer(model=m, args=args, train_dataset=enc(tr), eval_dataset=enc(va), data_collator=DataCollatorWithPadding(tok), compute_metrics=cm)
t.train(); print('TEST:', t.evaluate(enc(te))); t.save_model(f'{a.out}/best'); tok.save_pretrained(f'{a.out}/best')
