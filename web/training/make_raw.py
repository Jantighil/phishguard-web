"""Step 0: convert the 500k CSV into raw.parquet (run once).  python -m phishguard.make_raw path/to/phishing_detection_dataset_500k.csv"""
import sys, pandas as pd
cols = ['source_id','content_type','url','email_subject','email_body','email_urls','label','binary_label','duplicate_group_size','url_path_length','source_features_json','content_sha256']
pd.read_csv(sys.argv[1], usecols=cols, low_memory=False).to_parquet('raw.parquet')
