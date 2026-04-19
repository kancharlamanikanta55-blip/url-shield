import os

# Always delete old model to force retrain with correct features
if os.path.exists("model.pkl"):
    os.remove("model.pkl")
    print("Removed old model.pkl")

# Download dataset if not present
if not os.path.exists("malicious_phish_new.csv"):
    print("Downloading dataset from Kaggle...")
    os.system("pip install kaggle")
    os.system("kaggle datasets download -d sid321axn/malicious-urls-dataset --unzip")
    # Rename to expected filename
    for f in os.listdir('.'):
        if f.endswith('.csv') and f != 'malicious_phish_new.csv':
            os.rename(f, 'malicious_phish_new.csv')
            break
    print("Dataset ready!")

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
import joblib
from utility import (
    having_ip_address, abnormal_url, count_dot, count_www,
    count_atrate, no_of_dir, no_of_embed, shortening_service,
    count_https, count_http, count_per, count_ques, count_hyphen,
    count_equal, url_length, hostname_length, suspicious_words,
    digit_count, letter_count, fd_length, tld_length,
    url_entropy, special_char_count, subdomain_count, path_length
)
from tld import get_tld

# Load dataset
print("Loading dataset...")
df = pd.read_csv("malicious_phish_new.csv")
print(f"Dataset loaded: {len(df)} rows")

# Extract features
print("Extracting features (this may take a few minutes)...")
df['use_of_ip']          = df['url'].apply(having_ip_address)
df['abnormal_url']       = df['url'].apply(abnormal_url)
df['count.']             = df['url'].apply(count_dot)
df['count-www']          = df['url'].apply(count_www)
df['count@']             = df['url'].apply(count_atrate)
df['count_dir']          = df['url'].apply(no_of_dir)
df['count_embed_domain'] = df['url'].apply(no_of_embed)
df['short_url']          = df['url'].apply(shortening_service)
df['count-https']        = df['url'].apply(count_https)
df['count-http']         = df['url'].apply(count_http)
df['count%']             = df['url'].apply(count_per)
df['count?']             = df['url'].apply(count_ques)
df['count-']             = df['url'].apply(count_hyphen)
df['count=']             = df['url'].apply(count_equal)
df['url_length']         = df['url'].apply(url_length)
df['hostname_length']    = df['url'].apply(hostname_length)
df['sus_url']            = df['url'].apply(suspicious_words)
df['count-digits']       = df['url'].apply(digit_count)
df['count-letters']      = df['url'].apply(letter_count)
df['fd_length']          = df['url'].apply(fd_length)
df['tld']                = df['url'].apply(lambda i: get_tld(i, fail_silently=True))
df['tld_length']         = df['tld'].apply(tld_length)
df['url_entropy']        = df['url'].apply(url_entropy)
df['special_chars']      = df['url'].apply(special_char_count)
df['subdomain_count']    = df['url'].apply(subdomain_count)
df['path_length']        = df['url'].apply(path_length)
# Encode labels
label_map = {'benign': 0, 'defacement': 1, 'phishing': 1, 'malware': 1}
df['label'] = df['type'].map(label_map)

# Features and target
X = df[['use_of_ip','abnormal_url','count.','count-www','count@',
        'count_dir','count_embed_domain','short_url','count-https',
        'count-http','count%','count?','count-','count=','url_length',
        'hostname_length','sus_url','count-digits','count-letters',
        'fd_length','tld_length','url_entropy','special_chars',
        'subdomain_count','path_length']]
y = df['label']

# Balance the dataset
print("Balancing dataset...")
from sklearn.utils import resample
min_count = df['label'].value_counts().min()
df_balanced = pd.concat([
    resample(df[df['label']==0], n_samples=min_count, random_state=42),
    resample(df[df['label']==1], n_samples=min_count, random_state=42),
    
])

X = df_balanced[['use_of_ip','abnormal_url','count.','count-www','count@',
        'count_dir','count_embed_domain','short_url','count-https',
        'count-http','count%','count?','count-','count=','url_length',
        'hostname_length','sus_url','count-digits','count-letters',
        'fd_length','tld_length']]
y = df_balanced['label']

# Train
print("Training model...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    scale_pos_weight=1,
    use_label_encoder=False,
    eval_metric='mlogloss',
    random_state=42
)
model.fit(X_train, y_train)

# Evaluate
score = model.score(X_test, y_test)
print(f"Model accuracy: {score:.2%}")

# Save
joblib.dump(model, "model.pkl")
print("✅ model.pkl saved successfully!")