"""Separate Random Forest trained and tested on UNSW-NB15 (second-dataset evidence;
not a cross-dataset test of the CIC model). Reads data/unsw/; writes nothing."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import project_config as cfg  # noqa: E402

OUT_DIR = cfg.BASE_DIR / "models" / "retrained"  # never overwrites models/*.pkl
OUT_DIR.mkdir(parents=True, exist_ok=True)

import pandas as pd
import numpy as np
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score

# -------- LOAD DATA --------
train_df = pd.read_csv(cfg.UNSW_DIR / "UNSW_NB15_training-set.csv")
test_df = pd.read_csv(cfg.UNSW_DIR / "UNSW_NB15_testing-set.csv")

print("First 5 rows:\n", train_df.head())

print("\nDataset Shape:", train_df.shape)
print("\nColumns:\n", train_df.columns)

# -------- DROP USELESS --------
drop_cols = ['id', 'attack_cat']
train_df = train_df.drop(columns=drop_cols, errors='ignore')
test_df = test_df.drop(columns=drop_cols, errors='ignore')

# -------- HANDLE CATEGORICAL --------
categorical_cols = ['proto', 'service', 'state']

train_df = pd.get_dummies(train_df, columns=categorical_cols)
test_df = pd.get_dummies(test_df, columns=categorical_cols)

# Align columns (VERY IMPORTANT)
train_df, test_df = train_df.align(test_df, join='left', axis=1, fill_value=0)

# -------- LABEL DISTRIBUTION --------
print("\nLabel Distribution:\n", train_df['label'].value_counts())

print("\nDataset Balance:\n")
print(train_df['label'].value_counts(normalize=True) * 100)

# -------- SPLIT --------
X_train = train_df.drop(columns=['label'])
y_train = train_df['label']

X_test = test_df.drop(columns=['label'])
y_test = test_df['label']

# -------- TRAIN --------
print("\nTraining model...")
start = time.time()

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

train_time = time.time() - start

# -------- PREDICT --------
start = time.time()
y_pred = model.predict(X_test)
pred_time = time.time() - start

print(f"Training Time: {train_time:.2f} seconds")
print(f"Prediction Time: {pred_time:.4f} seconds")

# -------- ACCURACY --------
accuracy = accuracy_score(y_test, y_pred)
print("\nModel Accuracy:", accuracy)

# -------- CONFUSION MATRIX --------
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))

# -------- REPORT --------
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

# -------- FEATURE IMPORTANCE --------
importances = model.feature_importances_
feature_names = X_train.columns

feat_df = pd.DataFrame({
    'Feature': feature_names,
    'Importance': importances
}).sort_values(by='Importance', ascending=False)

print("\nTop 10 Important Features:\n")
print(feat_df.head(10))

print("\nLeast Important Features:\n")
print(feat_df.tail(10))

# -------- FEATURE CONTRIBUTION --------
attack_data = train_df[train_df['label'] == 1]
benign_data = train_df[train_df['label'] == 0]

attack_mean = attack_data.mean(numeric_only=True)
benign_mean = benign_data.mean(numeric_only=True)

diff = attack_mean - benign_mean

contribution_df = pd.DataFrame({
    'Attack Mean': attack_mean,
    'Benign Mean': benign_mean,
    'Difference': diff
}).sort_values(by='Difference', ascending=False)

print("\nTop Features Contributing to ATTACK:\n")
print(contribution_df.head(10))

print("\nTop Features Contributing to BENIGN:\n")
print(contribution_df.tail(10))