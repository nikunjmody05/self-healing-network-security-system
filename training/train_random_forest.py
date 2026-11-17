"""Original Random Forest training script (CIC-IDS2017, 100k sample, 80/20 split).
Writes to models/retrained/; the shipped models/rf_model.pkl is never overwritten.
Note: the original 80/20 split has no random_state, so retraining will not reproduce the shipped model exactly."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import project_config as cfg  # noqa: E402

OUT_DIR = cfg.BASE_DIR / "models" / "retrained"  # never overwrites models/*.pkl
OUT_DIR.mkdir(parents=True, exist_ok=True)

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import time

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report

# -------- LOAD DATA --------
df = pd.read_parquet(cfg.DATA_PATH)

print("First 5 rows:\n", df.head())
print("\nDataset Shape:", df.shape)
print("\nColumns:\n", df.columns)

print("\nLabel Distribution:\n", df['Label'].value_counts())
print("\nClassLabel Distribution:\n", df['ClassLabel'].value_counts())


# -------- PIE CHART (FULL DATASET) --------
top_n = 6
label_counts = df['ClassLabel'].value_counts()

top_labels = label_counts[:top_n]
others = pd.Series(label_counts[top_n:].sum(), index=['Others'])

final_counts = pd.concat([top_labels, others])

plt.figure(figsize=(7,7))
plt.pie(final_counts, labels=final_counts.index, autopct='%1.1f%%')
plt.title("Full Dataset Distribution (Top Attacks)")
plt.show()


# -------- PREPROCESSING --------

# Binary classification
df['target'] = df['Label'].apply(lambda x: 0 if x == 'Benign' else 1)

# Sampling
df_sample = df.sample(100000, random_state=42)

# -------- PIE CHART (SAMPLE DATA) --------
sample_counts = df_sample['ClassLabel'].value_counts()

top_labels_sample = sample_counts[:top_n]
others_sample = pd.Series(sample_counts[top_n:].sum(), index=['Others'])

final_sample = pd.concat([top_labels_sample, others_sample])

plt.figure(figsize=(7,7))
plt.pie(final_sample, labels=final_sample.index, autopct='%1.1f%%')
plt.title("Sample Dataset Distribution")
plt.show()


# -------- BALANCE CHECK --------
print("\nFull Dataset Balance:\n")
print(df['ClassLabel'].value_counts(normalize=True)*100)

print("\nSample Dataset Balance:\n")
print(df_sample['ClassLabel'].value_counts(normalize=True)*100)
df['ClassLabel'].value_counts().plot(kind='bar', figsize=(10,5))
plt.title("Full Dataset Class Distribution")
plt.show()


# -------- FEATURES --------
X = df_sample.drop(columns=['Label', 'ClassLabel', 'target'])
y = df_sample['target']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)


# -------- MODEL --------
model = RandomForestClassifier(n_estimators=50)

print("\nTraining model...")
start_train = time.time()
model.fit(X_train, y_train)
end_train = time.time()

print(f"Training Time: {end_train - start_train:.2f} seconds")


# -------- PREDICTION TIME --------
start_pred = time.time()
y_pred = model.predict(X_test)
end_pred = time.time()

print(f"Prediction Time: {end_pred - start_pred:.4f} seconds")


# -------- ACCURACY --------
accuracy = model.score(X_test, y_test)
print("\nModel Accuracy:", accuracy)


# -------- CONFUSION MATRIX (BINARY) --------
cm = confusion_matrix(y_test, y_pred)
print("\nConfusion Matrix (Binary):\n", cm)

plt.figure(figsize=(6,5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Benign', 'Attack'],
            yticklabels=['Benign', 'Attack'])
plt.title("Binary Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.show()


# -------- MULTI-CLASS CONFUSION MATRIX --------
X_multi = df_sample.drop(columns=['Label', 'ClassLabel', 'target'])
y_multi = df_sample['ClassLabel']

X_train_m, X_test_m, y_train_m, y_test_m = train_test_split(X_multi, y_multi, test_size=0.2)

model_multi = RandomForestClassifier(n_estimators=50)
model_multi.fit(X_train_m, y_train_m)

y_pred_m = model_multi.predict(X_test_m)
# -------- PER-ATTACK CONFUSION MATRIX (ONE-vs-ALL) --------

# Focus only on important attack classes
important_classes = ['DDoS', 'DoS', 'Botnet', 'Bruteforce']

print("\n--- Per-Class (One-vs-All) Confusion Matrices ---")

for cls in important_classes:
    
    if cls not in y_test_m.values:
        continue  # skip if not present in sample

    print(f"\nClass: {cls}")
    
    y_true_binary = (y_test_m == cls).astype(int)
    y_pred_binary = (y_pred_m == cls).astype(int)
    
    cm_cls = confusion_matrix(y_true_binary, y_pred_binary)
    print(cm_cls)

    plt.figure(figsize=(4,3))
    sns.heatmap(cm_cls, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Not ' + cls, cls],
                yticklabels=['Not ' + cls, cls])
    
    plt.title(f"{cls} Detection (One-vs-All)")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()
    plt.show()


# -------- CLASSIFICATION REPORT --------
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))


# -------- FEATURE IMPORTANCE --------
importances = model.feature_importances_
feature_names = X.columns

feat_df = pd.DataFrame({
    'Feature': feature_names,
    'Importance': importances
}).sort_values(by='Importance', ascending=False)

print("\nTop 10 Important Features:\n")
print(feat_df.head(10))


# -------- LEAST IMPORTANT FEATURES --------
print("\nLeast Important Features:\n")
print(feat_df.tail(10))


# -------- FEATURE IMPORTANCE PLOT --------
plt.figure(figsize=(10,6))
plt.barh(feat_df['Feature'][:10], feat_df['Importance'][:10])
plt.gca().invert_yaxis()
plt.title("Top 10 Feature Importances")
plt.xlabel("Importance")
plt.ylabel("Feature")
plt.tight_layout()
plt.show()


# -------- FEATURE CONTRIBUTION --------
attack_data = df_sample[df_sample['target'] == 1]
benign_data = df_sample[df_sample['target'] == 0]

attack_mean = attack_data.mean(numeric_only=True)
benign_mean = benign_data.mean(numeric_only=True)

comparison = pd.DataFrame({
    'Attack Mean': attack_mean,
    'Benign Mean': benign_mean
})

comparison['Difference'] = comparison['Attack Mean'] - comparison['Benign Mean']
comparison_sorted = comparison.sort_values(by='Difference', ascending=False)

print("\nTop Features Contributing to ATTACK:\n")
print(comparison_sorted.head(10))

print("\nTop Features Contributing to BENIGN:\n")
print(comparison_sorted.tail(10))

# -------- SAVE MODEL FOR RL --------
import joblib

joblib.dump(model, OUT_DIR / "rf_model.pkl")

print("\nModel saved successfully.")