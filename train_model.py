import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# ==============================
# CONFIG
# ==============================
DATASET_PATH = "phishing_features.csv"
MODEL_PATH = "phishing_model.pkl"
RANDOM_STATE = 42

FEATURE_COLUMNS = [
    "url_length",
    "count_dots",
    "count_hyphens",
    "count_slashes",
    "count_digits",
    "has_ip",
    "has_https",
    "suspicious_word_count",
    "domain_length",
    "subdomain_count"
]

# ==============================
# LOAD DATASET
# ==============================
print("[*] Loading feature dataset...")
df = pd.read_csv(DATASET_PATH)

print("[*] Encoding labels...")

# 🔴 FIX: convert string labels → numeric
df["label"] = df["label"].map({
    "legitimate": 0,
    "phishing": 1
})

# Safety check
if df["label"].isnull().any():
    raise ValueError("Label encoding failed. Check label values.")

X = df[FEATURE_COLUMNS]
y = df["label"]

print(f"[*] Total samples: {len(df)}")

# ==============================
# TRAIN / TEST SPLIT
# ==============================
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    stratify=y,
    random_state=RANDOM_STATE
)

# ==============================
# MODEL (SECURITY-OPTIMIZED)
# ==============================
print("[*] Training Random Forest model...")

model = RandomForestClassifier(
    n_estimators=400,
    max_depth=25,
    class_weight={0: 1, 1: 3},  # phishing is more important
    random_state=RANDOM_STATE,
    n_jobs=-1
)

model.fit(X_train, y_train)

# ==============================
# EVALUATION (CUSTOM THRESHOLD)
# ==============================
print("[*] Evaluating model...")

y_probs = model.predict_proba(X_test)[:, 1]
THRESHOLD = 0.35
y_pred = (y_probs >= THRESHOLD).astype(int)

print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

print("Confusion Matrix:\n")
print(confusion_matrix(y_test, y_pred))

# ==============================
# SAVE MODEL
# ==============================
joblib.dump(model, MODEL_PATH)
print(f"\n✅ Model saved successfully as: {MODEL_PATH}")
