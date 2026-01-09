import pandas as pd
from feature_extraction import extract_features

# ==============================
# CONFIG
# ==============================
DATASET_PATH = "dataset_phishing.csv"
OUTPUT_PATH = "phishing_features.csv"
SAMPLE_SIZE = None   # set to None for full dataset later

# ==============================
# LOAD DATASET
# ==============================
print("[*] Loading dataset...")
df = pd.read_csv(DATASET_PATH)

if SAMPLE_SIZE is not None:
    df = df.sample(SAMPLE_SIZE, random_state=42).reset_index(drop=True)
    print(f"[*] Using sample size: {SAMPLE_SIZE}")

print(f"[*] Total URLs: {len(df)}")

# ==============================
# FEATURE EXTRACTION
# ==============================
features_list = []

for i, row in enumerate(df.itertuples(index=False), start=1):
    url = row.url
    label = row.status  # 0 = legit, 1 = phishing

    feats = extract_features(url)
    feats["label"] = label
    features_list.append(feats)

    if i % 500 == 0:
        print(f"[*] Processed {i} URLs")

# ==============================
# SAVE
# ==============================
features_df = pd.DataFrame(features_list)
features_df.to_csv(OUTPUT_PATH, index=False)

print("\n✅ Feature extraction completed successfully!")
print("✅ Output file:", OUTPUT_PATH)
print(features_df.head())
