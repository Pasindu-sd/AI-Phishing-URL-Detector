import os
import joblib

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

if os.environ.get("ENABLE_URL_ENRICHMENT", "0") != "1":
    os.environ.setdefault("URL_WHOIS_SAMPLE_PERCENT", "0")
    os.environ.setdefault("URL_REDIRECT_SAMPLE_PERCENT", "0")

from features import extract_features

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(BASE_DIR, "urls.csv")

data = pd.read_csv(csv_path)
data = data.dropna(subset=["url", "label"])
data["label"] = data["label"].astype(str).str.strip().str.lower()
data = data[data["label"].isin(["legitimate", "phishing"])]

train_sample_limit = int(os.environ.get("TRAIN_SAMPLE_LIMIT", "50000"))
if len(data) > train_sample_limit:
    data = data.sample(n=train_sample_limit, random_state=42)

X = data["url"].apply(extract_features).tolist()

y = (
    data["label"].map({"legitimate": 0, "phishing": 1})
)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced_subsample",
    n_jobs=-1,
)

model.fit(X_train, y_train)

accuracy = model.score(X_test, y_test)
print(f"Test Accuracy: {accuracy * 100:.2f}%")

train_accuracy = model.score(X_train, y_train)
test_accuracy = model.score(X_test, y_test)

print(f"Train Accuracy: {train_accuracy * 100:.2f}%")
print(f"Test Accuracy: {test_accuracy * 100:.2f}%")

if train_accuracy > test_accuracy + 0.10:
    print("Warning: Model might be overfitting!")
else:
    print("Good: No significant overfitting detected.")


from sklearn.metrics import confusion_matrix, classification_report

y_pred = model.predict(X_test)

print("\n" + "="*50)
print("CONFUSION MATRIX:")
print("="*50)
cm = confusion_matrix(y_test, y_pred)
print(f"""
True Negatives (Safe→Safe):   {cm[0,0]}
False Positives (Safe→Phishing): {cm[0,1]}
False Negatives (Phishing→Safe): {cm[1,0]}
True Positives (Phishing→Phishing): {cm[1,1]}
""")

print("\n" + "="*50)
print("DETAILED CLASSIFICATION REPORT:")
print("="*50)
print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))


model_path = os.path.join(BASE_DIR, "url_model.pkl")
joblib.dump(model, model_path)

print("AI is trained and saved successfully")
