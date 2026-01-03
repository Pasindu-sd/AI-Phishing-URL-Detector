import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from features import extract_features
import joblib

data = pd.read_csv("urls.csv")

X = data["url"].apply(extract_features).tolist()
y = data["label"]

model = RandomForestClassifier()

model.fit(X, y)

joblib.dump(model, "model.pkl")

print("AI is trained and saved!")