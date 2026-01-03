# 1️⃣ Import required tools
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from features import extract_features
import joblib

# 2️⃣ Load training data
data = pd.read_csv("urls.csv")
data.head()

# 3️⃣ Prepare data for AI
X = data["url"].apply(extract_features).tolist()  # URL → numbers
y = data["label"]                                # label = 0 or 1

# 4️⃣ Create AI model
model = RandomForestClassifier()  # Random Forest = easy & strong

# 5️⃣ Teach AI
model.fit(X, y)

# 6️⃣ Save AI brain
joblib.dump(model, "model.pkl")

print("AI is trained and saved!")
