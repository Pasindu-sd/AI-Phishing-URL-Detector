import joblib
from features import extract_features

model = joblib.load("model.pkl")

while True:
    url = input("Enter URL (or 'exit' to quit): ")
    if url.lower() == "exit":
        break 

    features = extract_features(url)

    result = model.predict([features])[0]

    if result == 1:
        print("PHISHING URL")
    else:
        print("SAFE URL")
