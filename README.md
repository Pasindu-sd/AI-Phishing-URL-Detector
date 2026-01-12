# AI Phishing URL Detector

This project is an **AI-based phishing URL detection tool** using Python and Random Forest. It can detect whether a URL is **Safe (Legitimate)** or **Phishing** based on basic URL features.

---

## 🔹 Features

- Detects phishing URLs using a **Random Forest Classifier**
- Extracts features like:
  - URL length
  - Number of dots, dashes, and `@` symbols
  - Presence of HTTPS
  - IP address usage
  - Suspicious keywords (`login`, `verify`, `bank`, `secure`)
  - Query parameters
  - Shortened URLs (`bit.ly`, `tinyurl`, etc.)
- Provides **detailed metrics**:
  - Accuracy
  - Precision, Recall, F1-score
  - Confusion Matrix
- Trained on **450,000+ URLs**, achieving ~99% accuracy
- Safe for **warning users**, not automatic blocking

---

## 🔹 Installation

1. Clone this repository:

```bash
git clone https://github.com/Pasindu-sd/AI-Phishing-URL-Detector.git
cd AI-Phishing-URL-Detector
