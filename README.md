# 🛡️ PhishGuard AI — Phishing URL Detector

A professional, full-stack phishing URL detection web app powered by a **Random Forest + XGBoost ensemble** trained on the **PhiUSIIL** dataset from Kaggle.

---

## 📁 Project Structure

```
phishing-detector/
├── app.py                  ← Flask web server (API + serve UI)
├── train_model.py          ← Dataset download, preprocessing & model training
├── feature_extractor.py    ← Extracts 40+ features from any URL
├── requirements.txt        ← Python dependencies
├── run.bat                 ← One-click Windows launcher
├── models/                 ← Saved model artifacts (created after training)
│   ├── ensemble_model.joblib
│   ├── scaler.joblib
│   └── feature_columns.joblib
├── templates/
│   └── index.html          ← Frontend UI
└── static/
    ├── css/style.css        ← Dark-theme design system
    └── js/app.js            ← Frontend logic
```

---

## 🚀 Quick Start (Windows)

### Option A — Double-click launcher
```
Double-click  run.bat
```
It will automatically:
1. Install all Python dependencies
2. Download & train the model (first run only, ~5-10 min)
3. Open the app in your browser at `http://localhost:5000`

### Option B — Manual steps

```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Train the model (run once — downloads dataset from Kaggle)
python train_model.py

# 3. Start the web server
python app.py

# 4. Open browser
start http://localhost:5000
```

---

## 🔑 Kaggle Authentication

The dataset is downloaded via KaggleHub. On first run you may be prompted for credentials.  
Set them as environment variables:

```powershell
$env:KAGGLE_USERNAME = "your_username"
$env:KAGGLE_KEY      = "your_api_key"
```

Or place `kaggle.json` in `C:\Users\<you>\.kaggle\kaggle.json`.

Get your API key at: https://www.kaggle.com/settings → Account → API

---

## 🤖 AI Model Details

| Component      | Details |
|----------------|---------|
| Algorithms     | Random Forest (200 trees) + XGBoost (300 rounds) |
| Ensemble       | Soft-voting (probability averaging) |
| Dataset        | PhiUSIIL — phishing + legitimate URLs |
| Feature count  | 40+ URL-based statistical features |
| Preprocessing  | StandardScaler normalization |

### Features Extracted
- **Length-based**: URL length, domain length, path length, query length
- **Count-based**: dots, hyphens, slashes, `@`, `?`, `&`, `=`, `%` occurrences
- **Entropy**: Shannon entropy of URL, hostname, path
- **Binary flags**: Is IP address, has HTTPS, has port, is shortened URL, suspicious TLD, brand keyword
- **Structural**: Subdomain depth, number of path tokens, parameter count

---

## 🌐 API Reference

### `POST /api/predict`
```json
{ "url": "https://example.com" }
```
Response:
```json
{
  "success": true,
  "url": "https://example.com",
  "prediction": 0,
  "label": "Legitimate",
  "confidence": 97.3,
  "top_features": [...]
}
```

### `POST /api/batch`
```json
{ "urls": ["https://url1.com", "http://phish.tk/login"] }
```

### `GET /api/status`
Returns whether the model is loaded and ready.

---

## ⚠️ Disclaimer

This tool is built for **educational and research purposes**. It is not a substitute for a comprehensive security solution. Always exercise caution when clicking on unknown links.
