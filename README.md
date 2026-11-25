#  PhishGuard AI — Phishing URL Detector

A professional, full-stack phishing URL detection web app powered by a **Random Forest + XGBoost ensemble** trained on the included `Dataset.csv`.

---

## Project Structure

```
phishing-detector/
├── app.py                  ← Flask web server (API + serve UI)
├── Dataset.csv             ← Local training dataset
├── train_model.py          ← Preprocessing and model training
├── feature_extractor.py    ← Extracts the 25 model features from a URL
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

## Quick Start (Windows)

### Option A — Double-click launcher
```
Double-click  run.bat
```
It will automatically:
1. Install all Python dependencies
2. Train the model from `Dataset.csv` if no model is present
3. Open the app in your browser at `http://localhost:5000`

### Option B — Manual steps

```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Train the model from the included Dataset.csv
python train_model.py

# 3. Start the web server
python app.py

# 4. Open browser
start http://localhost:5000
```

---

## AI Model Details

| Component      | Details |
|----------------|---------|
| Algorithms     | Random Forest (200 trees) + XGBoost (300 rounds) |
| Ensemble       | Soft-voting (probability averaging) |
| Dataset        | Local `Dataset.csv` — 247,950 URLs |
| Feature count  | 25 selected URL-based statistical features |
| Preprocessing  | StandardScaler normalization |

The model uses the following selected features:

```text
url_length
average_subdomain_length
entropy_of_url
entropy_of_domain
domain_length
number_of_subdomains
number_of_special_char_in_url
number_of_digits_in_domain
number_of_dots_in_domain
number_of_digits_in_url
number_of_slash_in_url
number_of_dots_in_url
path_length
number_of_hyphens_in_domain
number_of_hyphens_in_url
having_digits_in_domain
number_of_equal_in_url
number_of_digits_in_subdomain
having_repeated_digits_in_domain
having_digits_in_subdomain
number_of_questionmark_in_url
number_of_special_characters_in_domain
number_of_underline_in_url
having_query
having_repeated_digits_in_url
```

---

## API Reference

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

## Disclaimer

This tool is built for **educational and research purposes**. It is not a substitute for a comprehensive security solution. Always exercise caution when clicking on unknown links.
