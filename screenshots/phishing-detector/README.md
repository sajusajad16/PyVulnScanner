# 🛡 PhishGuard AI

> **AI-Powered Phishing Detection Tool** — Analyse URLs, emails, and web pages in real time using machine learning and advanced heuristics.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.3+-black?style=flat-square&logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3+-orange?style=flat-square&logo=scikit-learn)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## 📖 Project Overview

PhishGuard AI is a modular, production-structured cybersecurity tool that detects phishing attacks across three attack surfaces:

| Surface    | What it analyses |
|------------|-----------------|
| **URL**    | Domain structure, typosquatting, TLD, entropy, keywords, ML prediction |
| **Email**  | Header spoofing, urgency language, embedded URLs, sender reputation |
| **HTML**   | Forms, password fields, hidden inputs, suspicious JS, external submissions |

The tool blends a **trained Random Forest ML model** (24 features) with a rule-based scoring engine to produce a 0–100 risk score with a human-readable verdict:

| Score     | Verdict     |
|-----------|-------------|
| 0 – 29    | ✅ Safe      |
| 30 – 59   | ⚠️ Suspicious |
| 60 – 100  | 🚨 Phishing  |

---

## ✨ Features

### Core Detection
- 🔗 **URL Analysis** — length, HTTPS, special chars, IP-as-domain, suspicious TLDs
- 🔤 **Keyword Detection** — 30+ suspicious terms across URL, email, and HTML
- 🔍 **Typosquatting Detection** — fuzzy similarity check against 35 trusted brands
- 📧 **Email Header Analysis** — From/Reply-To mismatch, SPF/DKIM absence
- 🌐 **HTML Analysis** — forms, password fields, external actions, obfuscated JS
- 🤖 **ML Model** — Random Forest trained on real phishing/legitimate URL dataset

### Backend & API
- ⚡ Flask REST API with 7 endpoints
- 🔒 Per-IP rate limiting (30 req / 60 sec)
- 🗄️ SQLite scan history logging
- 📊 JSON and HTML report generation
- 📋 Full API documentation at `/api/docs`

### Frontend
- 🖥️ Dark cybersecurity-themed single-page UI
- 📊 Animated risk score ring with breakdown bars
- 🗂️ Feature detail table
- 📜 Scan history table

### CLI
- 🖥️ Terminal scanning with coloured output
- 🗃️ Batch URL scanning
- 📄 Report generation from CLI
- 🕐 Scan history viewer

---

## 🗂 Project Structure

```
phishing-detector/
├── app.py                  ← Flask backend + API endpoints
├── model.py                ← ML training & prediction
├── cli.py                  ← Command-line interface
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
│
├── utils/
│   ├── feature_extractor.py  ← URL / email / HTML feature extraction
│   ├── scanner.py            ← High-level scan engine (ML + rules)
│   └── reporter.py           ← JSON & HTML report generation
│
├── dataset/
│   └── data.csv             ← Training data (phishing + legitimate URLs)
│
├── models/                  ← Saved model files (auto-created)
│
├── templates/
│   └── index.html           ← Frontend UI
│
├── static/
│   ├── css/style.css
│   └── js/app.js
│
├── logs/                    ← App logs + SQLite scan history
└── reports/                 ← Generated scan reports
```

---

## 🚀 Installation

### Prerequisites
- Python 3.10+
- pip

### 1 — Clone & Setup

```bash
git clone https://github.com/yourname/phishguard-ai.git
cd phishguard-ai
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2 — Train the ML Model

```bash
python cli.py train
```

### 3 — Start the Web Server

```bash
python app.py
```

Open **http://localhost:5000** in your browser.

---

## 🐳 Docker

```bash
# Build & run
docker compose up --build

# Or manually
docker build -t phishguard .
docker run -p 5000:5000 phishguard
```

---

## 💻 CLI Usage

```bash
# Scan a URL
python cli.py url "https://suspicious-site.example.com"

# Scan multiple URLs and generate an HTML report
python cli.py url "http://g00gle.tk" "http://paypa1.com" --report html

# Scan an email file
python cli.py email samples/phishing_email.txt

# Scan an HTML file
python cli.py html  samples/fake_login.html --json

# Re-train the ML model
python cli.py train

# View scan history
python cli.py history --limit 10
```

---

## 🌐 REST API

Base URL: `http://localhost:5000/api`

Full docs: `GET /api/docs`

### Scan a URL
```bash
curl -X POST http://localhost:5000/api/scan-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com"}'
```

**Response:**
```json
{
  "type":        "url",
  "target":      "https://suspicious-site.com",
  "risk_score":  78.5,
  "verdict":     "Phishing",
  "level":       "high",
  "color":       "red",
  "ml_score":    82.0,
  "rule_score":  72,
  "issues": [
    "🔴 Domain looks like a fake 'google' (typosquatting)",
    "⚠️  Suspicious top-level domain detected"
  ],
  "features":    { ... },
  "scanned_at":  "2025-01-01T12:00:00"
}
```

### Scan Email
```bash
curl -X POST http://localhost:5000/api/scan-email \
  -H "Content-Type: application/json" \
  -d '{"email": "From: noreply@paypa1.tk\n\nDear Customer..."}'
```

### Scan HTML
```bash
curl -X POST http://localhost:5000/api/scan-html \
  -H "Content-Type: application/json" \
  -d '{"html": "<form action=\"http://evil.com\">..."}'
```

### View History
```bash
curl http://localhost:5000/api/history?limit=10
```

---

## 🤖 ML Model Details

| Property       | Value |
|----------------|-------|
| Algorithm      | Random Forest (200 estimators) |
| Features       | 24 URL-derived features |
| Training split | 80% train / 20% test |
| Dataset size   | 80 samples (expandable) |
| Feature scaling| StandardScaler |

**Top Features:**
- `is_typosquatting` — high importance
- `suspicious_tld` — high importance
- `suspicious_keyword_count`
- `domain_entropy`
- `uses_https`

**Improve accuracy:** Add more samples to `dataset/data.csv` and re-run `python cli.py train`.

---

## 📸 Screenshots

> _Add screenshots here after running the tool._

- `docs/screenshot-ui.png` — Main scanner UI
- `docs/screenshot-result.png` — Phishing result with risk score
- `docs/screenshot-cli.png` — CLI output

---

## 🔮 Future Improvements

- [ ] Real WHOIS domain age lookup
- [ ] VirusTotal API integration
- [ ] Browser extension (Chrome/Firefox)
- [ ] BERT/transformer-based email classifier
- [ ] Bulk CSV URL scanning
- [ ] WebSocket live scanning status
- [ ] User authentication & scan dashboard
- [ ] Threat intelligence feed integration
- [ ] PDF report generation

---

## ⚠️ Disclaimer

PhishGuard AI is a **security research and educational tool**. It is designed to help users identify potential phishing threats but should not be the sole basis for security decisions. Always use multiple layers of protection.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
