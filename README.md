# 🔍 Social Engineering Risk Analyzer

A rule-based cybersecurity tool that analyzes social media profiles and scores them for social engineering indicators such as impersonation, urgency language, brand spoofing, and suspicious domains.

---

## 📌 What It Does

Social engineering attacks often follow predictable patterns — fake "official" accounts, urgent language, brand impersonation, and newly registered domains. This tool detects those patterns and generates a risk score to help identify potentially malicious profiles before engaging with them.

---

## 🚀 Features

- **Bio Analysis** — Detects impersonation, urgency, and brand-related keywords
- **Username Analysis** — Flags suspicious patterns like `paypal_support99`
- **Domain Analysis** — Performs WHOIS lookups to check domain age and suspicious TLDs (`.xyz`, `.online`, `.top`)
- **Account Age Analysis** — Flags newly created accounts
- **Risk Scoring Engine** — Generates a score (0–155), risk level (LOW / MEDIUM / HIGH), and confidence rating
- **JSON Output** — Machine-readable output via `--json` flag for integration with other tools

---

## 🛠️ Installation

**Clone the repository:**
```bash
git clone https://github.com/rach-db/social-engineering-risk-analyzer.git
cd social-engineering-risk-analyzer
```

**Install dependencies:**
```bash
pip install python-whois
```

---

## ▶️ Usage

**Run the CLI tool:**
```bash
python main.py
```

**Run with JSON output:**
```bash
python main.py --json
```

**Example session:**
```
===== SOCIAL ENGINEERING RISK ANALYZER =====
Enter username: amazon_support99
Enter bio/description: Official Amazon support. Act now to claim your refund!
Enter external link: secure-amazon-verify.xyz
Enter account creation date (YYYY-MM-DD): 2026-01-28

===== SOCIAL ENGINEERING RISK REPORT =====
Username:        amazon_support99
Risk Score:      95 / 155
Risk Percentage: 61.29%
Risk Level:      HIGH
Confidence:      HIGH
Account Age:     33 days
Domain Age:      Unknown

Triggered Indicators:
  - Impersonation language detected: official, support
  - Urgency language detected: act now, claim now
  - Brand impersonation detected: amazon
  - Impersonation + urgency combination
  - Brand + impersonation keywords in username
  - Suspicious digit pattern in username (e.g. support2024)
  - Suspicious domain keywords: secure, verify
```

## 📊 How Scoring Works

The tool uses a **weighted additive scoring system** — each detected red flag adds points to a running total:

| Signal | Points |
|---|---|
| Impersonation words in bio | up to 25 |
| Urgency words in bio | up to 15 |
| Brand + impersonation combo | +15 |
| Impersonation + urgency combo | +10 |
| Brand + impersonation in username | +15 |
| Suspicious digit pattern in username | +10 |
| Suspicious domain keywords | +10 |
| Suspicious TLD (.xyz, .online, etc.) | +10 |
| Very new domain (< 30 days) | +25 |
| New domain (< 6 months) | +15 |
| Very new account (< 7 days) | +20 |
| New account (< 30 days) | +10 |
| Old account + new domain mismatch | +20 |

**Risk Levels:**
- 🟢 **LOW** → Score 0–25
- 🟡 **MEDIUM** → Score 26–60
- 🔴 **HIGH** → Score 61+

---

## 📁 Project Structure

```
social-engineering-risk-analyzer/
│
├── main.py                  # Core Python CLI tool
└── README.md
```

---

## 🔮 Future Improvements

- [ ] Connect UI to Python backend via Flask/FastAPI for live WHOIS lookups
- [ ] Add unit tests with labeled dataset of real scam accounts
- [ ] Machine learning model trained on confirmed phishing profiles
- [ ] Browser extension for real-time profile scanning

---

## 🧰 Tech Stack

- **Python 3** — Core logic
- **python-whois** — Domain age lookup
- **argparse** — CLI argument handling

---

## ⚠️ Disclaimer

This tool is built for **educational and defensive security purposes only**. It is intended to help users identify potentially suspicious profiles, not to target or harass individuals.

---

## 👤 Author

**Rachel** — [github.com/rach-db](https://github.com/rach-db)
