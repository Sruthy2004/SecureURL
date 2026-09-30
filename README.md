# 🛡️ SecureURL — URL Risk Analyzer

A student-built Flask web application that performs a rule-based security analysis of URLs and presents potential risk indicators.

## 🌐 Live Demo

👉 https://secureurl-1.onrender.com/

No installation is required to use the live application.

## ✨ Features

- URL security analysis
- HTTPS detection
- URL length analysis
- IP-address URL detection
- Suspicious keyword detection
- Multiple-subdomain detection
- `@` symbol detection
- URL-shortener detection
- Risk score from 0–100
- LOW / MEDIUM / HIGH risk classification
- Security findings and explanations
- Responsive cybersecurity-themed interface

## 🛠️ Technology Stack

- Python
- Flask
- HTML5
- CSS3
- Gunicorn
- Render

## 🔒 How It Works

SecureURL analyzes the structure of a submitted URL using predefined security heuristics.

The analyzer **does not open, visit, or execute the submitted website**. It only examines the URL string and its parsed components.

## ⚠️ Important Limitation

SecureURL is a **rule-based educational security analyzer**.

A HIGH or LOW score does not prove that a website is malicious or safe. The analyzer does not perform real-time threat-intelligence lookups, malware scanning, or website-content inspection.

URL shortening services and suspicious keywords can produce warnings even when a URL may be legitimate.

## 📂 Project Structure

```text
SecureURL/
├── app.py
├── analyzer.py
├── requirements.txt
├── README.md
├── .gitignore
├── templates/
│   └── index.html
└── static/
    └── style.css