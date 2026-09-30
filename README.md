# SecureURL — URL Risk Analyzer

SecureURL is a student-built Flask web application that performs a rule-based heuristic analysis of a URL and presents potentially suspicious indicators.

## Features
- HTTPS usage check
- URL length check
- IP-address-based URL detection
- Suspicious keyword detection
- Multiple-subdomain check
- `@` symbol detection
- Common URL-shortener detection
- 0–100 heuristic risk score
- LOW / MEDIUM / HIGH classification
- Responsive web interface

## Tech Stack
Python · Flask · HTML · CSS

## How it works
The application parses the submitted URL locally and evaluates several observable URL characteristics. Selected indicators contribute to a heuristic score, which is mapped to LOW, MEDIUM, or HIGH risk.

## Run locally
```bash
pip install -r requirements.txt
python app.py
```
Then open `http://127.0.0.1:5000`.

## Limitations
SecureURL is an educational rule-based project. It does not contact threat-intelligence databases, visit the submitted website, or prove that a URL is safe or malicious. A production security product would require stronger validation, reputation data, robust URL parsing, and additional security controls.
