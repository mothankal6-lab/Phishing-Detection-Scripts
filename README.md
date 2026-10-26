# Phishing-Detection-Scripts
Defensive security tools for identifying phishing threats. Includes URL analysis, email header checks, and heuristic-based detection to help flag malicious links and message

Phishing-Detection-Scripts
Defensive security tools for identifying phishing threats. Includes URL analysis, email header checks, and heuristic-based detection to help flag malicious links and messages.
Overview
Phishing attacks trick people into visiting fake websites or sharing sensitive information through deceptive emails and links. This project is a collection of scripts that help detect common phishing indicators so suspicious content can be flagged before it causes harm.
It is built for learning, research, and defensive security use.
Features
URL analysis: flags suspicious links (e.g. IP addresses in URLs, excessive subdomains, lookalike domains, unusual characters, URL shorteners).
Email header checks: inspects sender details and headers for mismatches, spoofing signs, and failed authentication (SPF, DKIM, DMARC).
Heuristic detection: scores messages using common red flags such as urgent language, credential requests, and mismatched link text.
Getting Started
Requirements
Python 3.8 or higher
Installation
git clone https://github.com/mothankal6-lab/Phishing-Detection-Scripts.git
cd Phishing-Detection-Scripts
pip install -r requirements.txt
Usage
python url_checker.py "http://example.com/login"
python header_checker.py sample_email.eml
Script names above are examples; update them to match the files in this repository.
Project Structure
Phishing-Detection-Scripts/
├── url_checker.py
├── header_checker.py
├── requirements.txt
└── README.md
Disclaimer
These tools are for educational and defensive purposes only. Detection results are indicators, not proof, so always verify suspicious content before taking action. Use only on emails and systems you own or have permission to analyze.
Contributing
Suggestions and improvements are welcome. Open an issue or submit a pull request.