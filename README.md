# Security Workspace

Workspace terpadu untuk proyek keamanan siber perbankan, menggabungkan AI/ML, GRC, dan SOC automation.

## 📁 Struktur

```
CYBERSECURITY/
├── ai-soc-for-banking/   # AI-Powered SOC — SIEM-lite, Detection, SOAR, Compliance Dashboard
├── soc-automation/       # SOC Automation — Sigma Rules, IOC Manager, IR Playbooks, SOAR
├── sec-compliance/       # GRC Toolkit — Risk Assessment, Control Frameworks, Policy Templates
└── phishing_detector/    # ML-based URL Phishing Classifier (RandomForest + feature engineering)
```

## 🚀 Quick Start

```bash
# AI-SOC for Banking
cd ai-soc-for-banking
pip install -r requirements.txt
python -m pytest tests/ -v
streamlit run src/dashboard/app.py

# SOC Automation
cd soc-automation
pip install -r requirements.txt
python -m pytest tests/ -v

# SEC Compliance (GRC Toolkit)
cd sec-compliance
pip install -r requirements.txt
python -m pytest tests/ -v

# Phishing Detector
cd phishing_detector
pip install -r requirements.txt
python -m phishing_detector.src.train          # train model
python -m phishing_detector.src.classify --url "http://suspicious-login.xyz/verify"
```

## 🔗 Stack & References

- **NIST SP 800-61 Rev 2** — Incident Handling Guide
- **NIST Cybersecurity Framework 2.0**
- **ISO/IEC 27001:2022**
- **PCI DSS v4.0**
- **POJK No. 11/POJK.03/2022** — Indonesian Banking IT Risk Management
- **MITRE ATT&CK Framework**
