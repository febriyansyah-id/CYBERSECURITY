# Phishing Detector — ML-Based URL Classification

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Febriyansyah** — IT Cybersecurity & Infrastructure Leader (15+ yrs, Banking) | MTI Candidate

---

## Problem Statement

Phishing URLs bypass traditional blocklists through rapid domain generation and URL obfuscation. ML-based URL classifiers detect malicious intent from structural features alone — without requiring page content download or DNS resolution.

## Methodology

### Architecture

```
URL Input → Feature Extraction (10 features) → RandomForest Classifier → Phishing / Legitimate
```

### Feature Engineering

| Feature | Description |
|---|---|
| `url_length` | Total character length of the URL |
| `num_dots` | Dot count (deep subdomains = suspicious) |
| `num_hyphens` | Hyphen count (typosquatting pattern) |
| `num_slashes` | Slash count in path |
| `num_at` | `@` presence (credential bypass trick) |
| `has_https` | HTTPS usage (1 = yes) |
| `has_ip` | IP address as hostname (1 = suspicious) |
| `num_subdomains` | Subdomain depth |
| `path_length` | Length of URL path |
| `num_special_chars` | Count of `# ? & % = ;` chars |

### Classifier

- **Algorithm:** RandomForest (100 estimators)
- **Split:** 70% train / 30% test, stratified
- **Training data:** 30 labeled URLs (legitimate + phishing patterns)

## Repository Structure

```
phishing_detector/
├── src/
│   ├── features.py    # URL feature extraction
│   ├── train.py       # Model training script
│   └── classify.py    # Inference CLI (cached model)
├── models/
│   └── phishing_model.joblib   # Pre-trained model
└── tests/
    └── test_features.py
```

## Getting Started

```bash
pip install -r requirements.txt

# Train model (generates models/phishing_model.joblib)
python -m phishing_detector.src.train

# Classify a single URL
python -m phishing_detector.src.classify --url "http://secure-login.xyz/verify"

# Classify from file (one URL per line)
python -m phishing_detector.src.classify --file urls.txt
```

Example output:

```text
URL: http://secure-login.xyz/verify
Prediction: Phishing
Confidence: 87.00%
```

## Run Tests

```bash
python -m pytest tests/ -v
```

## Key Concepts

| Concept | Description |
|---|---|
| Content-agnostic | No page download required — features from URL string only |
| IP-as-hostname | Direct IP URLs strongly associated with phishing |
| Subdomain abuse | Deep subdomains used to fake legitimate brands |
| Model caching | Model loaded once at runtime — efficient batch inference |

## References

- Garera et al. (2007). *A framework for detection and measurement of phishing attacks.* ACM WORM.
- Ma et al. (2009). *Beyond blacklists: learning to detect malicious Web sites from suspicious URLs.* KDD '09.
- MITRE ATT&CK T1566 — Phishing

