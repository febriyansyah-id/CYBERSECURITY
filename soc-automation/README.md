# SOC-Automation — Incident Response & SOAR Toolkit

[![CI](https://github.com/febriyansyahresearch-lab/soc-automation/actions/workflows/test.yml/badge.svg)](https://github.com/febriyansyahresearch-lab/soc-automation/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-41%20passed-brightgreen)](tests/)

**Febriyansyah** — IT Cybersecurity & Infrastructure Leader (15+ yrs, Banking) | MTI Candidate

---

## Problem Statement

Security Operations Centers (SOCs) in banking face high alert volumes, complex incident response workflows, and pressure to meet SLA targets. Manual processes lead to inconsistent responses and delayed containment. This toolkit automates IR playbooks, SOAR workflows, detection rules, and reporting.

## Methodology

### Architecture

```
Alert Sources → Correlation Engine (time-windowed) → Incident
                        ↓
              IOC Manager (enrichment)
                        ↓
              SOAR Orchestrator → Playbook Execution → Report
```

1. **IR Playbooks** — Structured, multi-phase incident response for 6 incident types (malware, phishing, ransomware, data breach, DDoS, insider threat), aligned with NIST SP 800-61.
2. **SOAR Workflows** — Automated orchestration with conditional branching, TheHive case management, Cortex analyzer integration, and Shuffle workflow templates.
3. **Detection Rules** — Sigma-format detection rules (MITRE ATT&CK tagged), alert correlation engine with time-based windows, and IOC management with threat intelligence enrichment.
4. **Incident Reporting** — Automated report generation across executive, technical, and lessons-learned formats with SOC metrics and benchmarking.

### Incident Types Covered

| Incident | Playbook Steps | SOAR Workflows | Detection Rules |
|---|---|---|---|
| Malware | 20+ | Malware Analysis | Suspicious PowerShell, C2 (T1059, T1071) |
| Phishing | 15+ | Phishing Triage | Email analysis (T1566) |
| Ransomware | 20+ | Indicator Enrichment | Ransomware indicators (T1486) |
| Data Breach | 20+ | — | Credential dumping / LSASS (T1003) |
| DDoS | 15+ | — | Port scanning, C2 (T1046) |
| Insider Threat | 15+ | — | Privilege escalation (T1548) |

## Repository Structure

```
soc-automation/
├── src/
│   ├── detection/
│   │   ├── sigma_rules.py     # 8 Sigma rules (MITRE ATT&CK tagged)
│   │   ├── correlation.py     # Time-windowed alert correlation engine
│   │   └── ioc.py             # IOC manager (IP, hash, domain, URL)
│   ├── playbooks/
│   │   ├── ir_playbooks.py    # Playbook engine + phase/assignee model
│   │   ├── malware.py         # Malware IR playbook
│   │   ├── phishing.py        # Phishing IR playbook
│   │   ├── ransomware.py      # Ransomware IR playbook
│   │   ├── data_breach.py     # Data breach IR playbook
│   │   ├── ddos.py            # DDoS IR playbook
│   │   └── insider.py         # Insider threat IR playbook
│   ├── soar/
│   │   ├── orchestrator.py    # Workflow engine (phishing triage, malware analysis, IOC enrichment)
│   │   ├── thehive.py         # TheHive case management integration
│   │   ├── cortex.py          # Cortex analyzer integration
│   │   └── shfl.py            # Shuffle SOAR workflow templates
│   └── reporting/
│       ├── incident_report.py # Automated incident report generation
│       └── metrics.py         # SOC metrics: MTTR, alert volume, detection rate
└── tests/
    ├── test_detection.py
    ├── test_playbooks.py
    ├── test_reporting.py
    └── test_soar.py
```

## Getting Started

```bash
# Install dependencies
pip install -r requirements.txt

# Run all tests
python -m pytest tests/ -v
```

Example test output:

```text
41 passed
```

## Quick Demo

```python
from src.detection.ioc import get_sample_iocs
from src.detection.correlation import CorrelationEngine, get_correlation_rules
from src.playbooks.ir_playbooks import get_playbook_by_type, execute_playbook

# IOC lookup
manager = get_sample_iocs()
ioc = manager.search_ioc("185.220.101.42")
print(manager.enrich(ioc))

# Alert correlation
engine = CorrelationEngine()
engine.add_alert({"type": "failed_login", "source_ip": "10.0.0.5"})
engine.add_alert({"type": "failed_login", "source_ip": "10.0.0.5"})
engine.add_alert({"type": "failed_login", "source_ip": "10.0.0.5"})
incidents = engine.evaluate()

# Execute playbook
pb = get_playbook_by_type("phishing")
results = execute_playbook(pb, context={"email": "malicious@evil.com"})
```

## Key Concepts

| Concept | Description |
|---|---|
| NIST SP 800-61 | Incident phases: Preparation → Detection → Containment → Eradication → Recovery → Lessons Learned |
| Sigma Rules | MITRE ATT&CK-tagged generic log signature format |
| Alert Correlation | Time-windowed multi-event correlation (5–60 min windows) |
| MTTR | Mean Time to Respond — target: 45 min |
| IOC Confidence | Low / Medium / High confidence scoring per indicator |

## References

- NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide
- MITRE ATT&CK — https://attack.mitre.org/
- Sigma HQ — https://github.com/SigmaHQ/sigma
- TheHive Project — https://thehive-project.org/
- Shuffle SOAR — https://shuffler.io/
- FIRST CVSS — https://www.first.org/cvss/

