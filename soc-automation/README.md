# SOC-Automation — Incident Response & SOAR Toolkit

[![CI](https://github.com/febriyansyahresearch-lab/soc-automation/actions/workflows/test.yml/badge.svg)](https://github.com/febriyansyahresearch-lab/soc-automation/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-40%2B%20passed-brightgreen)](tests/)

**Febriyansyah** — IT Cybersecurity & Infrastructure Leader (15+ yrs, Banking) | MTI Candidate

## Problem Statement

Security Operations Centers (SOCs) in banking face high alert volumes, complex incident response workflows, and pressure to meet SLA targets. Manual processes lead to inconsistent responses and delayed containment. This toolkit automates IR playbooks, SOAR workflows, detection rules, and reporting.

## Methodology

### Architecture

1. **IR Playbooks** — Structured, multi-phase incident response procedures for 6 incident types (malware, phishing, ransomware, data breach, DDoS, insider threat), aligned with NIST SP 800-61.
2. **SOAR Workflows** — Automated orchestration with conditional branching, TheHive case management, Cortex analyzer integration, and Shuffle workflow templates.
3. **Detection Rules** — Sigma-format detection rules, alert correlation engine with time-based windows, and IOC management with threat intelligence enrichment.
4. **Incident Reporting** — Automated report generation across executive, technical, and lessons-learned formats with SOC metrics and benchmarking.

### Incident Types Covered

| Incident | Playbook Steps | SOAR Workflows | Detection Rules |
|---|---|---|---|
| Malware | 20+ | Malware Analysis | Suspicious PowerShell, C2 |
| Phishing | 15+ | Phishing Triage | Email analysis |
| Ransomware | 20+ | Indicator Enrichment | Ransomware indicators |
| Data Breach | 20+ | — | Credential dumping |
| DDoS | 15+ | — | Port scanning, C2 |
| Insider Threat | 15+ | — | Privilege escalation |

## Key Concepts

| Concept | Description |
|---|---|
| NIST SP 800-61 | Computer Security Incident Handling Guide phases |
| Sigma Rules | Generic signature format for log events |
| Alert Correlation | Time-based multi-event correlation |
| MTTR | Mean Time to Respond (target: 45 min) |
| SOAR | Security Orchestration, Automation, and Response |

## References

- NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide
- MITRE ATT&CK — https://attack.mitre.org/
- Sigma HQ — https://github.com/SigmaHQ/sigma
- TheHive Project — https://thehive-project.org/
- Shuffle SOAR — https://shuffler.io/
- FIRST CVSS — https://www.first.org/cvss/
