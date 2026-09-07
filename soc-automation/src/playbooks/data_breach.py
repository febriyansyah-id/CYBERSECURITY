"""Data breach incident IR playbook."""

from .ir_playbooks import Playbook, PlaybookStep


def get_data_breach_playbook():
    steps = [
        PlaybookStep('BRC-01', 'Scoping', 'Confirm breach', 'Verify data breach from detection or notification', 'tier2'),
        PlaybookStep('BRC-02', 'Scoping', 'Identify data type', 'Determine type of data exposed (PII, financial, credentials)', 'tier2'),
        PlaybookStep('BRC-03', 'Scoping', 'Determine scope', 'Identify data stores, systems, and users affected', 'tier2'),
        PlaybookStep('BRC-04', 'Scoping', 'Engage legal', 'Notify legal and compliance teams', 'leadership'),
        PlaybookStep('BRC-05', 'Forensics', 'Preserve evidence', 'Forensic image of affected systems', 'tier3'),
        PlaybookStep('BRC-06', 'Forensics', 'Analyze logs', 'Review access logs for exfiltration patterns', 'tier2', ['SIEM']),
        PlaybookStep('BRC-07', 'Forensics', 'Identify access vector', 'Determine how attacker gained access', 'tier3'),
        PlaybookStep('BRC-08', 'Forensics', 'Track exfiltration', 'Identify data exfiltration methods and volume', 'tier3'),
        PlaybookStep('BRC-09', 'Notification', 'Internal escalation', 'Escalate to management and board if required', 'leadership'),
        PlaybookStep('BRC-10', 'Notification', 'Legal counsel', 'Engage legal counsel for regulatory obligations', 'leadership'),
        PlaybookStep('BRC-11', 'Notification', 'Regulatory notification', 'Notify data protection authority per applicable regulations', 'leadership'),
        PlaybookStep('BRC-12', 'Notification', 'Affected users', 'Notify affected individuals if legally required', 'leadership'),
        PlaybookStep('BRC-13', 'Containment', 'Close access vector', 'Patch or disable exploited access path', 'tier3'),
        PlaybookStep('BRC-14', 'Containment', 'Revoke credentials', 'Rotate all potentially compromised credentials', 'tier2', ['IAM']),
        PlaybookStep('BRC-15', 'Containment', 'Secure data stores', 'Implement additional data access controls', 'tier2'),
        PlaybookStep('BRC-16', 'Remediation', 'Security improvements', 'Implement security enhancements to prevent recurrence', 'tier3'),
        PlaybookStep('BRC-17', 'Remediation', 'Monitor for misuse', 'Monitor for misuse of exposed data', 'tier1', ['SIEM']),
        PlaybookStep('BRC-18', 'Regulatory', 'POJK compliance', 'Comply with POJK breach notification requirements', 'leadership'),
        PlaybookStep('BRC-19', 'Regulatory', 'Documentation', 'Complete regulatory breach report documentation', 'tier3'),
        PlaybookStep('BRC-20', 'PostMortem', 'Root cause', 'Conduct root cause analysis and lessons learned', 'tier3'),
    ]
    return Playbook('IR-BRC-001', 'Data Breach Response', 'Data Breach', 'Critical', steps,
                    references=['GDPR', 'POJK No. 11/POJK.03/2022', 'NIST SP 800-61'])
