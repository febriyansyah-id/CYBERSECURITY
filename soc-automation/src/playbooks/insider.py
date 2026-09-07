"""Insider threat IR playbook."""

from .ir_playbooks import Playbook, PlaybookStep


def get_insider_threat_playbook():
    steps = [
        PlaybookStep('INS-01', 'Detection', 'Receive alert', 'Receive insider threat alert from UBA/SIEM/HR', 'tier2', ['UBA']),
        PlaybookStep('INS-02', 'Detection', 'Initial assessment', 'Assess severity and credibility of the alert', 'tier2'),
        PlaybookStep('INS-03', 'Investigation', 'Gather evidence', 'Collect logs, access records, and communications', 'tier2'),
        PlaybookStep('INS-04', 'Investigation', 'Interview witnesses', 'Interview relevant supervisors and coworkers', 'tier3'),
        PlaybookStep('INS-05', 'Investigation', 'Document findings', 'Document all evidence with chain of custody', 'tier2'),
        PlaybookStep('INS-06', 'Evidence', 'Preserve data', 'Preserve user data, emails, and file access logs', 'tier2'),
        PlaybookStep('INS-07', 'Evidence', 'Forensic imaging', 'Create forensic image of user workstation', 'tier3'),
        PlaybookStep('INS-08', 'Evidence', 'Network captures', 'Preserve network traffic captures if available', 'tier2'),
        PlaybookStep('INS-09', 'HR', 'HR consultation', 'Consult with HR on employment policies and procedures', 'leadership'),
        PlaybookStep('INS-10', 'HR', 'Legal consultation', 'Consult legal on privacy and employment law', 'leadership'),
        PlaybookStep('INS-11', 'HR', 'Determine action', 'Determine administrative action with HR and legal', 'leadership'),
        PlaybookStep('INS-12', 'Containment', 'Revoke access', 'Revoke system and physical access immediately', 'tier2', ['IAM']),
        PlaybookStep('INS-13', 'Containment', 'Disable credentials', 'Disable all user credentials and active sessions', 'tier2', ['IAM']),
        PlaybookStep('INS-14', 'Containment', 'Escort from premises', 'If required, escort employee from premises', 'security'),
        PlaybookStep('INS-15', 'Review', 'Assess damage', 'Determine data exfiltration or damage extent', 'tier3'),
    ]
    return Playbook('IR-INS-001', 'Insider Threat Response', 'Insider Threat', 'High', steps,
                    references=['CERT Insider Threat', 'NIST SP 800-61'])
