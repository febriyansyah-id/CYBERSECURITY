"""Phishing incident IR playbook."""

from .ir_playbooks import Playbook, PlaybookStep


def get_phishing_playbook():
    steps = [
        PlaybookStep('PHI-01', 'Triage', 'Receive report', 'Log phishing report from user or automated detection', 'tier1'),
        PlaybookStep('PHI-02', 'Triage', 'Initial assessment', 'Assess email headers, URLs, and attachments', 'tier1'),
        PlaybookStep('PHI-03', 'Triage', 'Check threat intel', 'Check URLs/hashes against threat intelligence', 'tier2'),
        PlaybookStep('PHI-04', 'Analysis', 'Analyze headers', 'Review email headers for spoofing indicators', 'tier2'),
        PlaybookStep('PHI-05', 'Analysis', 'Extract URLs', 'Extract and defang all URLs in email', 'tier2'),
        PlaybookStep('PHI-06', 'Analysis', 'Analyze attachments', 'Sandbox analysis of email attachments', 'tier2', ['sandbox']),
        PlaybookStep('PHI-07', 'Analysis', 'Determine scope', 'Check mail logs for other recipients', 'tier2'),
        PlaybookStep('PHI-08', 'Containment', 'Block sender', 'Block sender domain/address at email gateway', 'tier1', ['SEG']),
        PlaybookStep('PHI-09', 'Containment', 'Remove emails', 'Quarantine and remove emails from all inboxes', 'tier1', ['SEG', 'E365']),
        PlaybookStep('PHI-10', 'Containment', 'Block URLs', 'Add malicious URLs to web proxy blocklist', 'tier2', ['proxy']),
        PlaybookStep('PHI-11', 'User', 'Notify user', 'Inform reporting user of findings and next steps', 'tier1'),
        PlaybookStep('PHI-12', 'User', 'Identify victims', 'Identify users who clicked or entered credentials', 'tier2'),
        PlaybookStep('PHI-13', 'User', 'Credential reset', 'Force password reset for affected users', 'tier2', ['IAM']),
        PlaybookStep('PHI-14', 'User', 'Security awareness', 'Provide targeted security awareness coaching', 'tier2'),
        PlaybookStep('PHI-15', 'PostMortem', 'Document', 'Document incident details and response', 'tier3'),
    ]
    return Playbook('IR-PHI-001', 'Phishing Response', 'Phishing', 'High', steps,
                    references=['NIST SP 800-61', 'SANS Phishing'])


def get_phishing_triage_workflow():
    return {
        'name': 'Phishing Triage',
        'steps': [
            {'action': 'extract_iocs', 'params': {'email': '{{email}}'}},
            {'action': 'check_reputation', 'params': {'iocs': '{{iocs}}'}},
            {'action': 'create_case', 'params': {'title': 'Phishing: {{subject}}', 'severity': '{{severity}}'}},
        ]
    }
