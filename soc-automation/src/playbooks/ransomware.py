"""Ransomware incident IR playbook."""

from .ir_playbooks import Playbook, PlaybookStep


def get_ransomware_playbook():
    steps = [
        PlaybookStep('RAN-01', 'Detection', 'Confirm ransomware', 'Verify ransomware alert from EDR or user report', 'tier1'),
        PlaybookStep('RAN-02', 'Detection', 'Isolate immediately', 'Disconnect affected hosts from network', 'tier1', ['EDR']),
        PlaybookStep('RAN-03', 'Detection', 'Preserve evidence', 'Capture memory and disk forensics', 'tier2'),
        PlaybookStep('RAN-04', 'Assessment', 'Identify variant', 'Identify ransomware family from ransom note, extension', 'tier2'),
        PlaybookStep('RAN-05', 'Assessment', 'Check decryption', 'Check if decryption tools exist for variant', 'tier2'),
        PlaybookStep('RAN-06', 'Assessment', 'Determine scope', 'Identify all encrypted systems and shares', 'tier2'),
        PlaybookStep('RAN-07', 'Assessment', 'Assess backup status', 'Check last clean backup availability', 'tier2'),
        PlaybookStep('RAN-08', 'Containment', 'Network segmentation', 'Implement VLAN segmentation to contain spread', 'tier3', ['network']),
        PlaybookStep('RAN-09', 'Containment', 'Block C2', 'Block ransomware C2 domains/IPs at firewall', 'tier2', ['FW']),
        PlaybookStep('RAN-10', 'Containment', 'Disable lateral movement', 'Disable SMB/RDP if used for propagation', 'tier2'),
        PlaybookStep('RAN-11', 'Containment', 'Shield unaffected', 'Deploy detection rules for unaffected segments', 'tier2', ['SIEM']),
        PlaybookStep('RAN-12', 'Eradication', 'Remove malware', 'Clean ransomware artifacts from systems', 'tier2', ['EDR']),
        PlaybookStep('RAN-13', 'Eradication', 'Patch vulnerabilities', 'Patch exploited vulnerabilities', 'tier3', ['VMS']),
        PlaybookStep('RAN-14', 'Eradication', 'Verify clean', 'Run full scans across environment', 'tier1', ['AV']),
        PlaybookStep('RAN-15', 'Recovery', 'Restore from backup', 'Restore encrypted data from clean backups', 'tier2'),
        PlaybookStep('RAN-16', 'Recovery', 'Validate integrity', 'Validate restored data integrity', 'tier2'),
        PlaybookStep('RAN-17', 'Recovery', 'Phased reconnection', 'Reconnect systems in phases with monitoring', 'tier1'),
        PlaybookStep('RAN-18', 'Reporting', 'Executive summary', 'Prepare executive incident summary', 'tier3'),
        PlaybookStep('RAN-19', 'Reporting', 'Regulatory notification', 'Notify relevant authorities if required', 'leadership'),
        PlaybookStep('RAN-20', 'PostMortem', 'Lessons learned', 'Conduct post-incident review', 'tier3'),
    ]
    return Playbook('IR-RAN-001', 'Ransomware Response', 'Ransomware', 'Critical', steps,
                    references=['CISA Ransomware Guide', 'NIST SP 800-61'])
