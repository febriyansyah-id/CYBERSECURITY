"""DDoS attack IR playbook."""

from .ir_playbooks import Playbook, PlaybookStep


def get_ddos_playbook():
    steps = [
        PlaybookStep('DDS-01', 'Detection', 'Validate DDoS alert', 'Confirm volumetric or application-layer DDoS', 'tier1', ['NDR']),
        PlaybookStep('DDS-02', 'Detection', 'Identify target', 'Identify specific target IPs, domains, or services', 'tier1'),
        PlaybookStep('DDS-03', 'Detection', 'Characterize attack', 'Identify attack type (SYN flood, HTTP flood, DNS amplification)', 'tier2'),
        PlaybookStep('DDS-04', 'Detection', 'Measure impact', 'Determine bandwidth, packet rate, and impact to legitimate traffic', 'tier2'),
        PlaybookStep('DDS-05', 'Mitigation', 'Enable scrubbing', 'Route traffic through DDoS scrubbing center', 'tier3', ['DDOS_PROTECTION']),
        PlaybookStep('DDS-06', 'Mitigation', 'Rate limiting', 'Implement rate limiting at load balancer/WAF', 'tier2', ['WAF']),
        PlaybookStep('DDS-07', 'Mitigation', 'Blackhole traffic', 'Apply RTBH (Remotely Triggered Black Hole) if severe', 'tier3', ['BGP']),
        PlaybookStep('DDS-08', 'Mitigation', 'WAF rules', 'Deploy WAF rules for application-layer attacks', 'tier2', ['WAF']),
        PlaybookStep('DDS-09', 'Mitigation', 'Geo-blocking', 'Block traffic from source countries if appropriate', 'tier2'),
        PlaybookStep('DDS-10', 'Mitigation', 'Scale resources', 'Scale up compute/bandwidth resources if needed', 'tier3', ['CLOUD']),
        PlaybookStep('DDS-11', 'Coordination', 'ISP notification', 'Contact ISP for upstream filtering and null routes', 'tier3'),
        PlaybookStep('DDS-12', 'Coordination', 'Internal communication', 'Communicate incident status to stakeholders', 'leadership'),
        PlaybookStep('DDS-13', 'Coordination', 'Customer communication', 'If customer-facing service, prepare status updates', 'leadership'),
        PlaybookStep('DDS-14', 'Analysis', 'Post-attack analysis', 'Analyze attack patterns for future prevention', 'tier3'),
        PlaybookStep('DDS-15', 'Hardening', 'Improve defenses', 'Implement preventive measures based on findings', 'tier3'),
    ]
    return Playbook('IR-DDS-001', 'DDoS Attack Response', 'DDoS', 'High', steps,
                    references=['OWASP DoS', 'NIST SP 800-61'])
