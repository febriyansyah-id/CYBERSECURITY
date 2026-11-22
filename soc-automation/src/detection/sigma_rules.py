"""Sigma rule management and examples."""


class SigmaRule:
    def __init__(self, id, title, description, logsource, detection, level='medium', tags=None):
        self.id = id
        self.title = title
        self.description = description
        self.logsource = logsource
        self.detection = detection
        self.level = level
        self.tags = tags or []

    def to_dict(self):
        return {
            'title': self.title,
            'description': self.description,
            'logsource': self.logsource,
            'detection': self.detection,
            'level': self.level,
            'tags': self.tags,
        }


def get_sigma_rules():
    return [
        SigmaRule('SIG-001', 'Suspicious PowerShell Execution',
                  'Detects PowerShell execution with obfuscation or encoded commands',
                  {'category': 'process_creation', 'product': 'windows'},
                  {'selection': {'Image': '*powershell.exe', 'CommandLine': '*-EncodedCommand*'}, 'condition': 'selection'},
                  'high', ['attack.execution', 'attack.t1059.001']),
        SigmaRule('SIG-002', 'Ransomware File Indicators',
                  'Detects common ransomware file extensions and ransom notes',
                  {'category': 'file_event', 'product': 'windows'},
                  {'selection': {'TargetFilename': '*.lockbit*'}, 'condition': 'selection'},
                  'critical', ['attack.impact', 'attack.t1486']),
        SigmaRule('SIG-003', 'Credential Dumping via LSASS',
                  'Detects attempts to dump LSASS process memory',
                  {'category': 'process_access', 'product': 'windows'},
                  {'selection': {'TargetImage': '*lsass.exe', 'GrantedAccess': '0x1FFFFF'}, 'condition': 'selection'},
                  'critical', ['attack.credential_access', 'attack.t1003.001']),
        SigmaRule('SIG-004', 'C2 Beaconing Detection',
                  'Detects periodic beaconing to external C2 servers',
                  {'category': 'network_connection', 'product': 'windows'},
                  {'selection': {'DestinationPort': [80, 443, 8080], 'Initiated': 'true'}, 'condition': 'selection | count() by DestinationIp > 50'},
                  'high', ['attack.command_and_control', 'attack.t1071']),
        SigmaRule('SIG-005', 'Port Scanning Activity',
                  'Detects port scanning behavior from internal hosts',
                  {'category': 'network_connection', 'product': 'windows'},
                  {'selection': {'DestinationPort': '*', 'Initiated': 'true'}, 'condition': 'selection | count() by SourceIp > 100 | tail 10'},
                  'medium', ['attack.discovery', 'attack.t1046']),
        SigmaRule('SIG-006', 'DNS Tunneling Detection',
                  'Detects potential DNS tunneling via excessive TXT queries',
                  {'category': 'dns_query', 'product': 'windows'},
                  {'selection': {'QueryType': 'TXT', 'QueryName': '*.long-dns-name.*'}, 'condition': 'selection'},
                  'high', ['attack.exfiltration', 'attack.t1048']),
        SigmaRule('SIG-007', 'Linux Privilege Escalation',
                  'Detects common Linux privilege escalation techniques',
                  {'category': 'process_creation', 'product': 'linux'},
                  {'selection': {'CommandLine': '*sudo*'}, 'condition': 'selection'},
                  'high', ['attack.privilege_escalation', 'attack.t1548']),
        SigmaRule('SIG-008', 'Persistent Backdoor Detection',
                  'Detects persistence mechanisms via cron or systemd',
                  {'category': 'file_event', 'product': 'linux'},
                  {'selection': {'TargetFilename': '/etc/systemd/system/*.service'}, 'condition': 'selection'},
                  'high', ['attack.persistence', 'attack.t1543']),
    ]


def validate_sigma_rule(rule):
    required = ['title', 'description', 'logsource', 'detection', 'level']
    return all(hasattr(rule, r) and getattr(rule, r) for r in required)


def export_to_yaml(rule):
    """Export a SigmaRule to YAML string.

    Uses PyYAML when available for correct nested-dict / list serialization;
    falls back to a safe manual renderer otherwise.
    """
    try:
        import yaml  # optional dependency
        return yaml.dump(rule.to_dict(), default_flow_style=False, sort_keys=False).rstrip()
    except ImportError:
        pass

    # Manual fallback — handles one level of nesting safely
    def _val(v):
        if isinstance(v, (list, dict)):
            return repr(v)
        return str(v)

    lines = [f"title: {rule.title}", f"description: {rule.description}"]
    lines.append("logsource:")
    for k, v in rule.logsource.items():
        lines.append(f"  {k}: {_val(v)}")
    lines.append("detection:")
    for k, v in rule.detection.items():
        if isinstance(v, dict):
            lines.append(f"  {k}:")
            for dk, dv in v.items():
                lines.append(f"    {dk}: {_val(dv)}")
        else:
            lines.append(f"  {k}: {_val(v)}")
    lines.append(f"level: {rule.level}")
    if rule.tags:
        lines.append("tags:")
        for t in rule.tags:
            lines.append(f"  - {t}")
    return '\n'.join(lines)
