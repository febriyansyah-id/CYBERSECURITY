"""Incident Response Playbook engine and definitions."""


class PlaybookStep:
    def __init__(self, id, phase, action, description, assignee='analyst', tools=None, estimated_time='30m'):
        self.id = id
        self.phase = phase
        self.action = action
        self.description = description
        self.assignee = assignee
        self.tools = tools or []
        self.estimated_time = estimated_time

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()}


class Playbook:
    def __init__(self, id, name, incident_type, severity, steps, references=None):
        self.id = id
        self.name = name
        self.incident_type = incident_type
        self.severity = severity
        self.steps = steps
        self.references = references or []

    def total_estimated_time(self):
        """Return total estimated time in minutes (30 min per step by default)."""
        total = 0
        for step in self.steps:
            try:
                # Parse "30m", "1h", "2h" style strings
                raw = str(step.estimated_time)
                if raw.endswith('h'):
                    total += int(raw[:-1]) * 60
                elif raw.endswith('m'):
                    total += int(raw[:-1])
                else:
                    total += int(raw)
            except (ValueError, AttributeError):
                total += 30  # fallback: 30 min per step
        return total

    def get_steps_by_phase(self, phase):
        return [s for s in self.steps if s.phase == phase]


def get_all_playbooks():
    from .malware import get_malware_playbook
    from .phishing import get_phishing_playbook
    from .ransomware import get_ransomware_playbook
    from .data_breach import get_data_breach_playbook
    from .ddos import get_ddos_playbook
    from .insider import get_insider_threat_playbook
    return [
        get_malware_playbook(),
        get_phishing_playbook(),
        get_ransomware_playbook(),
        get_data_breach_playbook(),
        get_ddos_playbook(),
        get_insider_threat_playbook(),
    ]


def get_playbook_by_type(incident_type):
    for pb in get_all_playbooks():
        if pb.incident_type == incident_type:
            return pb
    return None


def execute_playbook(playbook, context=None):
    context = context or {}
    results = []
    for step in playbook.steps:
        result = {
            'step_id': step.id,
            'action': step.action,
            'status': 'completed',
            'description': step.description,
        }
        results.append(result)
    return results
