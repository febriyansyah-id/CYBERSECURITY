"""Alert correlation engine for SOC."""

from datetime import datetime, timedelta


class CorrelationRule:
    def __init__(self, id, name, conditions, window_minutes=10, severity='medium'):
        self.id = id
        self.name = name
        self.conditions = conditions
        self.window_minutes = window_minutes
        self.severity = severity

    def matches(self, alerts_window):
        return all(c(alerts_window) for c in self.conditions)


class CorrelationEngine:
    def __init__(self, rules=None):
        self.rules = rules or get_correlation_rules()
        self.alerts = []

    def add_alert(self, alert):
        self.alerts.append(alert)

    def evaluate(self):
        incidents = []
        now = datetime.now()
        for rule in self.rules:
            window_start = now - timedelta(minutes=rule.window_minutes)
            window_alerts = [
                a for a in self.alerts
                if (a.get('timestamp') or now) >= window_start
            ]
            # Use the rule's condition functions to validate the alert window
            if rule.matches(window_alerts):
                incident = {
                    'rule_id': rule.id,
                    'rule_name': rule.name,
                    'severity': rule.severity,
                    'alerts': window_alerts,
                    'timestamp': now.isoformat(),
                }
                incidents.append(incident)
        return incidents


def get_correlation_rules():
    def _failed_login_plus_success(alerts):
        failed = any('failed_login' in a.get('type', '') for a in alerts)
        success = any('successful_login' in a.get('type', '') for a in alerts)
        return failed and success

    def _multiple_failures(alerts):
        failed = [a for a in alerts if 'failed_login' in a.get('type', '')]
        return len(failed) >= 5

    def _malware_plus_c2(alerts):
        has_malware = any('malware' in a.get('type', '') for a in alerts)
        has_c2 = any('c2' in a.get('type', '') or 'beacon' in a.get('type', '') for a in alerts)
        return has_malware and has_c2

    def _phishing_plus_credential(alerts):
        has_phish = any('phish' in a.get('type', '') for a in alerts)
        has_cred = any('credential' in a.get('type', '') or 'login' in a.get('type', '') for a in alerts)
        return has_phish and has_cred

    return [
        CorrelationRule('CR-001', 'Multiple Failed Logins', [lambda a: len([x for x in a if 'failed' in x.get('type','')]) >= 3], 10, 'medium'),
        CorrelationRule('CR-002', 'Account Compromise', [_failed_login_plus_success], 15, 'high'),
        CorrelationRule('CR-003', 'Active C2 Communication', [_malware_plus_c2], 30, 'critical'),
        CorrelationRule('CR-004', 'Credential Theft via Phishing', [_phishing_plus_credential], 60, 'critical'),
        CorrelationRule('CR-005', 'Coordinated Attack', [lambda a: len(set(x.get('source_ip','') for x in a)) >= 3], 5, 'high'),
    ]
