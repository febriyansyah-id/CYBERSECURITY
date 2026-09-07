"""TheHive SOAR integration (simulated)."""

import json


class TheHiveClient:
    def __init__(self, base_url='http://thehive:9000', api_key='simulated-key'):
        self.base_url = base_url
        self.api_key = api_key
        self._cases = {}
        self._alerts = {}
        self._counter = 0

    def create_case(self, title, description='', severity=2, tags=None):
        self._counter += 1
        case = {
            'id': f'case_{self._counter}',
            'title': title,
            'description': description,
            'severity': severity,
            'tags': tags or [],
            'status': 'Open',
            'createdAt': '2026-01-01T00:00:00Z',
        }
        self._cases[case['id']] = case
        return case

    def get_case(self, case_id):
        return self._cases.get(case_id)

    def add_alert(self, title, source='soc-automation', severity=2):
        self._counter += 1
        alert = {
            'id': f'alert_{self._counter}',
            'title': title,
            'source': source,
            'severity': severity,
            'status': 'New',
        }
        self._alerts[alert['id']] = alert
        return alert

    def add_observable(self, case_id, data_type, data):
        case = self._cases.get(case_id)
        if not case:
            return None
        observable = {
            'dataType': data_type,
            'data': data,
            'case_id': case_id,
        }
        if 'observables' not in case:
            case['observables'] = []
        case['observables'].append(observable)
        return observable

    def list_cases(self):
        return list(self._cases.values())
