"""Shuffle SOAR workflow templates."""


def get_workflow_templates():
    return [
        {
            'name': 'Email Phishing Triage',
            'description': 'Triage phishing emails by extracting IOCs and checking reputation',
            'steps': [
                {'type': 'email-parse', 'field': 'subject'},
                {'type': 'extract-ioc', 'field': 'body'},
                {'type': 'http-request', 'url': 'https://www.virustotal.com/api/v3/files/{{ioc}}'},
                {'type': 'thehive-create-case', 'title': 'Phishing Alert: {{subject}}'},
            ]
        },
        {
            'name': 'IOC Enrichment',
            'description': 'Enrich indicators from multiple threat intelligence sources',
            'steps': [
                {'type': 'input', 'field': 'ioc'},
                {'type': 'http-request', 'url': 'https://www.virustotal.com/api/v3/search?query={{ioc}}'},
                {'type': 'http-request', 'url': 'https://www.abuseipdb.com/check/{{ioc}}'},
                {'type': 'format-json', 'input': '{{vt_result}}', 'output': 'enriched'},
            ]
        },
        {
            'name': 'Incident Escalation',
            'description': 'Escalate high-severity incidents to Tier 3 and management',
            'steps': [
                {'type': 'condition', 'expression': '{{incident.severity}} >= 3'},
                {'type': 'email-send', 'to': 'tier3@soc.bank', 'subject': 'Escalation: {{incident.title}}'},
                {'type': 'thehive-update-case', 'id': '{{incident.case_id}}', 'status': 'Escalated'},
                {'type': 'slack-send', 'channel': '#soc-critical', 'message': 'Incident {{incident.id}} escalated'},
            ]
        },
    ]


def generate_workflow_json(name, steps):
    return {
        'name': name,
        'is_active': True,
        'triggers': [{'type': 'webhook', 'endpoint': f'/api/workflow/{name.lower().replace(" ", "_")}'}],
        'branches': [
            {'id': f'step_{i}', 'type': s['type'], 'parameters': {k: v for k, v in s.items() if k != 'type'}}
            for i, s in enumerate(steps)
        ],
    }
