"""IOC (Indicator of Compromise) management."""

from datetime import datetime


class IOC:
    def __init__(self, value, ioc_type, source='internal', confidence='medium', first_seen=None, tags=None):
        self.value = value
        self.type = ioc_type
        self.source = source
        self.confidence = confidence
        self.first_seen = first_seen or datetime.now()
        self.tags = tags or []

    def to_dict(self):
        return {
            'value': self.value,
            'type': self.type,
            'source': self.source,
            'confidence': self.confidence,
            'first_seen': str(self.first_seen),
            'tags': self.tags,
        }


class IOCManager:
    def __init__(self):
        self._iocs = {}

    def add_ioc(self, ioc):
        self._iocs[ioc.value] = ioc

    def search_ioc(self, value):
        return self._iocs.get(value)

    def get_iocs_by_type(self, ioc_type):
        return [i for i in self._iocs.values() if i.type == ioc_type]

    def list_all(self):
        return list(self._iocs.values())

    def remove_ioc(self, value):
        return self._iocs.pop(value, None)

    def enrich(self, ioc):
        return {
            'value': ioc.value,
            'type': ioc.type,
            'geolocation': 'US' if ioc.type == 'ip' else 'N/A',
            'reputation_score': 85 if ioc.confidence == 'high' else 45,
            'related_malware': ['generic_downloader'],
        }


def get_sample_iocs():
    manager = IOCManager()
    samples = [
        IOC('185.220.101.42', 'ip', 'alienvault', 'high', tags=['c2', 'malware']),
        IOC('5.255.88.100', 'ip', 'abuseipdb', 'medium', tags=['scanning']),
        IOC('eicar-test-file-malware.exe', 'hash', 'internal', 'high', tags=['malware']),
        IOC('aad990f3e9cfe69bc6f08ec2e9a1c0e8', 'hash', 'virustotal', 'high', tags=['ransomware']),
        IOC('malicious-login.example.com', 'domain', 'internal', 'medium', tags=['phishing']),
        IOC('evil-downloader.biz', 'domain', 'threatfox', 'high', tags=['malware_download']),
        IOC('http://phishing-login.example.com/verify', 'url', 'phishing', 'high', tags=['phishing', 'credential']),
        IOC('http://malware-payload.example.com/sample.exe', 'url', 'sandbox', 'medium', tags=['malware']),
        IOC('45.33.32.156', 'ip', 'abuseipdb', 'low', tags=['scanner']),
        IOC('8.8.8.8', 'ip', 'external', 'low', tags=['dns']),
    ]
    for s in samples:
        manager.add_ioc(s)
    return manager
