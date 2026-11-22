"""Tests for detection module."""

from src.detection.sigma_rules import SigmaRule, get_sigma_rules, validate_sigma_rule, export_to_yaml
from src.detection.correlation import CorrelationEngine, get_correlation_rules
from src.detection.ioc import IOC, IOCManager, get_sample_iocs


def test_sigma_rules_count():
    rules = get_sigma_rules()
    assert len(rules) >= 8


def test_sigma_rule_validation():
    for rule in get_sigma_rules():
        assert validate_sigma_rule(rule)


def test_sigma_export_yaml():
    rule = get_sigma_rules()[0]
    yaml = export_to_yaml(rule)
    assert 'title:' in yaml
    assert 'logsource:' in yaml


def test_correlation_rules_exist():
    rules = get_correlation_rules()
    assert len(rules) >= 5


def test_correlation_engine_evaluate():
    engine = CorrelationEngine()
    # CR-001 fires when >= 3 failed_login alerts appear in the window
    engine.add_alert({'type': 'failed_login', 'timestamp': None})
    engine.add_alert({'type': 'failed_login', 'timestamp': None})
    engine.add_alert({'type': 'failed_login', 'timestamp': None})
    incidents = engine.evaluate()
    # CR-001 "Multiple Failed Logins" should match (3 >= 3)
    assert any(i['rule_id'] == 'CR-001' for i in incidents)


def test_correlation_engine_empty():
    engine = CorrelationEngine()
    incidents = engine.evaluate()
    assert len(incidents) == 0


def test_ioc_add_and_search():
    manager = IOCManager()
    ioc = IOC('8.8.8.8', 'ip', 'test', 'high')
    manager.add_ioc(ioc)
    found = manager.search_ioc('8.8.8.8')
    assert found is not None
    assert found.type == 'ip'


def test_ioc_search_not_found():
    manager = IOCManager()
    assert manager.search_ioc('1.1.1.1') is None


def test_ioc_get_by_type():
    manager = get_sample_iocs()
    ips = manager.get_iocs_by_type('ip')
    assert len(ips) >= 3


def test_ioc_enrich():
    manager = get_sample_iocs()
    ioc = manager.search_ioc('185.220.101.42')
    enriched = manager.enrich(ioc)
    assert 'geolocation' in enriched
    assert 'reputation_score' in enriched
