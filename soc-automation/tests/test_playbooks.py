"""Tests for IR playbooks."""

from src.playbooks.ir_playbooks import get_all_playbooks, get_playbook_by_type, execute_playbook
from src.playbooks.malware import get_malware_playbook
from src.playbooks.phishing import get_phishing_playbook
from src.playbooks.ransomware import get_ransomware_playbook
from src.playbooks.data_breach import get_data_breach_playbook
from src.playbooks.ddos import get_ddos_playbook
from src.playbooks.insider import get_insider_threat_playbook


def test_all_playbooks_returned():
    playbooks = get_all_playbooks()
    assert len(playbooks) == 6


def test_malware_playbook_has_20_steps():
    pb = get_malware_playbook()
    assert len(pb.steps) >= 20


def test_phishing_playbook_has_15_steps():
    pb = get_phishing_playbook()
    assert len(pb.steps) >= 15


def test_ransomware_playbook_has_20_steps():
    pb = get_ransomware_playbook()
    assert len(pb.steps) >= 20


def test_data_breach_playbook_has_20_steps():
    pb = get_data_breach_playbook()
    assert len(pb.steps) >= 20


def test_ddos_playbook_has_15_steps():
    pb = get_ddos_playbook()
    assert len(pb.steps) >= 15


def test_insider_playbook_has_15_steps():
    pb = get_insider_threat_playbook()
    assert len(pb.steps) >= 15


def test_get_playbook_by_type():
    pb = get_playbook_by_type('Malware')
    assert pb is not None
    assert pb.incident_type == 'Malware'


def test_get_playbook_by_type_nonexistent():
    pb = get_playbook_by_type('Unknown')
    assert pb is None


def test_execute_playbook_returns_results():
    pb = get_malware_playbook()
    results = execute_playbook(pb)
    assert len(results) == len(pb.steps)
    assert all(r['status'] == 'completed' for r in results)


def test_playbook_has_references():
    for pb in get_all_playbooks():
        assert len(pb.references) > 0


def test_playbook_steps_have_phases():
    for pb in get_all_playbooks():
        for step in pb.steps:
            assert step.phase
