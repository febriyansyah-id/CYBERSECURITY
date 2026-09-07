"""Tests for SOAR integration."""

from src.soar.orchestrator import WorkflowOrchestrator, Workflow, WorkflowStep, get_default_orchestrator
from src.soar.thehive import TheHiveClient
from src.soar.cortex import CortexClient
from src.soar.shfl import get_workflow_templates, generate_workflow_json


def test_orchestrator_register_and_run():
    orch = WorkflowOrchestrator()
    wf = Workflow('TEST-001', 'Test', [WorkflowStep('1', 'test_action', {})])
    orch.register(wf)
    result = orch.run('TEST-001')
    assert result['workflow_id'] == 'TEST-001'
    assert len(result['results']) == 1


def test_orchestrator_unknown_workflow():
    orch = WorkflowOrchestrator()
    try:
        orch.run('NONEXISTENT')
        assert False
    except ValueError:
        pass


def test_default_orchestrator_has_3_workflows():
    orch = get_default_orchestrator()
    assert len(orch.list_workflows()) == 3


def test_thehive_create_case():
    client = TheHiveClient()
    case = client.create_case('Test Case', 'Description', 2, ['test'])
    assert case['title'] == 'Test Case'
    assert case['severity'] == 2


def test_thehive_add_observable():
    client = TheHiveClient()
    case = client.create_case('Test')
    obs = client.add_observable(case['id'], 'ip', '8.8.8.8')
    assert obs is not None
    assert obs['data'] == '8.8.8.8'


def test_cortex_get_analyzers():
    client = CortexClient()
    analyzers = client.get_available_analyzers()
    assert len(analyzers) >= 4


def test_cortex_analyze_hash():
    client = CortexClient()
    result = client.analyze_hash('evilhash')
    assert result['success'] is True


def test_shuffle_templates_exist():
    templates = get_workflow_templates()
    assert len(templates) >= 3


def test_shuffle_generate_json():
    steps = [{'type': 'email-parse', 'field': 'subject'}]
    wf = generate_workflow_json('Test', steps)
    assert wf['name'] == 'Test'
    assert len(wf['branches']) == 1
