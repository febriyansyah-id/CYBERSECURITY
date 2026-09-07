"""SOAR workflow orchestration engine."""


class WorkflowStep:
    def __init__(self, id, action, params=None, on_success=None, on_failure=None):
        self.id = id
        self.action = action
        self.params = params or {}
        self.on_success = on_success
        self.on_failure = on_failure


class Workflow:
    def __init__(self, id, name, steps, triggers=None):
        self.id = id
        self.name = name
        self.steps = steps
        self.triggers = triggers or []


class WorkflowOrchestrator:
    def __init__(self):
        self.workflows = {}

    def register(self, workflow):
        self.workflows[workflow.id] = workflow

    def run(self, workflow_id, context=None):
        if workflow_id not in self.workflows:
            raise ValueError(f"Workflow {workflow_id} not found")
        wf = self.workflows[workflow_id]
        context = context or {}
        results = []
        for step in wf.steps:
            result = {
                'step_id': step.id,
                'action': step.action,
                'params': step.params,
                'status': 'completed',
            }
            results.append(result)
            context[f'step_{step.id}'] = result
        return {'workflow_id': workflow_id, 'results': results, 'context': context}

    def list_workflows(self):
        return {k: v.name for k, v in self.workflows.items()}


def get_default_orchestrator():
    orch = WorkflowOrchestrator()
    wf1 = Workflow('WF-PHI-001', 'Phishing Triage', [
        WorkflowStep('1', 'extract_iocs', {'email': '{{email}}'}),
        WorkflowStep('2', 'check_reputation', {'iocs': '{{extracted_iocs}}'}),
        WorkflowStep('3', 'create_case', {'title': 'Phishing: {{subject}}', 'severity': 'high'}),
    ], triggers=['email_alert'])
    wf2 = Workflow('WF-MLW-001', 'Malware Analysis', [
        WorkflowStep('1', 'hash_lookup', {'hash': '{{file_hash}}'}),
        WorkflowStep('2', 'sandbox_analysis', {'sample': '{{file_path}}'}),
        WorkflowStep('3', 'create_alert', {'findings': '{{analysis_results}}'}),
    ], triggers=['malware_detection'])
    wf3 = Workflow('WF-IOC-001', 'Indicator Enrichment', [
        WorkflowStep('1', 'query_virustotal', {'ioc': '{{indicator}}'}),
        WorkflowStep('2', 'query_abuseipdb', {'ioc': '{{indicator}}'}),
        WorkflowStep('3', 'enrich_case', {'enrichment': '{{vt_result}}{{abuseipdb_result}}'}),
    ], triggers=['ioc_alert'])
    orch.register(wf1)
    orch.register(wf2)
    orch.register(wf3)
    return orch
