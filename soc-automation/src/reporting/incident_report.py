"""Incident report generation."""

from datetime import datetime


class IncidentReport:
    def __init__(self, title, incident_type='Unspecified', severity='medium', status='Open'):
        self.id = f"IR-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.title = title
        self.incident_type = incident_type
        self.severity = severity
        self.status = status
        self.timeline = []
        self.evidence = []

    def add_timeline_entry(self, timestamp, action, actor):
        self.timeline.append({'timestamp': timestamp, 'action': action, 'actor': actor})

    def add_evidence(self, item):
        self.evidence.append(item)

    def generate_executive_summary(self):
        return (
            f"## Executive Summary\n\n"
            f"**Incident ID:** {self.id}\n"
            f"**Title:** {self.title}\n"
            f"**Type:** {self.incident_type}\n"
            f"**Severity:** {self.severity}\n"
            f"**Status:** {self.status}\n\n"
            f"A {self.severity}-severity {self.incident_type} incident was identified. "
            f"Response actions were executed per the corresponding playbook."
        )

    def generate_technical_report(self):
        report = f"## Technical Analysis\n\n**Incident:** {self.title}\n\n### Timeline\n"
        for entry in self.timeline:
            report += f"- {entry['timestamp']} | {entry['action']} by {entry['actor']}\n"
        report += f"\n### Evidence\n"
        for e in self.evidence:
            report += f"- {e}\n"
        return report

    def generate_lessons_learned(self):
        return (
            f"## Lessons Learned\n\n"
            f"### What went well\n- Rapid detection and classification\n- Effective containment procedures\n\n"
            f"### What could improve\n- Earlier user reporting\n- Additional monitoring coverage\n\n"
            f"### Action Items\n- Update detection rules\n- Conduct tabletop exercise\n"
        )


def generate_full_report(incident):
    return '\n\n'.join([
        incident.generate_executive_summary(),
        incident.generate_technical_report(),
        incident.generate_lessons_learned(),
    ])


def export_html(report_text):
    html = "<html><body><h1>Incident Report</h1>"
    html += report_text.replace('\n', '<br>')
    html += "</body></html>"
    return html
