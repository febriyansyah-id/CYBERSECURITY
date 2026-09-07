"""Tests for reporting module."""

from src.reporting.incident_report import IncidentReport, generate_full_report, export_html
from src.reporting.metrics import get_soc_metrics, generate_metrics_report, compare_to_benchmark


def test_incident_report_creation():
    report = IncidentReport('Test Incident', 'Malware', 'high')
    assert report.title == 'Test Incident'
    assert report.severity == 'high'


def test_executive_summary():
    report = IncidentReport('Test', 'Malware', 'critical')
    summary = report.generate_executive_summary()
    assert 'Executive Summary' in summary
    assert 'Test' in summary


def test_timeline_entries():
    report = IncidentReport('Test')
    report.add_timeline_entry('2026-01-01 10:00', 'Detected', 'SIEM')
    report.add_timeline_entry('2026-01-01 10:05', 'Contained', 'Analyst')
    assert len(report.timeline) == 2


def test_evidence():
    report = IncidentReport('Test')
    report.add_evidence('Network capture pcap01.pcap')
    report.add_evidence('Memory dump host01.dmp')
    assert len(report.evidence) == 2


def test_generate_full_report():
    report = IncidentReport('Full Test', 'Ransomware', 'critical')
    full = generate_full_report(report)
    assert 'Executive Summary' in full
    assert 'Technical Analysis' in full
    assert 'Lessons Learned' in full


def test_export_html():
    report = IncidentReport('HTML Test')
    text = generate_full_report(report)
    html = export_html(text)
    assert '<html>' in html
    assert '</html>' in html


def test_soc_metrics_count():
    metrics = get_soc_metrics()
    assert len(metrics) >= 5


def test_metrics_report():
    report = generate_metrics_report()
    assert 'SOC Metrics Report' in report
    assert 'Mean Time to Respond' in report


def test_metrics_benchmark():
    comparison = compare_to_benchmark()
    assert 'mttr' in comparison
    assert 'mttc' in comparison
    assert comparison['mttr']['industry_avg'] == 60


def test_metric_status():
    from src.reporting.metrics import SOCMetric
    good = SOCMetric('Test', 30, 60)
    assert good.status() == 'met'
    bad = SOCMetric('Test', 90, 60)
    assert bad.status() == 'breached'
