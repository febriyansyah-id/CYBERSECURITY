"""SOC metrics and KPI dashboard."""


class SOCMetric:
    def __init__(self, name, value, target, unit='minutes', period='daily'):
        self.name = name
        self.value = value
        self.target = target
        self.unit = unit
        self.period = period

    def status(self):
        if self.value <= self.target:
            return 'met'
        return 'breached'

    def gap(self):
        return max(0, self.value - self.target)


def get_soc_metrics():
    return {
        'mttr': SOCMetric('Mean Time to Respond', 42, 45, 'minutes', 'daily'),
        'mttc': SOCMetric('Mean Time to Contain', 85, 90, 'minutes', 'daily'),
        'alert_volume': SOCMetric('Daily Alert Volume', 150, 200, 'alerts', 'daily'),
        'fp_rate': SOCMetric('False Positive Rate', 3.2, 5.0, 'percent', 'daily'),
        'ticket_closure': SOCMetric('Ticket Closure Rate', 92, 95, 'percent', 'weekly'),
        'sla_adherence': SOCMetric('SLA Adherence', 88, 95, 'percent', 'monthly'),
    }


def generate_metrics_report(metrics=None):
    if metrics is None:
        metrics = get_soc_metrics()
    report = "# SOC Metrics Report\n\n"
    report += "| Metric | Value | Target | Status | Gap |\n"
    report += "|---|---|---|---|---|\n"
    for key, m in metrics.items():
        status = '✅' if m.status() == 'met' else '❌'
        report += f"| {m.name} | {m.value} {m.unit} | {m.target} {m.unit} | {status} | {m.gap()} |\n"
    return report


def compare_to_benchmark(metrics=None):
    if metrics is None:
        metrics = get_soc_metrics()
    benchmarks = {
        'mttr': {'industry_avg': 60, 'best_in_class': 15},
        'mttc': {'industry_avg': 120, 'best_in_class': 30},
        'fp_rate': {'industry_avg': 15, 'best_in_class': 2},
    }
    comparison = {}
    for key, bench in benchmarks.items():
        if key in metrics:
            m = metrics[key]
            comparison[key] = {
                'our_value': m.value,
                'industry_avg': bench['industry_avg'],
                'best_in_class': bench['best_in_class'],
                'vs_industry': 'above' if m.value <= bench['industry_avg'] else 'below',
            }
    return comparison
