from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
import logging

logger = logging.getLogger(__name__)

# Standard ports — connections to others are flagged as unusual
STANDARD_PORTS: set[int] = {80, 443, 22, 3306, 5432, 25, 53, 8080, 8443}

# High-risk country codes (ISO 3166-1 alpha-2)
HIGH_RISK_COUNTRIES: set[str] = {
    "KP", "IR", "RU", "CN", "SY", "CU", "VE", "BY", "MM", "AF",
}


@dataclass
class DetectionRule:
    id: str
    name: str
    description: str
    conditions: dict[str, Any]
    severity: str = "medium"
    tags: list[str] = field(default_factory=list)


BUILTIN_RULES = [
    DetectionRule(
        id="BRUTE-001",
        name="Multiple Failed Logins",
        description="5+ failed authentication attempts within 5 minutes",
        conditions={"event_type": "authentication", "status": "failed", "min_count": 5, "window_minutes": 5},
        severity="high",
        tags=["brute-force", "authentication"],
    ),
    DetectionRule(
        id="GEO-001",
        name="High-Risk Country Connection",
        description="Connection from a high-risk geolocation",
        conditions={"event_type": "connection", "country_risk": "high"},
        severity="high",
        tags=["geo", "threat-intel"],
    ),
    DetectionRule(
        id="PORT-001",
        name="Unusual Port Access",
        description="Access to non-standard ports (not 80, 443, 22, 3306, 5432)",
        conditions={"event_type": "connection", "port": "unusual"},
        severity="medium",
        tags=["network", "recon"],
    ),
    DetectionRule(
        id="HASH-001",
        name="Known Malicious Hash",
        description="File hash matches known malware database",
        conditions={"event_type": "file", "hash_status": "malicious"},
        severity="critical",
        tags=["malware", "hash"],
    ),
    DetectionRule(
        id="PRIV-001",
        name="Privilege Escalation Attempt",
        description="User attempted privilege escalation",
        conditions={"event_type": "authorization", "action": "escalation", "status": "denied"},
        severity="high",
        tags=["privilege-escalation", "authorization"],
    ),
]

# ---------------------------------------------------------------------------
# Stateful condition helpers
# ---------------------------------------------------------------------------

def _check_stateful_conditions(rule: DetectionRule, event: dict) -> bool:
    """Evaluate conditions that require contextual / meta-data about the event.

    Returns True when all stateful conditions in the rule are satisfied,
    or when the rule has no stateful conditions (not applicable).
    """
    conditions = rule.conditions

    # --- country_risk: compare against HIGH_RISK_COUNTRIES lookup ---
    if "country_risk" in conditions:
        required = conditions["country_risk"]
        country = event.get("country_code", "")
        is_high_risk = country.upper() in HIGH_RISK_COUNTRIES
        if required == "high" and not is_high_risk:
            return False

    # --- port: flag connections to non-standard ports ---
    if "port" in conditions:
        required = conditions["port"]
        port = event.get("dest_port") or event.get("port")
        if required == "unusual":
            try:
                if int(port) in STANDARD_PORTS:
                    return False
            except (TypeError, ValueError):
                return False  # malformed port field → no match

    # min_count / window_minutes are handled by evaluate_window(); skip here.
    return True


class RulesEngine:
    def __init__(self):
        self._rules: list[DetectionRule] = []

    def load_rules(self, rules: list[DetectionRule]) -> None:
        self._rules = rules

    def add_rule(self, rule: DetectionRule) -> None:
        self._rules.append(rule)

    def get_rules(self) -> list[DetectionRule]:
        return list(self._rules)

    def evaluate(self, event: dict) -> list[str]:
        """Evaluate a single event against all loaded rules.

        Stateful conditions (min_count / window_minutes) are skipped here;
        use evaluate_window() for time-windowed, count-based detection.
        """
        matched = []
        for rule in self._rules:
            # 1. Match simple key=value conditions (skip stateful keys)
            simple_keys = {
                k for k in rule.conditions
                if k not in ("min_count", "window_minutes", "country_risk", "port")
            }
            simple_ok = all(event.get(k) == rule.conditions[k] for k in simple_keys)
            if not simple_ok:
                continue

            # 2. Evaluate stateful / contextual conditions
            if not _check_stateful_conditions(rule, event):
                continue

            matched.append(rule.id)
        return matched

    def evaluate_window(self, events: list[dict]) -> list[str]:
        """Evaluate a list of events (time window) for count-based rules.

        Applies min_count + window_minutes filtering in addition to field matching.
        Call this with a pre-filtered sliding window of recent events.
        """
        matched: list[str] = []
        now = datetime.now()

        for rule in self._rules:
            min_count = rule.conditions.get("min_count")
            window_min = rule.conditions.get("window_minutes")

            # Only process count-based rules here
            if min_count is None:
                continue

            cutoff = (
                now - timedelta(minutes=int(window_min))
                if window_min is not None
                else datetime.min
            )

            # Filter events to those within the time window
            windowed = []
            for ev in events:
                ts_raw = ev.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts_raw) if ts_raw else now
                except (ValueError, TypeError):
                    ts = now
                if ts >= cutoff:
                    windowed.append(ev)

            # Match simple field conditions (excluding stateful meta-keys)
            simple_keys = {
                k for k in rule.conditions
                if k not in ("min_count", "window_minutes", "country_risk", "port")
            }
            qualifying = [
                ev for ev in windowed
                if all(ev.get(k) == rule.conditions[k] for k in simple_keys)
            ]

            if len(qualifying) >= int(min_count):
                logger.info(
                    "Rule %s triggered: %d events matched (required %d)",
                    rule.id, len(qualifying), min_count,
                )
                matched.append(rule.id)

        return matched
