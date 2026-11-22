from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class Asset:
    name: str
    value: float
    criticality: str


@dataclass
class Threat:
    name: str
    likelihood: int
    impact: int


@dataclass
class Risk:
    asset: Asset
    threat: Threat
    inherent_score: float
    residual_score: float
    control_effectiveness: float = 0.4
    inherent_level: str = ""
    residual_level: str = ""

    def __post_init__(self):
        self.inherent_level = risk_level(self.inherent_score)
        self.residual_level = risk_level(self.residual_score)


def calculate_score(
    likelihood: int,
    impact: int,
    control_effectiveness: float = 0.4,
) -> Tuple[float, float]:
    """Calculate inherent and residual risk scores.

    Args:
        likelihood: 1–5 scale.
        impact: 1–5 scale.
        control_effectiveness: fraction of risk mitigated by controls (0.0–1.0).
            Default 0.4 (40% reduction). Pass 0.0 for no controls.
            Use scoring.calculate_control_effectiveness() to derive this from
            an actual list of implemented controls.
    """
    if not (0.0 <= control_effectiveness <= 1.0):
        raise ValueError(f"control_effectiveness must be in [0, 1], got {control_effectiveness}")
    inherent = float(likelihood * impact)
    residual = inherent * (1.0 - control_effectiveness)
    return (inherent, residual)


def risk_level(score: float) -> str:
    if score >= 20:
        return "Critical"
    elif score >= 10:
        return "High"
    elif score >= 5:
        return "Medium"
    else:
        return "Low"


def assess(
    assets: List[Asset],
    threats: List[Threat],
    control_effectiveness: float = 0.4,
) -> List[Risk]:
    """Assess risk for each asset-threat pair.

    Args:
        assets: List of assets to evaluate.
        threats: List of threats to evaluate against each asset.
        control_effectiveness: Override the default control effectiveness.
            Use scoring.calculate_control_effectiveness() to compute this
            from your actual list of implemented controls.
    """
    results = []
    for asset in assets:
        for threat in threats:
            inherent, residual = calculate_score(
                threat.likelihood, threat.impact, control_effectiveness
            )
            results.append(
                Risk(
                    asset=asset,
                    threat=threat,
                    inherent_score=inherent,
                    residual_score=residual,
                    control_effectiveness=control_effectiveness,
                )
            )
    return results
