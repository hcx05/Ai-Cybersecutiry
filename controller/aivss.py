"""
OWASP AIVSS-Agentic scoring (official methodology).

Implemented from the official specification:
  OWASP "AIVSS Scoring System For OWASP Agentic AI Core Security Risks v0.8"
  source: https://aivss.owasp.org/assets/publications/
          AIVSS%20Scoring%20System%20For%20OWASP%20Agentic%20AI%20Core%20Security%20Risks%20v0.8.pdf
  sha256: a2abbd215f0d7790d273c30a893a09c0dc37a6c109765eb0363c01af897fd9af

This is NOT CVSS. Per spec section 3.1.1 the AIVSS baseline is the CVSS v4.0
Base Score, taken here as a numeric INPUT (the spec treats CVSS_Base as an
input/intermediate, section 3.5); the finding records the CVSS:4.0 vector and
the base score obtained from the FIRST v4.0 calculator alongside it.

Equations (spec sections 3.3-3.5):
  Risk_Gap   = 10 - CVSS_Base
  Factor_Sum = sum of the 10 agentic factors, each in {0.0, 0.5, 1.0}
  AARS       = Risk_Gap * (Factor_Sum / 10) * ThM            (section 3.3.1)
  AIVSS_raw  = (CVSS_Base + AARS) * Mitigation_Factor        (section 3.4)
  AIVSS      = RoundHalfUp(AIVSS_raw, 1)                      (section 3.5.1)

Validated against the spec's own worked examples (section 3.6 / Table 5):
  3.6.1  CVSS 9.4, FactorSum 9.0 -> AARS 0.5238 -> AIVSS 9.9 (Critical)
  3.6.2  CVSS 8.7, FactorSum 8.0 -> AIVSS 9.7 (Critical)
  3.6.6  CVSS 5.8, FactorSum 7.5 -> AIVSS 8.9 (High)
  3.6.10 CVSS 2.1, FactorSum 6.5 -> AIVSS 7.1 (High)
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal


AIVSS_SPEC_VERSION = "v0.8"
AIVSS_SPEC_SHA256 = (
    "a2abbd215f0d7790d273c30a893a09c0dc37a6c109765eb0363c01af897fd9af"
)
AIVSS_SPEC_SOURCE = (
    "https://aivss.owasp.org/assets/publications/"
    "AIVSS%20Scoring%20System%20For%20OWASP%20Agentic%20AI%20"
    "Core%20Security%20Risks%20v0.8.pdf"
)

# The 10 Risk Amplification Factors, in the exact vector order of spec 2.2.
FACTORS = (
    "autonomy",         # 1. Execution Autonomy
    "tools",            # 2. External Tool Control Surface
    "language",         # 3. Natural Language Interface
    "context",          # 4. Contextual Awareness
    "non_determinism",  # 5. Behavioral Non-Determinism
    "opacity",          # 6. Opacity & Reflexivity
    "persistence",      # 7. Persistent State Retention
    "identity",         # 8. Dynamic Identity
    "multi_agent",      # 9. Multi-Agent Interactions
    "self_mod",         # 10. Self-Modification
)

_ALLOWED_FACTOR_VALUES = {0.0, 0.5, 1.0}

# Threat Multiplier, spec Table 4a (section 3.3.2). Default = PoC (0.97).
THREAT_MULTIPLIER = {"attacked": 1.00, "poc": 0.97, "unreported": 0.50}
THM_DEFAULT = 0.97

# Mitigation Factor, spec Table 4b (section 3.4.1). Default = no/weak (1.00).
MITIGATION_FACTOR = {"none": 1.00, "partial": 0.83, "strong": 0.67}
MITIGATION_DEFAULT = 1.00


def round_half_up_tenth(value: float) -> float:
    """RoundHalfUp to the nearest tenth (spec 3.5.1: 8.64->8.6, 8.65->8.7)."""

    return float(Decimal(str(value)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def severity_band(score: float) -> str:
    """AIVSS severity bands (spec 3.5.2)."""

    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"       # 0.1 - 3.9
    if score < 7.0:
        return "Medium"    # 4.0 - 6.9
    if score < 9.0:
        return "High"      # 7.0 - 8.9
    return "Critical"      # 9.0 - 10.0


def _validate_factors(factors: dict) -> None:
    missing = [f for f in FACTORS if f not in factors]
    if missing:
        raise ValueError(f"missing agentic factors: {missing}")
    unknown = [f for f in factors if f not in FACTORS]
    if unknown:
        raise ValueError(f"unknown agentic factors: {unknown}")
    for name, value in factors.items():
        if float(value) not in _ALLOWED_FACTOR_VALUES:
            raise ValueError(
                f"factor {name}={value!r} must be one of 0.0, 0.5, 1.0 (spec 2.1)"
            )


def factor_sum(factors: dict) -> float:
    """Sum of the 10 factors (spec 3.3.1); each in {0.0, 0.5, 1.0}, max 10.0."""

    _validate_factors(factors)
    return float(sum(float(factors[f]) for f in FACTORS))


def _resolve_thm(thm) -> float:
    if isinstance(thm, str):
        key = thm.strip().lower()
        if key not in THREAT_MULTIPLIER:
            raise ValueError(f"unknown threat maturity {thm!r}")
        return THREAT_MULTIPLIER[key]
    return float(thm)


def _resolve_mitigation(mitigation) -> float:
    if isinstance(mitigation, str):
        key = mitigation.strip().lower()
        if key not in MITIGATION_FACTOR:
            raise ValueError(f"unknown mitigation strength {mitigation!r}")
        return MITIGATION_FACTOR[key]
    return float(mitigation)


def aars(cvss_base: float, factors: dict, thm=THM_DEFAULT) -> float:
    """Agentic AI Risk Score uplift, raw (unrounded), spec 3.3.1."""

    if not (0.0 <= float(cvss_base) <= 10.0):
        raise ValueError(f"cvss_base out of range 0..10: {cvss_base!r}")
    risk_gap = 10.0 - float(cvss_base)
    return risk_gap * (factor_sum(factors) / 10.0) * _resolve_thm(thm)


def aivss(
    cvss_base: float,
    factors: dict,
    thm=THM_DEFAULT,
    mitigation=MITIGATION_DEFAULT,
) -> float:
    """Final AIVSS score, rounded to the nearest tenth (spec 3.4 + 3.5.1)."""

    uplift = aars(cvss_base, factors, thm=thm)
    raw = (float(cvss_base) + uplift) * _resolve_mitigation(mitigation)
    raw = min(10.0, max(0.0, raw))
    return round_half_up_tenth(raw)


@dataclass
class AivssScore:
    name: str
    cvss_base: float
    cvss_vector: str          # the CVSS:4.0 vector string (recorded input)
    factors: dict
    thm: float
    mitigation: float
    factor_sum: float
    aars_raw: float
    aivss_score: float
    severity: str
    spec_version: str = AIVSS_SPEC_VERSION
    spec_sha256: str = AIVSS_SPEC_SHA256
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "framework": "OWASP AIVSS-Agentic",
            "spec_version": self.spec_version,
            "spec_sha256": self.spec_sha256,
            "spec_source": AIVSS_SPEC_SOURCE,
            "cvss_v4_base": self.cvss_base,
            "cvss_v4_vector": self.cvss_vector,
            "agentic_factors": {f: float(self.factors[f]) for f in FACTORS},
            "factor_sum": self.factor_sum,
            "threat_multiplier": self.thm,
            "mitigation_factor": self.mitigation,
            "aars_uplift": round(self.aars_raw, 4),
            "aivss_score": self.aivss_score,
            "aivss_severity": self.severity,
            "notes": self.notes,
        }


def score_finding(
    *,
    name: str,
    cvss_base: float,
    cvss_vector: str,
    agentic_factors: dict,
    thm=THM_DEFAULT,
    mitigation=MITIGATION_DEFAULT,
    notes: str = "",
) -> AivssScore:
    """Score one finding end-to-end per the official AIVSS v0.8 methodology.

    cvss_base / cvss_vector are the CVSS v4.0 base score and vector string
    (obtained from the FIRST v4.0 calculator) recorded as the baseline input.
    """

    if not (isinstance(cvss_vector, str) and cvss_vector.upper().startswith("CVSS:4.0")):
        raise ValueError(f"cvss_vector must be a CVSS:4.0 vector string: {cvss_vector!r}")
    thm_v = _resolve_thm(thm)
    mit_v = _resolve_mitigation(mitigation)
    fs = factor_sum(agentic_factors)
    uplift = aars(cvss_base, agentic_factors, thm=thm_v)
    score = aivss(cvss_base, agentic_factors, thm=thm_v, mitigation=mit_v)
    return AivssScore(
        name=name,
        cvss_base=float(cvss_base),
        cvss_vector=cvss_vector,
        factors={f: float(agentic_factors[f]) for f in FACTORS},
        thm=thm_v,
        mitigation=mit_v,
        factor_sum=fs,
        aars_raw=uplift,
        aivss_score=score,
        severity=severity_band(score),
        notes=notes,
    )
