"""
AIVSS scoring for Phase 2 findings.

Two layers, both deterministic and open to audit:

  1. CVSS v3.1 Base Score -- computed exactly per the FIRST CVSS v3.1
     specification (the Roundup, Impact, Exploitability and Base formulae are
     reproduced verbatim). Given a base metric vector it is fully deterministic.

  2. An agentic-AI factor overlay following the OWASP AIVSS methodology: named
     agentic risk factors scored on 0..1, aggregated into an Agentic AI Risk
     Score (AARS, 0..10), then blended 50/50 with the CVSS base score to give a
     Final AIVSS Score (0..10).

Integrity note: this run does not download the OWASP AIVSS document, so the
blend weight (`CVSS_AARS_BLEND`) and the per-factor weights (`AARS_WEIGHTS`)
are recorded here as explicit, versioned constants (`AIVSS_METHODOLOGY`). Every
score is therefore reproducible from its input vector and these constants, and
nothing is presented as an official OWASP figure that was not computed here from
these stated inputs. The CVSS base layer is standalone and authoritative; the
agentic overlay is labelled with its methodology version wherever it is shown.
"""

from __future__ import annotations

import math

from dataclasses import dataclass, field


AIVSS_METHODOLOGY = "aivss-local-v0"
CVSS_VERSION = "3.1"

# ---------------------------------------------------------------------------
# CVSS v3.1 Base metric weights (FIRST CVSS v3.1 specification, section 7.1).
# ---------------------------------------------------------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
# Privileges Required is scope-dependent: (unchanged, changed).
_PR = {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.5)}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_SCOPE = {"U", "C"}

_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_METRIC_DOMAINS = {
    "AV": set(_AV),
    "AC": set(_AC),
    "PR": set(_PR),
    "UI": set(_UI),
    "S": _SCOPE,
    "C": set(_CIA),
    "I": set(_CIA),
    "A": set(_CIA),
}


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A Roundup: ceil to one decimal place, FP-safe."""

    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def severity_rating(score: float) -> str:
    """CVSS v3.1 qualitative severity rating scale (section 5)."""

    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def parse_cvss_vector(vector: str) -> dict:
    """Parse an 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' base vector into a dict.

    An optional leading 'CVSS:3.1/' prefix is accepted. Only the eight Base
    metrics are read; raises ValueError on a missing metric or bad value.
    """

    text = vector.strip()
    if text.upper().startswith("CVSS:"):
        text = text.split("/", 1)[1] if "/" in text else ""
    metrics: dict[str, str] = {}
    for part in text.split("/"):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"malformed metric segment: {part!r}")
        key, _, val = part.partition(":")
        key, val = key.strip().upper(), val.strip().upper()
        if key in _METRIC_ORDER:
            metrics[key] = val
    for key in _METRIC_ORDER:
        if key not in metrics:
            raise ValueError(f"missing base metric {key} in vector {vector!r}")
        if metrics[key] not in _METRIC_DOMAINS[key]:
            raise ValueError(f"invalid value {metrics[key]!r} for metric {key}")
    return metrics


def cvss_v31_base(vector: str | dict) -> dict:
    """Compute the CVSS v3.1 Base Score from a base metric vector.

    Returns {score, severity, vector, version}. Deterministic.
    """

    m = parse_cvss_vector(vector) if isinstance(vector, str) else {
        k.upper(): str(v).upper() for k, v in vector.items()
    }
    # Re-validate when a dict was supplied.
    for key in _METRIC_ORDER:
        if m.get(key) not in _METRIC_DOMAINS[key]:
            raise ValueError(f"invalid/missing base metric {key}: {m.get(key)!r}")

    scope_changed = m["S"] == "C"
    iss = 1.0 - (
        (1.0 - _CIA[m["C"]]) * (1.0 - _CIA[m["I"]]) * (1.0 - _CIA[m["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    pr = _PR[m["PR"]][1 if scope_changed else 0]
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]

    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        score = _roundup(min(impact + exploitability, 10.0))

    canonical = "/".join(f"{k}:{m[k]}" for k in _METRIC_ORDER)
    return {
        "score": score,
        "severity": severity_rating(score),
        "vector": f"CVSS:{CVSS_VERSION}/{canonical}",
        "version": CVSS_VERSION,
        "impact_subscore": round(impact, 4),
        "exploitability_subscore": round(exploitability, 4),
    }


# ---------------------------------------------------------------------------
# Agentic AI Risk Score (AARS) overlay -- OWASP AIVSS methodology.
# Each factor is scored on 0..1 for the finding; the weighted mean is scaled to
# 0..10. Weights and the final blend are recorded constants so the Final AIVSS
# Score is reproducible from the factor vector alone.
# ---------------------------------------------------------------------------
AARS_FACTORS = (
    "autonomy",          # agent acts without a human in the loop per action
    "tool_use",          # exploit routes through the agent's privileged tools
    "non_determinism",   # outcome varies run-to-run (LLM sampling)
    "memory_persistence",  # poisoned state persists across sessions/tickets
    "multi_agent",       # exploit crosses agent boundaries
    "adaptability",      # agent re-plans in response to defender feedback
)

AARS_WEIGHTS = {
    "autonomy": 0.25,
    "tool_use": 0.25,
    "non_determinism": 0.15,
    "memory_persistence": 0.15,
    "multi_agent": 0.10,
    "adaptability": 0.10,
}

# Final AIVSS = blend * CVSS_base + (1 - blend) * AARS, both on 0..10.
CVSS_AARS_BLEND = 0.5


def agentic_risk_score(factors: dict) -> dict:
    """Weighted agentic AI risk score (0..10) from per-factor values in 0..1."""

    missing = [f for f in AARS_FACTORS if f not in factors]
    if missing:
        raise ValueError(f"missing agentic factors: {missing}")
    for name, value in factors.items():
        if name not in AARS_WEIGHTS:
            raise ValueError(f"unknown agentic factor: {name!r}")
        if not (0.0 <= float(value) <= 1.0):
            raise ValueError(f"factor {name} out of range 0..1: {value!r}")
    weighted = sum(AARS_WEIGHTS[f] * float(factors[f]) for f in AARS_FACTORS)
    total_weight = sum(AARS_WEIGHTS.values())
    aars_unit = weighted / total_weight
    return {
        "aars": round(aars_unit * 10.0, 1),
        "aars_unit": round(aars_unit, 4),
        "factors": {f: float(factors[f]) for f in AARS_FACTORS},
        "weights": dict(AARS_WEIGHTS),
    }


@dataclass
class AivssScore:
    name: str
    cvss: dict
    aars: dict
    final_score: float
    severity: str
    methodology: str = AIVSS_METHODOLOGY
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "methodology": self.methodology,
            "cvss_version": CVSS_VERSION,
            "cvss_base_score": self.cvss["score"],
            "cvss_base_severity": self.cvss["severity"],
            "cvss_vector": self.cvss["vector"],
            "agentic_risk_score": self.aars["aars"],
            "agentic_factors": self.aars["factors"],
            "cvss_aars_blend": CVSS_AARS_BLEND,
            "final_aivss_score": self.final_score,
            "final_aivss_severity": self.severity,
            "notes": self.notes,
        }


def score_finding(
    *,
    name: str,
    cvss_vector: str | dict,
    agentic_factors: dict,
    notes: str = "",
) -> AivssScore:
    """Score one finding end-to-end: CVSS base + AARS -> Final AIVSS Score."""

    cvss = cvss_v31_base(cvss_vector)
    aars = agentic_risk_score(agentic_factors)
    final = _roundup(
        min(
            CVSS_AARS_BLEND * cvss["score"]
            + (1.0 - CVSS_AARS_BLEND) * aars["aars"],
            10.0,
        )
    )
    return AivssScore(
        name=name,
        cvss=cvss,
        aars=aars,
        final_score=final,
        severity=severity_rating(final),
        notes=notes,
    )
