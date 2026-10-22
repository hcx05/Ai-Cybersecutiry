"""Tests for controller.aivss -- CVSS v3.1 base against published reference
scores, agentic overlay reproducibility, and end-to-end finding scoring."""

import math

import pytest

from controller import aivss


# (vector, expected base score, expected severity) from FIRST CVSS v3.1
# reference examples / the official calculator.
CVSS_CASES = [
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
    ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "High"),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"),
    ("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),
    ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"),
]


@pytest.mark.parametrize("vector,score,severity", CVSS_CASES)
def test_cvss_v31_base_reference_scores(vector, score, severity):
    result = aivss.cvss_v31_base(vector)
    assert result["score"] == score
    assert result["severity"] == severity
    assert result["version"] == "3.1"


def test_cvss_vector_accepts_prefix_and_roundtrips():
    r1 = aivss.cvss_v31_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert r1["score"] == 9.8
    assert r1["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_cvss_vector_accepts_dict():
    r = aivss.cvss_v31_base(
        {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
         "S": "U", "C": "H", "I": "H", "A": "H"}
    )
    assert r["score"] == 9.8


@pytest.mark.parametrize("bad", [
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",          # missing A
    "AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      # bad AV
    "AV:N/AC:L/PR:N/UI:N/S:Z/C:H/I:H/A:H",      # bad scope
])
def test_cvss_rejects_malformed(bad):
    with pytest.raises(ValueError):
        aivss.cvss_v31_base(bad)


def test_severity_rating_boundaries():
    assert aivss.severity_rating(0.0) == "None"
    assert aivss.severity_rating(0.1) == "Low"
    assert aivss.severity_rating(3.9) == "Low"
    assert aivss.severity_rating(4.0) == "Medium"
    assert aivss.severity_rating(6.9) == "Medium"
    assert aivss.severity_rating(7.0) == "High"
    assert aivss.severity_rating(8.9) == "High"
    assert aivss.severity_rating(9.0) == "Critical"
    assert aivss.severity_rating(10.0) == "Critical"


def test_roundup_ceils_to_one_decimal():
    assert aivss._roundup(4.02) == 4.1
    assert aivss._roundup(4.00) == 4.0
    assert aivss._roundup(6.007) == 6.1


def test_agentic_risk_score_bounds_and_weights():
    allzero = aivss.agentic_risk_score({f: 0.0 for f in aivss.AARS_FACTORS})
    assert allzero["aars"] == 0.0
    allone = aivss.agentic_risk_score({f: 1.0 for f in aivss.AARS_FACTORS})
    assert allone["aars"] == 10.0
    assert math.isclose(sum(aivss.AARS_WEIGHTS.values()), 1.0, abs_tol=1e-9)


def test_agentic_risk_score_is_weighted_mean():
    factors = {
        "autonomy": 1.0, "tool_use": 1.0, "non_determinism": 0.0,
        "memory_persistence": 0.0, "multi_agent": 0.0, "adaptability": 0.0,
    }
    # autonomy+tool_use carry 0.25+0.25 = 0.5 of the unit weight.
    assert aivss.agentic_risk_score(factors)["aars"] == 5.0


def test_agentic_risk_score_validates_inputs():
    with pytest.raises(ValueError):
        aivss.agentic_risk_score({"autonomy": 0.5})  # missing factors
    with pytest.raises(ValueError):
        aivss.agentic_risk_score({f: 2.0 for f in aivss.AARS_FACTORS})  # >1


def test_score_finding_blends_cvss_and_aars():
    s = aivss.score_finding(
        name="demo",
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
        agentic_factors={f: 1.0 for f in aivss.AARS_FACTORS},  # AARS 10.0
        notes="n/a",
    )
    # 0.5*9.8 + 0.5*10.0 = 9.9
    assert s.final_score == 9.9
    assert s.severity == "Critical"
    d = s.to_dict()
    assert d["methodology"] == aivss.AIVSS_METHODOLOGY
    assert d["cvss_base_score"] == 9.8
    assert d["agentic_risk_score"] == 10.0
    assert d["final_aivss_score"] == 9.9
    assert d["cvss_aars_blend"] == 0.5
