"""Tests for controller.aivss -- the official OWASP AIVSS-Agentic v0.8 method.

Baselines are the spec's own worked examples (section 3.6 / Table 5), per
handbook section 15.1: tests must validate against the PDF's example results,
not against adjusted expectations.
"""

import pytest

from controller import aivss


# Exact factor breakdowns transcribed from spec section 3.6 examples.
EX_3_6_1 = {  # Agentic AI Tool Misuse
    "autonomy": 1.0, "tools": 1.0, "language": 1.0, "context": 1.0,
    "non_determinism": 1.0, "opacity": 1.0, "persistence": 0.5,
    "identity": 1.0, "multi_agent": 1.0, "self_mod": 0.5,
}  # Factor_Sum = 9.0
EX_3_6_2 = {  # Agent Access Control Violation
    "autonomy": 1.0, "tools": 1.0, "language": 1.0, "context": 1.0,
    "non_determinism": 0.5, "opacity": 1.0, "persistence": 1.0,
    "identity": 1.0, "multi_agent": 0.5, "self_mod": 0.0,
}  # Factor_Sum = 8.0
EX_3_6_6 = {  # Agent Memory and Context Manipulation (RAG poisoning)
    "autonomy": 1.0, "tools": 0.5, "language": 1.0, "context": 1.0,
    "non_determinism": 0.5, "opacity": 1.0, "persistence": 1.0,
    "identity": 0.0, "multi_agent": 0.5, "self_mod": 1.0,
}  # Factor_Sum = 7.5


def test_spec_sha256_and_version_recorded():
    assert aivss.AIVSS_SPEC_VERSION == "v0.8"
    assert aivss.AIVSS_SPEC_SHA256 == (
        "a2abbd215f0d7790d273c30a893a09c0dc37a6c109765eb0363c01af897fd9af"
    )


def test_factor_order_matches_spec_2_2():
    assert aivss.FACTORS == (
        "autonomy", "tools", "language", "context", "non_determinism",
        "opacity", "persistence", "identity", "multi_agent", "self_mod",
    )


def test_factor_sums():
    assert aivss.factor_sum(EX_3_6_1) == 9.0
    assert aivss.factor_sum(EX_3_6_2) == 8.0
    assert aivss.factor_sum(EX_3_6_6) == 7.5


def test_example_3_6_1_tool_misuse():
    # AARS = (10-9.4)*(9.0/10)*0.97 = 0.5238 ; AIVSS = 9.9 Critical
    assert aivss.aars(9.4, EX_3_6_1) == pytest.approx(0.5238, abs=1e-6)
    assert aivss.aivss(9.4, EX_3_6_1) == 9.9
    assert aivss.severity_band(9.9) == "Critical"


def test_example_3_6_2_access_control():
    # AARS = (10-8.7)*(8.0/10)*0.97 = 1.0088 ; AIVSS = 9.7 Critical
    assert aivss.aars(8.7, EX_3_6_2) == pytest.approx(1.0088, abs=1e-6)
    assert aivss.aivss(8.7, EX_3_6_2) == 9.7


def test_example_3_6_6_memory_manipulation():
    # AARS = (10-5.8)*(7.5/10)*0.97 = 3.0555 ; AIVSS = 8.9 High
    assert aivss.aars(5.8, EX_3_6_6) == pytest.approx(3.0555, abs=1e-6)
    assert aivss.aivss(5.8, EX_3_6_6) == 8.9
    assert aivss.severity_band(8.9) == "High"


def test_example_3_6_10_goal_manipulation_low_cvss_high_aivss():
    # Table 5: CVSS 2.1, Factor_Sum 6.5 -> AARS ~5.0 -> AIVSS 7.1 High
    factors = dict.fromkeys(aivss.FACTORS, 0.0)
    for k in ("autonomy", "language", "non_determinism", "context", "persistence"):
        factors[k] = 1.0
    factors["opacity"] = 1.0
    factors["multi_agent"] = 0.5          # sum = 6.5
    assert aivss.factor_sum(factors) == 6.5
    assert aivss.aivss(2.1, factors) == 7.1


def test_round_half_up_tenth():
    assert aivss.round_half_up_tenth(8.64) == 8.6
    assert aivss.round_half_up_tenth(8.65) == 8.7
    assert aivss.round_half_up_tenth(9.9238) == 9.9
    assert aivss.round_half_up_tenth(8.8555) == 8.9


def test_severity_band_boundaries():
    assert aivss.severity_band(0.0) == "None"
    assert aivss.severity_band(0.1) == "Low"
    assert aivss.severity_band(3.9) == "Low"
    assert aivss.severity_band(4.0) == "Medium"
    assert aivss.severity_band(6.9) == "Medium"
    assert aivss.severity_band(7.0) == "High"
    assert aivss.severity_band(8.9) == "High"
    assert aivss.severity_band(9.0) == "Critical"
    assert aivss.severity_band(10.0) == "Critical"


def test_threat_multiplier_levels():
    assert aivss.THREAT_MULTIPLIER["attacked"] == 1.00
    assert aivss.THREAT_MULTIPLIER["poc"] == 0.97
    assert aivss.THREAT_MULTIPLIER["unreported"] == 0.50
    # Unreported halves the uplift vs active exploitation.
    a_att = aivss.aars(5.8, EX_3_6_6, thm="attacked")
    a_unr = aivss.aars(5.8, EX_3_6_6, thm="unreported")
    assert a_unr == pytest.approx(a_att * 0.50, abs=1e-9)


def test_mitigation_factor_levels_and_floor():
    assert aivss.MITIGATION_FACTOR["none"] == 1.00
    assert aivss.MITIGATION_FACTOR["partial"] == 0.83
    assert aivss.MITIGATION_FACTOR["strong"] == 0.67
    strong = aivss.aivss(8.7, EX_3_6_2, mitigation="strong")
    weak = aivss.aivss(8.7, EX_3_6_2, mitigation="none")
    assert strong < weak


def test_aivss_never_exceeds_10():
    full = dict.fromkeys(aivss.FACTORS, 1.0)
    assert aivss.aivss(9.4, full, thm="attacked", mitigation="none") <= 10.0


def test_factor_validation():
    bad = dict(EX_3_6_1)
    bad["autonomy"] = 0.3
    with pytest.raises(ValueError):
        aivss.factor_sum(bad)
    with pytest.raises(ValueError):
        aivss.factor_sum({"autonomy": 1.0})  # missing factors


def test_score_finding_end_to_end_and_requires_cvss4_vector():
    s = aivss.score_finding(
        name="demo",
        cvss_base=5.8,
        cvss_vector="CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N",
        agentic_factors=EX_3_6_6,
        notes="n/a",
    )
    assert s.aivss_score == 8.9
    assert s.severity == "High"
    assert s.factor_sum == 7.5
    d = s.to_dict()
    assert d["framework"] == "OWASP AIVSS-Agentic"
    assert d["spec_version"] == "v0.8"
    assert d["cvss_v4_base"] == 5.8
    assert d["aivss_score"] == 8.9
    with pytest.raises(ValueError):
        aivss.score_finding(
            name="x", cvss_base=5.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            agentic_factors=EX_3_6_6,
        )
