"""Pins the Phase 2 AIVSS finding scores and validates the CVSS v4.0 calculator
against the AIVSS spec's own worked examples (handbook section 15.1)."""

import pytest

cvss = pytest.importorskip("cvss")
from cvss import CVSS4  # noqa: E402

from experiments.phase2_data_attack import aivss_findings as af  # noqa: E402


# Handbook section 15.1: the CVSS v4.0 inputs must match the official
# calculator / the spec's examples. These three are the spec's worked examples.
@pytest.mark.parametrize("vector,expected", [
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.4),  # 3.6.1
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.7),  # 3.6.2
    ("CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N", 5.8),  # 3.6.6
])
def test_cvss4_matches_aivss_spec_examples(vector, expected):
    assert CVSS4(vector).base_score == expected


def test_factor_sum_is_5_5():
    assert af.aivss.factor_sum(af.VICTIM_FACTORS) == 5.5


def test_f1_is_critical_9_3():
    r = af.score_all()["findings"]["F1"]
    assert r["cvss_v4_base"] == 8.6
    assert r["aivss_score"] == 9.3
    assert r["aivss_severity"] == "Critical"
    assert r["threat_multiplier"] == 0.97
    assert r["mitigation_factor"] == 1.0


def test_f2_is_high_8_6():
    r = af.score_all()["findings"]["F2"]
    assert r["cvss_v4_base"] == 7.0
    assert r["aivss_score"] == 8.6
    assert r["aivss_severity"] == "High"


def test_f1_outranks_f2():
    f = af.score_all()["findings"]
    assert f["F1"]["aivss_score"] > f["F2"]["aivss_score"]


def test_spec_provenance_recorded():
    out = af.score_all()
    assert out["spec_version"] == "v0.8"
    assert out["spec_sha256"].startswith("a2abbd21")
