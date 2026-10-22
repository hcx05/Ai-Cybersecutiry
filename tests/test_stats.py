"""Tests for controller.stats.wilson_interval."""

import pytest

from controller.stats import wilson_interval, Z_95


def test_wilson_full_success_small_n():
    ci = wilson_interval(30, 30)
    assert ci.point == 1.0
    assert ci.high == 1.0
    # Wilson does not degenerate to a zero-width interval at p=1.
    assert 0.88 < ci.low < 0.90


def test_wilson_zero_success_small_n():
    ci = wilson_interval(0, 10)
    assert ci.point == 0.0
    assert ci.low == 0.0
    assert 0.27 < ci.high < 0.29


def test_wilson_half():
    ci = wilson_interval(5, 10)
    assert ci.point == 0.5
    # symmetric about 0.5 for p=0.5
    assert abs((ci.low + ci.high) / 2 - 0.5) < 1e-9
    assert 0.23 < ci.low < 0.25
    assert 0.75 < ci.high < 0.77


def test_wilson_n_zero():
    ci = wilson_interval(0, 0)
    assert ci.point == 0.0
    assert ci.low == 0.0
    assert ci.high == 1.0


def test_wilson_bounds_clamped_to_unit_interval():
    ci = wilson_interval(10, 10)
    assert 0.0 <= ci.low <= ci.high <= 1.0


def test_wilson_rejects_bad_counts():
    with pytest.raises(ValueError):
        wilson_interval(11, 10)
    with pytest.raises(ValueError):
        wilson_interval(-1, 10)


def test_wilson_z_default_is_95():
    ci = wilson_interval(5, 10)
    ci_explicit = wilson_interval(5, 10, z=Z_95)
    assert ci.low == ci_explicit.low
    assert ci.high == ci_explicit.high


def test_as_pct_formatting():
    ci = wilson_interval(30, 30)
    s = ci.as_pct()
    assert s.startswith("100.0%")
    assert "[" in s and "]" in s
