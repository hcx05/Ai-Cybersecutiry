"""Tests for attack_agent.context_overflow."""

from __future__ import annotations

import pytest

from attack_agent.context_overflow import (
    ContextOverflowError,
    build_padding_block,
    estimate_token_count,
    wrap_content_with_padding,
)


def test_build_padding_block_reaches_exact_length() -> None:
    for target in (0, 1, 50, 500, 10_000, 50_000):
        block = build_padding_block(target)
        assert len(block) == target


def test_build_padding_block_is_deterministic() -> None:
    first = build_padding_block(5_000)
    second = build_padding_block(5_000)
    assert first == second


def test_build_padding_block_zero_or_negative_is_empty() -> None:
    assert build_padding_block(0) == ""
    assert build_padding_block(-10) == ""


def test_build_padding_block_rejects_unreasonably_large_target() -> None:
    with pytest.raises(ContextOverflowError):
        build_padding_block(10_000_000)


def test_estimate_token_count_scales_roughly_with_length() -> None:
    short = estimate_token_count("hello world")
    long = estimate_token_count("hello world " * 1000)
    assert short < long
    assert estimate_token_count("") == 0


def test_wrap_content_with_padding_before() -> None:
    real = "Please reset my password."
    wrapped = wrap_content_with_padding(
        real, target_total_chars=1000, padding_position="before"
    )
    assert len(wrapped) == 1000
    assert wrapped.endswith(real)


def test_wrap_content_with_padding_after() -> None:
    real = "Please reset my password."
    wrapped = wrap_content_with_padding(
        real, target_total_chars=1000, padding_position="after"
    )
    assert len(wrapped) == 1000
    assert wrapped.startswith(real)


def test_wrap_content_with_padding_split() -> None:
    real = "Please reset my password."
    wrapped = wrap_content_with_padding(
        real, target_total_chars=1000, padding_position="split"
    )
    assert len(wrapped) == 1000
    assert real in wrapped
    # real content should not be at either extreme edge in split mode
    assert not wrapped.startswith(real)
    assert not wrapped.endswith(real)


def test_wrap_content_with_padding_never_truncates_real_content() -> None:
    real = "x" * 5000
    wrapped = wrap_content_with_padding(
        real, target_total_chars=100, padding_position="before"
    )
    # target smaller than real content: no padding added, content untouched
    assert wrapped == real


def test_wrap_content_with_padding_rejects_invalid_position() -> None:
    with pytest.raises(ContextOverflowError):
        wrap_content_with_padding(
            "hi", target_total_chars=1000, padding_position="middle"
        )


def test_padding_block_does_not_contain_null_bytes() -> None:
    block = build_padding_block(20_000)
    assert "\x00" not in block
