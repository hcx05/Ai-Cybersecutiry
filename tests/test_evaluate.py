"""
Tests for controller/evaluate.py's success-within-N-rounds curve.

Fixtures write raw round/summary log JSON directly (the same shape
attack_agent.agent.run_campaign() writes via _write_round_log /
_write_campaign_log) rather than running a real campaign, so these tests
stay independent of the Ollama-backed planner/payload-generator/Victim
Agent stack.
"""

from __future__ import annotations

import json

from pathlib import Path
from typing import Any

from controller.evaluate import (
    first_success_round,
    load_campaign_summaries,
    load_round_records,
    success_within_n_curve,
    summarize_goal,
)


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _round_record(
    *,
    round_number: int,
    achieved: bool,
    evaluated: bool = True,
) -> dict[str, Any]:
    return {
        "payload": {"round_number": round_number, "goal_id": "unauthorized_password_reset"},
        "victim_result": {"status": "completed"},
        "delivered_at": "2026-08-05T00:00:00+00:00",
        "oracle_result": {
            "goal_id": "unauthorized_password_reset",
            "evaluated": evaluated,
            "achieved": achieved,
            "evidence": {},
            "reasons": [],
        },
    }


def _write_campaign(
    log_dir: Path,
    *,
    campaign_id: str,
    goal_id: str,
    rounds: list[dict[str, Any]],
    stopped_reason: str,
    max_rounds: int = 12,
) -> None:
    round_filenames = []

    for record in rounds:
        filename = f"{campaign_id}_round_{record['payload']['round_number']}.json"
        _write_json(log_dir / filename, record)
        round_filenames.append(filename)

    summary = {
        "campaign_id": campaign_id,
        "goal": {"goal_id": goal_id},
        "ticket_id": "TICKET-001",
        "max_rounds": max_rounds,
        "rounds_run": len(rounds),
        "stopped_reason": stopped_reason,
        "round_log_filenames": round_filenames,
    }

    _write_json(log_dir / f"{campaign_id}_summary.json", summary)


# ---------------------------------------------------------------------------
# first_success_round / success_within_n_curve (pure functions)
# ---------------------------------------------------------------------------


def test_first_success_round_returns_none_when_never_achieved() -> None:
    records = [
        _round_record(round_number=1, achieved=False),
        _round_record(round_number=2, achieved=False),
    ]

    assert first_success_round(records) is None


def test_first_success_round_returns_first_matching_round_number() -> None:
    records = [
        _round_record(round_number=1, achieved=False),
        _round_record(round_number=2, achieved=True),
        _round_record(round_number=3, achieved=True),
    ]

    assert first_success_round(records) == 2


def test_success_within_n_curve_empty_campaigns_is_zero() -> None:
    curve = success_within_n_curve([], thresholds=(1, 3))
    assert curve == {1: 0.0, 3: 0.0}


def test_success_within_n_curve_computes_cumulative_fractions() -> None:
    # One campaign succeeded on round 1, one on round 5, one never.
    curve = success_within_n_curve([1, 5, None], thresholds=(1, 3, 5, 10))

    assert curve[1] == 1 / 3
    assert curve[3] == 1 / 3
    assert curve[5] == 2 / 3
    assert curve[10] == 2 / 3


# ---------------------------------------------------------------------------
# Loading logs from disk
# ---------------------------------------------------------------------------


def test_load_campaign_summaries_filters_by_goal_id(tmp_path: Path) -> None:
    _write_campaign(
        tmp_path,
        campaign_id="camp-a",
        goal_id="unauthorized_password_reset",
        rounds=[_round_record(round_number=1, achieved=True)],
        stopped_reason="oracle_success",
    )
    _write_campaign(
        tmp_path,
        campaign_id="camp-b",
        goal_id="leak_system_prompt",
        rounds=[_round_record(round_number=1, achieved=False)],
        stopped_reason="stop_exhausted",
    )

    summaries = load_campaign_summaries(
        log_dir=tmp_path, goal_id="unauthorized_password_reset"
    )

    assert len(summaries) == 1
    assert summaries[0]["campaign_id"] == "camp-a"


def test_load_round_records_sorted_by_round_number(tmp_path: Path) -> None:
    _write_campaign(
        tmp_path,
        campaign_id="camp-a",
        goal_id="unauthorized_password_reset",
        rounds=[
            _round_record(round_number=2, achieved=False),
            _round_record(round_number=1, achieved=False),
        ],
        stopped_reason="max_rounds_reached",
    )

    summaries = load_campaign_summaries(log_dir=tmp_path)
    records = load_round_records(summaries[0], log_dir=tmp_path)

    assert [r["payload"]["round_number"] for r in records] == [1, 2]


# ---------------------------------------------------------------------------
# summarize_goal end to end
# ---------------------------------------------------------------------------


def test_summarize_goal_builds_curve_across_multiple_campaigns(
    tmp_path: Path,
) -> None:
    _write_campaign(
        tmp_path,
        campaign_id="camp-round1",
        goal_id="unauthorized_password_reset",
        rounds=[_round_record(round_number=1, achieved=True)],
        stopped_reason="oracle_success",
    )
    _write_campaign(
        tmp_path,
        campaign_id="camp-round5",
        goal_id="unauthorized_password_reset",
        rounds=[
            _round_record(round_number=n, achieved=(n == 5))
            for n in range(1, 6)
        ],
        stopped_reason="oracle_success",
    )
    _write_campaign(
        tmp_path,
        campaign_id="camp-never",
        goal_id="unauthorized_password_reset",
        rounds=[
            _round_record(round_number=n, achieved=False) for n in range(1, 13)
        ],
        stopped_reason="stop_exhausted",
    )

    report = summarize_goal(
        goal_id="unauthorized_password_reset", log_dir=tmp_path
    )

    assert report["campaigns_evaluated"] == 3
    assert report["success_within_n_rounds"][1] == 1 / 3
    assert report["success_within_n_rounds"][5] == 2 / 3
    assert report["success_within_n_rounds"][10] == 2 / 3
    assert report["ever_succeeded_rate"] == 2 / 3
    # stop_exhausted is present only as a secondary/informational metric,
    # not folded into the success curve above.
    assert report["stop_exhausted_rate_secondary_metric"] == 1 / 3
    assert report["stopped_reason_counts"]["stop_exhausted"] == 1
    assert report["stopped_reason_counts"]["oracle_success"] == 2


def test_summarize_goal_no_campaigns_is_zero_not_an_error(
    tmp_path: Path,
) -> None:
    report = summarize_goal(goal_id="unauthorized_password_reset", log_dir=tmp_path)

    assert report["campaigns_evaluated"] == 0
    assert report["ever_succeeded_rate"] == 0.0
    assert report["success_within_n_rounds"] == {
        1: 0.0,
        3: 0.0,
        5: 0.0,
        10: 0.0,
    }
