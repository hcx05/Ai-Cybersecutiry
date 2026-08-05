"""
Tests for controller/reset_environment.py.

Covers both the whole-environment reset (reset_environment) used before a
campaign, and the single-ticket restore (restore_ticket_from_baseline)
used between rounds within a campaign.
"""

from __future__ import annotations

import json

from pathlib import Path
from typing import Any

import pytest

import controller.reset_environment as reset_environment


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


@pytest.fixture
def isolated_directories(tmp_path: Path) -> dict[str, Path]:
    """Build a minimal baseline/runtime directory layout under tmp_path."""

    baseline_tickets = tmp_path / "baseline" / "tickets"
    baseline_knowledge_base = tmp_path / "baseline" / "knowledge_base"
    runtime_inbox = tmp_path / "runtime" / "inbox"
    runtime_knowledge_base = tmp_path / "runtime" / "knowledge_base"
    runtime_accounts = tmp_path / "runtime" / "accounts"

    baseline_tickets.mkdir(parents=True)
    baseline_knowledge_base.mkdir(parents=True)

    _write_json(
        baseline_tickets / "TICKET-001.json",
        {
            "ticket_id": "TICKET-001",
            "subject": "Locked out",
            "description": "Original clean description.",
            "status": "open",
            "notes": [],
        },
    )

    return {
        "baseline_tickets": baseline_tickets,
        "baseline_knowledge_base": baseline_knowledge_base,
        "runtime_inbox": runtime_inbox,
        "runtime_knowledge_base": runtime_knowledge_base,
        "runtime_accounts": runtime_accounts,
    }


# ---------------------------------------------------------------------------
# reset_environment
# ---------------------------------------------------------------------------


def test_reset_environment_clears_and_restores_runtime(
    isolated_directories: dict[str, Path],
) -> None:
    runtime_inbox = isolated_directories["runtime_inbox"]
    runtime_inbox.mkdir(parents=True)

    _write_json(
        runtime_inbox / "TICKET-001.json",
        {
            "ticket_id": "TICKET-001",
            "description": "Contaminated by a previous round.",
            "status": "resolved",
            "notes": [{"author": "victim_agent", "content": "leftover"}],
        },
    )
    _write_json(
        runtime_inbox / "STALE-TICKET.json",
        {"ticket_id": "STALE-TICKET"},
    )

    result = reset_environment.reset_environment(
        baseline_tickets_dir=isolated_directories["baseline_tickets"],
        baseline_knowledge_base_dir=isolated_directories[
            "baseline_knowledge_base"
        ],
        runtime_inbox_dir=runtime_inbox,
        runtime_knowledge_base_dir=isolated_directories[
            "runtime_knowledge_base"
        ],
        runtime_accounts_dir=isolated_directories["runtime_accounts"],
    )

    assert result["status"] == "success"
    assert not (runtime_inbox / "STALE-TICKET.json").exists()

    restored = json.loads(
        (runtime_inbox / "TICKET-001.json").read_text(encoding="utf-8")
    )
    assert restored["description"] == "Original clean description."
    assert restored["status"] == "open"
    assert restored["notes"] == []


def test_reset_environment_rejects_matching_baseline_and_runtime(
    isolated_directories: dict[str, Path],
) -> None:
    with pytest.raises(reset_environment.ResetEnvironmentError):
        reset_environment.reset_environment(
            baseline_tickets_dir=isolated_directories["baseline_tickets"],
            baseline_knowledge_base_dir=isolated_directories[
                "baseline_knowledge_base"
            ],
            runtime_inbox_dir=isolated_directories["baseline_tickets"],
            runtime_knowledge_base_dir=isolated_directories[
                "runtime_knowledge_base"
            ],
            runtime_accounts_dir=isolated_directories["runtime_accounts"],
        )


def test_reset_environment_missing_baseline_fails_loudly(
    isolated_directories: dict[str, Path],
    tmp_path: Path,
) -> None:
    with pytest.raises(reset_environment.ResetEnvironmentError):
        reset_environment.reset_environment(
            baseline_tickets_dir=tmp_path / "does-not-exist",
            baseline_knowledge_base_dir=isolated_directories[
                "baseline_knowledge_base"
            ],
            runtime_inbox_dir=isolated_directories["runtime_inbox"],
            runtime_knowledge_base_dir=isolated_directories[
                "runtime_knowledge_base"
            ],
            runtime_accounts_dir=isolated_directories["runtime_accounts"],
        )


# ---------------------------------------------------------------------------
# restore_ticket_from_baseline
# ---------------------------------------------------------------------------


def test_restore_ticket_overwrites_only_the_named_ticket(
    isolated_directories: dict[str, Path],
) -> None:
    runtime_inbox = isolated_directories["runtime_inbox"]
    runtime_inbox.mkdir(parents=True)

    _write_json(
        runtime_inbox / "TICKET-001.json",
        {
            "ticket_id": "TICKET-001",
            "description": "Round 1 payload landed here.",
            "status": "resolved",
            "notes": [{"author": "employee", "content": "round 1 note"}],
        },
    )
    _write_json(
        runtime_inbox / "TICKET-002.json",
        {"ticket_id": "TICKET-002", "description": "unrelated ticket"},
    )

    result = reset_environment.restore_ticket_from_baseline(
        "TICKET-001",
        baseline_tickets_dir=isolated_directories["baseline_tickets"],
        runtime_inbox_dir=runtime_inbox,
    )

    assert result["status"] == "success"
    assert result["ticket_id"] == "TICKET-001"

    restored = json.loads(
        (runtime_inbox / "TICKET-001.json").read_text(encoding="utf-8")
    )
    assert restored["description"] == "Original clean description."
    assert restored["status"] == "open"
    assert restored["notes"] == []

    # A sibling ticket that was never named must be left untouched.
    untouched = json.loads(
        (runtime_inbox / "TICKET-002.json").read_text(encoding="utf-8")
    )
    assert untouched["description"] == "unrelated ticket"


def test_restore_ticket_missing_baseline_raises(
    isolated_directories: dict[str, Path],
) -> None:
    runtime_inbox = isolated_directories["runtime_inbox"]
    runtime_inbox.mkdir(parents=True)

    with pytest.raises(reset_environment.ResetEnvironmentError):
        reset_environment.restore_ticket_from_baseline(
            "TICKET-DOES-NOT-EXIST",
            baseline_tickets_dir=isolated_directories["baseline_tickets"],
            runtime_inbox_dir=runtime_inbox,
        )


@pytest.mark.parametrize(
    "malicious_ticket_id",
    [
        "../secret",
        "../../etc/passwd",
        "TICKET/001",
        "TICKET 001",
        "",
        "   ",
    ],
)
def test_restore_ticket_rejects_path_traversal_ids(
    isolated_directories: dict[str, Path],
    malicious_ticket_id: str,
) -> None:
    runtime_inbox = isolated_directories["runtime_inbox"]
    runtime_inbox.mkdir(parents=True)

    with pytest.raises(reset_environment.ResetEnvironmentError):
        reset_environment.restore_ticket_from_baseline(
            malicious_ticket_id,
            baseline_tickets_dir=isolated_directories["baseline_tickets"],
            runtime_inbox_dir=runtime_inbox,
        )


def test_restore_ticket_rejects_matching_baseline_and_runtime(
    isolated_directories: dict[str, Path],
) -> None:
    with pytest.raises(reset_environment.ResetEnvironmentError):
        reset_environment.restore_ticket_from_baseline(
            "TICKET-001",
            baseline_tickets_dir=isolated_directories["baseline_tickets"],
            runtime_inbox_dir=isolated_directories["baseline_tickets"],
        )


# ---------------------------------------------------------------------------
# clear_account_reset_log
# ---------------------------------------------------------------------------


def test_clear_account_reset_log_removes_existing_record(
    isolated_directories: dict[str, Path],
) -> None:
    runtime_accounts = isolated_directories["runtime_accounts"]
    runtime_accounts.mkdir(parents=True)

    _write_json(
        runtime_accounts / "TICKET-001.json",
        {"ticket_id": "TICKET-001", "employee_email": "j.tanaka@example.test"},
    )

    result = reset_environment.clear_account_reset_log(
        "TICKET-001",
        runtime_accounts_dir=runtime_accounts,
    )

    assert result["removed"] is True
    assert not (runtime_accounts / "TICKET-001.json").exists()


def test_clear_account_reset_log_no_record_is_a_no_op(
    isolated_directories: dict[str, Path],
) -> None:
    runtime_accounts = isolated_directories["runtime_accounts"]
    runtime_accounts.mkdir(parents=True)

    result = reset_environment.clear_account_reset_log(
        "TICKET-001",
        runtime_accounts_dir=runtime_accounts,
    )

    assert result["removed"] is False


# ---------------------------------------------------------------------------
# audited_reset_environment / manifest hashing
# ---------------------------------------------------------------------------


def test_audited_reset_environment_reports_a_matching_verification(
    isolated_directories: dict[str, Path],
) -> None:
    result = reset_environment.audited_reset_environment(
        baseline_tickets_dir=isolated_directories["baseline_tickets"],
        baseline_knowledge_base_dir=isolated_directories[
            "baseline_knowledge_base"
        ],
        runtime_inbox_dir=isolated_directories["runtime_inbox"],
        runtime_knowledge_base_dir=isolated_directories[
            "runtime_knowledge_base"
        ],
        runtime_accounts_dir=isolated_directories["runtime_accounts"],
    )

    assert result["status"] == "success"
    assert result["verification"]["matches"] is True
    assert "tickets_digest" in result["baseline_manifest"]
    assert "audited_at" in result


def test_build_baseline_manifest_digest_is_stable_across_calls(
    isolated_directories: dict[str, Path],
) -> None:
    first = reset_environment.build_baseline_manifest(
        baseline_tickets_dir=isolated_directories["baseline_tickets"],
        baseline_knowledge_base_dir=isolated_directories[
            "baseline_knowledge_base"
        ],
    )
    second = reset_environment.build_baseline_manifest(
        baseline_tickets_dir=isolated_directories["baseline_tickets"],
        baseline_knowledge_base_dir=isolated_directories[
            "baseline_knowledge_base"
        ],
    )

    assert first["tickets_digest"] == second["tickets_digest"]
    assert first["knowledge_base_digest"] == second["knowledge_base_digest"]


def test_verify_runtime_matches_baseline_detects_drift(
    isolated_directories: dict[str, Path],
) -> None:
    baseline_manifest = reset_environment.build_baseline_manifest(
        baseline_tickets_dir=isolated_directories["baseline_tickets"],
        baseline_knowledge_base_dir=isolated_directories[
            "baseline_knowledge_base"
        ],
    )

    runtime_inbox = isolated_directories["runtime_inbox"]
    runtime_inbox.mkdir(parents=True)

    _write_json(
        runtime_inbox / "TICKET-001.json",
        {
            "ticket_id": "TICKET-001",
            "description": "Drifted away from baseline.",
        },
    )

    report = reset_environment.verify_runtime_matches_baseline(
        baseline_manifest,
        runtime_inbox_dir=runtime_inbox,
        runtime_knowledge_base_dir=isolated_directories[
            "runtime_knowledge_base"
        ],
        runtime_accounts_dir=isolated_directories["runtime_accounts"],
    )

    assert report["matches"] is False
    assert report["tickets_match"] is False
