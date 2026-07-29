"""
Tests for the restricted Victim Agent account tool (reset_password).

All tests use temporary directories. They never read from or write to the
repository's real data/runtime directories.

reset_password re-reads the assigned ticket internally to verify that
employee_email matches the ticket's recorded submitted_by field, so these
tests redirect both victim_agent.tools.ticket.INBOX_DIR (the ticket the
tool reads for verification) and victim_agent.tools.account.ACCOUNTS_DIR
(where a successful reset is recorded).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import victim_agent.tools.account as account_tools
import victim_agent.tools.ticket as ticket_tools


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temporary_inbox(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Redirect ticket.py to an isolated temporary inbox."""

    inbox = tmp_path / "inbox"
    inbox.mkdir()

    monkeypatch.setattr(
        ticket_tools,
        "INBOX_DIR",
        inbox.resolve(),
    )

    return inbox


@pytest.fixture
def temporary_accounts_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Redirect account.py to an isolated temporary accounts directory."""

    accounts = tmp_path / "accounts"
    accounts.mkdir()

    monkeypatch.setattr(
        account_tools,
        "ACCOUNTS_DIR",
        accounts.resolve(),
    )

    return accounts


def write_ticket(
    inbox: Path,
    ticket_id: str = "TICKET-001",
    **overrides: Any,
) -> Path:
    """Create one valid ticket fixture."""

    ticket: dict[str, Any] = {
        "ticket_id": ticket_id,
        "subject": "Unable to connect to company VPN",
        "description": (
            "I cannot connect to the company VPN from my laptop."
        ),
        "submitted_by": "employee@example.test",
        "status": "open",
        "created_at": "2026-07-24T08:00:00+00:00",
        "updated_at": "2026-07-24T08:00:00+00:00",
        "notes": [],
    }

    ticket.update(overrides)

    path = inbox / f"{ticket_id}.json"
    path.write_text(
        json.dumps(
            ticket,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    return path


def read_account_log(
    accounts_dir: Path,
    ticket_id: str = "TICKET-001",
) -> dict[str, Any]:
    """Read back a recorded account-reset log entry."""

    return json.loads(
        (accounts_dir / f"{ticket_id}.json").read_text(
            encoding="utf-8"
        )
    )


# ---------------------------------------------------------------------------
# Successful resets
# ---------------------------------------------------------------------------


def test_reset_password_succeeds_when_identity_matches(
    temporary_inbox: Path,
    temporary_accounts_dir: Path,
) -> None:
    write_ticket(temporary_inbox)

    result = account_tools.reset_password(
        ticket_id="TICKET-001",
        employee_email="employee@example.test",
    )

    assert result["status"] == "success"
    assert result["operation"] == "reset_password"
    assert result["ticket_id"] == "TICKET-001"
    assert result["employee_email"] == "employee@example.test"
    assert result["error"] is None
    assert result["data"]["reset_at"]

    record = read_account_log(temporary_accounts_dir)

    assert record["ticket_id"] == "TICKET-001"
    assert record["employee_email"] == "employee@example.test"
    assert record["verified_submitted_by"] == "employee@example.test"
    assert record["reset_at"] == result["data"]["reset_at"]
    assert "password" not in record


def test_reset_password_identity_match_is_case_insensitive(
    temporary_inbox: Path,
    temporary_accounts_dir: Path,
) -> None:
    write_ticket(
        temporary_inbox,
        submitted_by="Employee@Example.Test",
    )

    result = account_tools.reset_password(
        ticket_id="TICKET-001",
        employee_email="employee@EXAMPLE.test",
    )

    assert result["status"] == "success"


def test_reset_password_trims_whitespace_in_email(
    temporary_inbox: Path,
    temporary_accounts_dir: Path,
) -> None:
    write_ticket(temporary_inbox)

    result = account_tools.reset_password(
        ticket_id="TICKET-001",
        employee_email="  employee@example.test  ",
    )

    assert result["status"] == "success"
    assert result["employee_email"] == "employee@example.test"


# ---------------------------------------------------------------------------
# Identity mismatch
# ---------------------------------------------------------------------------


def test_reset_password_blocked_when_email_does_not_match_submitter(
    temporary_inbox: Path,
    temporary_accounts_dir: Path,
) -> None:
    write_ticket(
        temporary_inbox,
        submitted_by="employee@example.test",
    )

    result = account_tools.reset_password(
        ticket_id="TICKET-001",
        employee_email="attacker@example.test",
    )

    assert result["status"] == "blocked"
    assert "does not match" in result["error"]
    assert not (temporary_accounts_dir / "TICKET-001.json").exists()


def test_reset_password_blocked_when_ticket_has_no_submitter(
    temporary_inbox: Path,
    temporary_accounts_dir: Path,
) -> None:
    write_ticket(
        temporary_inbox,
        submitted_by="",
    )

    result = account_tools.reset_password(
        ticket_id="TICKET-001",
        employee_email="employee@example.test",
    )

    assert result["status"] == "blocked"
    assert not (temporary_accounts_dir / "TICKET-001.json").exists()


# ---------------------------------------------------------------------------
# Ticket lookup failures propagate
# ---------------------------------------------------------------------------


def test_reset_password_returns_not_found_for_missing_ticket(
    temporary_inbox: Path,
    temporary_accounts_dir: Path,
) -> None:
    result = account_tools.reset_password(
        ticket_id="TICKET-404",
        employee_email="employee@example.test",
    )

    assert result["status"] == "not_found"
    assert not (temporary_accounts_dir / "TICKET-404.json").exists()


def test_reset_password_returns_error_for_malformed_ticket(
    temporary_inbox: Path,
    temporary_accounts_dir: Path,
) -> None:
    path = temporary_inbox / "TICKET-001.json"
    path.write_text(
        "{ invalid json",
        encoding="utf-8",
    )

    result = account_tools.reset_password(
        ticket_id="TICKET-001",
        employee_email="employee@example.test",
    )

    assert result["status"] == "error"
    assert not (temporary_accounts_dir / "TICKET-001.json").exists()


# ---------------------------------------------------------------------------
# Argument validation: ticket_id
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ticket_id",
    [
        "",
        "   ",
        "../TICKET-001",
        "../../etc/passwd",
        "/etc/passwd",
        "ticket/001",
        r"ticket\001",
        "TICKET 001",
        ".",
        "..",
    ],
)
def test_invalid_ticket_ids_are_blocked(
    temporary_inbox: Path,
    temporary_accounts_dir: Path,
    ticket_id: str,
) -> None:
    result = account_tools.reset_password(
        ticket_id=ticket_id,
        employee_email="employee@example.test",
    )

    assert result["status"] == "blocked"
    assert result["ticket_id"] is None
    assert "Access denied" in result["error"]


@pytest.mark.parametrize(
    "ticket_id",
    [
        None,
        123,
        True,
        ["TICKET-001"],
    ],
)
def test_non_string_ticket_ids_are_blocked(
    temporary_inbox: Path,
    temporary_accounts_dir: Path,
    ticket_id: object,
) -> None:
    result = account_tools.reset_password(
        ticket_id=ticket_id,  # type: ignore[arg-type]
        employee_email="employee@example.test",
    )

    assert result["status"] == "blocked"
    assert result["ticket_id"] is None


# ---------------------------------------------------------------------------
# Argument validation: employee_email
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "employee_email",
    [
        "",
        "   ",
        "not-an-email",
        "missing-domain@",
        "@missing-local.test",
        "double@@example.test",
        "no-tld@example",
    ],
)
def test_invalid_employee_email_formats_are_blocked(
    temporary_inbox: Path,
    temporary_accounts_dir: Path,
    employee_email: str,
) -> None:
    write_ticket(temporary_inbox)

    result = account_tools.reset_password(
        ticket_id="TICKET-001",
        employee_email=employee_email,
    )

    assert result["status"] == "blocked"
    assert not (temporary_accounts_dir / "TICKET-001.json").exists()


@pytest.mark.parametrize(
    "employee_email",
    [
        None,
        123,
        True,
        ["employee@example.test"],
    ],
)
def test_non_string_employee_email_is_blocked(
    temporary_inbox: Path,
    temporary_accounts_dir: Path,
    employee_email: object,
) -> None:
    write_ticket(temporary_inbox)

    result = account_tools.reset_password(
        ticket_id="TICKET-001",
        employee_email=employee_email,  # type: ignore[arg-type]
    )

    assert result["status"] == "blocked"


def test_overlong_employee_email_is_blocked(
    temporary_inbox: Path,
    temporary_accounts_dir: Path,
) -> None:
    write_ticket(temporary_inbox)

    overlong_email = (
        ("a" * (account_tools.MAX_EMAIL_LENGTH))
        + "@example.test"
    )

    result = account_tools.reset_password(
        ticket_id="TICKET-001",
        employee_email=overlong_email,
    )

    assert result["status"] == "blocked"
    assert "character limit" in result["error"]


def test_employee_email_with_null_byte_is_blocked(
    temporary_inbox: Path,
    temporary_accounts_dir: Path,
) -> None:
    write_ticket(temporary_inbox)

    result = account_tools.reset_password(
        ticket_id="TICKET-001",
        employee_email="employee@example.test\x00hidden",
    )

    assert result["status"] == "blocked"
    assert "control characters" in result["error"]


# ---------------------------------------------------------------------------
# Runtime accounts directory handling
# ---------------------------------------------------------------------------


def test_missing_accounts_directory_is_not_created_and_returns_error(
    temporary_inbox: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    The account-reset log directory must already exist. A missing
    directory is reported as a structured error instead of being
    silently created, mirroring the ticket inbox and knowledge-base
    directories.
    """

    write_ticket(temporary_inbox)

    missing_accounts_dir = (
        tmp_path / "accounts_that_does_not_exist"
    )

    monkeypatch.setattr(
        account_tools,
        "ACCOUNTS_DIR",
        missing_accounts_dir,
    )

    result = account_tools.reset_password(
        ticket_id="TICKET-001",
        employee_email="employee@example.test",
    )

    assert result["status"] == "error"
    assert not missing_accounts_dir.exists()
