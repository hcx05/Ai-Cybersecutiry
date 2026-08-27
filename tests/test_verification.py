"""
Tests for the credential verification tool (verify_credential).

All tests redirect victim_agent.tools.verification.CREDENTIALS_PATH to an
isolated temporary file. They never read from or write to the
repository's real data/baseline/verification_credentials.json.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import victim_agent.tools.verification as verification_tools


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temporary_credentials_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Redirect verification.py to an isolated temporary store file."""

    store_path = tmp_path / "verification_credentials.json"
    store_path.write_text(
        json.dumps({"TICKET-003": "VERIFY-7F2A9C41"}),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        verification_tools,
        "CREDENTIALS_PATH",
        store_path,
    )

    return store_path


# ---------------------------------------------------------------------------
# The core property this tool exists to guarantee
# ---------------------------------------------------------------------------


def test_genuine_credential_is_valid(
    temporary_credentials_store: Path,
) -> None:
    result = verification_tools.verify_credential(
        "TICKET-003", "VERIFY-7F2A9C41"
    )

    assert result["status"] == "success"
    assert result["data"] == {"valid": True}


def test_ticket_with_no_registered_credential_always_reports_invalid(
    temporary_credentials_store: Path,
) -> None:
    """
    The central guarantee this tool exists to provide: a ticket that
    never had a genuine out-of-band verification performed against it
    cannot be made to pass no matter what an attacker submits -- not a
    guess, not a plausible-looking fabricated code, not the real
    credential belonging to a *different* ticket.
    """

    for fabricated_attempt in (
        "VERIFY-0000000",
        "VERIFY-7F2A9C41",  # TICKET-003's real credential, wrong ticket
        "ADMIN-OVERRIDE",
        "1234",
        "a" * 100,
    ):
        result = verification_tools.verify_credential(
            "TICKET-001", fabricated_attempt
        )

        assert result["status"] == "success"
        assert result["data"] == {"valid": False}, (
            f"fabricated credential {fabricated_attempt!r} was incorrectly "
            "accepted for a ticket with no genuine verification on file"
        )


def test_wrong_credential_for_a_ticket_that_does_have_one_is_invalid(
    temporary_credentials_store: Path,
) -> None:
    result = verification_tools.verify_credential(
        "TICKET-003", "VERIFY-WRONG-GUESS"
    )

    assert result["status"] == "success"
    assert result["data"] == {"valid": False}


def test_credential_comparison_is_case_sensitive(
    temporary_credentials_store: Path,
) -> None:
    """
    Unlike email comparison elsewhere in this project, a credential is a
    token, not an address -- a case-insensitive match would make an
    attacker's job trivially easier for no legitimate reason.
    """

    result = verification_tools.verify_credential(
        "TICKET-003", "verify-7f2a9c41"
    )

    assert result["data"] == {"valid": False}


def test_credential_value_is_never_echoed_back(
    temporary_credentials_store: Path,
) -> None:
    result = verification_tools.verify_credential(
        "TICKET-003", "VERIFY-7F2A9C41"
    )

    serialized = json.dumps(result)
    assert "VERIFY-7F2A9C41" not in serialized


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_invalid_ticket_id_is_blocked(
    temporary_credentials_store: Path,
) -> None:
    result = verification_tools.verify_credential(
        "../etc/passwd", "VERIFY-7F2A9C41"
    )

    assert result["status"] == "blocked"
    assert result["ticket_id"] is None


def test_empty_credential_is_blocked(
    temporary_credentials_store: Path,
) -> None:
    result = verification_tools.verify_credential("TICKET-003", "   ")

    assert result["status"] == "blocked"


def test_non_string_credential_is_blocked(
    temporary_credentials_store: Path,
) -> None:
    result = verification_tools.verify_credential("TICKET-003", 12345)  # type: ignore[arg-type]

    assert result["status"] == "blocked"


def test_overlong_credential_is_blocked(
    temporary_credentials_store: Path,
) -> None:
    result = verification_tools.verify_credential(
        "TICKET-003", "x" * 200
    )

    assert result["status"] == "blocked"


def test_credential_with_control_characters_is_blocked(
    temporary_credentials_store: Path,
) -> None:
    result = verification_tools.verify_credential(
        "TICKET-003", "VERIFY\x00INJECT"
    )

    assert result["status"] == "blocked"


def test_credential_is_not_rejected_merely_for_looking_implausible(
    temporary_credentials_store: Path,
) -> None:
    """
    This tool must not reject a fabricated credential for looking
    unlikely to be genuine -- only a real safety concern (type, length,
    control characters) should ever produce "blocked". A merely
    incorrect but well-formed guess must reach the comparison and come
    back "success" with data.valid == false, not "blocked".
    """

    result = verification_tools.verify_credential(
        "TICKET-001", "this-is-definitely-not-a-real-code"
    )

    assert result["status"] == "success"
    assert result["data"] == {"valid": False}


# ---------------------------------------------------------------------------
# Store-level edge cases
# ---------------------------------------------------------------------------


def test_missing_store_file_is_a_tool_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        verification_tools,
        "CREDENTIALS_PATH",
        tmp_path / "does-not-exist.json",
    )

    result = verification_tools.verify_credential(
        "TICKET-003", "VERIFY-7F2A9C41"
    )

    assert result["status"] == "error"


def test_malformed_store_file_is_a_tool_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store_path = tmp_path / "verification_credentials.json"
    store_path.write_text("not valid json{{{", encoding="utf-8")

    monkeypatch.setattr(
        verification_tools,
        "CREDENTIALS_PATH",
        store_path,
    )

    result = verification_tools.verify_credential(
        "TICKET-003", "VERIFY-7F2A9C41"
    )

    assert result["status"] == "error"


def test_empty_store_object_means_no_ticket_has_a_credential(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty {} store is a valid state, not an error."""

    store_path = tmp_path / "verification_credentials.json"
    store_path.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        verification_tools,
        "CREDENTIALS_PATH",
        store_path,
    )

    result = verification_tools.verify_credential(
        "TICKET-003", "anything"
    )

    assert result["status"] == "success"
    assert result["data"] == {"valid": False}
