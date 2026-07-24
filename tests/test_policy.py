"""
Tests for the Victim Agent deterministic tool policy.

These tests verify that:

- Valid tool calls are allowed.
- Unknown tools are blocked.
- Invalid tool-call structures are blocked.
- Ticket IDs are validated.
- Tool arguments must match the exact schema.
- Knowledge-base search parameters are restricted.
- Ticket updates accept only approved statuses and safe notes.
- Allowed results contain normalized arguments.
"""

from __future__ import annotations

import pytest

from victim_agent.policy import (
    is_tool_call_allowed,
    validate_tool_call,
)


# ---------------------------------------------------------------------------
# Top-level tool-call validation
# ---------------------------------------------------------------------------


def test_tool_call_must_be_object() -> None:
    result = validate_tool_call("read_ticket")

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "TOOL_CALL_NOT_OBJECT"
    assert result["arguments"] is None


def test_tool_call_missing_name_is_blocked() -> None:
    result = validate_tool_call(
        {
            "arguments": {
                "ticket_id": "TICKET-001",
            }
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "TOOL_CALL_MISSING_FIELDS"


def test_tool_call_missing_arguments_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "read_ticket",
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "TOOL_CALL_MISSING_FIELDS"


def test_tool_call_with_unexpected_top_level_field_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "read_ticket",
            "arguments": {
                "ticket_id": "TICKET-001",
            },
            "execute_immediately": True,
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "TOOL_CALL_UNEXPECTED_FIELDS"


def test_tool_name_must_be_string() -> None:
    result = validate_tool_call(
        {
            "name": 123,
            "arguments": {},
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "TOOL_NAME_NOT_STRING"


def test_empty_tool_name_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "   ",
            "arguments": {},
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "TOOL_NAME_EMPTY"


def test_unknown_tool_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "restricted_shell",
            "arguments": {
                "command": "ls",
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "TOOL_NOT_ALLOWLISTED"
    assert result["tool_name"] == "restricted_shell"


def test_tool_arguments_must_be_object() -> None:
    result = validate_tool_call(
        {
            "name": "read_ticket",
            "arguments": "TICKET-001",
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "TOOL_ARGUMENTS_NOT_OBJECT"


# ---------------------------------------------------------------------------
# read_ticket validation
# ---------------------------------------------------------------------------


def test_valid_read_ticket_is_allowed() -> None:
    result = validate_tool_call(
        {
            "name": "read_ticket",
            "arguments": {
                "ticket_id": "TICKET-001",
            },
        }
    )

    assert result["decision"] == "allowed"
    assert result["rule_id"] == "READ_TICKET_ALLOWED"
    assert result["tool_name"] == "read_ticket"
    assert result["arguments"] == {
        "ticket_id": "TICKET-001",
    }


def test_read_ticket_normalizes_ticket_id_whitespace() -> None:
    result = validate_tool_call(
        {
            "name": "read_ticket",
            "arguments": {
                "ticket_id": "  TICKET-001  ",
            },
        }
    )

    assert result["decision"] == "allowed"
    assert result["arguments"]["ticket_id"] == "TICKET-001"


@pytest.mark.parametrize(
    "ticket_id",
    [
        "",
        "   ",
        "../TICKET-001",
        "../../etc/passwd",
        "ticket/001",
        r"ticket\001",
        "/etc/passwd",
        "TICKET 001",
        ".",
        "..",
        123,
        None,
    ],
)
def test_invalid_read_ticket_ids_are_blocked(ticket_id: object) -> None:
    result = validate_tool_call(
        {
            "name": "read_ticket",
            "arguments": {
                "ticket_id": ticket_id,
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "READ_TICKET_INVALID_ID"
    assert result["arguments"] is None


def test_read_ticket_missing_ticket_id_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "read_ticket",
            "arguments": {},
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "READ_TICKET_INVALID_ARGUMENT_KEYS"
    assert "ticket_id" in result["reason"]


def test_read_ticket_extra_argument_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "read_ticket",
            "arguments": {
                "ticket_id": "TICKET-001",
                "path": "/etc/passwd",
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "READ_TICKET_INVALID_ARGUMENT_KEYS"
    assert "path" in result["reason"]


def test_ticket_id_longer_than_limit_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "read_ticket",
            "arguments": {
                "ticket_id": "T" * 65,
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "READ_TICKET_INVALID_ID"


# ---------------------------------------------------------------------------
# search_knowledge_base validation
# ---------------------------------------------------------------------------


def test_valid_knowledge_base_search_is_allowed() -> None:
    result = validate_tool_call(
        {
            "name": "search_knowledge_base",
            "arguments": {
                "query": "How should an employee troubleshoot VPN access?",
                "top_k": 3,
            },
        }
    )

    assert result["decision"] == "allowed"
    assert result["rule_id"] == "KB_SEARCH_ALLOWED"
    assert result["tool_name"] == "search_knowledge_base"
    assert result["arguments"] == {
        "query": "How should an employee troubleshoot VPN access?",
        "top_k": 3,
    }


def test_knowledge_base_query_is_normalized() -> None:
    result = validate_tool_call(
        {
            "name": "search_knowledge_base",
            "arguments": {
                "query": "   password reset policy   ",
                "top_k": 2,
            },
        }
    )

    assert result["decision"] == "allowed"
    assert result["arguments"]["query"] == "password reset policy"


@pytest.mark.parametrize("top_k", [1, 2, 3, 4, 5])
def test_allowed_top_k_values(top_k: int) -> None:
    result = validate_tool_call(
        {
            "name": "search_knowledge_base",
            "arguments": {
                "query": "VPN support",
                "top_k": top_k,
            },
        }
    )

    assert result["decision"] == "allowed"
    assert result["arguments"]["top_k"] == top_k


@pytest.mark.parametrize("top_k", [0, -1, 6, 100])
def test_out_of_range_top_k_is_blocked(top_k: int) -> None:
    result = validate_tool_call(
        {
            "name": "search_knowledge_base",
            "arguments": {
                "query": "VPN support",
                "top_k": top_k,
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "KB_SEARCH_TOP_K_OUT_OF_RANGE"


@pytest.mark.parametrize(
    "top_k",
    [
        True,
        False,
        3.0,
        "3",
        None,
    ],
)
def test_non_integer_top_k_is_blocked(top_k: object) -> None:
    result = validate_tool_call(
        {
            "name": "search_knowledge_base",
            "arguments": {
                "query": "VPN support",
                "top_k": top_k,
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "KB_SEARCH_TOP_K_NOT_INTEGER"


@pytest.mark.parametrize("query", ["", "   "])
def test_empty_knowledge_base_query_is_blocked(query: str) -> None:
    result = validate_tool_call(
        {
            "name": "search_knowledge_base",
            "arguments": {
                "query": query,
                "top_k": 3,
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "KB_SEARCH_QUERY_EMPTY"


@pytest.mark.parametrize("query", [123, True, None, ["VPN"]])
def test_non_string_knowledge_base_query_is_blocked(
    query: object,
) -> None:
    result = validate_tool_call(
        {
            "name": "search_knowledge_base",
            "arguments": {
                "query": query,
                "top_k": 3,
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "KB_SEARCH_QUERY_NOT_STRING"


def test_overlong_knowledge_base_query_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "search_knowledge_base",
            "arguments": {
                "query": "A" * 501,
                "top_k": 3,
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "KB_SEARCH_QUERY_TOO_LONG"


def test_query_with_null_byte_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "search_knowledge_base",
            "arguments": {
                "query": "VPN policy\x00hidden content",
                "top_k": 3,
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "KB_SEARCH_QUERY_CONTROL_CHARACTERS"


def test_knowledge_base_search_missing_argument_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "search_knowledge_base",
            "arguments": {
                "query": "VPN support",
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "KB_SEARCH_INVALID_ARGUMENT_KEYS"


def test_knowledge_base_search_extra_argument_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "search_knowledge_base",
            "arguments": {
                "query": "VPN support",
                "top_k": 3,
                "include_unapproved": True,
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "KB_SEARCH_INVALID_ARGUMENT_KEYS"
    assert "include_unapproved" in result["reason"]


# ---------------------------------------------------------------------------
# update_ticket validation
# ---------------------------------------------------------------------------


def test_valid_update_ticket_is_allowed() -> None:
    result = validate_tool_call(
        {
            "name": "update_ticket",
            "arguments": {
                "ticket_id": "TICKET-001",
                "status": "in_progress",
                "note": "Reviewing the employee VPN issue.",
            },
        }
    )

    assert result["decision"] == "allowed"
    assert result["rule_id"] == "UPDATE_TICKET_ALLOWED"
    assert result["tool_name"] == "update_ticket"
    assert result["arguments"] == {
        "ticket_id": "TICKET-001",
        "status": "in_progress",
        "note": "Reviewing the employee VPN issue.",
    }


@pytest.mark.parametrize(
    "status",
    [
        "open",
        "in_progress",
        "resolved",
        "needs_human_review",
    ],
)
def test_allowed_ticket_statuses(status: str) -> None:
    result = validate_tool_call(
        {
            "name": "update_ticket",
            "arguments": {
                "ticket_id": "TICKET-001",
                "status": status,
                "note": "Test support note.",
            },
        }
    )

    assert result["decision"] == "allowed"
    assert result["arguments"]["status"] == status


def test_update_ticket_normalizes_arguments() -> None:
    result = validate_tool_call(
        {
            "name": "update_ticket",
            "arguments": {
                "ticket_id": "  TICKET-001  ",
                "status": "  IN_PROGRESS  ",
                "note": "  Reviewing the VPN issue.  ",
            },
        }
    )

    assert result["decision"] == "allowed"
    assert result["arguments"] == {
        "ticket_id": "TICKET-001",
        "status": "in_progress",
        "note": "Reviewing the VPN issue.",
    }


def test_update_ticket_invalid_ticket_id_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "update_ticket",
            "arguments": {
                "ticket_id": "../../etc/passwd",
                "status": "open",
                "note": "Test note.",
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "UPDATE_TICKET_INVALID_ID"


@pytest.mark.parametrize(
    "status",
    [
        "",
        "closed",
        "deleted",
        "admin_override",
        "pending_approval",
    ],
)
def test_unsupported_ticket_status_is_blocked(status: str) -> None:
    result = validate_tool_call(
        {
            "name": "update_ticket",
            "arguments": {
                "ticket_id": "TICKET-001",
                "status": status,
                "note": "Test support note.",
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "UPDATE_TICKET_STATUS_NOT_ALLOWED"


@pytest.mark.parametrize("status", [123, True, None])
def test_non_string_ticket_status_is_blocked(
    status: object,
) -> None:
    result = validate_tool_call(
        {
            "name": "update_ticket",
            "arguments": {
                "ticket_id": "TICKET-001",
                "status": status,
                "note": "Test support note.",
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "UPDATE_TICKET_STATUS_NOT_STRING"


@pytest.mark.parametrize("note", ["", "   "])
def test_empty_ticket_note_is_blocked(note: str) -> None:
    result = validate_tool_call(
        {
            "name": "update_ticket",
            "arguments": {
                "ticket_id": "TICKET-001",
                "status": "open",
                "note": note,
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "UPDATE_TICKET_NOTE_EMPTY"


@pytest.mark.parametrize("note", [123, True, None, ["note"]])
def test_non_string_ticket_note_is_blocked(note: object) -> None:
    result = validate_tool_call(
        {
            "name": "update_ticket",
            "arguments": {
                "ticket_id": "TICKET-001",
                "status": "open",
                "note": note,
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "UPDATE_TICKET_NOTE_NOT_STRING"


def test_overlong_ticket_note_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "update_ticket",
            "arguments": {
                "ticket_id": "TICKET-001",
                "status": "open",
                "note": "A" * 1_001,
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "UPDATE_TICKET_NOTE_TOO_LONG"


def test_ticket_note_with_null_byte_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "update_ticket",
            "arguments": {
                "ticket_id": "TICKET-001",
                "status": "open",
                "note": "Normal note\x00hidden data",
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "UPDATE_TICKET_NOTE_CONTROL_CHARACTERS"


def test_update_ticket_missing_argument_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "update_ticket",
            "arguments": {
                "ticket_id": "TICKET-001",
                "status": "open",
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "UPDATE_TICKET_INVALID_ARGUMENT_KEYS"


def test_update_ticket_extra_argument_is_blocked() -> None:
    result = validate_tool_call(
        {
            "name": "update_ticket",
            "arguments": {
                "ticket_id": "TICKET-001",
                "status": "resolved",
                "note": "Issue resolved.",
                "delete_ticket": True,
            },
        }
    )

    assert result["decision"] == "blocked"
    assert result["rule_id"] == "UPDATE_TICKET_INVALID_ARGUMENT_KEYS"
    assert "delete_ticket" in result["reason"]


# ---------------------------------------------------------------------------
# Convenience helper
# ---------------------------------------------------------------------------


def test_is_tool_call_allowed_returns_true_for_valid_request() -> None:
    allowed = is_tool_call_allowed(
        {
            "name": "read_ticket",
            "arguments": {
                "ticket_id": "TICKET-001",
            },
        }
    )

    assert allowed is True


def test_is_tool_call_allowed_returns_false_for_blocked_request() -> None:
    allowed = is_tool_call_allowed(
        {
            "name": "shell",
            "arguments": {
                "command": "ls",
            },
        }
    )

    assert allowed is False
