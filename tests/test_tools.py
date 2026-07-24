"""
Tests for the restricted Victim Agent ticket tools.

The tests use a temporary inbox directory so they never modify the real
data/runtime/inbox directory.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import victim_agent.tools.ticket as ticket_tools
import victim_agent.tools.knowledge_base as knowledge_base_tools

@pytest.fixture
def temporary_inbox(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """
    Redirect ticket.py to a temporary inbox for each test.

    pytest automatically removes the directory after the test finishes.
    """

    inbox = tmp_path / "inbox"
    inbox.mkdir()

    monkeypatch.setattr(
        ticket_tools,
        "INBOX_DIR",
        inbox.resolve(),
    )

    return inbox


def write_ticket(
    inbox: Path,
    ticket_id: str = "TICKET-001",
    **overrides: Any,
) -> Path:
    """Create a valid ticket fixture inside the temporary inbox."""

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
        json.dumps(ticket, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    return path


# ---------------------------------------------------------------------------
# read_ticket
# ---------------------------------------------------------------------------


def test_read_existing_ticket_succeeds(
    temporary_inbox: Path,
) -> None:
    write_ticket(temporary_inbox)

    result = ticket_tools.read_ticket("TICKET-001")

    assert result["status"] == "success"
    assert result["operation"] == "read_ticket"
    assert result["ticket_id"] == "TICKET-001"
    assert result["error"] is None

    ticket = result["data"]["ticket"]

    assert ticket["ticket_id"] == "TICKET-001"
    assert ticket["subject"] == "Unable to connect to company VPN"
    assert ticket["status"] == "open"
    assert ticket["notes"] == []


def test_read_ticket_adds_default_optional_fields(
    temporary_inbox: Path,
) -> None:
    path = temporary_inbox / "TICKET-001.json"

    path.write_text(
        json.dumps(
            {
                "subject": "VPN problem",
                "description": "VPN is unavailable.",
            }
        ),
        encoding="utf-8",
    )

    result = ticket_tools.read_ticket("TICKET-001")

    assert result["status"] == "success"

    ticket = result["data"]["ticket"]

    assert ticket["ticket_id"] == "TICKET-001"
    assert ticket["status"] == "open"
    assert ticket["notes"] == []


def test_read_missing_ticket_returns_not_found(
    temporary_inbox: Path,
) -> None:
    result = ticket_tools.read_ticket("TICKET-404")

    assert result["status"] == "not_found"
    assert result["operation"] == "read_ticket"
    assert result["ticket_id"] == "TICKET-404"
    assert result["data"] is None
    assert result["error"] == "The requested ticket does not exist."


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
    ticket_id: str,
) -> None:
    result = ticket_tools.read_ticket(ticket_id)

    assert result["status"] == "blocked"
    assert result["operation"] == "read_ticket"
    assert result["ticket_id"] is None
    assert result["data"] is None
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
    ticket_id: object,
) -> None:
    result = ticket_tools.read_ticket(ticket_id)  # type: ignore[arg-type]

    assert result["status"] == "blocked"
    assert result["ticket_id"] is None
    assert result["data"] is None


def test_ticket_id_longer_than_limit_is_blocked(
    temporary_inbox: Path,
) -> None:
    result = ticket_tools.read_ticket("T" * 65)

    assert result["status"] == "blocked"
    assert result["data"] is None


def test_invalid_json_ticket_returns_error(
    temporary_inbox: Path,
) -> None:
    path = temporary_inbox / "TICKET-001.json"
    path.write_text("{ invalid json", encoding="utf-8")

    result = ticket_tools.read_ticket("TICKET-001")

    assert result["status"] == "error"
    assert result["data"] is None
    assert result["error"] == (
        "Ticket file does not contain valid JSON."
    )


def test_ticket_json_must_be_object(
    temporary_inbox: Path,
) -> None:
    path = temporary_inbox / "TICKET-001.json"
    path.write_text(
        json.dumps(["not", "an", "object"]),
        encoding="utf-8",
    )

    result = ticket_tools.read_ticket("TICKET-001")

    assert result["status"] == "error"
    assert result["error"] == (
        "Ticket JSON must contain one object."
    )


def test_stored_ticket_id_must_match_requested_id(
    temporary_inbox: Path,
) -> None:
    write_ticket(temporary_inbox)

    path = temporary_inbox / "TICKET-001.json"
    ticket = json.loads(path.read_text(encoding="utf-8"))
    ticket["ticket_id"] = "TICKET-999"
    path.write_text(
        json.dumps(ticket),
        encoding="utf-8",
    )

    result = ticket_tools.read_ticket("TICKET-001")

    assert result["status"] == "error"
    assert result["error"] == (
        "Ticket ID does not match the requested ticket."
    )

def test_ticket_notes_must_be_list(
    temporary_inbox: Path,
) -> None:
    write_ticket(
        temporary_inbox,
        notes="not-a-list",
    )

    result = ticket_tools.read_ticket("TICKET-001")

    assert result["status"] == "error"
    assert result["error"] == (
        "Ticket field 'notes' must be a list."
    )


def test_ticket_path_must_be_regular_file(
    temporary_inbox: Path,
) -> None:
    ticket_directory = temporary_inbox / "TICKET-001.json"
    ticket_directory.mkdir()

    result = ticket_tools.read_ticket("TICKET-001")

    assert result["status"] == "error"
    assert result["error"] == (
        "Requested ticket path is not a regular file."
    )


def test_oversized_ticket_file_returns_error(
    temporary_inbox: Path,
) -> None:
    path = temporary_inbox / "TICKET-001.json"
    path.write_text(
        "A" * (ticket_tools.MAX_TICKET_FILE_SIZE + 1),
        encoding="utf-8",
    )

    result = ticket_tools.read_ticket("TICKET-001")

    assert result["status"] == "error"
    assert result["error"] == (
        "Ticket file exceeds the maximum allowed size."
    )


# ---------------------------------------------------------------------------
# update_ticket
# ---------------------------------------------------------------------------


def test_update_ticket_changes_status_and_adds_note(
    temporary_inbox: Path,
) -> None:
    write_ticket(temporary_inbox)

    result = ticket_tools.update_ticket(
        ticket_id="TICKET-001",
        status="in_progress",
        note="Reviewing the employee VPN issue.",
    )

    assert result["status"] == "success"
    assert result["operation"] == "update_ticket"
    assert result["ticket_id"] == "TICKET-001"
    assert result["error"] is None

    assert result["data"]["new_status"] == "in_progress"
    assert result["data"]["note_added"] is True
    assert result["data"]["updated_at"]

    stored_ticket = json.loads(
        (
            temporary_inbox / "TICKET-001.json"
        ).read_text(encoding="utf-8")
    )

    assert stored_ticket["status"] == "in_progress"
    assert len(stored_ticket["notes"]) == 1

    note = stored_ticket["notes"][0]

    assert note["author"] == "victim_agent"
    assert note["content"] == (
        "Reviewing the employee VPN issue."
    )
    assert note["timestamp"] == stored_ticket["updated_at"]


def test_update_ticket_preserves_existing_fields(
    temporary_inbox: Path,
) -> None:
    write_ticket(
        temporary_inbox,
        priority="medium",
        department="engineering",
    )

    result = ticket_tools.update_ticket(
        ticket_id="TICKET-001",
        status="resolved",
        note="VPN configuration was corrected.",
    )

    assert result["status"] == "success"

    stored_ticket = json.loads(
        (
            temporary_inbox / "TICKET-001.json"
        ).read_text(encoding="utf-8")
    )

    assert stored_ticket["subject"] == (
        "Unable to connect to company VPN"
    )
    assert stored_ticket["description"] == (
        "I cannot connect to the company VPN from my laptop."
    )
    assert stored_ticket["priority"] == "medium"
    assert stored_ticket["department"] == "engineering"


def test_update_ticket_preserves_existing_notes(
    temporary_inbox: Path,
) -> None:
    existing_note = {
        "author": "human_agent",
        "timestamp": "2026-07-24T09:00:00+00:00",
        "content": "Initial review completed.",
    }

    write_ticket(
        temporary_inbox,
        notes=[existing_note],
    )

    result = ticket_tools.update_ticket(
        ticket_id="TICKET-001",
        status="in_progress",
        note="Victim Agent is reviewing the issue.",
    )

    assert result["status"] == "success"

    stored_ticket = json.loads(
        (
            temporary_inbox / "TICKET-001.json"
        ).read_text(encoding="utf-8")
    )

    assert len(stored_ticket["notes"]) == 2
    assert stored_ticket["notes"][0] == existing_note
    assert stored_ticket["notes"][1]["author"] == "victim_agent"


@pytest.mark.parametrize(
    "status",
    [
        "open",
        "in_progress",
        "resolved",
        "needs_human_review",
    ],
)
def test_update_ticket_accepts_allowed_statuses(
    temporary_inbox: Path,
    status: str,
) -> None:
    write_ticket(temporary_inbox)

    result = ticket_tools.update_ticket(
        ticket_id="TICKET-001",
        status=status,
        note="Valid support note.",
    )

    assert result["status"] == "success"
    assert result["data"]["new_status"] == status


def test_update_ticket_normalizes_status_and_note(
    temporary_inbox: Path,
) -> None:
    write_ticket(temporary_inbox)

    result = ticket_tools.update_ticket(
        ticket_id="TICKET-001",
        status="  IN_PROGRESS  ",
        note="  Reviewing the VPN issue.  ",
    )

    assert result["status"] == "success"
    assert result["data"]["new_status"] == "in_progress"

    stored_ticket = json.loads(
        (
            temporary_inbox / "TICKET-001.json"
        ).read_text(encoding="utf-8")
    )

    assert stored_ticket["notes"][0]["content"] == (
        "Reviewing the VPN issue."
    )


@pytest.mark.parametrize(
    "status",
    [
        "",
        "closed",
        "deleted",
        "admin_override",
        "pending",
    ],
)
def test_update_ticket_blocks_invalid_status(
    temporary_inbox: Path,
    status: str,
) -> None:
    write_ticket(temporary_inbox)

    result = ticket_tools.update_ticket(
        ticket_id="TICKET-001",
        status=status,
        note="Test note.",
    )

    assert result["status"] == "blocked"
    assert result["operation"] == "update_ticket"
    assert result["data"] is None
    assert "Unsupported ticket status" in result["error"]


@pytest.mark.parametrize(
    "note",
    [
        "",
        "   ",
    ],
)
def test_update_ticket_blocks_empty_note(
    temporary_inbox: Path,
    note: str,
) -> None:
    write_ticket(temporary_inbox)

    result = ticket_tools.update_ticket(
        ticket_id="TICKET-001",
        status="open",
        note=note,
    )

    assert result["status"] == "blocked"
    assert result["error"] == "Ticket note cannot be empty."


def test_update_ticket_blocks_overlong_note(
    temporary_inbox: Path,
) -> None:
    write_ticket(temporary_inbox)

    result = ticket_tools.update_ticket(
        ticket_id="TICKET-001",
        status="open",
        note="A" * (ticket_tools.MAX_NOTE_LENGTH + 1),
    )

    assert result["status"] == "blocked"
    assert "character limit" in result["error"]


def test_update_ticket_blocks_path_traversal_id(
    temporary_inbox: Path,
) -> None:
    write_ticket(temporary_inbox)

    result = ticket_tools.update_ticket(
        ticket_id="../../etc/passwd",
        status="resolved",
        note="Attempted unsafe update.",
    )

    assert result["status"] == "blocked"
    assert result["ticket_id"] is None
    assert result["data"] is None
    assert "Access denied" in result["error"]


def test_update_missing_ticket_returns_not_found(
    temporary_inbox: Path,
) -> None:
    result = ticket_tools.update_ticket(
        ticket_id="TICKET-404",
        status="resolved",
        note="This ticket does not exist.",
    )

    assert result["status"] == "not_found"
    assert result["ticket_id"] == "TICKET-404"
    assert result["data"] is None


def test_update_ticket_with_invalid_json_returns_error(
    temporary_inbox: Path,
) -> None:
    path = temporary_inbox / "TICKET-001.json"
    path.write_text("{ invalid json", encoding="utf-8")

    result = ticket_tools.update_ticket(
        ticket_id="TICKET-001",
        status="resolved",
        note="Test note.",
    )

    assert result["status"] == "error"
    assert result["error"] == (
        "Ticket file does not contain valid JSON."
    )


def test_update_ticket_with_non_string_status_returns_error(
    temporary_inbox: Path,
) -> None:
    write_ticket(temporary_inbox)

    result = ticket_tools.update_ticket(
        ticket_id="TICKET-001",
        status=123,  # type: ignore[arg-type]
        note="Test note.",
    )

    assert result["status"] == "error"
    assert result["error"] == (
        "Ticket status must be a string."
    )


def test_update_ticket_with_non_string_note_returns_error(
    temporary_inbox: Path,
) -> None:
    write_ticket(temporary_inbox)

    result = ticket_tools.update_ticket(
        ticket_id="TICKET-001",
        status="open",
        note=123,  # type: ignore[arg-type]
    )

    assert result["status"] == "error"
    assert result["error"] == (
        "Ticket note must be a string."
    )


def test_update_ticket_result_can_be_read_again(
    temporary_inbox: Path,
) -> None:
    write_ticket(temporary_inbox)

    update_result = ticket_tools.update_ticket(
        ticket_id="TICKET-001",
        status="needs_human_review",
        note="Suspicious instructions were detected in the ticket.",
    )

    assert update_result["status"] == "success"

    read_result = ticket_tools.read_ticket("TICKET-001")

    assert read_result["status"] == "success"

    ticket = read_result["data"]["ticket"]

    assert ticket["status"] == "needs_human_review"
    assert len(ticket["notes"]) == 1
    assert ticket["notes"][0]["content"] == (
        "Suspicious instructions were detected in the ticket."
    )


# ---------------------------------------------------------------------------
# Knowledge-base test helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def temporary_knowledge_base(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """
    Redirect knowledge_base.py to a temporary directory.

    Tests never read or modify the real:
        data/runtime/knowledge_base/
    """

    knowledge_base = tmp_path / "knowledge_base"
    knowledge_base.mkdir()

    monkeypatch.setattr(
        knowledge_base_tools,
        "KNOWLEDGE_BASE_DIR",
        knowledge_base.resolve(),
    )

    return knowledge_base


def write_knowledge_article(
    knowledge_base: Path,
    article_id: str = "KB-VPN-001",
    *,
    filename: str | None = None,
    **overrides: Any,
) -> Path:
    """Create a valid knowledge-base article for testing."""

    article: dict[str, Any] = {
        "article_id": article_id,
        "title": "Company VPN Connection Troubleshooting",
        "content": (
            "Employees who cannot connect to the company VPN should "
            "verify their internet connection, restart the VPN client, "
            "and contact the internal IT support desk if the issue continues."
        ),
        "approved": True,
        "category": "network",
        "source": "internal_it",
    }

    article.update(overrides)

    output_filename = filename or f"{article_id}.json"
    path = knowledge_base / output_filename

    path.write_text(
        json.dumps(
            article,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    return path


# ---------------------------------------------------------------------------
# search_knowledge_base
# ---------------------------------------------------------------------------


def test_knowledge_base_search_finds_approved_article(
    temporary_knowledge_base: Path,
) -> None:
    write_knowledge_article(temporary_knowledge_base)

    result = knowledge_base_tools.search_knowledge_base(
        query="VPN connection problem",
        top_k=3,
    )

    assert result["status"] == "success"
    assert result["operation"] == "search_knowledge_base"
    assert result["query"] == "VPN connection problem"
    assert result["top_k"] == 3
    assert result["result_count"] == 1
    assert result["scanned_articles"] == 1
    assert result["eligible_articles"] == 1
    assert result["warnings"] == []
    assert result["error"] is None

    article = result["results"][0]

    assert article["article_id"] == "KB-VPN-001"
    assert article["approved"] is True
    assert article["category"] == "network"
    assert article["source"] == "internal_it"
    assert article["score"] > 0
    assert "vpn" in article["matched_terms"]


def test_knowledge_base_search_normalizes_query(
    temporary_knowledge_base: Path,
) -> None:
    write_knowledge_article(temporary_knowledge_base)

    result = knowledge_base_tools.search_knowledge_base(
        query="   VPN connection   ",
        top_k=3,
    )

    assert result["status"] == "success"
    assert result["query"] == "VPN connection"


def test_unapproved_knowledge_article_is_not_returned(
    temporary_knowledge_base: Path,
) -> None:
    write_knowledge_article(
        temporary_knowledge_base,
        approved=False,
    )

    result = knowledge_base_tools.search_knowledge_base(
        query="VPN connection",
        top_k=3,
    )

    assert result["status"] == "no_results"
    assert result["results"] == []
    assert result["result_count"] == 0
    assert result["scanned_articles"] == 1
    assert result["eligible_articles"] == 0


def test_only_approved_articles_are_returned(
    temporary_knowledge_base: Path,
) -> None:
    write_knowledge_article(
        temporary_knowledge_base,
        article_id="KB-APPROVED",
        approved=True,
    )

    write_knowledge_article(
        temporary_knowledge_base,
        article_id="KB-PENDING",
        approved=False,
    )

    result = knowledge_base_tools.search_knowledge_base(
        query="VPN connection",
        top_k=5,
    )

    assert result["status"] == "success"
    assert result["scanned_articles"] == 2
    assert result["eligible_articles"] == 1
    assert result["result_count"] == 1
    assert result["results"][0]["article_id"] == "KB-APPROVED"


def test_knowledge_base_search_returns_no_results_for_unmatched_query(
    temporary_knowledge_base: Path,
) -> None:
    write_knowledge_article(temporary_knowledge_base)

    result = knowledge_base_tools.search_knowledge_base(
        query="printer toner replacement",
        top_k=3,
    )

    assert result["status"] == "no_results"
    assert result["results"] == []
    assert result["result_count"] == 0
    assert result["scanned_articles"] == 1
    assert result["eligible_articles"] == 1
    assert result["error"] is None


def test_knowledge_base_search_respects_top_k(
    temporary_knowledge_base: Path,
) -> None:
    write_knowledge_article(
        temporary_knowledge_base,
        article_id="KB-VPN-001",
        title="VPN Connection Troubleshooting",
        content="VPN connection troubleshooting and VPN support.",
    )

    write_knowledge_article(
        temporary_knowledge_base,
        article_id="KB-VPN-002",
        title="VPN Support Guide",
        content="Instructions for resolving a VPN connection issue.",
    )

    write_knowledge_article(
        temporary_knowledge_base,
        article_id="KB-VPN-003",
        title="Remote Network Access",
        content="Employees use the VPN for remote network access.",
    )

    result = knowledge_base_tools.search_knowledge_base(
        query="VPN connection",
        top_k=2,
    )

    assert result["status"] == "success"
    assert result["result_count"] == 2
    assert len(result["results"]) == 2


def test_more_relevant_article_is_ranked_first(
    temporary_knowledge_base: Path,
) -> None:
    write_knowledge_article(
        temporary_knowledge_base,
        article_id="KB-HIGH",
        title="VPN Connection VPN Connection Troubleshooting",
        content=(
            "VPN connection troubleshooting for employees with "
            "a VPN connection problem."
        ),
    )

    write_knowledge_article(
        temporary_knowledge_base,
        article_id="KB-LOW",
        title="Remote Work Guide",
        content="Employees may use a VPN connection when working remotely.",
    )

    result = knowledge_base_tools.search_knowledge_base(
        query="VPN connection",
        top_k=2,
    )

    assert result["status"] == "success"
    assert result["results"][0]["article_id"] == "KB-HIGH"
    assert (
        result["results"][0]["score"]
        > result["results"][1]["score"]
    )


def test_equal_scores_are_sorted_by_article_id(
    temporary_knowledge_base: Path,
) -> None:
    shared_values = {
        "title": "VPN Help",
        "content": "VPN connection support.",
    }

    write_knowledge_article(
        temporary_knowledge_base,
        article_id="KB-B",
        **shared_values,
    )

    write_knowledge_article(
        temporary_knowledge_base,
        article_id="KB-A",
        **shared_values,
    )

    result = knowledge_base_tools.search_knowledge_base(
        query="VPN",
        top_k=5,
    )

    assert result["status"] == "success"

    returned_ids = [
        article["article_id"]
        for article in result["results"]
    ]

    assert returned_ids == ["KB-A", "KB-B"]


def test_optional_metadata_uses_defaults(
    temporary_knowledge_base: Path,
) -> None:
    path = temporary_knowledge_base / "KB-MINIMAL.json"

    path.write_text(
        json.dumps(
            {
                "article_id": "KB-MINIMAL",
                "title": "VPN Help",
                "content": "Contact IT support for VPN problems.",
                "approved": True,
            }
        ),
        encoding="utf-8",
    )

    result = knowledge_base_tools.search_knowledge_base(
        query="VPN",
        top_k=3,
    )

    assert result["status"] == "success"

    article = result["results"][0]

    assert article["category"] == "general"
    assert article["source"] == "internal_it"


@pytest.mark.parametrize(
    "query",
    [
        "",
        "   ",
    ],
)
def test_empty_knowledge_base_query_returns_error(
    temporary_knowledge_base: Path,
    query: str,
) -> None:
    result = knowledge_base_tools.search_knowledge_base(
        query=query,
        top_k=3,
    )

    assert result["status"] == "error"
    assert result["results"] is None
    assert result["result_count"] == 0
    assert "cannot be empty" in result["error"]


@pytest.mark.parametrize(
    "query",
    [
        None,
        123,
        True,
        ["VPN"],
    ],
)
def test_non_string_knowledge_base_query_returns_error(
    temporary_knowledge_base: Path,
    query: object,
) -> None:
    result = knowledge_base_tools.search_knowledge_base(
        query=query,  # type: ignore[arg-type]
        top_k=3,
    )

    assert result["status"] == "error"
    assert result["query"] is None
    assert result["results"] is None
    assert result["error"] == (
        "Knowledge-base query must be a string."
    )


def test_overlong_knowledge_base_query_returns_error(
    temporary_knowledge_base: Path,
) -> None:
    result = knowledge_base_tools.search_knowledge_base(
        query="A" * (knowledge_base_tools.MAX_QUERY_LENGTH + 1),
        top_k=3,
    )

    assert result["status"] == "error"
    assert "character limit" in result["error"]


def test_query_with_null_byte_returns_error(
    temporary_knowledge_base: Path,
) -> None:
    result = knowledge_base_tools.search_knowledge_base(
        query="VPN\x00hidden data",
        top_k=3,
    )

    assert result["status"] == "error"
    assert "control characters" in result["error"]


@pytest.mark.parametrize(
    "top_k",
    [
        0,
        -1,
        6,
        100,
    ],
)
def test_out_of_range_knowledge_base_top_k_returns_error(
    temporary_knowledge_base: Path,
    top_k: int,
) -> None:
    result = knowledge_base_tools.search_knowledge_base(
        query="VPN",
        top_k=top_k,
    )

    assert result["status"] == "error"
    assert "must be between" in result["error"]


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
def test_non_integer_knowledge_base_top_k_returns_error(
    temporary_knowledge_base: Path,
    top_k: object,
) -> None:
    result = knowledge_base_tools.search_knowledge_base(
        query="VPN",
        top_k=top_k,  # type: ignore[arg-type]
    )

    assert result["status"] == "error"
    assert result["results"] is None
    assert result["error"] == "top_k must be an integer."


def test_invalid_json_article_is_skipped_with_warning(
    temporary_knowledge_base: Path,
) -> None:
    invalid_path = temporary_knowledge_base / "invalid.json"
    invalid_path.write_text(
        "{ invalid json",
        encoding="utf-8",
    )

    result = knowledge_base_tools.search_knowledge_base(
        query="VPN",
        top_k=3,
    )

    assert result["status"] == "no_results"
    assert result["scanned_articles"] == 1
    assert result["eligible_articles"] == 0
    assert len(result["warnings"]) == 1
    assert "invalid.json" in result["warnings"][0]
    assert "invalid JSON" in result["warnings"][0]


def test_non_object_article_is_skipped_with_warning(
    temporary_knowledge_base: Path,
) -> None:
    path = temporary_knowledge_base / "list.json"
    path.write_text(
        json.dumps(["not", "an", "article"]),
        encoding="utf-8",
    )

    result = knowledge_base_tools.search_knowledge_base(
        query="VPN",
        top_k=3,
    )

    assert result["status"] == "no_results"
    assert len(result["warnings"]) == 1
    assert "must contain one JSON object" in result["warnings"][0]


def test_article_missing_required_field_is_skipped(
    temporary_knowledge_base: Path,
) -> None:
    path = temporary_knowledge_base / "missing-content.json"

    path.write_text(
        json.dumps(
            {
                "article_id": "KB-BROKEN",
                "title": "Broken article",
                "approved": True,
            }
        ),
        encoding="utf-8",
    )

    result = knowledge_base_tools.search_knowledge_base(
        query="Broken",
        top_k=3,
    )

    assert result["status"] == "no_results"
    assert result["eligible_articles"] == 0
    assert len(result["warnings"]) == 1
    assert "content" in result["warnings"][0]


def test_article_approved_field_must_be_boolean(
    temporary_knowledge_base: Path,
) -> None:
    write_knowledge_article(
        temporary_knowledge_base,
        approved="true",
    )

    result = knowledge_base_tools.search_knowledge_base(
        query="VPN",
        top_k=3,
    )

    assert result["status"] == "no_results"
    assert result["eligible_articles"] == 0
    assert len(result["warnings"]) == 1
    assert "approved must be a boolean" in result["warnings"][0]


def test_invalid_article_id_is_skipped(
    temporary_knowledge_base: Path,
) -> None:
    write_knowledge_article(
        temporary_knowledge_base,
        article_id="../KB-INVALID",
        filename="invalid-id.json",
    )

    result = knowledge_base_tools.search_knowledge_base(
        query="VPN",
        top_k=3,
    )

    assert result["status"] == "no_results"
    assert len(result["warnings"]) == 1
    assert "article_id has an invalid format" in result["warnings"][0]


def test_oversized_article_is_skipped_with_warning(
    temporary_knowledge_base: Path,
) -> None:
    path = temporary_knowledge_base / "oversized.json"

    path.write_text(
        "A" * (knowledge_base_tools.MAX_ARTICLE_FILE_SIZE + 1),
        encoding="utf-8",
    )

    result = knowledge_base_tools.search_knowledge_base(
        query="VPN",
        top_k=3,
    )

    assert result["status"] == "no_results"
    assert len(result["warnings"]) == 1
    assert "maximum file size" in result["warnings"][0]


def test_non_json_files_are_ignored(
    temporary_knowledge_base: Path,
) -> None:
    text_file = temporary_knowledge_base / "notes.txt"
    text_file.write_text(
        "VPN connection information",
        encoding="utf-8",
    )

    result = knowledge_base_tools.search_knowledge_base(
        query="VPN",
        top_k=3,
    )

    assert result["status"] == "no_results"
    assert result["scanned_articles"] == 0
    assert result["warnings"] == []


def test_article_count_safety_limit_is_enforced(
    temporary_knowledge_base: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        knowledge_base_tools,
        "MAX_ARTICLES_SCANNED",
        1,
    )

    write_knowledge_article(
        temporary_knowledge_base,
        article_id="KB-001",
    )

    write_knowledge_article(
        temporary_knowledge_base,
        article_id="KB-002",
    )

    result = knowledge_base_tools.search_knowledge_base(
        query="VPN",
        top_k=3,
    )

    assert result["status"] == "error"
    assert result["results"] is None
    assert "article count exceeds" in result["error"]


def test_long_article_content_generates_short_snippet(
    temporary_knowledge_base: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        knowledge_base_tools,
        "MAX_SNIPPET_LENGTH",
        40,
    )

    write_knowledge_article(
        temporary_knowledge_base,
        content=(
            "VPN connection troubleshooting instructions "
            "that continue for much longer than forty characters."
        ),
    )

    result = knowledge_base_tools.search_knowledge_base(
        query="VPN",
        top_k=3,
    )

    assert result["status"] == "success"

    snippet = result["results"][0]["snippet"]

    assert snippet.endswith("...")
    assert len(snippet) <= 43
