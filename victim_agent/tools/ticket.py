"""
Restricted ticket tools for the Victim IT Helpdesk Agent.

The Victim Agent must not access ticket files directly. It may only propose
structured tool calls that are validated and executed through this module.

Runtime ticket location:

    data/runtime/inbox/<ticket_id>.json

Supported operations:

    read_ticket(ticket_id)
    update_ticket(ticket_id, status, note)
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# Project root:
# Ai-Cyversecurity/
# └── victim_agent/
#     └── tools/
#         └── ticket.py
PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_INBOX_DIR = PROJECT_ROOT / "data" / "runtime" / "inbox"

# Docker or tests may override the runtime inbox location.
INBOX_DIR = Path(
    os.getenv("TICKET_INBOX_DIR", str(DEFAULT_INBOX_DIR))
).resolve()

ALLOWED_STATUSES = {
    "open",
    "in_progress",
    "resolved",
    "needs_human_review",
}

# Prevent "/", "\", "..", spaces, and other path-related characters.
TICKET_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

MAX_NOTE_LENGTH = 1_000
MAX_TICKET_FILE_SIZE = 1_000_000  # 1 MB


class TicketToolError(Exception):
    """Base exception for controlled ticket-tool failures."""


class InvalidTicketIDError(TicketToolError):
    """Raised when a ticket ID does not match the approved format."""


class TicketNotFoundError(TicketToolError):
    """Raised when the requested ticket does not exist."""


class InvalidTicketDataError(TicketToolError):
    """Raised when a ticket file does not contain valid ticket JSON."""


def _utc_timestamp() -> str:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def _base_response(
    *,
    status: str,
    operation: str,
    ticket_id: str | None,
    data: dict[str, Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """Create a consistent response returned to the controller."""

    return {
        "status": status,
        "operation": operation,
        "ticket_id": ticket_id,
        "data": data,
        "error": error,
    }


def _validate_ticket_id(ticket_id: str) -> str:
    """
    Validate and normalize a ticket ID.

    Valid examples:
        TICKET-001
        ticket_001
        INC12345

    Invalid examples:
        ../secret
        ticket/001
        ticket 001
        /etc/passwd
    """

    if not isinstance(ticket_id, str):
        raise InvalidTicketIDError("Ticket ID must be a string.")

    normalized = ticket_id.strip()

    if not normalized:
        raise InvalidTicketIDError("Ticket ID cannot be empty.")

    if not TICKET_ID_PATTERN.fullmatch(normalized):
        raise InvalidTicketIDError(
            "Ticket ID contains unsupported characters."
        )

    return normalized


def _resolve_ticket_path(ticket_id: str) -> Path:
    """
    Resolve the ticket path and confirm it remains inside the runtime inbox.

    Even though ticket IDs are already restricted, this performs an additional
    canonical path boundary check as defense in depth.
    """

    normalized_id = _validate_ticket_id(ticket_id)

    inbox_root = INBOX_DIR.resolve()
    ticket_path = (inbox_root / f"{normalized_id}.json").resolve()

    try:
        ticket_path.relative_to(inbox_root)
    except ValueError as exc:
        raise InvalidTicketIDError(
            "Ticket path violates the inbox safety boundary."
        ) from exc

    return ticket_path


def _load_ticket(ticket_id: str) -> tuple[Path, dict[str, Any]]:
    """Load and validate a ticket JSON file."""

    ticket_path = _resolve_ticket_path(ticket_id)

    if not ticket_path.exists():
        raise TicketNotFoundError(f"Ticket not found: {ticket_id}")

    if not ticket_path.is_file():
        raise InvalidTicketDataError(
            "Requested ticket path is not a regular file."
        )

    if ticket_path.stat().st_size > MAX_TICKET_FILE_SIZE:
        raise InvalidTicketDataError(
            "Ticket file exceeds the maximum allowed size."
        )

    try:
        raw_content = ticket_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TicketToolError("Ticket file could not be read.") from exc

    try:
        ticket = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        raise InvalidTicketDataError(
            "Ticket file does not contain valid JSON."
        ) from exc

    if not isinstance(ticket, dict):
        raise InvalidTicketDataError(
            "Ticket JSON must contain one object."
        )

    stored_ticket_id = ticket.get("ticket_id")

    if stored_ticket_id is not None and stored_ticket_id != ticket_id:
        raise InvalidTicketDataError(
            "Ticket ID does not match the requested ticket."
        )

    ticket.setdefault("ticket_id", ticket_id)
    ticket.setdefault("status", "open")
    ticket.setdefault("notes", [])

    if not isinstance(ticket["notes"], list):
        raise InvalidTicketDataError(
            "Ticket field 'notes' must be a list."
        )

    return ticket_path, ticket


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    """
    Write JSON atomically.

    The updated content is first written to a temporary file and then replaces
    the original file. This reduces the chance of leaving a partially written
    ticket if the process stops unexpectedly.
    """

    path.parent.mkdir(parents=True, exist_ok=True)

    serialized = json.dumps(
        data,
        indent=2,
        ensure_ascii=False,
        sort_keys=False,
    )

    temporary_path: str | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.stem}_",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_file.write(serialized)
            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
            temporary_path = temporary_file.name

        os.replace(temporary_path, path)

    except OSError as exc:
        if temporary_path:
            Path(temporary_path).unlink(missing_ok=True)

        raise TicketToolError(
            "Ticket update could not be saved."
        ) from exc


def read_ticket(ticket_id: str) -> dict[str, Any]:
    """
    Read one ticket from the runtime inbox.

    Returns:
        {
            "status": "success | blocked | not_found | error",
            "operation": "read_ticket",
            "ticket_id": "...",
            "data": {...} | null,
            "error": "..." | null
        }
    """

    try:
        normalized_id = _validate_ticket_id(ticket_id)
        _, ticket = _load_ticket(normalized_id)

        return _base_response(
            status="success",
            operation="read_ticket",
            ticket_id=normalized_id,
            data={"ticket": ticket},
        )

    except InvalidTicketIDError:
        return _base_response(
            status="blocked",
            operation="read_ticket",
            ticket_id=None,
            error="Access denied: invalid ticket identifier.",
        )

    except TicketNotFoundError:
        return _base_response(
            status="not_found",
            operation="read_ticket",
            ticket_id=ticket_id if isinstance(ticket_id, str) else None,
            error="The requested ticket does not exist.",
        )

    except InvalidTicketDataError as exc:
        return _base_response(
            status="error",
            operation="read_ticket",
            ticket_id=ticket_id if isinstance(ticket_id, str) else None,
            error=str(exc),
        )

    except TicketToolError:
        return _base_response(
            status="error",
            operation="read_ticket",
            ticket_id=ticket_id if isinstance(ticket_id, str) else None,
            error="The ticket could not be read safely.",
        )

    except Exception:
        return _base_response(
            status="error",
            operation="read_ticket",
            ticket_id=ticket_id if isinstance(ticket_id, str) else None,
            error="Unexpected ticket tool error.",
        )


def update_ticket(
    ticket_id: str,
    status: str,
    note: str,
) -> dict[str, Any]:
    """
    Update a ticket's status and append a support note.

    This function does not allow arbitrary ticket fields to be modified.
    Only the status, notes, and updated_at fields may be changed.
    """

    try:
        normalized_id = _validate_ticket_id(ticket_id)

        if not isinstance(status, str):
            raise TicketToolError("Ticket status must be a string.")

        normalized_status = status.strip().lower()

        if normalized_status not in ALLOWED_STATUSES:
            return _base_response(
                status="blocked",
                operation="update_ticket",
                ticket_id=normalized_id,
                error=(
                    "Unsupported ticket status. Allowed statuses are: "
                    + ", ".join(sorted(ALLOWED_STATUSES))
                ),
            )

        if not isinstance(note, str):
            raise TicketToolError("Ticket note must be a string.")

        normalized_note = note.strip()

        if not normalized_note:
            return _base_response(
                status="blocked",
                operation="update_ticket",
                ticket_id=normalized_id,
                error="Ticket note cannot be empty.",
            )

        if len(normalized_note) > MAX_NOTE_LENGTH:
            return _base_response(
                status="blocked",
                operation="update_ticket",
                ticket_id=normalized_id,
                error=(
                    f"Ticket note exceeds the {MAX_NOTE_LENGTH}-character limit."
                ),
            )

        ticket_path, ticket = _load_ticket(normalized_id)
        timestamp = _utc_timestamp()

        ticket["status"] = normalized_status
        ticket["updated_at"] = timestamp
        ticket["notes"].append(
            {
                "author": "victim_agent",
                "timestamp": timestamp,
                "content": normalized_note,
            }
        )

        _atomic_write_json(ticket_path, ticket)

        return _base_response(
            status="success",
            operation="update_ticket",
            ticket_id=normalized_id,
            data={
                "ticket_id": normalized_id,
                "new_status": normalized_status,
                "note_added": True,
                "updated_at": timestamp,
            },
        )

    except InvalidTicketIDError:
        return _base_response(
            status="blocked",
            operation="update_ticket",
            ticket_id=None,
            error="Access denied: invalid ticket identifier.",
        )

    except TicketNotFoundError:
        return _base_response(
            status="not_found",
            operation="update_ticket",
            ticket_id=ticket_id if isinstance(ticket_id, str) else None,
            error="The requested ticket does not exist.",
        )

    except InvalidTicketDataError as exc:
        return _base_response(
            status="error",
            operation="update_ticket",
            ticket_id=ticket_id if isinstance(ticket_id, str) else None,
            error=str(exc),
        )

    except TicketToolError as exc:
        return _base_response(
            status="error",
            operation="update_ticket",
            ticket_id=ticket_id if isinstance(ticket_id, str) else None,
            error=str(exc),
        )

    except Exception:
        return _base_response(
            status="error",
            operation="update_ticket",
            ticket_id=ticket_id if isinstance(ticket_id, str) else None,
            error="Unexpected ticket tool error.",
        )
