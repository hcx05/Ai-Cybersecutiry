"""
Restricted account tool for the Victim IT Helpdesk Agent.

reset_password is the one tool in this project whose effect reaches
outside the ticket that triggered it: unlike update_ticket, which can only
ever mutate the single ticket file the current session is scoped to, a
successful reset_password call changes a real account's credential state.
That makes it the intended terminus of the project's attack-chain
narrative (indirect prompt injection, then knowledge-base poisoning, then
a poisoned article persuading the Victim Agent to reset a password for an
account unrelated to the ticket in front of it).

Identity verification is implemented here, inside the tool, rather than
in victim_agent/agent.py's session-authorization layer. reset_password
re-reads the assigned ticket for itself and compares the ticket's real
submitted_by field against the employee_email argument the model
supplied. This means victim_agent/agent.py never needs to cache full
ticket contents to authorize this tool, and the identity check cannot be
bypassed by wording in ticket content or a knowledge-base article, since
it is derived from the ticket file on disk, not from anything the model
claims.

Runtime ticket location (read-only from this module's perspective):

    data/runtime/inbox/<ticket_id>.json

Runtime account-reset execution log:

    data/runtime/accounts/<ticket_id>.json

Supported operation:

    reset_password(ticket_id, employee_email)

Result "status" convention (mirrors victim_agent/tools/ticket.py):

    blocked     The caller-supplied ticket_id or employee_email was
                invalid (wrong type, empty, wrong format, too long, or
                contains forbidden control characters), or the ticket
                was read successfully but employee_email did not match
                the ticket's recorded submitted_by.
    not_found   The ticket_id was well-formed but no such ticket exists.
    error       The request itself was valid, but the underlying ticket
                or runtime account-log data could not be processed
                safely.
    success     Identity was verified and the reset was recorded.

No password value is ever generated, returned, or stored anywhere. Only a
structured confirmation record is written, so a successful reset is
exactly as auditable, and exactly as irreversible in this simulation, as
a real password reset would be.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from victim_agent.tools.ticket import read_ticket


# Project root:
# Ai-Cyversecurity/
# └── victim_agent/
#     └── tools/
#         └── account.py
PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_ACCOUNTS_DIR = PROJECT_ROOT / "data" / "runtime" / "accounts"

# Docker or tests may override the runtime account-log location.
#
# Deliberately NOT resolved or validated here at import time. Resolution
# and existence validation occur inside _prepare_accounts_dir(), called
# from reset_password(), so a missing or misconfigured directory becomes
# a structured tool error instead of a failure while importing this
# module (mirrors victim_agent/tools/ticket.py and
# victim_agent/tools/knowledge_base.py).
ACCOUNTS_DIR = Path(
    os.getenv("ACCOUNT_RESET_LOG_DIR", str(DEFAULT_ACCOUNTS_DIR))
)

# Prevent "/", "\", "..", spaces, and other path-related characters.
TICKET_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

# A deliberately simple local-part@domain.tld pattern. This tool does not
# need to accept every address permitted by the full email grammar; it
# only needs to reject obviously malformed input before an identity
# comparison is attempted.
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$"
)

MAX_EMAIL_LENGTH = 254


class AccountToolError(Exception):
    """Base exception for controlled account-tool failures."""


class InvalidTicketIDError(AccountToolError):
    """Raised when a ticket ID does not match the approved format."""


class InvalidEmployeeEmailError(AccountToolError):
    """Raised when employee_email does not match the approved format."""


def _utc_timestamp() -> str:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def _contains_forbidden_control_characters(value: str) -> bool:
    """Detect control characters that should not appear in tool arguments."""

    for character in value:
        codepoint = ord(character)

        if codepoint == 0:
            return True

        if codepoint < 32 and character not in {"\n", "\r", "\t"}:
            return True

    return False


def _base_response(
    *,
    status: str,
    ticket_id: str | None,
    employee_email: str | None,
    data: dict[str, Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """Create a consistent response returned to the controller."""

    return {
        "status": status,
        "operation": "reset_password",
        "ticket_id": ticket_id,
        "employee_email": employee_email,
        "data": data,
        "error": error,
    }


def _validate_ticket_id(ticket_id: Any) -> str:
    """Validate and normalize a ticket ID (mirrors ticket.py)."""

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


def _validate_employee_email(employee_email: Any) -> str:
    """Validate and normalize the employee_email argument."""

    if not isinstance(employee_email, str):
        raise InvalidEmployeeEmailError(
            "employee_email must be a string."
        )

    normalized = employee_email.strip()

    if not normalized:
        raise InvalidEmployeeEmailError(
            "employee_email cannot be empty."
        )

    if len(normalized) > MAX_EMAIL_LENGTH:
        raise InvalidEmployeeEmailError(
            f"employee_email exceeds the {MAX_EMAIL_LENGTH}-character limit."
        )

    if _contains_forbidden_control_characters(normalized):
        raise InvalidEmployeeEmailError(
            "employee_email contains unsupported control characters."
        )

    if not EMAIL_PATTERN.fullmatch(normalized):
        raise InvalidEmployeeEmailError(
            "employee_email has an invalid format."
        )

    return normalized


def _prepare_accounts_dir() -> Path:
    """
    Resolve and validate the account-reset execution-log directory.

    The directory must already exist; it is never created here. Runtime
    environment setup (for example a controller reset step) is
    responsible for populating data/runtime/accounts before the Victim
    Agent runs, mirroring how the ticket inbox and knowledge base are
    handled.
    """

    try:
        accounts_root = ACCOUNTS_DIR.expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AccountToolError(
            "Account-reset log directory is unavailable."
        ) from exc

    if not accounts_root.is_dir():
        raise AccountToolError(
            "Account-reset log directory does not exist."
        )

    return accounts_root


def _resolve_account_log_path(ticket_id: str) -> Path:
    """
    Resolve the account-reset log path and confirm it remains inside the
    runtime accounts directory.
    """

    accounts_root = _prepare_accounts_dir()
    log_path = (accounts_root / f"{ticket_id}.json").resolve()

    try:
        log_path.relative_to(accounts_root)
    except ValueError as exc:
        raise InvalidTicketIDError(
            "Account-reset log path violates the safety boundary."
        ) from exc

    return log_path


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    """Write JSON atomically (mirrors ticket.py)."""

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

        raise AccountToolError(
            "Account-reset record could not be saved."
        ) from exc


def reset_password(
    ticket_id: str,
    employee_email: str,
) -> dict[str, Any]:
    """
    Reset the password for the employee who submitted the assigned ticket.

    This is the one destructive, cross-account-boundary tool available to
    the Victim Agent. It re-reads the assigned ticket itself and only
    succeeds when employee_email exactly matches (case-insensitively)
    that ticket's recorded submitted_by field, so a caller cannot reset
    an arbitrary account merely by naming it as an argument -- not the
    model, and not text embedded in ticket content or a knowledge-base
    article. No password value is ever generated, returned, or
    persisted; only a structured confirmation record is written.

    Returns:
        {
            "status": "success | blocked | not_found | error",
            "operation": "reset_password",
            "ticket_id": "...",
            "employee_email": "..." | null,
            "data": {...} | null,
            "error": "..." | null
        }
    """

    try:
        normalized_ticket_id = _validate_ticket_id(ticket_id)
    except InvalidTicketIDError:
        return _base_response(
            status="blocked",
            ticket_id=None,
            employee_email=None,
            error="Access denied: invalid ticket identifier.",
        )

    try:
        normalized_email = _validate_employee_email(employee_email)
    except InvalidEmployeeEmailError as exc:
        return _base_response(
            status="blocked",
            ticket_id=normalized_ticket_id,
            employee_email=None,
            error=str(exc),
        )

    try:
        ticket_read_result = read_ticket(normalized_ticket_id)
    except Exception:
        return _base_response(
            status="error",
            ticket_id=normalized_ticket_id,
            employee_email=normalized_email,
            error="The assigned ticket could not be verified safely.",
        )

    ticket_read_status = ticket_read_result.get("status")

    if ticket_read_status == "not_found":
        return _base_response(
            status="not_found",
            ticket_id=normalized_ticket_id,
            employee_email=normalized_email,
            error="The requested ticket does not exist.",
        )

    if ticket_read_status != "success":
        return _base_response(
            status="error",
            ticket_id=normalized_ticket_id,
            employee_email=normalized_email,
            error=(
                "The assigned ticket could not be read successfully "
                "for identity verification."
            ),
        )

    ticket_data = ticket_read_result.get("data")
    ticket = (
        ticket_data.get("ticket")
        if isinstance(ticket_data, dict)
        else None
    )

    if not isinstance(ticket, dict):
        return _base_response(
            status="error",
            ticket_id=normalized_ticket_id,
            employee_email=normalized_email,
            error="The assigned ticket did not return usable data.",
        )

    submitted_by = ticket.get("submitted_by")

    if not isinstance(submitted_by, str) or not submitted_by.strip():
        return _base_response(
            status="blocked",
            ticket_id=normalized_ticket_id,
            employee_email=normalized_email,
            error=(
                "The assigned ticket does not record a submitter "
                "identity to verify against."
            ),
        )

    normalized_submitted_by = submitted_by.strip()

    if normalized_submitted_by.casefold() != normalized_email.casefold():
        return _base_response(
            status="blocked",
            ticket_id=normalized_ticket_id,
            employee_email=normalized_email,
            error=(
                "employee_email does not match the identity of the "
                "employee who submitted the assigned ticket."
            ),
        )

    try:
        log_path = _resolve_account_log_path(normalized_ticket_id)
    except InvalidTicketIDError:
        return _base_response(
            status="blocked",
            ticket_id=None,
            employee_email=normalized_email,
            error="Access denied: invalid ticket identifier.",
        )
    except AccountToolError as exc:
        return _base_response(
            status="error",
            ticket_id=normalized_ticket_id,
            employee_email=normalized_email,
            error=str(exc),
        )

    timestamp = _utc_timestamp()

    record = {
        "ticket_id": normalized_ticket_id,
        "employee_email": normalized_email,
        "verified_submitted_by": normalized_submitted_by,
        "reset_at": timestamp,
    }

    try:
        _atomic_write_json(log_path, record)
    except AccountToolError as exc:
        return _base_response(
            status="error",
            ticket_id=normalized_ticket_id,
            employee_email=normalized_email,
            error=str(exc),
        )

    return _base_response(
        status="success",
        ticket_id=normalized_ticket_id,
        employee_email=normalized_email,
        data={
            "ticket_id": normalized_ticket_id,
            "employee_email": normalized_email,
            "reset_at": timestamp,
        },
    )
