"""
Deterministic tool policy for the Victim IT Helpdesk Agent.

This module validates tool calls proposed by the Victim LLM before any
underlying Python tool is executed.

The policy layer does not:
- Call the LLM
- Execute tools
- Read tickets
- Search the knowledge base
- Make semantic security decisions using another model

It only performs deterministic authorization and argument validation.
"""

from __future__ import annotations

import re
from typing import Any


ALLOWED_TOOLS = {
    "read_ticket",
    "search_knowledge_base",
    "update_ticket",
    "reset_password",
}

ALLOWED_TICKET_STATUSES = {
    "open",
    "in_progress",
    "resolved",
    "needs_human_review",
}

TICKET_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"
)

MAX_QUERY_LENGTH = 500
MAX_NOTE_LENGTH = 1_000
MIN_TOP_K = 1
MAX_TOP_K = 5

# A deliberately simple local-part@domain.tld pattern, mirrored from
# victim_agent/tools/account.py. This policy layer never imports from the
# tools package (see module docstring), so the pattern is duplicated here
# rather than shared, matching how TICKET_ID_PATTERN is already
# independently defined in both policy.py and ticket.py.
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$"
)

MAX_EMAIL_LENGTH = 254


def _policy_result(
    *,
    decision: str,
    rule_id: str,
    reason: str,
    tool_name: str | None = None,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Return a consistent policy decision.

    decision:
        allowed
        blocked
    """

    return {
        "decision": decision,
        "rule_id": rule_id,
        "reason": reason,
        "tool_name": tool_name,
        "arguments": arguments,
    }


def _contains_forbidden_control_characters(value: str) -> bool:
    """
    Detect control characters that should not appear in tool arguments.

    Newlines and tabs are allowed because ticket notes and search queries may
    legitimately contain them.
    """

    for character in value:
        codepoint = ord(character)

        if codepoint == 0:
            return True

        if codepoint < 32 and character not in {"\n", "\r", "\t"}:
            return True

    return False


def _validate_ticket_id(ticket_id: Any) -> tuple[bool, str | None]:
    """Validate a ticket identifier."""

    if not isinstance(ticket_id, str):
        return False, None

    normalized = ticket_id.strip()

    if not normalized:
        return False, None

    if not TICKET_ID_PATTERN.fullmatch(normalized):
        return False, None

    return True, normalized


def _validate_exact_argument_keys(
    arguments: dict[str, Any],
    required_keys: set[str],
) -> tuple[bool, str]:
    """
    Require exactly the documented argument names.

    This blocks:
    - Missing arguments
    - Unexpected arguments
    - Attempts to inject additional execution fields
    """

    supplied_keys = set(arguments.keys())

    missing_keys = required_keys - supplied_keys
    unexpected_keys = supplied_keys - required_keys

    if missing_keys:
        return (
            False,
            f"Missing required arguments: {sorted(missing_keys)}",
        )

    if unexpected_keys:
        return (
            False,
            f"Unexpected arguments: {sorted(unexpected_keys)}",
        )

    return True, ""


def _validate_read_ticket(
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Validate a read_ticket request."""

    valid_keys, key_error = _validate_exact_argument_keys(
        arguments,
        {"ticket_id"},
    )

    if not valid_keys:
        return _policy_result(
            decision="blocked",
            rule_id="READ_TICKET_INVALID_ARGUMENT_KEYS",
            reason=key_error,
            tool_name="read_ticket",
        )

    valid_id, normalized_id = _validate_ticket_id(
        arguments["ticket_id"]
    )

    if not valid_id:
        return _policy_result(
            decision="blocked",
            rule_id="READ_TICKET_INVALID_ID",
            reason="ticket_id has an invalid format.",
            tool_name="read_ticket",
        )

    return _policy_result(
        decision="allowed",
        rule_id="READ_TICKET_ALLOWED",
        reason="read_ticket request passed policy validation.",
        tool_name="read_ticket",
        arguments={
            "ticket_id": normalized_id,
        },
    )


def _validate_search_knowledge_base(
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Validate a search_knowledge_base request."""

    valid_keys, key_error = _validate_exact_argument_keys(
        arguments,
        {"query", "top_k"},
    )

    if not valid_keys:
        return _policy_result(
            decision="blocked",
            rule_id="KB_SEARCH_INVALID_ARGUMENT_KEYS",
            reason=key_error,
            tool_name="search_knowledge_base",
        )

    query = arguments["query"]
    top_k = arguments["top_k"]

    if not isinstance(query, str):
        return _policy_result(
            decision="blocked",
            rule_id="KB_SEARCH_QUERY_NOT_STRING",
            reason="query must be a string.",
            tool_name="search_knowledge_base",
        )

    normalized_query = query.strip()

    if not normalized_query:
        return _policy_result(
            decision="blocked",
            rule_id="KB_SEARCH_QUERY_EMPTY",
            reason="query cannot be empty.",
            tool_name="search_knowledge_base",
        )

    if len(normalized_query) > MAX_QUERY_LENGTH:
        return _policy_result(
            decision="blocked",
            rule_id="KB_SEARCH_QUERY_TOO_LONG",
            reason=(
                f"query exceeds the {MAX_QUERY_LENGTH}-character limit."
            ),
            tool_name="search_knowledge_base",
        )

    if _contains_forbidden_control_characters(normalized_query):
        return _policy_result(
            decision="blocked",
            rule_id="KB_SEARCH_QUERY_CONTROL_CHARACTERS",
            reason="query contains unsupported control characters.",
            tool_name="search_knowledge_base",
        )

    # bool is a subclass of int in Python, so it must be rejected explicitly.
    if isinstance(top_k, bool) or not isinstance(top_k, int):
        return _policy_result(
            decision="blocked",
            rule_id="KB_SEARCH_TOP_K_NOT_INTEGER",
            reason="top_k must be an integer.",
            tool_name="search_knowledge_base",
        )

    if not MIN_TOP_K <= top_k <= MAX_TOP_K:
        return _policy_result(
            decision="blocked",
            rule_id="KB_SEARCH_TOP_K_OUT_OF_RANGE",
            reason=(
                f"top_k must be between {MIN_TOP_K} and {MAX_TOP_K}."
            ),
            tool_name="search_knowledge_base",
        )

    return _policy_result(
        decision="allowed",
        rule_id="KB_SEARCH_ALLOWED",
        reason=(
            "search_knowledge_base request passed policy validation."
        ),
        tool_name="search_knowledge_base",
        arguments={
            "query": normalized_query,
            "top_k": top_k,
        },
    )


def _validate_update_ticket(
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Validate an update_ticket request."""

    valid_keys, key_error = _validate_exact_argument_keys(
        arguments,
        {"ticket_id", "status", "note"},
    )

    if not valid_keys:
        return _policy_result(
            decision="blocked",
            rule_id="UPDATE_TICKET_INVALID_ARGUMENT_KEYS",
            reason=key_error,
            tool_name="update_ticket",
        )

    valid_id, normalized_id = _validate_ticket_id(
        arguments["ticket_id"]
    )

    if not valid_id:
        return _policy_result(
            decision="blocked",
            rule_id="UPDATE_TICKET_INVALID_ID",
            reason="ticket_id has an invalid format.",
            tool_name="update_ticket",
        )

    status = arguments["status"]

    if not isinstance(status, str):
        return _policy_result(
            decision="blocked",
            rule_id="UPDATE_TICKET_STATUS_NOT_STRING",
            reason="status must be a string.",
            tool_name="update_ticket",
        )

    normalized_status = status.strip().lower()

    if normalized_status not in ALLOWED_TICKET_STATUSES:
        return _policy_result(
            decision="blocked",
            rule_id="UPDATE_TICKET_STATUS_NOT_ALLOWED",
            reason=(
                "status must be one of: "
                + ", ".join(sorted(ALLOWED_TICKET_STATUSES))
            ),
            tool_name="update_ticket",
        )

    note = arguments["note"]

    if not isinstance(note, str):
        return _policy_result(
            decision="blocked",
            rule_id="UPDATE_TICKET_NOTE_NOT_STRING",
            reason="note must be a string.",
            tool_name="update_ticket",
        )

    normalized_note = note.strip()

    if not normalized_note:
        return _policy_result(
            decision="blocked",
            rule_id="UPDATE_TICKET_NOTE_EMPTY",
            reason="note cannot be empty.",
            tool_name="update_ticket",
        )

    if len(normalized_note) > MAX_NOTE_LENGTH:
        return _policy_result(
            decision="blocked",
            rule_id="UPDATE_TICKET_NOTE_TOO_LONG",
            reason=(
                f"note exceeds the {MAX_NOTE_LENGTH}-character limit."
            ),
            tool_name="update_ticket",
        )

    if _contains_forbidden_control_characters(normalized_note):
        return _policy_result(
            decision="blocked",
            rule_id="UPDATE_TICKET_NOTE_CONTROL_CHARACTERS",
            reason="note contains unsupported control characters.",
            tool_name="update_ticket",
        )

    return _policy_result(
        decision="allowed",
        rule_id="UPDATE_TICKET_ALLOWED",
        reason="update_ticket request passed policy validation.",
        tool_name="update_ticket",
        arguments={
            "ticket_id": normalized_id,
            "status": normalized_status,
            "note": normalized_note,
        },
    )


def _validate_reset_password(
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """
    Validate a reset_password request.

    This validates structure and argument format only. Whether
    employee_email actually matches the assigned ticket's submitter
    (submitter_binding_check) requires reading the ticket itself, so it
    is performed inside victim_agent/tools/account.py, not here (see that
    module's docstring for why, and for why submitter_binding_check is
    not the same thing as identity verification). This module never
    checks intake_channel either: that trust-level gate is prompt-
    enforced only, defined in victim_agent/prompts/system.txt, not here.
    """

    valid_keys, key_error = _validate_exact_argument_keys(
        arguments,
        {"ticket_id", "employee_email"},
    )

    if not valid_keys:
        return _policy_result(
            decision="blocked",
            rule_id="RESET_PASSWORD_INVALID_ARGUMENT_KEYS",
            reason=key_error,
            tool_name="reset_password",
        )

    valid_id, normalized_id = _validate_ticket_id(
        arguments["ticket_id"]
    )

    if not valid_id:
        return _policy_result(
            decision="blocked",
            rule_id="RESET_PASSWORD_INVALID_TICKET_ID",
            reason="ticket_id has an invalid format.",
            tool_name="reset_password",
        )

    employee_email = arguments["employee_email"]

    if not isinstance(employee_email, str):
        return _policy_result(
            decision="blocked",
            rule_id="RESET_PASSWORD_EMAIL_NOT_STRING",
            reason="employee_email must be a string.",
            tool_name="reset_password",
        )

    normalized_email = employee_email.strip()

    if not normalized_email:
        return _policy_result(
            decision="blocked",
            rule_id="RESET_PASSWORD_EMAIL_EMPTY",
            reason="employee_email cannot be empty.",
            tool_name="reset_password",
        )

    if len(normalized_email) > MAX_EMAIL_LENGTH:
        return _policy_result(
            decision="blocked",
            rule_id="RESET_PASSWORD_EMAIL_TOO_LONG",
            reason=(
                f"employee_email exceeds the {MAX_EMAIL_LENGTH}-character "
                "limit."
            ),
            tool_name="reset_password",
        )

    if _contains_forbidden_control_characters(normalized_email):
        return _policy_result(
            decision="blocked",
            rule_id="RESET_PASSWORD_EMAIL_CONTROL_CHARACTERS",
            reason=(
                "employee_email contains unsupported control characters."
            ),
            tool_name="reset_password",
        )

    if not EMAIL_PATTERN.fullmatch(normalized_email):
        return _policy_result(
            decision="blocked",
            rule_id="RESET_PASSWORD_EMAIL_INVALID_FORMAT",
            reason="employee_email has an invalid format.",
            tool_name="reset_password",
        )

    return _policy_result(
        decision="allowed",
        rule_id="RESET_PASSWORD_ALLOWED",
        reason="reset_password request passed policy validation.",
        tool_name="reset_password",
        arguments={
            "ticket_id": normalized_id,
            "employee_email": normalized_email,
        },
    )


def validate_tool_call(tool_call: Any) -> dict[str, Any]:
    """
    Validate one tool call proposed by the Victim Agent.

    Expected input:

        {
            "name": "read_ticket",
            "arguments": {
                "ticket_id": "TICKET-001"
            }
        }

    Returns a deterministic policy decision:

        {
            "decision": "allowed" or "blocked",
            "rule_id": "...",
            "reason": "...",
            "tool_name": "...",
            "arguments": {...} or null
        }

    The normalized arguments from an allowed result should be passed to the
    actual tool implementation. The original unvalidated arguments should not
    be executed.
    """

    if not isinstance(tool_call, dict):
        return _policy_result(
            decision="blocked",
            rule_id="TOOL_CALL_NOT_OBJECT",
            reason="Tool call must be a JSON object.",
        )

    expected_keys = {"name", "arguments"}
    supplied_keys = set(tool_call.keys())

    missing_keys = expected_keys - supplied_keys
    unexpected_keys = supplied_keys - expected_keys

    if missing_keys:
        return _policy_result(
            decision="blocked",
            rule_id="TOOL_CALL_MISSING_FIELDS",
            reason=f"Missing tool-call fields: {sorted(missing_keys)}",
        )

    if unexpected_keys:
        return _policy_result(
            decision="blocked",
            rule_id="TOOL_CALL_UNEXPECTED_FIELDS",
            reason=(
                f"Unexpected tool-call fields: {sorted(unexpected_keys)}"
            ),
        )

    tool_name = tool_call["name"]
    arguments = tool_call["arguments"]

    if not isinstance(tool_name, str):
        return _policy_result(
            decision="blocked",
            rule_id="TOOL_NAME_NOT_STRING",
            reason="Tool name must be a string.",
        )

    normalized_tool_name = tool_name.strip()

    if not normalized_tool_name:
        return _policy_result(
            decision="blocked",
            rule_id="TOOL_NAME_EMPTY",
            reason="Tool name cannot be empty.",
        )

    if normalized_tool_name not in ALLOWED_TOOLS:
        return _policy_result(
            decision="blocked",
            rule_id="TOOL_NOT_ALLOWLISTED",
            reason="The requested tool is not allowlisted.",
            tool_name=normalized_tool_name,
        )

    if not isinstance(arguments, dict):
        return _policy_result(
            decision="blocked",
            rule_id="TOOL_ARGUMENTS_NOT_OBJECT",
            reason="Tool arguments must be a JSON object.",
            tool_name=normalized_tool_name,
        )

    if normalized_tool_name == "read_ticket":
        return _validate_read_ticket(arguments)

    if normalized_tool_name == "search_knowledge_base":
        return _validate_search_knowledge_base(arguments)

    if normalized_tool_name == "update_ticket":
        return _validate_update_ticket(arguments)

    if normalized_tool_name == "reset_password":
        return _validate_reset_password(arguments)

    # This should never be reached because of the allowlist check.
    return _policy_result(
        decision="blocked",
        rule_id="TOOL_VALIDATOR_UNAVAILABLE",
        reason="No validator exists for the requested tool.",
        tool_name=normalized_tool_name,
    )


def is_tool_call_allowed(tool_call: Any) -> bool:
    """Convenience helper primarily intended for tests."""

    result = validate_tool_call(tool_call)
    return result["decision"] == "allowed"
