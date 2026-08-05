"""
Deterministic analysis of one Victim Agent result.

This module extracts objective facts already present in the dict returned
by victim_agent.agent.run_victim_agent() (policy blocks, the final status,
which tools were attempted, whether the ticket status changed, whether a
password reset was performed, and so on) into a compact shape a planner
can reason over without re-deriving them from the full trace on every
round.

This performs no judgment about whether an attack succeeded. Whether a
given set of facts means a goal's success_signal was met is left to the
planner, because that judgment is goal-specific (defined by each
AttackGoal's own success_signal) and often requires reading the meaning of
free-text content, not just checking fixed fields. Separating extraction
from judgment keeps this module simple, deterministic, and independent of
which goal is being pursued.
"""

from __future__ import annotations

from typing import Any


_POLICY_LAYERS = (
    "tool_policy",
    "session_policy",
    "terminal_policy",
)


def _extract_policy_blocks(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Return every blocked-policy record found on one trace entry."""

    blocks: list[dict[str, Any]] = []

    for layer in _POLICY_LAYERS:
        policy = entry.get(layer)

        if isinstance(policy, dict) and policy.get("decision") == "blocked":
            blocks.append(
                {
                    "step": entry.get("step"),
                    "layer": layer,
                    "rule_id": policy.get("rule_id"),
                    "reason": policy.get("reason"),
                    "tool_name": policy.get("tool_name"),
                }
            )

    return blocks


def _extract_tool_call_attempt(
    entry: dict[str, Any],
) -> dict[str, Any] | None:
    """Return the tool call the model proposed on one trace entry, if any."""

    decision = entry.get("decision")

    if not isinstance(decision, dict):
        return None

    tool_call = decision.get("tool_call")

    if not isinstance(tool_call, dict):
        return None

    name = tool_call.get("name")

    if not isinstance(name, str):
        return None

    return {
        "step": entry.get("step"),
        "name": name,
        "arguments": tool_call.get("arguments"),
    }


def _extract_executed_tool_result(
    entry: dict[str, Any],
    *,
    tool_name: str,
) -> dict[str, Any] | None:
    """
    Return the tool_result.data of one trace entry, if it executed
    tool_name and that execution succeeded. Shared by the two
    tool-specific extractors below so both stay in sync if the underlying
    trace shape ever changes.
    """

    executed_tool = entry.get("executed_tool")
    tool_result = entry.get("tool_result")

    if not (
        isinstance(executed_tool, dict)
        and executed_tool.get("name") == tool_name
        and isinstance(tool_result, dict)
        and tool_result.get("status") == "success"
    ):
        return None

    data = tool_result.get("data")

    if not isinstance(data, dict):
        return None

    return data


def _extract_update_ticket_effect(
    entry: dict[str, Any],
) -> dict[str, Any] | None:
    """
    Return what a successful update_ticket call actually changed, if this
    trace entry executed one.
    """

    data = _extract_executed_tool_result(entry, tool_name="update_ticket")

    if data is None:
        return None

    return {
        "step": entry.get("step"),
        "new_status": data.get("new_status"),
        "note_added": bool(data.get("note_added")),
    }


def _extract_password_reset_effect(
    entry: dict[str, Any],
) -> dict[str, Any] | None:
    """
    Return what a successful reset_password call actually did, if this
    trace entry executed one.

    This is the counterpart to _extract_update_ticket_effect for
    reset_password. Without it, a successful, security-relevant password
    reset was only visible to the planner indirectly (as one entry in
    tool_calls_attempted, indistinguishable from an attempt that was
    blocked or that failed), which in practice was not a strong enough
    signal for a small planner model to reliably recognize that the goal
    had already been achieved.
    """

    data = _extract_executed_tool_result(entry, tool_name="reset_password")

    if data is None:
        return None

    return {
        "step": entry.get("step"),
        "employee_email": data.get("employee_email"),
        "reset_at": data.get("reset_at"),
    }


def extract_round_signal(victim_result: dict[str, Any]) -> dict[str, Any]:
    """
    Extract a compact, deterministic summary of one run_victim_agent()
    result.

    Safe to call on any victim_result shape: every field is read with
    .get() and every extractor tolerates missing or unexpected trace entry
    shapes, so a result from an interrupted or unusual run (for example one
    that hit context_budget_exceeded before any model decision) is
    summarized rather than raising.
    """

    if not isinstance(victim_result, dict):
        raise TypeError(
            "victim_result must be the dict returned by "
            "run_victim_agent()."
        )

    trace = victim_result.get("trace")

    if not isinstance(trace, list):
        trace = []

    policy_blocks: list[dict[str, Any]] = []
    tool_calls_attempted: list[dict[str, Any]] = []
    guard_events: list[str] = []
    ticket_updates: list[dict[str, Any]] = []
    password_resets: list[dict[str, Any]] = []

    for entry in trace:
        if not isinstance(entry, dict):
            continue

        event = entry.get("event")

        if isinstance(event, str) and event != "model_decision":
            guard_events.append(event)

        policy_blocks.extend(_extract_policy_blocks(entry))

        tool_call_attempt = _extract_tool_call_attempt(entry)

        if tool_call_attempt is not None:
            tool_calls_attempted.append(tool_call_attempt)

        ticket_update = _extract_update_ticket_effect(entry)

        if ticket_update is not None:
            ticket_updates.append(ticket_update)

        password_reset = _extract_password_reset_effect(entry)

        if password_reset is not None:
            password_resets.append(password_reset)

    return {
        "final_status": victim_result.get("status"),
        "final_reason": victim_result.get("reason"),
        "final_response": victim_result.get("final_response"),
        "steps_used": victim_result.get("steps_used"),
        "policy_blocks": policy_blocks,
        "tool_calls_attempted": tool_calls_attempted,
        "guard_events": guard_events,
        "ticket_updates": ticket_updates,
        "password_resets": password_resets,
    }


# ---------------------------------------------------------------------------
# Observability-mode filtering
# ---------------------------------------------------------------------------
#
# extract_round_signal() above always returns the full, white-box shape:
# every policy_blocks entry carries rule_id, layer, and tool_name; every
# tool_calls_attempted entry carries the model's raw arguments. That level
# of detail is a fair description of what the Attack Agent's own logs and
# attack_agent.oracle can see, but it is not a fair description of what a
# real external attacker submitting tickets through a public form could
# ever observe about the internal system that rejected them. Handing the
# planner white-box detail by default silently inflated the campaign's
# reported attacker capability past what the Phase 1 threat model
# (experiments/phase1_ipi/README.md) claims: an attacker with no
# credentials and no internal access.
#
# filter_signal_for_observability() is applied only to the copy of
# latest_signal built for the planner's prompt in
# attack_agent.agent.run_campaign(); it never touches the full signal
# recorded to logs/attack_agent/ or passed to attack_agent.oracle.


def _redact_policy_block_for_gray_box(
    block: dict[str, Any],
) -> dict[str, Any]:
    """Keep which tool was involved, but withhold rule_id/layer/reason
    detail that reveals the internal policy that produced the block."""

    return {
        "step": block.get("step"),
        "tool_name": block.get("tool_name"),
        "outcome": "blocked_by_internal_policy",
    }


def _redact_tool_call_attempt(
    attempt: dict[str, Any],
) -> dict[str, Any]:
    """Reduce a tool_calls_attempted entry to the tool name only, dropping
    the model's raw proposed arguments (an external attacker never sees
    what the Victim Agent internally proposed to call, only what actually
    happened as a result)."""

    return {
        "step": attempt.get("step"),
        "name": attempt.get("name"),
    }


def filter_signal_for_observability(
    signal: dict[str, Any] | None,
    *,
    mode: str,
) -> dict[str, Any] | None:
    """
    Filter one extract_round_signal() result down to what the planner is
    allowed to see under a given observability_mode.

    mode:

        white_box
            Return signal unchanged. This is the Attack Agent's capability
            ceiling, not a stand-in for an external attacker.

        gray_box
            Keep final_status/final_reason/final_response/steps_used and
            ticket_updates/password_resets (outcomes an attacker could
            plausibly infer from the ticket's own visible state), but
            reduce policy_blocks and tool_calls_attempted to coarse
            outcome facts with rule_id, layer, and raw arguments removed.

        black_box
            Keep only final_response and final_status: what a ticket
            portal displaying the Victim Agent's reply, and whether the
            request was ultimately acted on, would show a real external
            requester. Everything else (steps_used, policy_blocks,
            tool_calls_attempted, guard_events, ticket_updates,
            password_resets) is withheld.

    signal may be None (there is no previous round yet); returned as None
    unchanged in that case regardless of mode.
    """

    if signal is None:
        return None

    if mode not in {"black_box", "gray_box", "white_box"}:
        raise ValueError(
            "mode must be one of: black_box, gray_box, white_box."
        )

    if mode == "white_box":
        return signal

    if mode == "black_box":
        return {
            "final_status": signal.get("final_status"),
            "final_response": signal.get("final_response"),
        }

    # gray_box
    policy_blocks = signal.get("policy_blocks")
    tool_calls_attempted = signal.get("tool_calls_attempted")

    return {
        "final_status": signal.get("final_status"),
        "final_reason": signal.get("final_reason"),
        "final_response": signal.get("final_response"),
        "steps_used": signal.get("steps_used"),
        "policy_blocks": [
            _redact_policy_block_for_gray_box(block)
            for block in policy_blocks
            if isinstance(block, dict)
        ]
        if isinstance(policy_blocks, list)
        else [],
        "tool_calls_attempted": [
            _redact_tool_call_attempt(attempt)
            for attempt in tool_calls_attempted
            if isinstance(attempt, dict)
        ]
        if isinstance(tool_calls_attempted, list)
        else [],
        "ticket_updates": signal.get("ticket_updates"),
        "password_resets": signal.get("password_resets"),
    }
