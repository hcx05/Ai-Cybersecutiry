"""
Deterministic analysis of one Victim Agent result.

This module extracts objective facts already present in the dict returned
by victim_agent.agent.run_victim_agent() (policy blocks, the final status,
which tools were attempted, whether the ticket status changed, and so on)
into a compact shape a planner can reason over without re-deriving them
from the full trace on every round.

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


def _extract_update_ticket_effect(
    entry: dict[str, Any],
) -> dict[str, Any] | None:
    """
    Return what a successful update_ticket call actually changed, if this
    trace entry executed one.
    """

    executed_tool = entry.get("executed_tool")
    tool_result = entry.get("tool_result")

    if not (
        isinstance(executed_tool, dict)
        and executed_tool.get("name") == "update_ticket"
        and isinstance(tool_result, dict)
        and tool_result.get("status") == "success"
    ):
        return None

    data = tool_result.get("data")

    if not isinstance(data, dict):
        return None

    return {
        "step": entry.get("step"),
        "new_status": data.get("new_status"),
        "note_added": bool(data.get("note_added")),
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

    return {
        "final_status": victim_result.get("status"),
        "final_reason": victim_result.get("reason"),
        "final_response": victim_result.get("final_response"),
        "steps_used": victim_result.get("steps_used"),
        "policy_blocks": policy_blocks,
        "tool_calls_attempted": tool_calls_attempted,
        "guard_events": guard_events,
        "ticket_updates": ticket_updates,
    }
