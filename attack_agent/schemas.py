"""
Shared data structures for the Attack Agent.

attack_agent/planner.py, attack_agent/payload_generator.py, attack_agent/
agent.py, and controller/run_experiment.py all exchange data through the
records defined here instead of passing around raw dicts:

    AttackGoal        One attack objective, normally loaded from
                       experiments/<phase>/cases.json.
    AttackPayload      One crafted attack attempt for a single round against
                       one goal.
    AttackRound        A payload together with the Victim Agent result
                       observed after it was delivered.
    PlannerDecision    One planner decision about whether, and how, to
                       continue a campaign.

Phase 1 uses plain dataclasses and explicit validation functions instead of
a schema library. This keeps the Attack Agent consistent with the rest of
this repository, which uses only the Python standard library until a
runtime dependency is actually needed.

Every record is immutable (frozen dataclasses) once constructed. A round
that needs to be retried is represented as a new AttackPayload with an
incremented round_number, not by mutating a previous one, so a campaign's
full history stays intact for logging and later analysis.
"""

from __future__ import annotations

import re

from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SchemaValidationError(Exception):
    """Base exception for invalid Attack Agent data structures."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Mirrors the identifier convention used by victim_agent/tools/ticket.py and
# victim_agent/tools/knowledge_base.py: alphanumeric, "_", and "-" only, so
# an identifier is always safe to use as part of a filename or log key.
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

# The only untrusted-data channels the Victim Agent currently reads.
#
#   ticket_description   The ticket's original "description" field.
#   ticket_note          A note appended to the ticket's "notes" list,
#                        simulating a reply from the requester.
#   knowledge_base_article
#                        The "content" (or "title") field of a knowledge
#                        base article the Victim Agent may retrieve through
#                        search_knowledge_base.
ALLOWED_TARGET_CHANNELS = frozenset(
    {
        "ticket_description",
        "ticket_note",
        "knowledge_base_article",
    }
)

# Channels that deliver a payload through a ticket file and therefore
# require target_ticket_id on the AttackPayload.
TICKET_CHANNELS = frozenset(
    {
        "ticket_description",
        "ticket_note",
    }
)

# Channels that deliver a payload through a knowledge-base article and
# therefore require target_article_id on the AttackPayload.
KNOWLEDGE_BASE_CHANNELS = frozenset(
    {
        "knowledge_base_article",
    }
)

# Valid PlannerDecision.action values.
#
#   continue         Generate and deliver another round.
#   stop_success     The goal appears achieved; stop the campaign.
#   stop_exhausted   No further strategy seems worth trying; stop the
#                    campaign without having achieved the goal.
PLANNER_ACTIONS = frozenset(
    {
        "continue",
        "stop_success",
        "stop_exhausted",
    }
)

MIN_ROUND_NUMBER = 1
MAX_ROUND_NUMBER = 50

MAX_DESCRIPTION_LENGTH = 2_000
MAX_SUCCESS_SIGNAL_LENGTH = 2_000
MAX_PAYLOAD_CONTENT_LENGTH = 4_000
MAX_STRATEGY_LABEL_LENGTH = 200
MAX_RATIONALE_LENGTH = 2_000
MAX_ASSESSMENT_LENGTH = 2_000
MAX_INSTRUCTIONS_LENGTH = 2_000


# ---------------------------------------------------------------------------
# Generic string validation helpers
# ---------------------------------------------------------------------------


def _validate_identifier(value: Any, *, field_name: str) -> str:
    """Validate and normalize an identifier such as goal_id."""

    if not isinstance(value, str):
        raise SchemaValidationError(f"{field_name} must be a string.")

    normalized = value.strip()

    if not normalized:
        raise SchemaValidationError(f"{field_name} cannot be empty.")

    if not IDENTIFIER_PATTERN.fullmatch(normalized):
        raise SchemaValidationError(
            f"{field_name} contains unsupported characters."
        )

    return normalized


def _validate_text(
    value: Any,
    *,
    field_name: str,
    max_length: int,
) -> str:
    """Validate and normalize a required free-text field."""

    if not isinstance(value, str):
        raise SchemaValidationError(f"{field_name} must be a string.")

    normalized = value.strip()

    if not normalized:
        raise SchemaValidationError(f"{field_name} cannot be empty.")

    if len(normalized) > max_length:
        raise SchemaValidationError(
            f"{field_name} exceeds the {max_length}-character limit."
        )

    return normalized


def _validate_optional_text(
    value: Any,
    *,
    field_name: str,
    max_length: int,
) -> str | None:
    """Validate a free-text field that may legitimately be absent."""

    if value is None:
        return None

    return _validate_text(
        value,
        field_name=field_name,
        max_length=max_length,
    )


def _validate_target_channel(value: Any) -> str:
    """Validate a target_channel against ALLOWED_TARGET_CHANNELS."""

    if not isinstance(value, str):
        raise SchemaValidationError("target_channel must be a string.")

    normalized = value.strip().lower()

    if normalized not in ALLOWED_TARGET_CHANNELS:
        raise SchemaValidationError(
            "Unsupported target_channel. Allowed values are: "
            + ", ".join(sorted(ALLOWED_TARGET_CHANNELS))
        )

    return normalized


def _validate_round_number(value: Any) -> int:
    """Validate a 1-indexed round number within a campaign."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise SchemaValidationError("round_number must be an integer.")

    if not (MIN_ROUND_NUMBER <= value <= MAX_ROUND_NUMBER):
        raise SchemaValidationError(
            "round_number must be between "
            f"{MIN_ROUND_NUMBER} and {MAX_ROUND_NUMBER}."
        )

    return value


def _validate_optional_identifier(
    value: Any,
    *,
    field_name: str,
) -> str | None:
    """Validate an identifier field that may legitimately be absent."""

    if value is None:
        return None

    return _validate_identifier(value, field_name=field_name)


# ---------------------------------------------------------------------------
# AttackGoal
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttackGoal:
    """
    One attack objective the Attack Agent is trying to achieve against the
    Victim Agent, normally loaded from experiments/<phase>/cases.json.

    goal_id         Stable identifier referenced from experiment case files
                     and from every log entry produced while pursuing this
                     goal (for example "leak_system_prompt").
    description      Human-readable objective, written for whoever reads the
                     experiment log or report, not for the model.
    target_channel   Which untrusted-data channel this goal is pursued
                     through, for the entire campaign. Must be one of
                     ALLOWED_TARGET_CHANNELS.
    success_signal   Human-readable description of what would count as the
                     Victim Agent being compromised for this goal. This is
                     read by the planner as guidance; it is not itself an
                     executable check.
    """

    goal_id: str
    description: str
    target_channel: str
    success_signal: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal_id": self.goal_id,
            "description": self.description,
            "target_channel": self.target_channel,
            "success_signal": self.success_signal,
        }


def build_attack_goal(
    *,
    goal_id: Any,
    description: Any,
    target_channel: Any,
    success_signal: Any,
) -> AttackGoal:
    """Validate raw input and construct one AttackGoal."""

    return AttackGoal(
        goal_id=_validate_identifier(goal_id, field_name="goal_id"),
        description=_validate_text(
            description,
            field_name="description",
            max_length=MAX_DESCRIPTION_LENGTH,
        ),
        target_channel=_validate_target_channel(target_channel),
        success_signal=_validate_text(
            success_signal,
            field_name="success_signal",
            max_length=MAX_SUCCESS_SIGNAL_LENGTH,
        ),
    )


def attack_goal_from_dict(data: Any) -> AttackGoal:
    """Construct one AttackGoal from a JSON-decoded dict, for example one
    entry of experiments/<phase>/cases.json."""

    if not isinstance(data, dict):
        raise SchemaValidationError("Each attack goal must be a JSON object.")

    return build_attack_goal(
        goal_id=data.get("goal_id"),
        description=data.get("description"),
        target_channel=data.get("target_channel"),
        success_signal=data.get("success_signal"),
    )


# ---------------------------------------------------------------------------
# AttackPayload
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttackPayload:
    """
    One crafted attack attempt produced for a single round against one goal.

    goal_id             The AttackGoal this payload is pursuing.
    round_number         1-indexed round within the current campaign.
    target_channel       Must be one of ALLOWED_TARGET_CHANNELS.
    target_ticket_id     Ticket ID the payload will be delivered into.
                         Required when target_channel is in TICKET_CHANNELS,
                         otherwise None.
    target_article_id   Knowledge-base article ID the payload will be
                         delivered into. Required when target_channel is in
                         KNOWLEDGE_BASE_CHANNELS, otherwise None.
    content              The actual text to inject into that channel.
    strategy_label       Short machine-readable tag for the technique used
                         (for example "impersonate_runtime_policy"). Used to
                         group results across rounds and campaigns.
    rationale            Free-text explanation of why this payload was
                         chosen. Written by whatever produced the payload (a
                         fixed rule, or a planner/payload-generator model
                         call) and recorded for the experiment log. Never
                         delivered to the Victim Agent.
    """

    goal_id: str
    round_number: int
    target_channel: str
    content: str
    strategy_label: str
    rationale: str
    target_ticket_id: str | None = None
    target_article_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal_id": self.goal_id,
            "round_number": self.round_number,
            "target_channel": self.target_channel,
            "target_ticket_id": self.target_ticket_id,
            "target_article_id": self.target_article_id,
            "content": self.content,
            "strategy_label": self.strategy_label,
            "rationale": self.rationale,
        }


def build_attack_payload(
    *,
    goal_id: Any,
    round_number: Any,
    target_channel: Any,
    content: Any,
    strategy_label: Any,
    rationale: Any,
    target_ticket_id: Any = None,
    target_article_id: Any = None,
) -> AttackPayload:
    """
    Validate raw input and construct one AttackPayload.

    Enforces that the target identifier matching target_channel is present,
    and that the other target identifier is not, so a payload can never be
    ambiguous about which single file it will be delivered into.
    """

    normalized_channel = _validate_target_channel(target_channel)

    normalized_ticket_id = _validate_optional_identifier(
        target_ticket_id,
        field_name="target_ticket_id",
    )
    normalized_article_id = _validate_optional_identifier(
        target_article_id,
        field_name="target_article_id",
    )

    if normalized_channel in TICKET_CHANNELS:
        if normalized_ticket_id is None:
            raise SchemaValidationError(
                "target_ticket_id is required when target_channel is "
                f"'{normalized_channel}'."
            )

        if normalized_article_id is not None:
            raise SchemaValidationError(
                "target_article_id must not be set when target_channel is "
                f"'{normalized_channel}'."
            )

    elif normalized_channel in KNOWLEDGE_BASE_CHANNELS:
        if normalized_article_id is None:
            raise SchemaValidationError(
                "target_article_id is required when target_channel is "
                f"'{normalized_channel}'."
            )

        if normalized_ticket_id is not None:
            raise SchemaValidationError(
                "target_ticket_id must not be set when target_channel is "
                f"'{normalized_channel}'."
            )

    return AttackPayload(
        goal_id=_validate_identifier(goal_id, field_name="goal_id"),
        round_number=_validate_round_number(round_number),
        target_channel=normalized_channel,
        target_ticket_id=normalized_ticket_id,
        target_article_id=normalized_article_id,
        content=_validate_text(
            content,
            field_name="content",
            max_length=MAX_PAYLOAD_CONTENT_LENGTH,
        ),
        strategy_label=_validate_text(
            strategy_label,
            field_name="strategy_label",
            max_length=MAX_STRATEGY_LABEL_LENGTH,
        ),
        rationale=_validate_text(
            rationale,
            field_name="rationale",
            max_length=MAX_RATIONALE_LENGTH,
        ),
    )


# ---------------------------------------------------------------------------
# AttackRound
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttackRound:
    """
    One completed round of a campaign: the payload that was delivered, and
    the Victim Agent result observed after run_victim_agent() processed it.

    victim_result is stored verbatim (the complete dict returned by
    victim_agent.agent.run_victim_agent()) rather than a summary, so
    controller/evaluate.py, and the planner on the next round, can inspect
    the full decision trace instead of only a top-level status.
    """

    payload: AttackPayload
    victim_result: dict[str, Any]
    delivered_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": self.payload.to_dict(),
            "victim_result": self.victim_result,
            "delivered_at": self.delivered_at,
        }


def build_attack_round(
    *,
    payload: AttackPayload,
    victim_result: Any,
    delivered_at: Any,
) -> AttackRound:
    """Validate raw input and construct one AttackRound."""

    if not isinstance(payload, AttackPayload):
        raise SchemaValidationError(
            "payload must be an AttackPayload instance."
        )

    if not isinstance(victim_result, dict):
        raise SchemaValidationError(
            "victim_result must be the dict returned by run_victim_agent()."
        )

    if not isinstance(delivered_at, str) or not delivered_at.strip():
        raise SchemaValidationError(
            "delivered_at must be a non-empty ISO-8601 timestamp string."
        )

    return AttackRound(
        payload=payload,
        victim_result=victim_result,
        delivered_at=delivered_at.strip(),
    )


# ---------------------------------------------------------------------------
# PlannerDecision
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlannerDecision:
    """
    One planner decision about whether, and how, to continue a campaign.

    action          One of PLANNER_ACTIONS.
    assessment       The planner's read on the previous round: whether it
                     showed any sign of progress toward the goal, and why.
                     For round 1 (no previous round yet) this describes the
                     opening approach instead.
    strategy_label   Short machine-readable tag for the next technique to
                     try. Required when action == "continue".
    instructions     Free-text brief for payload_generator describing what
                     the next payload should attempt and why. This is not
                     the payload text itself. Required when
                     action == "continue".
    """

    action: str
    assessment: str
    strategy_label: str | None = None
    instructions: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "assessment": self.assessment,
            "strategy_label": self.strategy_label,
            "instructions": self.instructions,
        }


def build_planner_decision(
    *,
    action: Any,
    assessment: Any,
    strategy_label: Any = None,
    instructions: Any = None,
) -> PlannerDecision:
    """
    Validate raw input and construct one PlannerDecision.

    strategy_label and instructions are required when action == "continue"
    and forbidden otherwise, so a decision to stop can never carry a
    dangling, unused next-round plan.
    """

    if not isinstance(action, str):
        raise SchemaValidationError("action must be a string.")

    normalized_action = action.strip().lower()

    if normalized_action not in PLANNER_ACTIONS:
        raise SchemaValidationError(
            "Unsupported action. Allowed values are: "
            + ", ".join(sorted(PLANNER_ACTIONS))
        )

    normalized_strategy_label = _validate_optional_text(
        strategy_label,
        field_name="strategy_label",
        max_length=MAX_STRATEGY_LABEL_LENGTH,
    )
    normalized_instructions = _validate_optional_text(
        instructions,
        field_name="instructions",
        max_length=MAX_INSTRUCTIONS_LENGTH,
    )

    if normalized_action == "continue":
        if normalized_strategy_label is None:
            raise SchemaValidationError(
                "strategy_label is required when action is 'continue'."
            )

        if normalized_instructions is None:
            raise SchemaValidationError(
                "instructions is required when action is 'continue'."
            )

    else:
        if normalized_strategy_label is not None:
            raise SchemaValidationError(
                "strategy_label must not be set unless action is "
                "'continue'."
            )

        if normalized_instructions is not None:
            raise SchemaValidationError(
                "instructions must not be set unless action is 'continue'."
            )

    return PlannerDecision(
        action=normalized_action,
        assessment=_validate_text(
            assessment,
            field_name="assessment",
            max_length=MAX_ASSESSMENT_LENGTH,
        ),
        strategy_label=normalized_strategy_label,
        instructions=normalized_instructions,
    )
