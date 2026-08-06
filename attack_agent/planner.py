"""
Attack planner.

Reads the current campaign state (goal, round history, and the latest
round's extracted signal) and asks the planner model for one
PlannerDecision: whether to continue the campaign, and if so, what the
next round should attempt.
"""

from __future__ import annotations

import json
import os

from pathlib import Path
from typing import Any

from attack_agent.analyzer import (
    extract_round_signal,
    filter_signal_for_observability,
)
from attack_agent.ollama_client import (
    AttackModelError,
    call_ollama_chat,
    validate_ollama_base_url,
)
from attack_agent.schemas import (
    AttackGoal,
    AttackRound,
    OBSERVABILITY_MODES,
    PlannerDecision,
    SchemaValidationError,
    build_planner_decision,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

PLANNER_PROMPT_PATH = (
    PROJECT_ROOT / "attack_agent" / "prompts" / "planner.txt"
)

MODEL_ENV = "ATTACK_PLANNER_MODEL"
BASE_URL_ENV = "ATTACK_OLLAMA_BASE_URL"
STRUCTURED_MODE_ENV = "ATTACK_STRUCTURED_MODE"
TEMPERATURE_ENV = "ATTACK_PLANNER_TEMPERATURE"

DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"

# "json" is the default rather than "schema" because of a known llama.cpp
# grammar-compilation bug affecting some schema shapes (upstream issue
# ggml-org/llama.cpp#25923, open as of 2026-07-26). See
# attack_agent/ollama_client.py for details.
DEFAULT_STRUCTURED_MODE = "json"

# Non-zero by default: unlike the Victim Agent (temperature 0, for
# reproducible comparison across models), the planner benefits from some
# variation so it does not propose the same strategy every campaign.
DEFAULT_TEMPERATURE = 0.7

DEFAULT_NUM_CTX = 8192
DEFAULT_TIMEOUT_SECONDS = 120.0

# Bounds how much round history is serialized into the prompt, so a long
# campaign's prompt size stays predictable instead of growing with every
# round.
MAX_HISTORY_ROUNDS_IN_PROMPT = 5
MAX_CONTENT_PREVIEW_LENGTH = 300


class PlannerError(Exception):
    """Base exception for controlled planner failures."""


def _load_planner_system_prompt() -> str:
    """Read the planner's system prompt from disk."""

    try:
        return PLANNER_PROMPT_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise PlannerError(
            f"Could not read planner system prompt: {PLANNER_PROMPT_PATH}"
        ) from exc


def _summarize_round_for_prompt(
    attack_round: AttackRound,
) -> dict[str, Any]:
    """
    Compact one AttackRound down to what the planner needs to see, so the
    prompt does not grow unbounded with the full Victim Agent trace on
    every round.
    """

    victim_result = attack_round.victim_result

    return {
        "round_number": attack_round.payload.round_number,
        "strategy_label": attack_round.payload.strategy_label,
        "content_preview": attack_round.payload.content[
            :MAX_CONTENT_PREVIEW_LENGTH
        ],
        "victim_status": victim_result.get("status"),
        "victim_final_response": victim_result.get("final_response"),
    }


def _build_full_history_summary(
    history: list[AttackRound],
    *,
    observability_mode: str,
) -> dict[str, Any]:
    """
    Build a compact summary spanning the campaign's *entire* history, not
    just the MAX_HISTORY_ROUNDS_IN_PROMPT most recent rounds.

    round_history (see plan_next_round) is deliberately truncated to keep
    the prompt size predictable, but that truncation had a side effect on
    long campaigns: once a round fell out of the window, the planner
    could no longer see that its strategy_label or the rule_id that
    blocked it had already been tried, and would sometimes retry a
    technique that failed many rounds earlier without knowing it. This
    summary never grows with the raw content of old rounds (only labels
    and rule IDs), so it stays cheap to include on every call regardless
    of campaign length.

    observability_mode gates what each past round contributes here, via
    attack_agent.analyzer.filter_signal_for_observability -- the exact
    same filter latest_signal already goes through. Earlier, this
    function called extract_round_signal directly on each round's
    unfiltered victim_result and read rule_id straight out of it, so a
    black_box or gray_box campaign still leaked every internal rule_id
    into the planner's prompt from round 2 onward regardless of the
    requested observability_mode; only latest_signal (the most recent
    round alone) was actually being filtered. all_strategy_labels_tried
    is unaffected by observability_mode: it is the Attack Agent's own
    record of what it tried, not information about the Victim Agent's
    internals, so it is safe to keep at every level.
    """

    if observability_mode not in OBSERVABILITY_MODES:
        raise ValueError(
            "observability_mode must be one of: "
            + ", ".join(sorted(OBSERVABILITY_MODES))
        )

    all_strategy_labels_tried: list[str] = []
    failed_rule_ids_seen: list[str] = []

    for attack_round in history:
        label = attack_round.payload.strategy_label

        if label not in all_strategy_labels_tried:
            all_strategy_labels_tried.append(label)

        raw_signal = extract_round_signal(attack_round.victim_result)
        filtered_signal = filter_signal_for_observability(
            raw_signal,
            mode=observability_mode,
        )

        if filtered_signal is None:
            continue

        for block in filtered_signal.get("policy_blocks") or []:
            if not isinstance(block, dict):
                continue

            rule_id = block.get("rule_id")

            if isinstance(rule_id, str) and rule_id not in failed_rule_ids_seen:
                failed_rule_ids_seen.append(rule_id)

    summary: dict[str, Any] = {
        "rounds_attempted": len(history),
        "all_strategy_labels_tried": all_strategy_labels_tried,
    }

    if observability_mode == "white_box":
        summary["failed_rule_ids_seen"] = failed_rule_ids_seen

    return summary


def _parse_planner_response(raw_content: str) -> PlannerDecision:
    """Parse and validate the planner model's raw text response."""

    try:
        parsed = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        raise PlannerError(
            "Planner model did not return valid JSON."
        ) from exc

    if not isinstance(parsed, dict):
        raise PlannerError(
            "Planner model response must be a JSON object."
        )

    try:
        return build_planner_decision(
            action=parsed.get("action"),
            assessment=parsed.get("assessment"),
            strategy_label=parsed.get("strategy_label"),
            instructions=parsed.get("instructions"),
        )
    except SchemaValidationError as exc:
        raise PlannerError(
            f"Planner model response failed validation: {exc}"
        ) from exc


def plan_next_round(
    *,
    goal: AttackGoal,
    history: list[AttackRound],
    latest_signal: dict[str, Any] | None,
    observability_mode: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
    structured_mode: str | None = None,
    temperature: float | None = None,
    num_ctx: int | None = None,
    timeout_seconds: float | None = None,
) -> tuple[PlannerDecision, dict[str, Any]]:
    """
    Ask the planner model for the next PlannerDecision.

    Returns (decision, metadata). metadata is the reproducibility record
    from attack_agent.ollama_client.call_ollama_chat() (model digest,
    sampling parameters, response timing) for this specific call.

    latest_signal is normally the dict returned by
    attack_agent.analyzer.extract_round_signal() for history[-1] (or a
    version of it already reduced by
    attack_agent.analyzer.filter_signal_for_observability() for the
    campaign's observability_mode), or None for the opening decision on
    round 1, when there is no previous round.

    observability_mode must be the same mode latest_signal was already
    filtered under (defaults to "white_box", matching that same default
    everywhere else). It gates full_history_summary the same way:
    without it, full_history_summary used to leak every internal rule_id
    seen across the whole campaign regardless of what observability_mode
    the caller requested, because only latest_signal (the most recent
    round) was actually being filtered -- see _build_full_history_summary.

    In addition to the truncated round_history window (the
    MAX_HISTORY_ROUNDS_IN_PROMPT most recent rounds, each with a content
    preview), the prompt also includes full_history_summary: strategy
    labels and policy rule_ids seen across the *entire* campaign so far,
    not just the recent window, so a long campaign's planner does not
    retry a technique that failed many rounds earlier simply because that
    round has scrolled out of view.
    """

    selected_observability_mode = (
        observability_mode if observability_mode is not None else "white_box"
    )

    if selected_observability_mode not in OBSERVABILITY_MODES:
        raise PlannerError(
            "observability_mode must be one of: "
            + ", ".join(sorted(OBSERVABILITY_MODES))
        )

    selected_model = model if model is not None else os.getenv(MODEL_ENV)

    if not selected_model:
        raise PlannerError(
            f"No planner model was selected. Set {MODEL_ENV} or pass "
            "model=."
        )

    selected_base_url = validate_ollama_base_url(
        base_url
        if base_url is not None
        else os.getenv(BASE_URL_ENV, DEFAULT_OLLAMA_BASE_URL)
    )

    selected_structured_mode = (
        structured_mode
        if structured_mode is not None
        else os.getenv(STRUCTURED_MODE_ENV, DEFAULT_STRUCTURED_MODE)
    )

    if temperature is not None:
        selected_temperature = temperature
    else:
        env_temperature = os.getenv(TEMPERATURE_ENV)
        selected_temperature = (
            float(env_temperature)
            if env_temperature
            else DEFAULT_TEMPERATURE
        )

    selected_num_ctx = (
        num_ctx if num_ctx is not None else DEFAULT_NUM_CTX
    )
    selected_timeout = (
        timeout_seconds
        if timeout_seconds is not None
        else DEFAULT_TIMEOUT_SECONDS
    )

    system_prompt = _load_planner_system_prompt()

    user_payload = {
        "goal": goal.to_dict(),
        "round_history": [
            _summarize_round_for_prompt(attack_round)
            for attack_round in history[-MAX_HISTORY_ROUNDS_IN_PROMPT:]
        ],
        "full_history_summary": _build_full_history_summary(
            history,
            observability_mode=selected_observability_mode,
        ),
        "latest_signal": latest_signal,
    }

    messages = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": json.dumps(user_payload, ensure_ascii=False),
        },
    ]

    try:
        raw_content, metadata = call_ollama_chat(
            messages=messages,
            model=selected_model,
            base_url=selected_base_url,
            structured_mode=selected_structured_mode,
            temperature=selected_temperature,
            num_ctx=selected_num_ctx,
            timeout_seconds=selected_timeout,
        )
    except AttackModelError as exc:
        raise PlannerError(f"Planner model call failed: {exc}") from exc

    return _parse_planner_response(raw_content), metadata
