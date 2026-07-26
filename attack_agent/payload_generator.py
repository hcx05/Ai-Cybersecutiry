"""
Attack payload generator.

Given a goal, the planner's decision for the current round, and prior
round history, asks the payload generator model to write the actual text
to inject into the goal's target channel.
"""

from __future__ import annotations

import json
import os

from pathlib import Path
from typing import Any

from attack_agent.ollama_client import (
    AttackModelError,
    call_ollama_chat,
    validate_ollama_base_url,
)
from attack_agent.schemas import AttackGoal, AttackRound, PlannerDecision


PROJECT_ROOT = Path(__file__).resolve().parents[1]

PAYLOAD_GENERATOR_PROMPT_PATH = (
    PROJECT_ROOT / "attack_agent" / "prompts" / "payload_generator.txt"
)

MODEL_ENV = "ATTACK_PAYLOAD_GENERATOR_MODEL"
BASE_URL_ENV = "ATTACK_OLLAMA_BASE_URL"
STRUCTURED_MODE_ENV = "ATTACK_STRUCTURED_MODE"
TEMPERATURE_ENV = "ATTACK_PAYLOAD_GENERATOR_TEMPERATURE"

DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"

# See attack_agent/planner.py for why "json" rather than "schema" is the
# default (upstream issue ggml-org/llama.cpp#25923).
DEFAULT_STRUCTURED_MODE = "json"

# Higher than the planner's default: generating varied, natural-sounding
# injection wording benefits from more sampling variation than deciding a
# strategy does.
DEFAULT_TEMPERATURE = 0.9

DEFAULT_NUM_CTX = 8192
DEFAULT_TIMEOUT_SECONDS = 120.0

MAX_HISTORY_ROUNDS_IN_PROMPT = 5
MAX_CONTENT_PREVIEW_LENGTH = 300


class PayloadGeneratorError(Exception):
    """Base exception for controlled payload-generator failures."""


def _load_payload_generator_system_prompt() -> str:
    """Read the payload generator's system prompt from disk."""

    try:
        return PAYLOAD_GENERATOR_PROMPT_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise PayloadGeneratorError(
            "Could not read payload generator system prompt: "
            f"{PAYLOAD_GENERATOR_PROMPT_PATH}"
        ) from exc


def _summarize_round_for_prompt(
    attack_round: AttackRound,
) -> dict[str, Any]:
    """Compact one AttackRound down to what the payload generator needs to
    see, to avoid repeating wording that already failed."""

    return {
        "round_number": attack_round.payload.round_number,
        "strategy_label": attack_round.payload.strategy_label,
        "content_preview": attack_round.payload.content[
            :MAX_CONTENT_PREVIEW_LENGTH
        ],
        "victim_status": attack_round.victim_result.get("status"),
    }


def _parse_payload_generator_response(
    raw_content: str,
) -> tuple[str, str | None, str]:
    """
    Parse and validate the payload generator model's raw text response.

    Returns (content, title, rationale). title is None unless the model
    provided a non-empty one.
    """

    try:
        parsed = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        raise PayloadGeneratorError(
            "Payload generator model did not return valid JSON."
        ) from exc

    if not isinstance(parsed, dict):
        raise PayloadGeneratorError(
            "Payload generator response must be a JSON object."
        )

    content = parsed.get("content")

    if not isinstance(content, str) or not content.strip():
        raise PayloadGeneratorError(
            "Payload generator response is missing non-empty 'content'."
        )

    rationale = parsed.get("rationale")

    if not isinstance(rationale, str) or not rationale.strip():
        raise PayloadGeneratorError(
            "Payload generator response is missing non-empty 'rationale'."
        )

    raw_title = parsed.get("title")
    title = (
        raw_title.strip()
        if isinstance(raw_title, str) and raw_title.strip()
        else None
    )

    return content.strip(), title, rationale.strip()


def generate_payload_content(
    *,
    goal: AttackGoal,
    decision: PlannerDecision,
    history: list[AttackRound],
    model: str | None = None,
    base_url: str | None = None,
    structured_mode: str | None = None,
    temperature: float | None = None,
    num_ctx: int | None = None,
    timeout_seconds: float | None = None,
) -> tuple[str, str | None, str]:
    """
    Ask the payload generator model to write the injection text for this
    round.

    Returns (content, title, rationale). title is only meaningful when
    goal.target_channel is a knowledge-base channel; it is None otherwise
    unless the model still supplied one.
    """

    if decision.action != "continue":
        raise PayloadGeneratorError(
            "generate_payload_content requires a 'continue' "
            "PlannerDecision."
        )

    selected_model = model if model is not None else os.getenv(MODEL_ENV)

    if not selected_model:
        raise PayloadGeneratorError(
            f"No payload generator model was selected. Set {MODEL_ENV} "
            "or pass model=."
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

    system_prompt = _load_payload_generator_system_prompt()

    user_payload = {
        "goal": goal.to_dict(),
        "strategy_label": decision.strategy_label,
        "planner_instructions": decision.instructions,
        "round_history": [
            _summarize_round_for_prompt(attack_round)
            for attack_round in history[-MAX_HISTORY_ROUNDS_IN_PROMPT:]
        ],
    }

    messages = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": json.dumps(user_payload, ensure_ascii=False),
        },
    ]

    try:
        raw_content = call_ollama_chat(
            messages=messages,
            model=selected_model,
            base_url=selected_base_url,
            structured_mode=selected_structured_mode,
            temperature=selected_temperature,
            num_ctx=selected_num_ctx,
            timeout_seconds=selected_timeout,
        )
    except AttackModelError as exc:
        raise PayloadGeneratorError(
            f"Payload generator model call failed: {exc}"
        ) from exc

    return _parse_payload_generator_response(raw_content)
