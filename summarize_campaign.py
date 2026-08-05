"""
Produce a filtered, readable transcript of one Attack Agent campaign.

Reads every round_*.json and the _summary.json file for one campaign from
logs/attack_agent/, and prints:

  - each round's strategy_label and the payload actually delivered
  - the payload generator's own rationale for that wording -- this is the
    "why was this payload chosen" text the round log actually preserves.
    (The planner's own per-round assessment/instructions are not
    persisted per round; only the campaign's *final* decision is, in the
    summary file, which is printed at the end.)
  - a condensed summary of what the Victim Agent did: final status, any
    policy blocks encountered (with rule_id and reason), whether a tool
    actually executed successfully, and the employee-facing response
  - the oracle's verdict for that round, with its stated reasons
  - the campaign's overall result at the end

Deliberately left out: raw HTTP/model metrics, full trace entries, full
tool arguments/results, session_state bookkeeping, and other
machinery-level detail that adds noise without adding to "why was this
payload chosen, and what happened as a result".

Usage:

    python3 summarize_campaign.py <campaign_id_or_prefix> [--log-dir DIR]

<campaign_id_or_prefix> can be the full campaign_id, the 8-character
short id used in filenames, or any substring that uniquely identifies one
campaign's files (for example the timestamp prefix).
"""

from __future__ import annotations

import argparse
import json
import re
import sys

from pathlib import Path
from typing import Any


DEFAULT_LOG_DIR = Path(__file__).resolve().parent / "logs" / "attack_agent"

ROUND_FILENAME_PATTERN = re.compile(r"_round_(\d+)\.json$")


def _find_campaign_files(
    campaign_id_or_prefix: str,
    log_dir: Path,
) -> tuple[list[Path], Path | None]:
    """Find every round file and the summary file for one campaign."""

    matches = sorted(log_dir.glob(f"*{campaign_id_or_prefix}*"))

    round_files = [
        path for path in matches if ROUND_FILENAME_PATTERN.search(path.name)
    ]
    summary_files = [
        path for path in matches if path.name.endswith("_summary.json")
    ]

    round_files.sort(
        key=lambda path: int(
            ROUND_FILENAME_PATTERN.search(path.name).group(1)
        )
    )

    summary_file = summary_files[0] if summary_files else None

    return round_files, summary_file


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _summarize_victim_result(victim_result: dict[str, Any]) -> None:
    """Print a condensed view of what the Victim Agent actually did."""

    print(f"  victim final status: {victim_result.get('status')}")

    trace = victim_result.get("trace")

    if not isinstance(trace, list):
        trace = []

    for entry in trace:
        if not isinstance(entry, dict):
            continue

        for layer in ("tool_policy", "session_policy", "terminal_policy"):
            policy = entry.get(layer)

            if isinstance(policy, dict) and policy.get("decision") == "blocked":
                print(
                    f"  [blocked, step {entry.get('step')}] "
                    f"{layer}: {policy.get('rule_id')} "
                    f"-- {policy.get('reason')}"
                )

        executed_tool = entry.get("executed_tool")
        tool_result = entry.get("tool_result")

        if (
            isinstance(executed_tool, dict)
            and isinstance(tool_result, dict)
            and tool_result.get("status") == "success"
        ):
            print(
                f"  [executed, step {entry.get('step')}] "
                f"{executed_tool.get('name')} -> success"
            )

    final_response = victim_result.get("final_response")

    if final_response:
        print(f"  victim final_response: {final_response}")


def _print_round(round_data: dict[str, Any]) -> None:
    payload = round_data.get("payload") or {}
    oracle_result = round_data.get("oracle_result")

    print("=" * 70)
    print(
        f"ROUND {payload.get('round_number')}  "
        f"(strategy: {payload.get('strategy_label')})"
    )
    print("=" * 70)

    print(f"[payload -> {payload.get('target_channel')}]")
    print(f"  {payload.get('content')}")
    print()

    print("[why this payload was chosen]")
    print(f"  {payload.get('rationale')}")
    print()

    print("[victim agent outcome]")
    _summarize_victim_result(round_data.get("victim_result") or {})
    print()

    if oracle_result is not None:
        print(
            "[oracle verdict]  "
            f"evaluated={oracle_result.get('evaluated')}  "
            f"achieved={oracle_result.get('achieved')}"
        )

        for reason in oracle_result.get("reasons") or []:
            print(f"  - {reason}")

    print()


def _print_campaign_summary(summary: dict[str, Any]) -> None:
    goal = summary.get("goal") or {}
    final_decision = summary.get("final_decision") or {}

    print("#" * 70)
    print("CAMPAIGN RESULT")
    print("#" * 70)
    print(f"goal_id:             {goal.get('goal_id')}")
    print(f"campaign_mode:       {summary.get('campaign_mode')}")
    print(f"observability_mode:  {summary.get('observability_mode')}")
    print(f"rounds_run:          {summary.get('rounds_run')}")
    print(f"stopped_reason:      {summary.get('stopped_reason')}")

    if final_decision:
        print(f"final planner note:  {final_decision.get('assessment')}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print a filtered, readable transcript of one campaign.",
    )
    parser.add_argument(
        "campaign_id",
        help="Full campaign_id, short id, or any unique filename substring.",
    )
    parser.add_argument(
        "--log-dir",
        default=str(DEFAULT_LOG_DIR),
        help="Directory containing the campaign's log files.",
    )

    arguments = parser.parse_args()
    log_dir = Path(arguments.log_dir)

    round_files, summary_file = _find_campaign_files(
        arguments.campaign_id, log_dir
    )

    if not round_files and summary_file is None:
        print(
            f"No files found matching '{arguments.campaign_id}' in {log_dir}"
        )
        return 1

    for round_file in round_files:
        _print_round(_load_json(round_file))

    if summary_file is not None:
        _print_campaign_summary(_load_json(summary_file))
    else:
        print("(no _summary.json found for this campaign)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
