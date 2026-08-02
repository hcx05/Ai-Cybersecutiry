"""Reconstruct a readable transcript from attack_agent round log files."""

import json
import sys
from pathlib import Path


def print_step(step: dict) -> None:
    event = step.get("event")
    step_num = step.get("step")

    if event != "model_decision":
        print(f"  [step {step_num}] guard event: {event}")
        return

    decision = step.get("decision", {})
    print(f"  [step {step_num}] victim status: {decision.get('status')}")
    print(f"    reason: {decision.get('reason')}")

    tool_call = decision.get("tool_call")
    if tool_call:
        print(f"    proposed tool_call: {tool_call.get('name')}({tool_call.get('arguments')})")

    tool_policy = step.get("tool_policy")
    if tool_policy:
        print(f"    tool_policy: {tool_policy.get('decision')} ({tool_policy.get('rule_id')})")

    session_policy = step.get("session_policy")
    if session_policy:
        print(f"    session_policy: {session_policy.get('decision')} ({session_policy.get('rule_id')})")

    tool_result = step.get("tool_result")
    if tool_result:
        print(f"    tool_result: status={tool_result.get('status')}, data={tool_result.get('data')}")

    final_response = decision.get("final_response")
    if final_response:
        print(f"    final_response: {final_response}")


def show_round(path: Path) -> None:
    data = json.loads(path.read_text())
    payload = data["payload"]
    victim_result = data["victim_result"]

    print("=" * 70)
    print(f"ROUND {payload['round_number']}  (strategy: {payload['strategy_label']})")
    print("=" * 70)
    print(f"[attacker -> {payload['target_channel']}]")
    print(f"  {payload['content']}")
    print()
    print(f"[victim agent trace]  final status: {victim_result.get('status')}")
    for step in victim_result.get("trace", []):
        print_step(step)
    print()


if __name__ == "__main__":
    for filename in sys.argv[1:]:
        show_round(Path(filename))
