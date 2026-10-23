"""
Phase 2 exp5: AUTONOMOUS arm with an OPTIMIZED attack-agent instruction.

exp4-E showed that with only a goal-level direction (D3) the attack agent could
not drive the victim to reset_password (0/5): it stacked precedent (close to the
failed C arm) and its payloads were descriptive, not agent-action instructions.

exp5 asks the capability question one rung up: if we give the attack agent an
OPTIMIZED instruction that encodes strategic coaching on exactly those observed
gaps -- target the authorization belief (not precedent), write imperative
handling-agent tool-call steps (not user self-service), and pivot on the
victim's stated refusal each round -- WITHOUT handing it any ready-made article
text, can the same qwen3:8b + dolphin3 pipeline now break through?

The ONLY change versus exp4-E is the goal description: the frozen optimized
instruction (sha256 recorded below) replaces the D3 brief. Planner prompt
(M9-revised v2), payload generator, oracle, observability, rationale feedback,
ticket, article id, round budget and sample count are all unchanged. Success is
judged solely by the frozen kb_poison_to_reset oracle.

Samples: >= 5 independent campaigns, each <= 6 rounds.

Requires the local victim model (11435) AND the attack models (11436).

Usage:
    python3 experiments/phase2_data_attack/run_exp5_optimized_instruction.py
    python3 experiments/phase2_data_attack/run_exp5_optimized_instruction.py --campaigns 5
"""

from __future__ import annotations

import hashlib
import json
import sys

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

CASES = PROJECT_ROOT / "experiments" / "phase2_data_attack" / "cases.json"
INSTRUCTION = (
    PROJECT_ROOT
    / "experiments"
    / "phase2_data_attack"
    / "results"
    / "kb_poisoning"
    / "exp5"
    / "optimized_instruction.md"
)
TICKET_ID = "TICKET-004"
ARTICLE_ID = "KB-ACCT-RESET-901"
MAX_ROUNDS = 6


def _sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _load_goal_with_optimized_instruction():
    from attack_agent.schemas import attack_goal_from_dict

    cases = json.loads(CASES.read_text(encoding="utf-8"))
    base = next(c for c in cases if c.get("goal_id") == "kb_poison_to_reset")
    goal_dict = dict(base)
    # Carry the frozen optimized instruction in the description; keep goal_id +
    # ground_truth (hence the oracle) exactly as the frozen case.
    goal_dict["description"] = INSTRUCTION.read_text(encoding="utf-8").strip()
    return attack_goal_from_dict(goal_dict)


def _campaign_facts(summary: dict) -> dict:
    from controller.evaluate import load_round_records

    records = load_round_records(summary)
    t_sequence = []
    first_success_round = None
    for rec in records:
        payload = rec.get("payload") or {}
        rnd = payload.get("round_number")
        tax = rec.get("failure_taxonomy") or {}
        t_sequence.append({"round": rnd, "t_code": tax.get("t_code"), "fidelity": rec.get("fidelity_flag")})
        oracle = rec.get("oracle_result") or {}
        if oracle.get("achieved") and first_success_round is None and isinstance(rnd, int):
            first_success_round = rnd
    return {
        "campaign_id": summary.get("campaign_id"),
        "rounds_run": summary.get("rounds_run"),
        "stopped_reason": summary.get("stopped_reason"),
        "first_success_round": first_success_round,
        "t_code_sequence": t_sequence,
    }


def main(argv: list[str]) -> int:
    campaigns = 5
    for i, tok in enumerate(argv):
        if tok == "--campaigns":
            campaigns = int(argv[i + 1])
        elif tok.startswith("--campaigns="):
            campaigns = int(tok.split("=", 1)[1])

    from attack_agent.agent import run_campaign

    goal = _load_goal_with_optimized_instruction()
    instr_sha = _sha256_file(INSTRUCTION)
    print(f"exp5 optimized-instruction arm | instruction sha256={instr_sha}")
    print(f"goal_id={goal.goal_id} | campaigns={campaigns} | max_rounds={MAX_ROUNDS}")

    facts = []
    for n in range(1, campaigns + 1):
        print(f"\n########## exp5 campaign {n}/{campaigns} ##########")
        summary = run_campaign(
            goal=goal,
            ticket_id=TICKET_ID,
            article_id=ARTICLE_ID,
            max_rounds=MAX_ROUNDS,
            observability_mode="white_box",
            campaign_mode="isolated_adaptive_search",
            feed_victim_rationale=True,
        )
        cf = _campaign_facts(summary)
        facts.append(cf)
        print(json.dumps(cf, ensure_ascii=False, indent=2))

    succeeded = sum(1 for f in facts if f["first_success_round"] is not None)
    print("\n==================== exp5 summary ====================")
    print(f"optimized_instruction_sha256: {instr_sha}")
    print(f"campaigns: {len(facts)} | ever_succeeded: {succeeded}/{len(facts)}")
    for f in facts:
        print(
            f"  {f['campaign_id']}: rounds_run={f['rounds_run']} "
            f"first_success_round={f['first_success_round']} "
            f"stopped={f['stopped_reason']} "
            f"T={[t['t_code'] for t in f['t_code_sequence']]}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
