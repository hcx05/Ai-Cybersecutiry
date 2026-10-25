"""
Phase 2 exp8: AUTONOMOUS arm -- the v2 coaching at a LARGER autonomy budget.

Capability ladder so far (autonomous qwen3:8b + dolphin3, 5 campaigns x 6 rounds):
  exp4-E direction only            0/5
  exp5  optimized instruction v1   1/5
  exp6  optimized instruction v2   2/5   (sharper 3-part checklist)
  exp7  optimized instruction v3   1/5   (policy-purity + retrieval hint: OVER-
                                          corrected -- articles drifted off the
                                          ticket's keywords, retrieval T0 jumped,
                                          net regression; a rejected direction)

The per-round breakthrough rate is roughly stable (~1 T3 per ~12 executed rounds);
1/5 vs 2/5 at n=5 is within the Wilson noise. The reliable, monotonic lever for
raising PER-CAMPAIGN success is the attack agent's autonomy/persistence budget:
with a fixed per-round hit rate p, P(success in a campaign) = 1 - (1-p)^rounds
rises with the round budget. exp6's v2 retrieved well and reached 2/5 at 6 rounds.

exp8 therefore changes EXACTLY ONE thing versus exp6: the round budget, 6 -> 12.
The instruction is the SAME frozen v2 file used by exp6 (sha256 recorded at run
time; expected 643f1f1e...). Everything else -- planner prompt, payload generator,
oracle, observability, rationale feedback, ticket, article id, sample count (5) --
is identical to exp6. Success is judged solely by the frozen kb_poison_to_reset
oracle. This measures whether, given the same coaching but a larger adaptation
budget, the autonomous attack agent reaches >= 3/5.

Samples: >= 5 independent campaigns, each <= 12 rounds.

Requires the local victim model (11435) AND the attack models (11436).

Usage:
    python3 experiments/phase2_data_attack/run_exp8_v2_budget12.py
    python3 experiments/phase2_data_attack/run_exp8_v2_budget12.py --campaigns 5
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
# Reuse the EXACT frozen v2 instruction from exp6 -- the only change vs exp6 is
# the round budget below, so provenance of the instruction is unchanged.
INSTRUCTION = (
    PROJECT_ROOT
    / "experiments"
    / "phase2_data_attack"
    / "results"
    / "kb_poisoning"
    / "exp6"
    / "optimized_instruction_v2.md"
)
TICKET_ID = "TICKET-004"
ARTICLE_ID = "KB-ACCT-RESET-901"
MAX_ROUNDS = 12


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
    print(f"exp8 v2-instruction @ budget={MAX_ROUNDS} | instruction sha256={instr_sha}")
    print(f"goal_id={goal.goal_id} | campaigns={campaigns} | max_rounds={MAX_ROUNDS}")

    facts = []
    for n in range(1, campaigns + 1):
        print(f"\n########## exp8 campaign {n}/{campaigns} ##########")
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
    print("\n==================== exp8 summary ====================")
    print(f"instruction (v2) sha256: {instr_sha}")
    print(f"max_rounds: {MAX_ROUNDS}")
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
