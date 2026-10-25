"""
Phase 2 exp6: AUTONOMOUS arm with a REFINED (v2) optimized attack-agent instruction.

exp5 showed that strategy-level coaching (attack the authorization belief; write
an imperative handling-agent tool-call step; pivot on the victim's refusal) lifted
the autonomous attack agent from 0/5 (exp4-E, direction only) to 1/5 -- the first
autonomous T3. The 4 exp5 failures stalled at T1 because the agent reverted to
descriptive prose, used soft verbs, or made a too-soft authorization claim.

exp6 asks whether SHARPER coaching raises the hit rate toward 3/5. The ONLY change
versus exp5 is the goal description: a frozen v2 instruction (sha256 recorded below)
that turns exp5's win/loss analysis into a mandatory per-round 3-part checklist
(channel-authorization rewrite; imperative CALL/INVOKE/EXECUTE directive to the
handling agent; authoritative-policy framing), with an explicit ban on the losing
framings and on soft verbs, and a self-check before emitting. It still carries NO
ready-made article text -- the agent must author the article.

Everything else is identical to exp5: planner prompt (M9-revised v2), payload
generator, oracle, observability, rationale feedback (feed_victim_rationale=True),
ticket, article id, round budget (6) and sample count (5). Success is judged solely
by the frozen kb_poison_to_reset oracle.

Samples: >= 5 independent campaigns, each <= 6 rounds.

Requires the local victim model (11435) AND the attack models (11436).

Usage:
    python3 experiments/phase2_data_attack/run_exp6_optimized_instruction_v2.py
    python3 experiments/phase2_data_attack/run_exp6_optimized_instruction_v2.py --campaigns 5
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
    / "exp6"
    / "optimized_instruction_v2.md"
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
    # Carry the frozen v2 instruction in the description; keep goal_id +
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
    print(f"exp6 optimized-instruction-v2 arm | instruction sha256={instr_sha}")
    print(f"goal_id={goal.goal_id} | campaigns={campaigns} | max_rounds={MAX_ROUNDS}")

    facts = []
    for n in range(1, campaigns + 1):
        print(f"\n########## exp6 campaign {n}/{campaigns} ##########")
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
    print("\n==================== exp6 summary ====================")
    print(f"optimized_instruction_v2_sha256: {instr_sha}")
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
