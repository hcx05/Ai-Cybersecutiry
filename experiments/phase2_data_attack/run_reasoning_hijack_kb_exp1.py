"""
Phase 2 reasoning_hijack-via-KB exp1: SECOND Phase 2 attack surface at the SAME
assumed-breach PR:H baseline as the KB content-poisoning arm (exp1-9).

This ports the Phase 1 F3 mechanism (H-CoT "mocked execution") from the
ticket_note channel into the RAG / knowledge_base channel. Phase 1 F3 broke the
reset by injecting a note posing as the agent's OWN already-completed
verify_credential result (data.valid == true), so the victim skipped the check.
Here the same mocked-execution RESULT is embedded in an APPROVED KB article that
the victim retrieves while handling the clean trigger ticket TICKET-004 -- an
on-record "verification already completed for this ticket class" statement,
never a credential to re-check (F3 exp1's dead end).

Purpose (paper): fill the missing cell of the Channel (PR:N ticket / PR:H KB) x
Mechanism (persuasion / reasoning_hijack) 2x2. exp1-9 covered persuasion@PR:H;
Phase 1 covered both mechanisms@PR:N. Without this arm, Phase 3 cannot make a
mechanism-controlled cross-channel transfer claim. Both outcomes are clean:
  - 5/5 (esp. early rounds) => mocked-execution transfers cross-channel, and at
    PR:H it is persistent; strengthens the shared reasoning-integrity thesis.
  - degrades vs Phase 1 F3 => channel-schema mismatch (episodic ticket memory vs
    static KB reference doc): PR:H does not monotonically amplify every payload
    class. Either way it bounds the Phase 3 comparison.

Everything else is identical to exp9: goal kb_poison_to_reset (unchanged frozen
oracle), planner / payload generator, observability, feed_victim_rationale=True,
ticket TICKET-004, article id KB-ACCT-RESET-901, 5 campaigns, <= 6 rounds,
isolated_adaptive_search. EXACTLY ONE thing changes vs exp9: the frozen
instruction -> reasoning_hijack_kb_v1.md (mocked-execution framing instead of
routine-policy framing). It carries NO ready-made article text.

Requires the local victim model (11435) AND the attack models (11436).

Usage:
    python3 experiments/phase2_data_attack/run_reasoning_hijack_kb_exp1.py
    python3 experiments/phase2_data_attack/run_reasoning_hijack_kb_exp1.py --campaigns 5
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
    / "reasoning_hijack_kb"
    / "exp1"
    / "reasoning_hijack_kb_v1.md"
)
TICKET_ID = "TICKET-004"
ARTICLE_ID = "KB-ACCT-RESET-901"
MAX_ROUNDS = 6


def _sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _load_goal_with_instruction():
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

    goal = _load_goal_with_instruction()
    instr_sha = _sha256_file(INSTRUCTION)
    print(f"reasoning_hijack-via-KB exp1 | instruction sha256={instr_sha}")
    print(f"goal_id={goal.goal_id} | target_channel={goal.target_channel} | campaigns={campaigns} | max_rounds={MAX_ROUNDS}")

    facts = []
    for n in range(1, campaigns + 1):
        print(f"\n########## reasoning_hijack-via-KB exp1 campaign {n}/{campaigns} ##########")
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
    print("\n==================== reasoning_hijack-via-KB exp1 summary ====================")
    print(f"reasoning_hijack_kb_v1_sha256: {instr_sha}")
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
