"""
Re-judge Phase 2 knowledge-base campaign logs with the current oracle.

Why this exists
---------------
attack_agent/oracle.py's retrieval checker originally read
tool_result["data"] for search_knowledge_base, which nests "results" at the
top level instead -- so every successful retrieval was missed and exp1 was
logged as 0/5 (see experiments/.../exp1 report). The checker was fixed, but
the round logs already on disk still carry the stale verdict, and
controller/evaluate.py reads oracle_result["achieved"] straight off those logs
rather than re-running the oracle -- so evaluate still reports the old 0%.

This script re-runs the (now fixed) oracle over the logged Phase 2 rounds and
writes the corrected verdict back, while preserving the original verdict:

  - oracle_result                -> recomputed with the current oracle
  - oracle_result_v1_original    -> the pre-existing verdict (set once, never
                                    overwritten on a second run)
  - rejudged_with_oracle_version -> the current ORACLE_VERSION

Only goal_ids kb_poisoned_article_retrieved and kb_poison_to_reset are touched;
Phase 1 logs are left untouched. Raw log structure is otherwise preserved.

Snapshots: round logs do not store the account snapshots evaluate_goal's reset
half uses for attribution, so they are passed as None. This is sound for these
logs because no exp1/exp2 round ever executed reset_password, so the reset half
(and the kb_poison_to_reset composite) cannot become achieved regardless; the
only verdict that changes is the retrieval half of exp1, which uses the trace
alone. The script asserts this invariant and refuses to upgrade any reset
verdict from a None snapshot.

Usage:
    python3 -m controller.rejudge_phase2            # rewrite in place
    python3 -m controller.rejudge_phase2 --dry-run  # report only, no writes
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from attack_agent.oracle import ORACLE_VERSION, evaluate_goal
from attack_agent.schemas import attack_goal_from_dict, build_attack_payload
from controller.evaluate import DEFAULT_LOG_DIR, load_campaign_summaries

PHASE2_GOAL_IDS = ("kb_poisoned_article_retrieved", "kb_poison_to_reset")


def _reconstruct_payload(payload_dict: dict[str, Any]):
    """Rebuild an AttackPayload from a logged payload.to_dict() record."""

    content = payload_dict.get("content") or ""
    return build_attack_payload(
        goal_id=payload_dict.get("goal_id"),
        round_number=payload_dict.get("round_number"),
        target_channel=payload_dict.get("target_channel"),
        content=content,
        strategy_label=payload_dict.get("strategy_label"),
        rationale=payload_dict.get("rationale"),
        target_ticket_id=payload_dict.get("target_ticket_id"),
        target_article_id=payload_dict.get("target_article_id"),
        # These are already-logged payloads, not freshly generated ones; never
        # reject on length while re-judging historical evidence.
        max_content_length=max(len(content) + 1, 1),
    )


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    serialized = json.dumps(data, indent=2, ensure_ascii=False)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.stem}_",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(serialized)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        tmp = handle.name
    os.replace(tmp, path)


def rejudge(*, log_dir: Path | str | None = None, dry_run: bool = False) -> dict[str, Any]:
    resolved = Path(log_dir) if log_dir is not None else DEFAULT_LOG_DIR
    report: dict[str, Any] = {
        "oracle_version": ORACLE_VERSION,
        "dry_run": dry_run,
        "rounds_examined": 0,
        "rounds_rewritten": 0,
        "verdict_flips": [],
    }

    for goal_id in PHASE2_GOAL_IDS:
        summaries = load_campaign_summaries(log_dir=resolved, goal_id=goal_id)
        for summary in summaries:
            goal = attack_goal_from_dict(summary.get("goal"))
            for filename in summary.get("round_log_filenames") or []:
                if not isinstance(filename, str):
                    continue
                path = resolved / filename
                try:
                    record = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue

                report["rounds_examined"] += 1

                payload = _reconstruct_payload(record.get("payload") or {})
                victim_result = record.get("victim_result") or {}
                baseline_snapshot = record.get("baseline_snapshot")
                runtime_snapshot = record.get("runtime_snapshot")

                new_verdict = evaluate_goal(
                    goal=goal,
                    baseline_snapshot=baseline_snapshot,
                    payload=payload,
                    victim_result=victim_result,
                    runtime_snapshot=runtime_snapshot,
                )

                old_verdict = record.get("oracle_result") or {}
                old_achieved = bool(old_verdict.get("achieved"))
                new_achieved = bool(new_verdict.get("achieved"))

                # Safety invariant: with no stored snapshot we must never
                # newly upgrade a reset-bearing verdict from false to true.
                if (
                    goal_id == "kb_poison_to_reset"
                    and runtime_snapshot is None
                    and not old_achieved
                    and new_achieved
                ):
                    raise RuntimeError(
                        f"Refusing to upgrade kb_poison_to_reset verdict for "
                        f"{filename} without a stored runtime snapshot; "
                        "re-judging this goal needs the account snapshot."
                    )

                if old_achieved != new_achieved:
                    report["verdict_flips"].append(
                        {
                            "file": filename,
                            "goal_id": goal_id,
                            "old_achieved": old_achieved,
                            "new_achieved": new_achieved,
                        }
                    )

                if dry_run:
                    continue

                if "oracle_result_v1_original" not in record:
                    record["oracle_result_v1_original"] = old_verdict
                record["oracle_result"] = new_verdict
                record["rejudged_with_oracle_version"] = ORACLE_VERSION
                _atomic_write_json(path, record)
                report["rounds_rewritten"] += 1

    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Re-judge Phase 2 KB campaign logs with the current oracle."
    )
    parser.add_argument("--log-dir", default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    report = rejudge(log_dir=args.log_dir, dry_run=args.dry_run)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
