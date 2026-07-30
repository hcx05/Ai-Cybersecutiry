"""
Environment reset utility for the Attack Agent experiment harness.

Runtime state under data/runtime/ (the ticket inbox and knowledge base the
Victim Agent actually reads) is gitignored and mutated by every Attack
Agent round: notes get appended to tickets, articles can be added or
edited. Left alone between rounds, that state would drift and make one
experiment case contaminate the next.

data/baseline/ holds the committed, read-only source of truth: a clean
ticket per case and any knowledge-base articles that should always be
present. reset_environment() clears data/runtime/ and repopulates it from
data/baseline/ so every experiment case, and every round within a
campaign, starts from the same known state.

data/runtime/accounts/ (the reset_password execution log) has no
baseline counterpart: nothing should ever be "restored" into it, only
cleared, so a password-reset record from a previous round can never leak
into the next case's results.

Runtime destination directories are imported directly from
victim_agent.tools.ticket, victim_agent.tools.knowledge_base, and
victim_agent.tools.account rather than re-reading TICKET_INBOX_DIR /
KNOWLEDGE_BASE_DIR / ACCOUNT_RESET_LOG_DIR independently, so a reset can
never target a different location than the one the Victim Agent actually
reads from or writes to.

Typical use, from controller/run_experiment.py, before every case:

    from controller.reset_environment import reset_environment
    reset_environment()

Or from the command line:

    python3 -m controller.reset_environment
"""

from __future__ import annotations

import argparse
import json
import sys

from pathlib import Path
from typing import Any

from victim_agent.tools.account import (
    ACCOUNTS_DIR as DEFAULT_RUNTIME_ACCOUNTS_DIR,
)
from victim_agent.tools.knowledge_base import (
    KNOWLEDGE_BASE_DIR as DEFAULT_RUNTIME_KNOWLEDGE_BASE_DIR,
)
from victim_agent.tools.ticket import (
    INBOX_DIR as DEFAULT_RUNTIME_INBOX_DIR,
    TICKET_ID_PATTERN,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_BASELINE_TICKETS_DIR = (
    PROJECT_ROOT / "data" / "baseline" / "tickets"
)
DEFAULT_BASELINE_KNOWLEDGE_BASE_DIR = (
    PROJECT_ROOT / "data" / "baseline" / "knowledge_base"
)

JSON_SUFFIX = ".json"


class ResetEnvironmentError(Exception):
    """Base exception for controlled environment reset failures."""


def _resolve_baseline_directory(path: Path, *, label: str) -> Path:
    """
    Resolve and validate a baseline source directory.

    Baseline directories are committed to the repository. They must
    already exist; this never creates them, so a missing or misconfigured
    baseline fails loudly instead of silently resetting to an empty state.
    """

    try:
        resolved = path.expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ResetEnvironmentError(
            f"{label} directory is unavailable: {path}"
        ) from exc

    if not resolved.is_dir():
        raise ResetEnvironmentError(
            f"{label} directory does not exist: {resolved}"
        )

    return resolved


def _resolve_runtime_directory(path: Path, *, label: str) -> Path:
    """
    Resolve a runtime destination directory, creating it if necessary.

    victim_agent/tools/ticket.py and victim_agent/tools/knowledge_base.py
    deliberately never create data/runtime/*; they document that a
    controller reset step is responsible for that instead. This is that
    step.
    """

    try:
        resolved = path.expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ResetEnvironmentError(
            f"{label} directory is unavailable: {path}"
        ) from exc

    try:
        resolved.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ResetEnvironmentError(
            f"{label} directory could not be created: {resolved}"
        ) from exc

    return resolved


def _reject_matching_directories(
    baseline: Path,
    runtime: Path,
    *,
    label: str,
) -> None:
    """
    Fail closed if a baseline and its runtime destination resolve to the
    same directory.

    This can only happen through environment misconfiguration (for example
    TICKET_INBOX_DIR accidentally pointed at data/baseline/tickets), but if
    it did, the clear step below would delete the baseline itself. This
    check exists so that specific failure mode is impossible rather than
    merely unlikely.
    """

    if baseline == runtime:
        raise ResetEnvironmentError(
            f"{label} baseline and runtime directories must not be the "
            f"same path: {baseline}"
        )


def _clear_runtime_directory(directory: Path) -> list[str]:
    """
    Delete every *.json file directly inside a runtime directory.

    Only *.json files are removed. .gitkeep, subdirectories, and any other
    file type are left untouched, so this can never delete something
    outside the intended runtime scope even if the directory also holds
    unrelated files.
    """

    removed: list[str] = []

    try:
        entries = sorted(directory.iterdir())
    except OSError as exc:
        raise ResetEnvironmentError(
            f"Could not list runtime directory: {directory}"
        ) from exc

    for entry in entries:
        if entry.is_file() and entry.suffix == JSON_SUFFIX:
            try:
                entry.unlink()
            except OSError as exc:
                raise ResetEnvironmentError(
                    f"Could not remove runtime file: {entry}"
                ) from exc

            removed.append(entry.name)

    return removed


def _copy_baseline_directory(
    source: Path,
    destination: Path,
) -> list[str]:
    """Copy every *.json file from a baseline directory into a runtime
    directory, byte for byte."""

    copied: list[str] = []

    try:
        entries = sorted(source.iterdir())
    except OSError as exc:
        raise ResetEnvironmentError(
            f"Could not list baseline directory: {source}"
        ) from exc

    for entry in entries:
        if not (entry.is_file() and entry.suffix == JSON_SUFFIX):
            continue

        try:
            content = entry.read_bytes()
            (destination / entry.name).write_bytes(content)
        except OSError as exc:
            raise ResetEnvironmentError(
                f"Could not restore baseline file: {entry.name}"
            ) from exc

        copied.append(entry.name)

    return copied


def _validate_ticket_id_for_restore(ticket_id: str) -> str:
    """
    Validate a ticket ID before using it to build a filesystem path.

    Mirrors victim_agent.tools.ticket's own TICKET_ID_PATTERN so a ticket
    ID this function will accept is always one the Victim Agent's own
    tools could also have produced.
    """

    if not isinstance(ticket_id, str):
        raise ResetEnvironmentError("Ticket ID must be a string.")

    normalized = ticket_id.strip()

    if not TICKET_ID_PATTERN.fullmatch(normalized):
        raise ResetEnvironmentError(
            f"Ticket ID contains unsupported characters: {ticket_id!r}"
        )

    return normalized


def _resolve_single_file(
    directory: Path,
    filename: str,
    *,
    label: str,
) -> Path:
    """
    Resolve one file inside a directory and confirm it stays inside that
    directory's boundary, as defense in depth on top of
    _validate_ticket_id_for_restore.
    """

    resolved = (directory / filename).resolve(strict=False)

    try:
        resolved.relative_to(directory)
    except ValueError as exc:
        raise ResetEnvironmentError(
            f"{label} path violates the directory safety boundary: "
            f"{filename}"
        ) from exc

    return resolved


def restore_ticket_from_baseline(
    ticket_id: str,
    *,
    baseline_tickets_dir: Path | str | None = None,
    runtime_inbox_dir: Path | str | None = None,
) -> dict[str, Any]:
    """
    Restore a single ticket to its committed baseline content.

    Copies only data/baseline/tickets/<ticket_id>.json over
    data/runtime/inbox/<ticket_id>.json, leaving every other runtime
    ticket and the knowledge base untouched. This is the per-round
    counterpart to reset_environment(): intended to run immediately
    before each round's payload is delivered in
    attack_agent.agent.run_campaign(), so a round's ticket always starts
    from the same clean baseline regardless of what a previous round's
    payload delivery or Victim Agent tool calls left behind, while
    round_history passed to the planner keeps the full campaign record
    in memory unaffected.
    """

    normalized_id = _validate_ticket_id_for_restore(ticket_id)

    baseline_tickets = _resolve_baseline_directory(
        Path(baseline_tickets_dir)
        if baseline_tickets_dir is not None
        else DEFAULT_BASELINE_TICKETS_DIR,
        label="Baseline tickets",
    )
    runtime_inbox = _resolve_runtime_directory(
        Path(runtime_inbox_dir)
        if runtime_inbox_dir is not None
        else DEFAULT_RUNTIME_INBOX_DIR,
        label="Runtime inbox",
    )

    _reject_matching_directories(
        baseline_tickets,
        runtime_inbox,
        label="Tickets",
    )

    filename = f"{normalized_id}{JSON_SUFFIX}"

    baseline_path = _resolve_single_file(
        baseline_tickets,
        filename,
        label="Baseline ticket",
    )

    if not baseline_path.is_file():
        raise ResetEnvironmentError(
            f"No baseline ticket found for: {normalized_id}"
        )

    runtime_path = _resolve_single_file(
        runtime_inbox,
        filename,
        label="Runtime ticket",
    )

    try:
        content = baseline_path.read_bytes()
        runtime_path.write_bytes(content)
    except OSError as exc:
        raise ResetEnvironmentError(
            f"Could not restore baseline ticket: {normalized_id}"
        ) from exc

    return {
        "status": "success",
        "ticket_id": normalized_id,
        "baseline_path": str(baseline_path),
        "runtime_path": str(runtime_path),
    }


def reset_environment(
    *,
    baseline_tickets_dir: Path | str | None = None,
    baseline_knowledge_base_dir: Path | str | None = None,
    runtime_inbox_dir: Path | str | None = None,
    runtime_knowledge_base_dir: Path | str | None = None,
    runtime_accounts_dir: Path | str | None = None,
) -> dict[str, Any]:
    """
    Reset data/runtime/ to the known clean state committed under
    data/baseline/.

    Every existing *.json ticket and knowledge-base article under
    data/runtime/ is deleted first, then every *.json file under the
    corresponding data/baseline/ directory is copied in. This is intended
    to run before every experiment case in controller/run_experiment.py,
    so each Attack Agent round starts from the same ticket and
    knowledge-base content regardless of what a previous round wrote.

    data/runtime/accounts/ (the reset_password execution log) is cleared
    the same way, but has no baseline counterpart to restore from: it
    should simply be empty at the start of every case.

    Returns a structured summary rather than printing directly, so the
    caller can record it as part of the experiment log.
    """

    baseline_tickets = _resolve_baseline_directory(
        Path(baseline_tickets_dir)
        if baseline_tickets_dir is not None
        else DEFAULT_BASELINE_TICKETS_DIR,
        label="Baseline tickets",
    )
    baseline_knowledge_base = _resolve_baseline_directory(
        Path(baseline_knowledge_base_dir)
        if baseline_knowledge_base_dir is not None
        else DEFAULT_BASELINE_KNOWLEDGE_BASE_DIR,
        label="Baseline knowledge base",
    )

    runtime_inbox = _resolve_runtime_directory(
        Path(runtime_inbox_dir)
        if runtime_inbox_dir is not None
        else DEFAULT_RUNTIME_INBOX_DIR,
        label="Runtime inbox",
    )
    runtime_knowledge_base = _resolve_runtime_directory(
        Path(runtime_knowledge_base_dir)
        if runtime_knowledge_base_dir is not None
        else DEFAULT_RUNTIME_KNOWLEDGE_BASE_DIR,
        label="Runtime knowledge base",
    )
    runtime_accounts = _resolve_runtime_directory(
        Path(runtime_accounts_dir)
        if runtime_accounts_dir is not None
        else DEFAULT_RUNTIME_ACCOUNTS_DIR,
        label="Runtime accounts",
    )

    _reject_matching_directories(
        baseline_tickets,
        runtime_inbox,
        label="Tickets",
    )
    _reject_matching_directories(
        baseline_knowledge_base,
        runtime_knowledge_base,
        label="Knowledge base",
    )

    removed_tickets = _clear_runtime_directory(runtime_inbox)
    removed_articles = _clear_runtime_directory(runtime_knowledge_base)
    removed_account_records = _clear_runtime_directory(runtime_accounts)

    restored_tickets = _copy_baseline_directory(
        baseline_tickets,
        runtime_inbox,
    )
    restored_articles = _copy_baseline_directory(
        baseline_knowledge_base,
        runtime_knowledge_base,
    )

    return {
        "status": "success",
        "tickets": {
            "baseline_dir": str(baseline_tickets),
            "runtime_dir": str(runtime_inbox),
            "removed": removed_tickets,
            "restored": restored_tickets,
        },
        "knowledge_base": {
            "baseline_dir": str(baseline_knowledge_base),
            "runtime_dir": str(runtime_knowledge_base),
            "removed": removed_articles,
            "restored": restored_articles,
        },
        "accounts": {
            "baseline_dir": None,
            "runtime_dir": str(runtime_accounts),
            "removed": removed_account_records,
            "restored": [],
        },
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser for standalone use."""

    parser = argparse.ArgumentParser(
        description=(
            "Reset data/runtime/ to the clean state committed under "
            "data/baseline/."
        ),
    )

    parser.add_argument(
        "--baseline-tickets-dir",
        default=None,
        help="Override the baseline tickets directory.",
    )
    parser.add_argument(
        "--baseline-knowledge-base-dir",
        default=None,
        help="Override the baseline knowledge-base directory.",
    )
    parser.add_argument(
        "--runtime-inbox-dir",
        default=None,
        help="Override the runtime ticket inbox directory.",
    )
    parser.add_argument(
        "--runtime-knowledge-base-dir",
        default=None,
        help="Override the runtime knowledge-base directory.",
    )
    parser.add_argument(
        "--runtime-accounts-dir",
        default=None,
        help="Override the runtime account-reset log directory.",
    )

    return parser


def main() -> int:
    """Run the environment reset from the command line."""

    parser = _build_argument_parser()
    arguments = parser.parse_args()

    try:
        result = reset_environment(
            baseline_tickets_dir=arguments.baseline_tickets_dir,
            baseline_knowledge_base_dir=(
                arguments.baseline_knowledge_base_dir
            ),
            runtime_inbox_dir=arguments.runtime_inbox_dir,
            runtime_knowledge_base_dir=(
                arguments.runtime_knowledge_base_dir
            ),
            runtime_accounts_dir=arguments.runtime_accounts_dir,
        )
    except ResetEnvironmentError as exc:
        print(
            json.dumps(
                {"status": "error", "error": str(exc)},
                indent=2,
                ensure_ascii=False,
            )
        )
        return 1

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
