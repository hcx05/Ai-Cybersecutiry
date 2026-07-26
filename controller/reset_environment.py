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

Runtime destination directories are imported directly from
victim_agent.tools.ticket and victim_agent.tools.knowledge_base rather
than re-reading TICKET_INBOX_DIR / KNOWLEDGE_BASE_DIR independently, so a
reset can never target a different location than the one the Victim Agent
actually reads from.

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

from victim_agent.tools.knowledge_base import (
    KNOWLEDGE_BASE_DIR as DEFAULT_RUNTIME_KNOWLEDGE_BASE_DIR,
)
from victim_agent.tools.ticket import (
    INBOX_DIR as DEFAULT_RUNTIME_INBOX_DIR,
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


def reset_environment(
    *,
    baseline_tickets_dir: Path | str | None = None,
    baseline_knowledge_base_dir: Path | str | None = None,
    runtime_inbox_dir: Path | str | None = None,
    runtime_knowledge_base_dir: Path | str | None = None,
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
