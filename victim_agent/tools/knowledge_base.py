"""
Restricted knowledge-base search tool for the Victim IT Helpdesk Agent.

Phase 1 uses deterministic keyword search instead of a vector database.
This keeps the initial experiment simple and reproducible.

Runtime knowledge-base location:

    data/runtime/knowledge_base/*.json

Supported operation:

    search_knowledge_base(query, top_k)

Only articles with:

    "approved": true

are eligible for retrieval.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


# Repository root:
#
# Ai-Cyversecurity/
# └── victim_agent/
#     └── tools/
#         └── knowledge_base.py
PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_KNOWLEDGE_BASE_DIR = (
    PROJECT_ROOT / "data" / "runtime" / "knowledge_base"
)

# Tests and Docker may override this directory.
KNOWLEDGE_BASE_DIR = Path(
    os.getenv(
        "KNOWLEDGE_BASE_DIR",
        str(DEFAULT_KNOWLEDGE_BASE_DIR),
    )
).resolve()


MIN_TOP_K = 1
MAX_TOP_K = 5
MAX_QUERY_LENGTH = 500
MAX_ARTICLE_FILE_SIZE = 1_000_000  # 1 MB
MAX_ARTICLES_SCANNED = 1_000
MAX_SNIPPET_LENGTH = 300

ARTICLE_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$"
)

WORD_PATTERN = re.compile(r"[A-Za-z0-9_'-]+")


class KnowledgeBaseToolError(Exception):
    """Base exception for controlled knowledge-base failures."""


class InvalidKnowledgeArticleError(KnowledgeBaseToolError):
    """Raised when a knowledge-base article is malformed."""


def _base_response(
    *,
    status: str,
    query: str | None,
    top_k: int | None,
    results: list[dict[str, Any]] | None = None,
    scanned_articles: int = 0,
    eligible_articles: int = 0,
    warnings: list[str] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """Create a consistent tool response."""

    return {
        "status": status,
        "operation": "search_knowledge_base",
        "query": query,
        "top_k": top_k,
        "results": results,
        "result_count": len(results) if results is not None else 0,
        "scanned_articles": scanned_articles,
        "eligible_articles": eligible_articles,
        "warnings": warnings or [],
        "error": error,
    }


def _contains_forbidden_control_characters(value: str) -> bool:
    """Detect unsupported control characters such as null bytes."""

    for character in value:
        codepoint = ord(character)

        if codepoint == 0:
            return True

        if codepoint < 32 and character not in {"\n", "\r", "\t"}:
            return True

    return False


def _validate_query(query: Any) -> str:
    """Validate and normalize a search query."""

    if not isinstance(query, str):
        raise KnowledgeBaseToolError(
            "Knowledge-base query must be a string."
        )

    normalized = query.strip()

    if not normalized:
        raise KnowledgeBaseToolError(
            "Knowledge-base query cannot be empty."
        )

    if len(normalized) > MAX_QUERY_LENGTH:
        raise KnowledgeBaseToolError(
            f"Knowledge-base query exceeds the "
            f"{MAX_QUERY_LENGTH}-character limit."
        )

    if _contains_forbidden_control_characters(normalized):
        raise KnowledgeBaseToolError(
            "Knowledge-base query contains unsupported "
            "control characters."
        )

    return normalized


def _validate_top_k(top_k: Any) -> int:
    """Validate the number of requested results."""

    # bool is a subclass of int in Python.
    if isinstance(top_k, bool) or not isinstance(top_k, int):
        raise KnowledgeBaseToolError(
            "top_k must be an integer."
        )

    if not MIN_TOP_K <= top_k <= MAX_TOP_K:
        raise KnowledgeBaseToolError(
            f"top_k must be between {MIN_TOP_K} and {MAX_TOP_K}."
        )

    return top_k


def _tokenize(value: str) -> list[str]:
    """
    Convert text into normalized searchable terms.

    This is intentionally simple and deterministic for Phase 1.
    """

    return [
        token.lower()
        for token in WORD_PATTERN.findall(value)
        if token.strip()
    ]


def _create_snippet(content: str) -> str:
    """Create a short one-line preview of an article."""

    normalized = " ".join(content.split())

    if len(normalized) <= MAX_SNIPPET_LENGTH:
        return normalized

    return normalized[:MAX_SNIPPET_LENGTH].rstrip() + "..."


def _load_article(path: Path) -> dict[str, Any]:
    """Read and validate one knowledge-base JSON article."""

    if not path.is_file():
        raise InvalidKnowledgeArticleError(
            "Knowledge-base path is not a regular file."
        )

    if path.stat().st_size > MAX_ARTICLE_FILE_SIZE:
        raise InvalidKnowledgeArticleError(
            "Knowledge-base article exceeds the maximum file size."
        )

    try:
        raw_content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InvalidKnowledgeArticleError(
            "Knowledge-base article could not be read."
        ) from exc

    try:
        article = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        raise InvalidKnowledgeArticleError(
            "Knowledge-base article contains invalid JSON."
        ) from exc

    if not isinstance(article, dict):
        raise InvalidKnowledgeArticleError(
            "Knowledge-base article must contain one JSON object."
        )

    required_fields = {
        "article_id",
        "title",
        "content",
        "approved",
    }

    missing_fields = required_fields - set(article.keys())

    if missing_fields:
        raise InvalidKnowledgeArticleError(
            f"Missing required fields: {sorted(missing_fields)}"
        )

    article_id = article["article_id"]
    title = article["title"]
    content = article["content"]
    approved = article["approved"]

    if not isinstance(article_id, str):
        raise InvalidKnowledgeArticleError(
            "article_id must be a string."
        )

    normalized_article_id = article_id.strip()

    if not ARTICLE_ID_PATTERN.fullmatch(normalized_article_id):
        raise InvalidKnowledgeArticleError(
            "article_id has an invalid format."
        )

    if not isinstance(title, str) or not title.strip():
        raise InvalidKnowledgeArticleError(
            "title must be a non-empty string."
        )

    if not isinstance(content, str) or not content.strip():
        raise InvalidKnowledgeArticleError(
            "content must be a non-empty string."
        )

    if not isinstance(approved, bool):
        raise InvalidKnowledgeArticleError(
            "approved must be a boolean."
        )

    category = article.get("category", "general")
    source = article.get("source", "internal_it")

    if not isinstance(category, str):
        raise InvalidKnowledgeArticleError(
            "category must be a string."
        )

    if not isinstance(source, str):
        raise InvalidKnowledgeArticleError(
            "source must be a string."
        )

    return {
        "article_id": normalized_article_id,
        "title": title.strip(),
        "content": content.strip(),
        "approved": approved,
        "category": category.strip() or "general",
        "source": source.strip() or "internal_it",
    }


def _score_article(
    query: str,
    article: dict[str, Any],
) -> tuple[int, list[str]]:
    """
    Calculate a deterministic relevance score.

    Scoring:
    - Query term in title: 3 points per occurrence
    - Query term in content: 1 point per occurrence
    - Exact query phrase in title: 8 bonus points
    - Exact query phrase in content: 4 bonus points
    """

    query_terms = _tokenize(query)

    if not query_terms:
        return 0, []

    title = article["title"].lower()
    content = article["content"].lower()
    normalized_query = query.lower()

    score = 0
    matched_terms: set[str] = set()

    for term in query_terms:
        title_matches = title.count(term)
        content_matches = content.count(term)

        if title_matches or content_matches:
            matched_terms.add(term)

        score += title_matches * 3
        score += content_matches

    if normalized_query in title:
        score += 8

    if normalized_query in content:
        score += 4

    return score, sorted(matched_terms)


def search_knowledge_base(
    query: str,
    top_k: int = 3,
) -> dict[str, Any]:
    """
    Search approved internal IT knowledge-base articles.

    Returns:

        {
            "status": "success | no_results | error",
            "operation": "search_knowledge_base",
            "query": "...",
            "top_k": 3,
            "results": [...],
            "result_count": 1,
            "scanned_articles": 5,
            "eligible_articles": 4,
            "warnings": [],
            "error": null
        }

    Only approved articles are returned. Invalid or malformed files are
    skipped and reported through the warnings field.
    """

    try:
        normalized_query = _validate_query(query)
        normalized_top_k = _validate_top_k(top_k)

    except KnowledgeBaseToolError as exc:
        return _base_response(
            status="error",
            query=query if isinstance(query, str) else None,
            top_k=top_k if isinstance(top_k, int) else None,
            results=None,
            error=str(exc),
        )

    knowledge_base_root = KNOWLEDGE_BASE_DIR.resolve()

    try:
        knowledge_base_root.mkdir(
            parents=True,
            exist_ok=True,
        )
    except OSError:
        return _base_response(
            status="error",
            query=normalized_query,
            top_k=normalized_top_k,
            results=None,
            error="Knowledge-base directory is unavailable.",
        )

    article_paths = sorted(
        knowledge_base_root.glob("*.json")
    )

    if len(article_paths) > MAX_ARTICLES_SCANNED:
        return _base_response(
            status="error",
            query=normalized_query,
            top_k=normalized_top_k,
            results=None,
            error=(
                "Knowledge-base article count exceeds the "
                "configured safety limit."
            ),
        )

    scored_results: list[dict[str, Any]] = []
    warnings: list[str] = []
    scanned_articles = 0
    eligible_articles = 0

    for article_path in article_paths:
        scanned_articles += 1

        try:
            resolved_path = article_path.resolve()

            # Defense-in-depth boundary check.
            resolved_path.relative_to(knowledge_base_root)

            article = _load_article(resolved_path)

        except (InvalidKnowledgeArticleError, ValueError) as exc:
            warnings.append(
                f"{article_path.name}: {str(exc)}"
            )
            continue

        # Unapproved articles cannot enter search results.
        if article["approved"] is not True:
            continue

        eligible_articles += 1

        score, matched_terms = _score_article(
            normalized_query,
            article,
        )

        if score <= 0:
            continue

        scored_results.append(
            {
                "article_id": article["article_id"],
                "title": article["title"],
                "category": article["category"],
                "source": article["source"],
                "approved": True,
                "score": score,
                "matched_terms": matched_terms,
                "content": article["content"],
                "snippet": _create_snippet(
                    article["content"]
                ),
            }
        )

    # Highest score first. article_id provides stable ordering for ties.
    scored_results.sort(
        key=lambda item: (
            -item["score"],
            item["article_id"],
        )
    )

    selected_results = scored_results[:normalized_top_k]

    if not selected_results:
        return _base_response(
            status="no_results",
            query=normalized_query,
            top_k=normalized_top_k,
            results=[],
            scanned_articles=scanned_articles,
            eligible_articles=eligible_articles,
            warnings=warnings,
            error=None,
        )

    return _base_response(
        status="success",
        query=normalized_query,
        top_k=normalized_top_k,
        results=selected_results,
        scanned_articles=scanned_articles,
        eligible_articles=eligible_articles,
        warnings=warnings,
        error=None,
    )
