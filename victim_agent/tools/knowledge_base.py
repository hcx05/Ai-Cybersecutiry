"""
Restricted knowledge-base search tool for the Victim IT Helpdesk Agent.

Phase 1 uses deterministic token-based search instead of a vector database.
This keeps retrieval behavior simple, inspectable, and reproducible.

Runtime knowledge-base location:

    data/runtime/knowledge_base/*.json

Supported operation:

    search_knowledge_base(query, top_k)

Only articles with:

    "approved": true

are eligible for retrieval.

Security and integrity properties:

- Query terms are matched as complete normalized tokens, never substrings.
- Duplicate query terms do not multiply an article's score.
- Basic English stop words are ignored.
- Duplicate article_id values fail closed with a structured error.
- Files outside the configured knowledge-base directory are rejected.
- Directory, path, file, parsing, and unexpected runtime failures are
  converted into structured tool responses.
"""

from __future__ import annotations

import json
import os
import re

from collections import Counter
from pathlib import Path
from typing import Any, Sequence


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_KNOWLEDGE_BASE_DIR = (
    PROJECT_ROOT
    / "data"
    / "runtime"
    / "knowledge_base"
)

# Keep this unresolved at import time.
#
# Tests and Docker may replace or override it. Resolution and filesystem
# validation occur inside search_knowledge_base(), where failures can be
# returned as structured tool errors instead of crashing module import.
KNOWLEDGE_BASE_DIR = Path(
    os.getenv(
        "KNOWLEDGE_BASE_DIR",
        str(DEFAULT_KNOWLEDGE_BASE_DIR),
    )
)


# ---------------------------------------------------------------------------
# Limits and deterministic scoring configuration
# ---------------------------------------------------------------------------

MIN_TOP_K = 1
MAX_TOP_K = 5

MAX_QUERY_LENGTH = 500
MAX_ARTICLE_FILE_SIZE = 1_000_000  # 1 MB
MAX_ARTICLES_SCANNED = 1_000
MAX_SNIPPET_LENGTH = 300

TITLE_TERM_WEIGHT = 3
CONTENT_TERM_WEIGHT = 1
TITLE_PHRASE_BONUS = 8
CONTENT_PHRASE_BONUS = 4

SCORING_VERSION = "deterministic-token-frequency-v1"

ARTICLE_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$"
)

# Matches complete Unicode alphanumeric terms. Hyphens, underscores, and
# punctuation act as token boundaries, so "sign-in" becomes "sign", "in".
WORD_PATTERN = re.compile(
    r"[^\W_]+",
    flags=re.UNICODE,
)

# Intentionally small and static. These are common English function words
# that usually add noise to short IT support searches.
#
# Negations such as "not", "cannot", and "failed" are deliberately retained
# because they may materially change the meaning of a support issue.
STOP_WORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "how",
        "i",
        "in",
        "is",
        "it",
        "my",
        "of",
        "on",
        "or",
        "our",
        "the",
        "their",
        "this",
        "to",
        "was",
        "we",
        "were",
        "with",
        "you",
        "your",
    }
)


# ---------------------------------------------------------------------------
# Controlled exceptions
# ---------------------------------------------------------------------------


class KnowledgeBaseToolError(Exception):
    """Base exception for controlled knowledge-base failures."""


class InvalidKnowledgeArticleError(KnowledgeBaseToolError):
    """Raised when one knowledge-base article is malformed."""


class DuplicateArticleIDError(KnowledgeBaseToolError):
    """Raised when multiple files declare the same article_id."""


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


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
    """Create a consistent structured tool response."""

    return {
        "status": status,
        "operation": "search_knowledge_base",
        "query": query,
        "top_k": top_k,
        "results": results,
        "result_count": (
            len(results)
            if results is not None
            else 0
        ),
        "scanned_articles": scanned_articles,
        "eligible_articles": eligible_articles,
        "scoring_version": SCORING_VERSION,
        "warnings": warnings or [],
        "error": error,
    }


def _structured_directory_error(
    *,
    query: str,
    top_k: int,
) -> dict[str, Any]:
    """Return a generic directory-level filesystem error."""

    return _base_response(
        status="error",
        query=query,
        top_k=top_k,
        results=None,
        error=(
            "Knowledge-base directory could not be accessed "
            "or validated safely."
        ),
    )


def _structured_unexpected_error(
    *,
    query: str | None,
    top_k: int | None,
    scanned_articles: int = 0,
    eligible_articles: int = 0,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    """Fail closed without exposing internal exception details."""

    return _base_response(
        status="error",
        query=query,
        top_k=top_k,
        results=None,
        scanned_articles=scanned_articles,
        eligible_articles=eligible_articles,
        warnings=warnings,
        error=(
            "Knowledge-base search stopped because an unexpected "
            "internal error occurred."
        ),
    )


# ---------------------------------------------------------------------------
# Validation and tokenization
# ---------------------------------------------------------------------------


def _contains_forbidden_control_characters(
    value: str,
) -> bool:
    """Detect unsupported control characters such as null bytes."""

    for character in value:
        codepoint = ord(character)

        if codepoint == 0:
            return True

        if (
            codepoint < 32
            and character not in {
                "\n",
                "\r",
                "\t",
            }
        ):
            return True

    return False


def _validate_query(
    query: Any,
) -> str:
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
            "Knowledge-base query exceeds the "
            f"{MAX_QUERY_LENGTH}-character limit."
        )

    if _contains_forbidden_control_characters(
        normalized
    ):
        raise KnowledgeBaseToolError(
            "Knowledge-base query contains unsupported "
            "control characters."
        )

    return normalized


def _validate_top_k(
    top_k: Any,
) -> int:
    """Validate the number of requested results."""

    # bool is a subclass of int in Python.
    if (
        isinstance(top_k, bool)
        or not isinstance(top_k, int)
    ):
        raise KnowledgeBaseToolError(
            "top_k must be an integer."
        )

    if not MIN_TOP_K <= top_k <= MAX_TOP_K:
        raise KnowledgeBaseToolError(
            f"top_k must be between {MIN_TOP_K} "
            f"and {MAX_TOP_K}."
        )

    return top_k


def _tokenize(
    value: str,
) -> list[str]:
    """
    Convert text into lowercase complete tokens.

    This function never performs substring matching.
    """

    return [
        token.casefold()
        for token in WORD_PATTERN.findall(value)
        if token
    ]


def _unique_terms_preserving_order(
    terms: Sequence[str],
) -> list[str]:
    """Deduplicate terms without introducing nondeterministic ordering."""

    return list(dict.fromkeys(terms))


def _prepare_query_terms(
    query: str,
) -> list[str]:
    """
    Tokenize, remove stop words, and deduplicate query terms.

    Example:

        "how to vpn vpn connection"
        -> ["vpn", "connection"]
    """

    filtered_terms = [
        token
        for token in _tokenize(query)
        if token not in STOP_WORDS
    ]

    return _unique_terms_preserving_order(
        filtered_terms
    )


def _count_token_sequence(
    tokens: Sequence[str],
    phrase_tokens: Sequence[str],
) -> int:
    """
    Count exact contiguous token-sequence occurrences.

    This is phrase matching over complete tokens, not raw-text substring
    matching. A one-token query does not receive a phrase bonus.
    """

    phrase_length = len(phrase_tokens)

    if phrase_length < 2:
        return 0

    if phrase_length > len(tokens):
        return 0

    matches = 0

    for start_index in range(
        len(tokens) - phrase_length + 1
    ):
        if list(
            tokens[
                start_index:
                start_index + phrase_length
            ]
        ) == list(phrase_tokens):
            matches += 1

    return matches


# ---------------------------------------------------------------------------
# Article loading and validation
# ---------------------------------------------------------------------------


def _create_snippet(
    content: str,
) -> str:
    """Create a short one-line preview of an article."""

    normalized = " ".join(
        content.split()
    )

    if len(normalized) <= MAX_SNIPPET_LENGTH:
        return normalized

    return (
        normalized[:MAX_SNIPPET_LENGTH].rstrip()
        + "..."
    )


def _load_article(
    path: Path,
) -> dict[str, Any]:
    """
    Read and validate one knowledge-base JSON article.

    Filesystem exceptions are converted into controlled article errors.
    """

    try:
        if not path.is_file():
            raise InvalidKnowledgeArticleError(
                "Knowledge-base path is not a regular file."
            )

        file_size = path.stat().st_size

    except InvalidKnowledgeArticleError:
        raise

    except (
        OSError,
        RuntimeError,
    ) as exc:
        raise InvalidKnowledgeArticleError(
            "Knowledge-base article metadata could not be read."
        ) from exc

    if file_size > MAX_ARTICLE_FILE_SIZE:
        raise InvalidKnowledgeArticleError(
            "Knowledge-base article exceeds the maximum file size."
        )

    try:
        raw_content = path.read_text(
            encoding="utf-8"
        )

    except (
        OSError,
        RuntimeError,
        UnicodeError,
    ) as exc:
        raise InvalidKnowledgeArticleError(
            "Knowledge-base article could not be read as UTF-8."
        ) from exc

    try:
        article = json.loads(
            raw_content
        )

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

    missing_fields = (
        required_fields
        - set(article.keys())
    )

    if missing_fields:
        raise InvalidKnowledgeArticleError(
            "Missing required fields: "
            f"{sorted(missing_fields)}"
        )

    article_id = article["article_id"]
    title = article["title"]
    content = article["content"]
    approved = article["approved"]

    if not isinstance(article_id, str):
        raise InvalidKnowledgeArticleError(
            "article_id must be a string."
        )

    normalized_article_id = (
        article_id.strip()
    )

    if not ARTICLE_ID_PATTERN.fullmatch(
        normalized_article_id
    ):
        raise InvalidKnowledgeArticleError(
            "article_id has an invalid format."
        )

    if (
        not isinstance(title, str)
        or not title.strip()
    ):
        raise InvalidKnowledgeArticleError(
            "title must be a non-empty string."
        )

    if (
        not isinstance(content, str)
        or not content.strip()
    ):
        raise InvalidKnowledgeArticleError(
            "content must be a non-empty string."
        )

    if not isinstance(approved, bool):
        raise InvalidKnowledgeArticleError(
            "approved must be a boolean."
        )

    category = article.get(
        "category",
        "general",
    )

    source = article.get(
        "source",
        "internal_it",
    )

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
        "category": (
            category.strip()
            or "general"
        ),
        "source": (
            source.strip()
            or "internal_it"
        ),
    }


# ---------------------------------------------------------------------------
# Deterministic scoring
# ---------------------------------------------------------------------------


def _score_article(
    query_terms: Sequence[str],
    article: dict[str, Any],
) -> tuple[
    int,
    list[str],
    dict[str, Any],
]:
    """
    Calculate an explainable deterministic relevance score.

    Scoring uses only complete normalized tokens:

    - Each title occurrence of a unique query term:
      TITLE_TERM_WEIGHT points
    - Each content occurrence of a unique query term:
      CONTENT_TERM_WEIGHT points
    - Exact multi-token query sequence in title:
      TITLE_PHRASE_BONUS per occurrence
    - Exact multi-token query sequence in content:
      CONTENT_PHRASE_BONUS per occurrence

    Repeated terms in the query have already been removed, so:

        "vpn vpn vpn"

    receives the same query-term weighting as:

        "vpn"
    """

    if not query_terms:
        return (
            0,
            [],
            {
                "title_term_occurrences": {},
                "content_term_occurrences": {},
                "title_phrase_occurrences": 0,
                "content_phrase_occurrences": 0,
                "title_term_points": 0,
                "content_term_points": 0,
                "title_phrase_points": 0,
                "content_phrase_points": 0,
            },
        )

    title_tokens = _tokenize(
        article["title"]
    )

    content_tokens = _tokenize(
        article["content"]
    )

    title_counts = Counter(
        title_tokens
    )

    content_counts = Counter(
        content_tokens
    )

    matched_terms: list[str] = []
    title_term_occurrences: dict[str, int] = {}
    content_term_occurrences: dict[str, int] = {}

    title_term_points = 0
    content_term_points = 0

    for term in query_terms:
        title_occurrences = (
            title_counts.get(term, 0)
        )

        content_occurrences = (
            content_counts.get(term, 0)
        )

        if (
            title_occurrences > 0
            or content_occurrences > 0
        ):
            matched_terms.append(term)

        if title_occurrences > 0:
            title_term_occurrences[
                term
            ] = title_occurrences

        if content_occurrences > 0:
            content_term_occurrences[
                term
            ] = content_occurrences

        title_term_points += (
            title_occurrences
            * TITLE_TERM_WEIGHT
        )

        content_term_points += (
            content_occurrences
            * CONTENT_TERM_WEIGHT
        )

    title_phrase_occurrences = (
        _count_token_sequence(
            title_tokens,
            query_terms,
        )
    )

    content_phrase_occurrences = (
        _count_token_sequence(
            content_tokens,
            query_terms,
        )
    )

    title_phrase_points = (
        title_phrase_occurrences
        * TITLE_PHRASE_BONUS
    )

    content_phrase_points = (
        content_phrase_occurrences
        * CONTENT_PHRASE_BONUS
    )

    score = (
        title_term_points
        + content_term_points
        + title_phrase_points
        + content_phrase_points
    )

    score_breakdown = {
        "title_term_occurrences": (
            title_term_occurrences
        ),
        "content_term_occurrences": (
            content_term_occurrences
        ),
        "title_phrase_occurrences": (
            title_phrase_occurrences
        ),
        "content_phrase_occurrences": (
            content_phrase_occurrences
        ),
        "title_term_points": (
            title_term_points
        ),
        "content_term_points": (
            content_term_points
        ),
        "title_phrase_points": (
            title_phrase_points
        ),
        "content_phrase_points": (
            content_phrase_points
        ),
    }

    return (
        score,
        matched_terms,
        score_breakdown,
    )


# ---------------------------------------------------------------------------
# Filesystem preparation
# ---------------------------------------------------------------------------


def _prepare_knowledge_base_root() -> Path:
    """
    Resolve and validate the runtime knowledge-base directory.

    Any failure is converted to KnowledgeBaseToolError so callers can return
    a structured response.
    """

    try:
        configured_path = Path(
            KNOWLEDGE_BASE_DIR
        ).expanduser()

        knowledge_base_root = (
            configured_path.resolve(
                strict=False
            )
        )

        knowledge_base_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        if not knowledge_base_root.is_dir():
            raise KnowledgeBaseToolError(
                "Knowledge-base path is not a directory."
            )

        return knowledge_base_root

    except KnowledgeBaseToolError:
        raise

    except (
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        raise KnowledgeBaseToolError(
            "Knowledge-base directory is unavailable."
        ) from exc


def _list_article_paths(
    knowledge_base_root: Path,
) -> list[Path]:
    """List JSON articles in stable filename order."""

    try:
        article_paths = sorted(
            knowledge_base_root.glob(
                "*.json"
            ),
            key=lambda path: path.name,
        )

    except (
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        raise KnowledgeBaseToolError(
            "Knowledge-base directory could not be scanned."
        ) from exc

    if len(article_paths) > MAX_ARTICLES_SCANNED:
        raise KnowledgeBaseToolError(
            "Knowledge-base article count exceeds the "
            "configured safety limit."
        )

    return article_paths


def _resolve_article_path(
    *,
    article_path: Path,
    knowledge_base_root: Path,
) -> Path:
    """
    Resolve one article and require it to remain inside the KB directory.
    """

    try:
        resolved_path = article_path.resolve(
            strict=True
        )

        resolved_path.relative_to(
            knowledge_base_root
        )

        return resolved_path

    except (
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        raise InvalidKnowledgeArticleError(
            "Knowledge-base article path could not be processed safely."
        ) from exc


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


def search_knowledge_base(
    query: str,
    top_k: int = 3,
) -> dict[str, Any]:
    """
    Search approved internal IT knowledge-base articles.

    Return shape:

        {
            "status": "success | no_results | error",
            "operation": "search_knowledge_base",
            "query": "...",
            "top_k": 3,
            "results": [...],
            "result_count": 1,
            "scanned_articles": 5,
            "eligible_articles": 4,
            "scoring_version": "deterministic-token-frequency-v1",
            "warnings": [],
            "error": null
        }

    Invalid individual article files are skipped and represented as
    structured warnings.

    Directory-level failures, duplicate article IDs, article-count limit
    violations, and unexpected internal failures return status="error".
    """

    normalized_query: str | None = None
    normalized_top_k: int | None = None

    scanned_articles = 0
    eligible_articles = 0
    warnings: list[str] = []

    try:
        normalized_query = _validate_query(
            query
        )

        normalized_top_k = _validate_top_k(
            top_k
        )

    except KnowledgeBaseToolError as exc:
        return _base_response(
            status="error",
            query=(
                query
                if isinstance(query, str)
                else None
            ),
            top_k=(
                top_k
                if (
                    isinstance(top_k, int)
                    and not isinstance(
                        top_k,
                        bool,
                    )
                )
                else None
            ),
            results=None,
            error=str(exc),
        )

    try:
        query_terms = _prepare_query_terms(
            normalized_query
        )

        knowledge_base_root = (
            _prepare_knowledge_base_root()
        )

        article_paths = (
            _list_article_paths(
                knowledge_base_root
            )
        )

    except KnowledgeBaseToolError as exc:
        return _base_response(
            status="error",
            query=normalized_query,
            top_k=normalized_top_k,
            results=None,
            scanned_articles=scanned_articles,
            eligible_articles=eligible_articles,
            warnings=warnings,
            error=str(exc),
        )

    except Exception:
        return _structured_unexpected_error(
            query=normalized_query,
            top_k=normalized_top_k,
            scanned_articles=scanned_articles,
            eligible_articles=eligible_articles,
            warnings=warnings,
        )

    scored_results: list[
        dict[str, Any]
    ] = []

    article_id_sources: dict[
        str,
        str,
    ] = {}

    try:
        for article_path in article_paths:
            scanned_articles += 1

            try:
                resolved_path = (
                    _resolve_article_path(
                        article_path=article_path,
                        knowledge_base_root=(
                            knowledge_base_root
                        ),
                    )
                )

                article = _load_article(
                    resolved_path
                )

            except InvalidKnowledgeArticleError as exc:
                warnings.append(
                    f"{article_path.name}: {str(exc)}"
                )
                continue

            except (
                OSError,
                RuntimeError,
                ValueError,
            ):
                warnings.append(
                    f"{article_path.name}: "
                    "Knowledge-base article could not be "
                    "processed safely."
                )
                continue

            article_id = article[
                "article_id"
            ]

            previous_source = (
                article_id_sources.get(
                    article_id
                )
            )

            if previous_source is not None:
                warnings.append(
                    "Duplicate article_id "
                    f"'{article_id}' was declared by "
                    f"'{previous_source}' and "
                    f"'{article_path.name}'."
                )

                raise DuplicateArticleIDError(
                    "Knowledge-base integrity validation failed "
                    "because duplicate article_id values were "
                    "detected."
                )

            article_id_sources[
                article_id
            ] = article_path.name

            # Unapproved articles remain part of uniqueness validation,
            # but cannot enter search results.
            if article["approved"] is not True:
                continue

            eligible_articles += 1

            (
                score,
                matched_terms,
                score_breakdown,
            ) = _score_article(
                query_terms,
                article,
            )

            if score <= 0:
                continue

            scored_results.append(
                {
                    "article_id": (
                        article["article_id"]
                    ),
                    "title": article["title"],
                    "category": (
                        article["category"]
                    ),
                    "source": article["source"],
                    "approved": True,
                    "score": score,
                    "scoring_version": (
                        SCORING_VERSION
                    ),
                    "matched_terms": (
                        matched_terms
                    ),
                    "score_breakdown": (
                        score_breakdown
                    ),
                    "content": (
                        article["content"]
                    ),
                    "snippet": _create_snippet(
                        article["content"]
                    ),
                }
            )

    except DuplicateArticleIDError as exc:
        return _base_response(
            status="error",
            query=normalized_query,
            top_k=normalized_top_k,
            results=None,
            scanned_articles=scanned_articles,
            eligible_articles=eligible_articles,
            warnings=warnings,
            error=str(exc),
        )

    except (
        OSError,
        RuntimeError,
        ValueError,
    ):
        return _base_response(
            status="error",
            query=normalized_query,
            top_k=normalized_top_k,
            results=None,
            scanned_articles=scanned_articles,
            eligible_articles=eligible_articles,
            warnings=warnings,
            error=(
                "Knowledge-base filesystem processing "
                "failed safely."
            ),
        )

    except Exception:
        return _structured_unexpected_error(
            query=normalized_query,
            top_k=normalized_top_k,
            scanned_articles=scanned_articles,
            eligible_articles=eligible_articles,
            warnings=warnings,
        )

    # Highest score first. article_id and title provide deterministic
    # ordering when multiple articles receive the same score.
    scored_results.sort(
        key=lambda item: (
            -item["score"],
            item["article_id"],
            item["title"].casefold(),
        )
    )

    selected_results = (
        scored_results[
            :normalized_top_k
        ]
    )

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
