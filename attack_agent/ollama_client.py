"""
Shared, restricted Ollama HTTP client for the Attack Agent.

attack_agent/planner.py and attack_agent/payload_generator.py both need to
call an Ollama model. Rather than duplicate victim_agent/agent.py's HTTP
plumbing, or import from it, this module provides an independent copy with
the same security properties:

1. Requests do not use environment proxies and do not follow redirects.
2. The Ollama host and port are allowlisted.
3. Responses are size-bounded and must decode as one JSON object.

This is kept independent from victim_agent/agent.py on purpose. victim_agent
is the system under test; nothing in attack_agent should import from it or
change its behavior. Some duplication with victim_agent/agent.py's own
Ollama-calling code is accepted here in exchange for that isolation.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request

from typing import Any
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AttackModelError(Exception):
    """Base exception for controlled Attack Agent model-call failures."""


class AttackModelConfigurationError(AttackModelError):
    """Raised when Attack Agent model configuration is invalid."""


class AttackModelConnectionError(AttackModelError):
    """Raised when the configured Ollama server cannot be reached safely."""


class AttackModelResponseError(AttackModelError):
    """Raised when Ollama returns a response that cannot be processed."""


# ---------------------------------------------------------------------------
# Defaults and limits
# ---------------------------------------------------------------------------

DEFAULT_ALLOWED_OLLAMA_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "host.docker.internal",
    "ollama",
}

DEFAULT_ALLOWED_OLLAMA_PORTS = {
    11434,
}

MAX_MODEL_RESPONSE_BYTES = 1_000_000
MAX_HTTP_ERROR_CHARACTERS = 2_000


# ---------------------------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------------------------


def _parse_allowed_hosts(value: Any) -> set[str]:
    """Parse and validate an Ollama hostname allowlist."""

    if value is None:
        return set(DEFAULT_ALLOWED_OLLAMA_HOSTS)

    if isinstance(value, str):
        hosts = {
            item.strip().lower()
            for item in value.split(",")
            if item.strip()
        }

    elif isinstance(value, (set, list, tuple)):
        hosts = set()

        for item in value:
            if not isinstance(item, str):
                raise AttackModelConfigurationError(
                    "Allowed-hosts entries must be strings."
                )

            normalized = item.strip().lower()

            if normalized:
                hosts.add(normalized)

    else:
        raise AttackModelConfigurationError(
            "Allowed hosts must be a comma-separated string."
        )

    if not hosts:
        raise AttackModelConfigurationError(
            "Allowed hosts cannot be empty."
        )

    return hosts


def _parse_allowed_ports(value: Any) -> set[int]:
    """Parse and validate an Ollama TCP-port allowlist."""

    if value is None:
        return set(DEFAULT_ALLOWED_OLLAMA_PORTS)

    raw_values: list[Any]

    if isinstance(value, str):
        raw_values = [
            item.strip()
            for item in value.split(",")
            if item.strip()
        ]

    elif isinstance(value, (set, list, tuple)):
        raw_values = list(value)

    else:
        raise AttackModelConfigurationError(
            "Allowed ports must be a comma-separated string."
        )

    if not raw_values:
        raise AttackModelConfigurationError(
            "Allowed ports cannot be empty."
        )

    ports: set[int] = set()

    for raw_port in raw_values:
        try:
            port = int(str(raw_port).strip(), 10)
        except ValueError as exc:
            raise AttackModelConfigurationError(
                "Allowed ports entries must be base-10 integers."
            ) from exc

        if not (1 <= port <= 65535):
            raise AttackModelConfigurationError(
                "Allowed ports entries must be between 1 and 65535."
            )

        ports.add(port)

    return ports


def _effective_port(parsed: Any) -> int:
    """Return the effective TCP port, applying the scheme default."""

    if parsed.port is not None:
        return parsed.port

    return 443 if parsed.scheme.lower() == "https" else 80


def validate_ollama_base_url(
    base_url: Any,
    *,
    allowed_hosts: set[str] | None = None,
    allowed_ports: set[int] | None = None,
) -> str:
    """Validate and restrict an Ollama server root URL."""

    if not isinstance(base_url, str):
        raise AttackModelConfigurationError(
            "Ollama base URL must be a string."
        )

    normalized = base_url.strip().rstrip("/")

    if not normalized:
        raise AttackModelConfigurationError(
            "Ollama base URL cannot be empty."
        )

    parsed = urlparse(normalized)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise AttackModelConfigurationError(
            "Ollama base URL must use HTTP or HTTPS."
        )

    if not parsed.hostname:
        raise AttackModelConfigurationError(
            "Ollama base URL must include a hostname."
        )

    if parsed.username or parsed.password:
        raise AttackModelConfigurationError(
            "Credentials cannot be included in the Ollama base URL."
        )

    if parsed.query or parsed.fragment or parsed.params:
        raise AttackModelConfigurationError(
            "Ollama base URL cannot contain parameters, a query, or a "
            "fragment."
        )

    if parsed.path.rstrip("/"):
        raise AttackModelConfigurationError(
            "Ollama base URL must point to the Ollama server root."
        )

    hosts = (
        set(allowed_hosts)
        if allowed_hosts is not None
        else _parse_allowed_hosts(os.getenv("ATTACK_OLLAMA_ALLOWED_HOSTS"))
    )
    ports = (
        set(allowed_ports)
        if allowed_ports is not None
        else _parse_allowed_ports(os.getenv("ATTACK_OLLAMA_ALLOWED_PORTS"))
    )

    normalized_hostname = parsed.hostname.lower()
    effective_port = _effective_port(parsed)

    if normalized_hostname not in hosts:
        raise AttackModelConfigurationError(
            "Ollama base URL hostname is not allowlisted."
        )

    if effective_port not in ports:
        raise AttackModelConfigurationError(
            "Ollama base URL port is not allowlisted."
        )

    return normalized


# ---------------------------------------------------------------------------
# Secure HTTP client
# ---------------------------------------------------------------------------


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent urllib from following HTTP redirects."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _build_secure_opener() -> urllib.request.OpenerDirector:
    """Build an opener that ignores environment proxies and redirects."""

    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _RejectRedirectHandler(),
    )


def _canonical_url(value: str) -> tuple[str, str, int, str, str]:
    """Return a canonical endpoint tuple for final-URL verification."""

    parsed = urlparse(value)

    if not parsed.hostname:
        raise AttackModelConnectionError(
            "Ollama returned an invalid final URL."
        )

    port = _effective_port(parsed)

    return (
        parsed.scheme.lower(),
        parsed.hostname.lower(),
        port,
        parsed.path,
        parsed.query,
    )


def _validate_final_response_url(*, final_url: str, expected_url: str) -> None:
    """Ensure urllib did not reach a different endpoint."""

    if _canonical_url(final_url) != _canonical_url(expected_url):
        raise AttackModelConnectionError(
            "The Ollama response originated from an unexpected URL."
        )


def _read_http_error_body(error: urllib.error.HTTPError) -> str:
    """Read a bounded HTTP error body for a controlled message."""

    try:
        raw_body = error.read(MAX_HTTP_ERROR_CHARACTERS)
    except OSError:
        return ""

    return raw_body.decode("utf-8", errors="replace").strip()


def request_ollama_json(
    *,
    endpoint: str,
    method: str,
    timeout_seconds: float,
    body: dict[str, Any] | None = None,
    max_response_bytes: int = MAX_MODEL_RESPONSE_BYTES,
) -> dict[str, Any]:
    """Perform one proxy-free, redirect-free Ollama JSON request."""

    encoded_body: bytes | None = None

    if body is not None:
        encoded_body = json.dumps(body, ensure_ascii=False).encode("utf-8")

    request = urllib.request.Request(
        endpoint,
        data=encoded_body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method=method,
    )

    opener = _build_secure_opener()

    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            final_url_getter = getattr(response, "geturl", None)
            final_url = (
                final_url_getter()
                if callable(final_url_getter)
                else endpoint
            )

            _validate_final_response_url(
                final_url=final_url,
                expected_url=endpoint,
            )

            raw_response = response.read(max_response_bytes + 1)

    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise AttackModelConnectionError(
                "Ollama HTTP redirects are not permitted."
            ) from exc

        error_body = _read_http_error_body(exc)

        raise AttackModelConnectionError(
            f"Ollama returned HTTP {exc.code}"
            + (f": {error_body}" if error_body else ".")
        ) from exc

    except urllib.error.URLError as exc:
        raise AttackModelConnectionError(
            "Could not connect to the configured Ollama server."
        ) from exc

    except (TimeoutError, socket.timeout) as exc:
        raise AttackModelConnectionError(
            "The Ollama request timed out."
        ) from exc

    except OSError as exc:
        raise AttackModelConnectionError(
            "The Ollama request failed at the network boundary."
        ) from exc

    if len(raw_response) > max_response_bytes:
        raise AttackModelResponseError(
            "Ollama response exceeded the configured size limit."
        )

    try:
        decoded = raw_response.decode("utf-8")
        response_object = json.loads(decoded)

    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttackModelResponseError(
            "Ollama returned an invalid JSON response."
        ) from exc

    if not isinstance(response_object, dict):
        raise AttackModelResponseError(
            "Ollama response must be a JSON object."
        )

    return response_object


def call_ollama_chat(
    *,
    messages: list[dict[str, str]],
    model: str,
    base_url: str,
    structured_mode: str,
    temperature: float,
    num_ctx: int,
    timeout_seconds: float,
    json_schema: dict[str, Any] | None = None,
) -> str:
    """
    Request one chat completion from an Ollama model and return its raw
    text content.

    structured_mode:

        schema
            Send json_schema as constrained output. Currently avoided by
            default (see attack_agent/planner.py and
            attack_agent/payload_generator.py) because of a known
            llama.cpp grammar-compilation bug affecting some schema shapes
            (upstream issue ggml-org/llama.cpp#25923, open as of
            2026-07-26).

        json
            Request JSON output without a full schema constraint.

        prompt
            Rely on the system prompt alone; the caller is responsible for
            parsing and validating the response.
    """

    endpoint = f"{base_url.rstrip('/')}/api/chat"

    request_body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_ctx": num_ctx,
            "think": False,
        },
    }

    if structured_mode == "schema":
        if json_schema is None:
            raise AttackModelConfigurationError(
                "json_schema is required when structured_mode is 'schema'."
            )

        request_body["format"] = json_schema

    elif structured_mode == "json":
        request_body["format"] = "json"

    elif structured_mode != "prompt":
        raise AttackModelConfigurationError(
            "structured_mode must be 'schema', 'json', or 'prompt'."
        )

    response_object = request_ollama_json(
        endpoint=endpoint,
        method="POST",
        timeout_seconds=timeout_seconds,
        body=request_body,
    )

    message = response_object.get("message")

    if not isinstance(message, dict):
        raise AttackModelResponseError(
            "Ollama response is missing the message object."
        )

    content = message.get("content")

    if not isinstance(content, str) or not content.strip():
        raise AttackModelResponseError(
            "Ollama returned an empty model message."
        )

    return content
