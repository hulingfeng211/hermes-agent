"""Turn-local, plugin-readable metadata for agent execution.

``turn_metadata`` is an ephemeral JSON object carried beside a submitted
prompt.  It is deliberately separate from the user message and conversation
history: plugins may inspect it while that turn is executing, but it is never
model context or durable session state.

Top-level keys are namespaces owned by the contributing plugin/capability.
Callers receive defensive copies so there is no mutation API for the bound
turn context.
"""

from __future__ import annotations

import copy
import json
import math
import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Any


TURN_METADATA_MAX_BYTES = 16 * 1024
TURN_METADATA_MAX_DEPTH = 8
TURN_METADATA_MAX_NODES = 256
TURN_METADATA_MAX_NAMESPACES = 32

_NAMESPACE_RE = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z")
_UNSAFE_OBJECT_KEYS = frozenset({"__proto__", "prototype", "constructor"})


class _TurnMetadataScope:
    """A revocable metadata snapshot shared by copied execution contexts."""

    def __init__(self, metadata: dict[str, Any] | None) -> None:
        self._lock = threading.Lock()
        self._active = True
        self._metadata = copy.deepcopy(metadata or {})

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            if not self._active:
                return {}
            return copy.deepcopy(self._metadata)

    def revoke(self) -> None:
        with self._lock:
            self._active = False
            self._metadata = {}


@dataclass(frozen=True)
class _TurnMetadataBinding:
    token: Token
    scope: _TurnMetadataScope


_CURRENT_TURN_METADATA: ContextVar[_TurnMetadataScope | None] = ContextVar(
    "HERMES_TURN_METADATA", default=None
)


class TurnMetadataValidationError(ValueError):
    """Raised when a submitted turn metadata object is not safe bounded JSON."""


def _validate_object_key(key: Any, *, path: str) -> str:
    if not isinstance(key, str):
        raise TurnMetadataValidationError(f"{path} keys must be strings")
    if not key or len(key) > 128:
        raise TurnMetadataValidationError(
            f"{path} keys must contain between 1 and 128 characters"
        )
    if key in _UNSAFE_OBJECT_KEYS or key.startswith("__"):
        raise TurnMetadataValidationError(f"{path} contains a reserved object key")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in key):
        raise TurnMetadataValidationError(f"{path} contains a control character")
    return key


def normalize_turn_metadata(value: Any) -> dict[str, Any]:
    """Validate and defensively copy one submitted ``turn_metadata`` object.

    The accepted value is bounded JSON: no Python-only containers, non-finite
    numbers, prototype-pollution keys, excessive nesting, or oversized
    payloads.  Top-level keys use a canonical lowercase namespace syntax so
    independent plugins cannot accidentally claim spelling variants of the
    same namespace.
    """

    if not isinstance(value, dict):
        raise TurnMetadataValidationError("turn_metadata must be a JSON object")
    if len(value) > TURN_METADATA_MAX_NAMESPACES:
        raise TurnMetadataValidationError(
            f"turn_metadata may contain at most {TURN_METADATA_MAX_NAMESPACES} namespaces"
        )

    nodes = 0

    def visit(item: Any, *, depth: int, path: str) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > TURN_METADATA_MAX_NODES:
            raise TurnMetadataValidationError(
                f"turn_metadata may contain at most {TURN_METADATA_MAX_NODES} values"
            )
        if depth > TURN_METADATA_MAX_DEPTH:
            raise TurnMetadataValidationError(
                f"turn_metadata nesting may not exceed {TURN_METADATA_MAX_DEPTH} levels"
            )

        if item is None or isinstance(item, (bool, str, int)):
            return item
        if isinstance(item, float):
            if not math.isfinite(item):
                raise TurnMetadataValidationError(
                    f"{path} contains a non-finite number"
                )
            return item
        if isinstance(item, list):
            return [visit(child, depth=depth + 1, path=f"{path}[]") for child in item]
        if isinstance(item, dict):
            result: dict[str, Any] = {}
            for raw_key, child in item.items():
                key = _validate_object_key(raw_key, path=path)
                result[key] = visit(child, depth=depth + 1, path=f"{path}.{key}")
            return result
        raise TurnMetadataValidationError(
            f"{path} contains a value that is not valid JSON"
        )

    normalized: dict[str, Any] = {}
    for raw_namespace, namespace_value in value.items():
        namespace = _validate_object_key(raw_namespace, path="turn_metadata")
        if len(namespace) > 64 or _NAMESPACE_RE.fullmatch(namespace) is None:
            raise TurnMetadataValidationError(
                "turn_metadata namespace keys must be lowercase identifiers "
                "using letters, digits, '.', '_' or '-'"
            )
        normalized[namespace] = visit(
            namespace_value, depth=1, path=f"turn_metadata.{namespace}"
        )

    try:
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise TurnMetadataValidationError(
            "turn_metadata must be valid UTF-8 JSON"
        ) from exc
    if len(encoded) > TURN_METADATA_MAX_BYTES:
        raise TurnMetadataValidationError(
            f"turn_metadata may not exceed {TURN_METADATA_MAX_BYTES} UTF-8 bytes"
        )
    return normalized


def get_turn_metadata(namespace: str | None = None) -> Any:
    """Return a defensive snapshot of metadata bound to the active turn.

    With no argument, returns the complete namespace map.  With ``namespace``,
    returns that namespace's JSON value or ``None``.  Mutating the returned
    object never changes the active turn context.
    """

    scope = _CURRENT_TURN_METADATA.get()
    snapshot = scope.snapshot() if scope is not None else {}
    if namespace is None:
        return snapshot
    return snapshot.get(namespace)


def get_turn_metadata_namespace(namespace: str) -> Any:
    """Explicit namespace-oriented alias for :func:`get_turn_metadata`."""

    return get_turn_metadata(namespace)


def _bind_turn_metadata(
    metadata: dict[str, Any] | None,
) -> _TurnMetadataBinding:
    """Bind trusted, already-normalized metadata for one execution context."""

    scope = _TurnMetadataScope(metadata)
    return _TurnMetadataBinding(
        token=_CURRENT_TURN_METADATA.set(scope),
        scope=scope,
    )


def _reset_turn_metadata(binding: _TurnMetadataBinding) -> None:
    """Revoke one turn scope everywhere, then restore the prior local scope."""

    binding.scope.revoke()
    _CURRENT_TURN_METADATA.reset(binding.token)


@contextmanager
def _suspend_turn_metadata() -> Iterator[None]:
    """Hide parent-turn metadata across a nested model-turn boundary."""

    token = _CURRENT_TURN_METADATA.set(None)
    try:
        yield
    finally:
        _CURRENT_TURN_METADATA.reset(token)


__all__ = [
    "TURN_METADATA_MAX_BYTES",
    "TurnMetadataValidationError",
    "get_turn_metadata",
    "get_turn_metadata_namespace",
    "normalize_turn_metadata",
]
