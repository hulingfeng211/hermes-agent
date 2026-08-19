import contextvars
import math
import threading

import pytest

from hermes_cli.turn_context import (
    TURN_METADATA_MAX_BYTES,
    TURN_METADATA_MAX_DEPTH,
    TURN_METADATA_MAX_NAMESPACES,
    TURN_METADATA_MAX_NODES,
    TurnMetadataValidationError,
    _bind_turn_metadata,
    _reset_turn_metadata,
    _suspend_turn_metadata,
    get_turn_metadata,
    get_turn_metadata_namespace,
    normalize_turn_metadata,
)


def test_normalize_accepts_namespaced_bounded_json_and_copies_input():
    source = {
        "acme.review": {
            "mode": "bypass",
            "reasons": ["non-knowledge", None, True, 3],
        }
    }

    normalized = normalize_turn_metadata(source)
    source["acme.review"]["mode"] = "changed"
    source["acme.review"]["reasons"].append("late")

    assert normalized == {
        "acme.review": {
            "mode": "bypass",
            "reasons": ["non-knowledge", None, True, 3],
        }
    }


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {"Bad Namespace": {}},
        {"safe": {"__proto__": {"polluted": True}}},
        {"safe": {"value": math.inf}},
        {"safe": {"value": ("python", "tuple")}},
    ],
)
def test_normalize_rejects_malformed_or_unsafe_values(value):
    with pytest.raises(TurnMetadataValidationError):
        normalize_turn_metadata(value)


def test_normalize_rejects_oversized_payload():
    value = {"safe": {"value": "x" * TURN_METADATA_MAX_BYTES}}

    with pytest.raises(TurnMetadataValidationError, match="may not exceed"):
        normalize_turn_metadata(value)


def test_normalize_enforces_namespace_count_at_the_boundary():
    accepted = {
        f"namespace{index}": None for index in range(TURN_METADATA_MAX_NAMESPACES)
    }

    assert normalize_turn_metadata(accepted) == accepted

    rejected = dict(accepted)
    rejected["namespaceoverflow"] = None
    with pytest.raises(TurnMetadataValidationError, match="namespaces"):
        normalize_turn_metadata(rejected)


def test_normalize_enforces_node_count_at_the_boundary():
    accepted = {"safe": [None] * (TURN_METADATA_MAX_NODES - 1)}
    assert normalize_turn_metadata(accepted) == accepted

    rejected = {"safe": [None] * TURN_METADATA_MAX_NODES}
    with pytest.raises(TurnMetadataValidationError, match="values"):
        normalize_turn_metadata(rejected)


def test_normalize_enforces_depth_at_the_boundary():
    accepted = 0
    for _ in range(TURN_METADATA_MAX_DEPTH - 1):
        accepted = [accepted]
    assert normalize_turn_metadata({"safe": accepted}) == {"safe": accepted}

    rejected = [accepted]
    with pytest.raises(TurnMetadataValidationError, match="nesting"):
        normalize_turn_metadata({"safe": rejected})


@pytest.mark.parametrize(
    "key",
    ["prototype", "constructor", "__private", "control\x00key"],
)
def test_normalize_rejects_reserved_or_control_character_object_keys(key):
    with pytest.raises(TurnMetadataValidationError):
        normalize_turn_metadata({"safe": {key: True}})


def test_normalize_enforces_object_and_namespace_key_lengths():
    accepted_object_key = "k" * 128
    accepted_namespace = "n" * 64
    accepted = {accepted_namespace: {accepted_object_key: True}}
    assert normalize_turn_metadata(accepted) == accepted

    with pytest.raises(TurnMetadataValidationError, match="1 and 128"):
        normalize_turn_metadata({"safe": {"k" * 129: True}})
    with pytest.raises(TurnMetadataValidationError, match="namespace keys"):
        normalize_turn_metadata({"n" * 65: {}})


def test_normalize_rejects_invalid_utf8_surrogates():
    with pytest.raises(TurnMetadataValidationError, match="UTF-8 JSON"):
        normalize_turn_metadata({"safe": {"value": "\ud800"}})


def test_turn_context_is_nested_resettable_and_defensively_read_only():
    outer = _bind_turn_metadata({"outer": {"value": [1]}})
    try:
        returned = get_turn_metadata()
        returned["outer"]["value"].append(2)
        assert get_turn_metadata_namespace("outer") == {"value": [1]}

        inner = _bind_turn_metadata({"inner": {"enabled": True}})
        try:
            assert get_turn_metadata() == {"inner": {"enabled": True}}
        finally:
            _reset_turn_metadata(inner)

        assert get_turn_metadata() == {"outer": {"value": [1]}}
    finally:
        _reset_turn_metadata(outer)

    assert get_turn_metadata() == {}


def test_concurrent_turn_contexts_do_not_cross_contaminate():
    barrier = threading.Barrier(2)
    observed = {}

    def worker(namespace: str) -> None:
        token = _bind_turn_metadata({namespace: {"owner": namespace}})
        try:
            barrier.wait(timeout=2)
            observed[namespace] = get_turn_metadata()
        finally:
            _reset_turn_metadata(token)
        observed[f"{namespace}:after"] = get_turn_metadata()

    first = threading.Thread(target=worker, args=("acme.first",))
    second = threading.Thread(target=worker, args=("acme.second",))
    first.start()
    second.start()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive() and not second.is_alive()
    assert observed == {
        "acme.first": {"acme.first": {"owner": "acme.first"}},
        "acme.first:after": {},
        "acme.second": {"acme.second": {"owner": "acme.second"}},
        "acme.second:after": {},
    }


def test_reset_revokes_metadata_in_an_already_copied_thread_context():
    copied_ready = threading.Event()
    read_after_reset = threading.Event()
    observed = {}
    binding = _bind_turn_metadata({"acme.review": {"mode": "strict"}})
    copied_context = contextvars.copy_context()

    def worker() -> None:
        observed["before"] = get_turn_metadata()
        copied_ready.set()
        assert read_after_reset.wait(timeout=2)
        observed["after"] = get_turn_metadata()

    thread = threading.Thread(target=copied_context.run, args=(worker,))
    thread.start()
    try:
        assert copied_ready.wait(timeout=2)
    finally:
        _reset_turn_metadata(binding)
        read_after_reset.set()
    thread.join(timeout=2)

    assert not thread.is_alive()
    assert observed == {
        "before": {"acme.review": {"mode": "strict"}},
        "after": {},
    }
    assert get_turn_metadata() == {}


def test_suspended_turn_metadata_is_nested_and_restores_parent_scope():
    binding = _bind_turn_metadata({"parent": {"enabled": True}})
    try:
        with _suspend_turn_metadata():
            assert get_turn_metadata() == {}
            with _suspend_turn_metadata():
                assert get_turn_metadata() == {}
            assert get_turn_metadata() == {}
        assert get_turn_metadata() == {"parent": {"enabled": True}}
    finally:
        _reset_turn_metadata(binding)

    assert get_turn_metadata() == {}
