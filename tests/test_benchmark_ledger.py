from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from reproassert.benchmark import (
    MAX_PUBLIC_EXCERPT_BYTES,
    _append_event,
    canonical_json_bytes,
    event_sha256,
    is_exact_prefix,
    read_ledger,
    sanitize_public_excerpt,
)
from reproassert.errors import PolicyRejection

_RECORDED_AT = "2026-07-10T12:00:00.000Z"


def _append(
    path: Path,
    *,
    attempt_id: str = "attempt-001",
    event_type: str = "attempt_started",
    payload: dict[str, object] | None = None,
    lane: str = "scored",
) -> dict[str, object]:
    return _append_event(
        path,
        lane=lane,
        batch_id="batch-001",
        attempt_id=attempt_id,
        case_id="rk-v0.1-001",
        event_type=event_type,
        payload=payload or {"phase": "generation"},
        recorded_at=_RECORDED_AT,
    )


def test_canonical_json_and_event_hash_are_stable() -> None:
    value = {"z": "café", "a": [1, True, None]}
    expected = b'{"a":[1,true,null],"z":"caf\\u00e9"}'

    assert canonical_json_bytes(value) == expected
    assert canonical_json_bytes({"a": [1, True, None], "z": "café"}) == expected

    event = {"z": 2, "a": 1, "event_sha256": "0" * 64}
    expected_hash = hashlib.sha256(b'{"a":1,"z":2}').hexdigest()
    assert event_sha256(event) == expected_hash
    assert event_sha256({"a": 1, "event_sha256": "f" * 64, "z": 2}) == expected_hash

    with pytest.raises(PolicyRejection) as exc:
        canonical_json_bytes({"not_finite": float("nan")})
    assert exc.value.code == "benchmark_event_json"


def test_first_and_second_append_form_a_canonical_hash_chain(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    first = _append(ledger, payload={"budget_usd": 1})
    second = _append(
        ledger,
        attempt_id="attempt-002",
        event_type="model_call_started",
        payload={"provider": "example"},
    )

    snapshot = read_ledger(ledger, expected_lane="scored")

    assert snapshot.errors == ()
    assert snapshot.events == (first, second)
    assert first["sequence"] == 1
    assert first["previous_event_sha256"] is None
    assert first["event_sha256"] == event_sha256(first)
    assert second["sequence"] == 2
    assert second["previous_event_sha256"] == first["event_sha256"]
    assert second["event_sha256"] == event_sha256(second)
    assert snapshot.head_event_sha256 == second["event_sha256"]
    assert snapshot.encoded == (
        canonical_json_bytes(first) + b"\n" + canonical_json_bytes(second) + b"\n"
    )
    assert snapshot.sha256 == hashlib.sha256(snapshot.encoded).hexdigest()


@pytest.mark.parametrize(
    ("corruption", "expected_error"),
    [
        ("noncanonical", "event is not canonical JSON"),
        ("mutated", "event_sha256 does not match canonical event"),
        ("reordered", "sequence must be"),
        ("deleted", "sequence must be 1"),
        ("missing_newline", "ledger must end with a newline"),
        ("blank_line", "blank ledger rows are forbidden"),
    ],
)
def test_read_ledger_rejects_corrupt_history(
    tmp_path: Path, corruption: str, expected_error: str
) -> None:
    ledger = tmp_path / "events.jsonl"
    _append(ledger)
    _append(ledger, attempt_id="attempt-002", event_type="attempt_finished")
    lines = ledger.read_bytes().splitlines()

    if corruption == "noncanonical":
        decoded = json.loads(lines[0])
        lines[0] = json.dumps(decoded, sort_keys=True).encode("ascii")
        corrupted = b"\n".join(lines) + b"\n"
    elif corruption == "mutated":
        decoded = json.loads(lines[0])
        decoded["payload"]["phase"] = "tampered"
        lines[0] = canonical_json_bytes(decoded)
        corrupted = b"\n".join(lines) + b"\n"
    elif corruption == "reordered":
        corrupted = b"\n".join(reversed(lines)) + b"\n"
    elif corruption == "deleted":
        corrupted = lines[1] + b"\n"
    elif corruption == "missing_newline":
        corrupted = b"\n".join(lines)
    else:
        corrupted = lines[0] + b"\n\n" + lines[1] + b"\n"
    ledger.write_bytes(corrupted)

    snapshot = read_ledger(ledger, expected_lane="scored")

    assert snapshot.errors
    assert any(expected_error in error for error in snapshot.errors)


def test_wrong_lane_is_visible_and_cannot_be_appended(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _append(ledger, lane="scored")
    original = ledger.read_bytes()

    snapshot = read_ledger(ledger, expected_lane="smoke")
    assert any("event lane does not match ledger lane smoke" in error for error in snapshot.errors)

    with pytest.raises(PolicyRejection) as exc:
        _append(ledger, attempt_id="attempt-002", lane="smoke")
    assert exc.value.code == "benchmark_ledger_invalid"
    assert ledger.read_bytes() == original

    with pytest.raises(PolicyRejection) as invalid_lane:
        _append(tmp_path / "invalid.jsonl", lane="public")
    assert invalid_lane.value.code == "benchmark_event_lane"


def test_exact_prefix_accepts_only_byte_for_byte_append_history(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _append(ledger)
    previous = ledger.read_bytes()
    _append(ledger, attempt_id="attempt-002", event_type="attempt_finished")
    current = ledger.read_bytes()

    assert is_exact_prefix(previous, current)
    assert is_exact_prefix(current, current)
    assert is_exact_prefix(b"", current)
    assert not is_exact_prefix(current, previous)
    assert not is_exact_prefix(previous[:-1] + b"X", current)
    assert not is_exact_prefix(previous + b"extra", current)


def test_concurrent_appends_have_unique_hashes_and_contiguous_sequences(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    count = 40

    def append_index(index: int) -> dict[str, object]:
        return _append(
            ledger,
            attempt_id=f"attempt-{index:03d}",
            event_type="attempt_started",
            payload={"index": index},
        )

    with ThreadPoolExecutor(max_workers=12) as executor:
        returned = list(executor.map(append_index, range(count)))

    snapshot = read_ledger(ledger, expected_lane="scored")

    assert snapshot.errors == ()
    assert len(snapshot.events) == count
    assert sorted(event["sequence"] for event in returned) == list(range(1, count + 1))
    assert [event["sequence"] for event in snapshot.events] == list(range(1, count + 1))
    assert len({event["event_sha256"] for event in snapshot.events}) == count
    assert {event["attempt_id"] for event in snapshot.events} == {
        f"attempt-{index:03d}" for index in range(count)
    }
    for previous, current in zip(snapshot.events[:-1], snapshot.events[1:], strict=True):
        assert current["previous_event_sha256"] == previous["event_sha256"]


def test_unmatched_start_events_remain_durable_and_visible(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    attempt_start = _append(
        ledger,
        event_type="attempt_started",
        payload={"budget_seconds": 600},
    )
    model_start = _append(
        ledger,
        event_type="model_call_started",
        payload={"provider": "example", "request_id": "request-001"},
    )

    snapshot = read_ledger(ledger, expected_lane="scored")

    assert snapshot.errors == ()
    assert snapshot.events == (attempt_start, model_start)
    assert [event["event_type"] for event in snapshot.events] == [
        "attempt_started",
        "model_call_started",
    ]
    assert all(not str(event["event_type"]).endswith("finished") for event in snapshot.events)


def test_append_refuses_a_corrupt_ledger_without_changing_it(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _append(ledger)
    ledger.write_bytes(ledger.read_bytes() + b"\n")
    corrupted = ledger.read_bytes()

    with pytest.raises(PolicyRejection) as exc:
        _append(ledger, attempt_id="attempt-002")

    assert exc.value.code == "benchmark_ledger_invalid"
    assert ledger.read_bytes() == corrupted


@pytest.mark.skipif(
    os.name == "nt" or not hasattr(os, "O_NOFOLLOW"),
    reason="final-component no-follow semantics are not portable on this platform",
)
def test_read_and_append_refuse_a_symlink_ledger(tmp_path: Path) -> None:
    target = tmp_path / "target.jsonl"
    target.write_bytes(b"")
    ledger = tmp_path / "events.jsonl"
    ledger.symlink_to(target)

    with pytest.raises(PolicyRejection) as read_exc:
        read_ledger(ledger)
    assert read_exc.value.code == "benchmark_ledger_path"

    with pytest.raises(PolicyRejection) as append_exc:
        _append(ledger)
    assert append_exc.value.code == "benchmark_ledger_path"
    assert target.read_bytes() == b""


def test_public_excerpt_redacts_secrets_ansi_and_host_paths() -> None:
    bearer_value = "bearer-" + "secret-value"
    api_value = "api-" + "secret-value"
    github_value = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    legacy_openai_value = "sk_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    current_openai_value = "sk-" + "proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    hostile = (
        "\x1b[31merror\x1b[0m\n"
        f"Authorization: Bearer {bearer_value}\n"
        f"api_key={api_value}\n"
        f"github={github_value}\n"
        f"openai_legacy={legacy_openai_value}\n"
        f"openai_current={current_openai_value}\n"
        "at /Users/alice/reproassert/source.py:42\n"
        "at /home/bob/work/test_case.py:8\n"
        "at /private/tmp/reproassert/output.log\n"
        "at C:\\Users\\Alice\\repo\\test_case.py:9"
    )

    result = sanitize_public_excerpt(hostile)
    excerpt = result["excerpt"]
    assert isinstance(excerpt, str)

    assert result["policy"] == "redacted_excerpt_v1"
    assert result["captured_bytes"] == len(hostile.encode("utf-8"))
    assert result["excerpt_bytes"] == len(excerpt.encode("utf-8"))
    assert result["excerpt_sha256"] == hashlib.sha256(excerpt.encode("utf-8")).hexdigest()
    for secret in (
        bearer_value,
        api_value,
        github_value,
        legacy_openai_value,
        current_openai_value,
    ):
        assert secret not in excerpt
    assert "\x1b" not in excerpt
    assert "/Users/alice" not in excerpt
    assert "/home/bob" not in excerpt
    assert "/private/tmp" not in excerpt
    assert "C:\\Users\\Alice" not in excerpt
    assert "<redacted>" in excerpt
    assert "<redacted-token>" in excerpt
    assert excerpt.count("<host-path>") == 4


def test_public_excerpt_is_valid_utf8_and_bounded_to_2048_bytes() -> None:
    text = chr(0x1F642) * 1_000

    result = sanitize_public_excerpt(text)
    excerpt = result["excerpt"]
    assert isinstance(excerpt, str)
    encoded = excerpt.encode("utf-8")

    assert result["captured_bytes"] == 4_000
    assert result["excerpt_bytes"] == len(encoded)
    assert len(encoded) <= MAX_PUBLIC_EXCERPT_BYTES == 2_048
    assert result["truncated"] is True
    assert excerpt.endswith("\n[excerpt truncated]")
    assert result["excerpt_sha256"] == hashlib.sha256(encoded).hexdigest()


def test_public_excerpt_at_exact_byte_limit_is_not_truncated() -> None:
    text = "x" * MAX_PUBLIC_EXCERPT_BYTES

    result = sanitize_public_excerpt(text)

    assert result["excerpt"] == text
    assert result["excerpt_bytes"] == MAX_PUBLIC_EXCERPT_BYTES
    assert result["truncated"] is False
