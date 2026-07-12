from __future__ import annotations

import hashlib
import json
from collections.abc import Callable

import pytest

from reproassert.benchmark_v021_openai_adapter import (
    BoundedV021OpenAIAdapter,
    FrozenOpenAIPricing,
    parse_v021_candidate_output,
)
from reproassert.errors import PolicyRejection, ReproAssertError


def _pricing() -> FrozenOpenAIPricing:
    return FrozenOpenAIPricing(250_000, 25_000, 2_000_000)


def _candidate(issue: int = 7) -> dict[str, str]:
    symptom = "wrong normalized value"
    return {
        "expected_symptom": symptom,
        "rationale": "Directly exercises the reported behavior.",
        "test_content": (
            "from example import normalize\n\n"
            f"def test_issue_{issue}_reproduction():\n"
            f"    assert normalize('bad') == 'good', '{symptom}'\n"
        ),
    }


def _response(
    *,
    output_text: str | None = None,
    usage: object = None,
    response_id: object = "resp_test_1",
    model: object = "gpt-5.4-mini-2026-03-17",
) -> bytes:
    payload: dict[str, object] = {
        "id": response_id,
        "model": model,
        "output_text": output_text if output_text is not None else json.dumps(_candidate()),
        "status": "completed",
        "usage": (
            usage
            if usage is not None
            else {
                "input_tokens": 1_000,
                "input_tokens_details": {"cached_tokens": 200},
                "output_tokens": 100,
                "total_tokens": 1_100,
            }
        ),
    }
    return json.dumps(payload).encode()


def _invoke(
    monkeypatch: pytest.MonkeyPatch,
    response: bytes,
    *,
    transport: Callable[..., bytes] | None = None,
):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key")
    body = b'{"model":"gpt-test","store":false}'
    observed: dict[str, object] = {}

    def fake_transport(request_body: bytes, *, api_key: str, timeout_seconds: float) -> bytes:
        observed.update(body=request_body, key=api_key, timeout=timeout_seconds)
        return response

    adapter = BoundedV021OpenAIAdapter(
        pricing=_pricing(), transport=transport or fake_transport, timeout_seconds=3
    )
    result = adapter.invoke(body, expected_request_sha256=hashlib.sha256(body).hexdigest())
    return result, observed


def test_exact_frozen_bytes_usage_cost_and_secret_free_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, observed = _invoke(monkeypatch, _response())

    assert observed == {
        "body": b'{"model":"gpt-test","store":false}',
        "key": "sk-test-not-a-real-key",
        "timeout": 3,
    }
    assert result.cost_microusd == 405
    assert result.usage.to_dict() == {
        "cached_input_tokens": 200,
        "input_tokens": 1_000,
        "output_tokens": 100,
        "total_tokens": 1_100,
    }
    metadata = dict(result.durable_metadata)
    assert metadata["response_id_sha256"] == hashlib.sha256(b"resp_test_1").hexdigest()
    assert "sk-test" not in repr(metadata)
    assert "resp_test_1" not in repr(metadata)
    assert result.output_text not in repr(metadata)


def test_credential_is_read_only_after_exact_request_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    adapter = BoundedV021OpenAIAdapter(
        pricing=_pricing(), transport=lambda *_args, **_kwargs: _response()
    )
    body = b"{}"
    with pytest.raises(ReproAssertError, match="changed before call"):
        adapter.invoke(body, expected_request_sha256="0" * 64)
    with pytest.raises(ReproAssertError, match="OPENAI_API_KEY is required"):
        adapter.invoke(body, expected_request_sha256=hashlib.sha256(body).hexdigest())


@pytest.mark.parametrize("key", [" bad", "bad\nkey", "caf\N{LATIN SMALL LETTER E WITH ACUTE}"])
def test_credential_format_is_rejected(monkeypatch: pytest.MonkeyPatch, key: str) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", key)
    body = b"{}"
    adapter = BoundedV021OpenAIAdapter(
        pricing=_pricing(), transport=lambda *_args, **_kwargs: _response()
    )
    with pytest.raises(ReproAssertError, match="invalid format"):
        adapter.invoke(body, expected_request_sha256=hashlib.sha256(body).hexdigest())


@pytest.mark.parametrize(
    "usage",
    [
        None,
        "unknown",
        {"input_tokens": True, "output_tokens": 1, "total_tokens": 2},
        {"input_tokens": 1, "output_tokens": 1, "total_tokens": 9},
        {
            "input_tokens": 1,
            "input_tokens_details": {"cached_tokens": 2},
            "output_tokens": 1,
            "total_tokens": 2,
        },
    ],
)
def test_missing_or_malformed_usage_fails_closed(
    monkeypatch: pytest.MonkeyPatch, usage: object
) -> None:
    response = (
        _response(usage=usage)
        if usage is not None
        else json.dumps(
            {
                "id": "resp_x",
                "model": "gpt-test",
                "output_text": json.dumps(_candidate()),
                "status": "completed",
            }
        ).encode()
    )
    with pytest.raises(ReproAssertError) as raised:
        _invoke(monkeypatch, response)
    assert raised.value.code == "v021_openai_usage"


def test_output_overflow_and_cost_over_cap_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ReproAssertError, match="exceeded 64 KiB"):
        _invoke(monkeypatch, _response(output_text="x" * (64 * 1024 + 1)))
    expensive_usage = {
        "input_tokens": 0,
        "output_tokens": 200_000,
        "total_tokens": 200_000,
    }
    with pytest.raises(ReproAssertError, match="per-case cap"):
        _invoke(monkeypatch, _response(usage=expensive_usage))


@pytest.mark.parametrize(
    "response",
    [
        b"not-json",
        json.dumps([]).encode(),
        _response(response_id=1),
        _response(model={}),
    ],
)
def test_malformed_response_json_and_types_fail_closed(
    monkeypatch: pytest.MonkeyPatch, response: bytes
) -> None:
    with pytest.raises(ReproAssertError):
        _invoke(monkeypatch, response)


def test_transport_error_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*_args: object, **_kwargs: object) -> bytes:
        raise RuntimeError("sensitive transport internals")

    with pytest.raises(ReproAssertError, match="failed before a valid response") as raised:
        _invoke(monkeypatch, _response(), transport=broken)
    assert "sensitive" not in str(raised.value)


def test_candidate_parser_accepts_only_output_object_and_revalidates_policy() -> None:
    candidate = parse_v021_candidate_output(json.dumps(_candidate()), issue_number=7)
    assert candidate.test_function == "test_issue_7_reproduction"
    with pytest.raises(ReproAssertError, match="one JSON object"):
        parse_v021_candidate_output("[]", issue_number=7)
    with pytest.raises(PolicyRejection, match="exactly"):
        parse_v021_candidate_output(
            json.dumps({**_candidate(), "raw_provider_response": {"id": "resp_x"}}),
            issue_number=7,
        )
    invalid = _candidate()
    invalid["test_content"] = "def test_issue_7_reproduction():\n    assert False\n"
    with pytest.raises(PolicyRejection, match="Unconditional"):
        parse_v021_candidate_output(json.dumps(invalid), issue_number=7)


def test_candidate_parser_rejects_malformed_json_types_and_overflow() -> None:
    with pytest.raises(ReproAssertError, match="one JSON object"):
        parse_v021_candidate_output("{", issue_number=7)
    with pytest.raises(ReproAssertError, match="must be text"):
        parse_v021_candidate_output(1, issue_number=7)  # type: ignore[arg-type]
    with pytest.raises(ReproAssertError, match="exceeded 64 KiB"):
        parse_v021_candidate_output("x" * (64 * 1024 + 1), issue_number=7)
