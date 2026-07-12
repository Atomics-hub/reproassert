"""Bounded OpenAI Responses adapter for frozen v0.2.1 benchmark requests."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from reproassert.candidate import ValidatedCandidate, validate_candidate_payload
from reproassert.errors import ReproAssertError
from reproassert.generator import (
    MAX_OPENAI_REPORTED_TOKENS,
    MAX_OPENAI_REQUEST_BYTES,
    MAX_OPENAI_RESPONSE_BYTES,
    _decode_openai_response,
    _extract_openai_output_text,
    _post_openai_response,
    _read_openai_api_key,
)

MAX_V021_OUTPUT_BYTES = 64 * 1024
MAX_V021_CASE_COST_MICROUSD = 250_000
TOKENS_PER_MILLION = 1_000_000
OPENAI_API_HOST = "api.openai.com"
OPENAI_RESPONSES_PATH = "/v1/responses"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RESPONSE_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


@dataclass(frozen=True)
class FrozenOpenAIPricing:
    """Integer micro-USD prices per one million tokens from a frozen artifact."""

    input_microusd_per_million_tokens: int
    cached_input_microusd_per_million_tokens: int
    output_microusd_per_million_tokens: int

    def __post_init__(self) -> None:
        for value in (
            self.input_microusd_per_million_tokens,
            self.cached_input_microusd_per_million_tokens,
            self.output_microusd_per_million_tokens,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10**12:
                raise ReproAssertError(
                    "v021_openai_pricing", "Frozen OpenAI pricing must use bounded integers."
                )

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self.to_dict())).hexdigest()

    def to_dict(self) -> dict[str, int]:
        return {
            "cached_input_microusd_per_million_tokens": (
                self.cached_input_microusd_per_million_tokens
            ),
            "input_microusd_per_million_tokens": self.input_microusd_per_million_tokens,
            "output_microusd_per_million_tokens": self.output_microusd_per_million_tokens,
        }


@dataclass(frozen=True)
class OpenAIUsage:
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    total_tokens: int

    def to_dict(self) -> dict[str, int]:
        return {
            "cached_input_tokens": self.cached_input_tokens,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass(frozen=True)
class V021OpenAIProviderResult:
    """Parsed provider output plus a secret-free durable receipt projection."""

    response_id: str = field(repr=False)
    output_text: str = field(repr=False)
    usage: OpenAIUsage
    cost_microusd: int
    durable_metadata: Mapping[str, object]


Transport = Callable[..., bytes]


class BoundedV021OpenAIAdapter:
    """Transmit exact frozen request bytes and fail closed on usage or cost ambiguity."""

    def __init__(
        self,
        *,
        pricing: FrozenOpenAIPricing,
        timeout_seconds: float = 120.0,
        max_case_cost_microusd: int = MAX_V021_CASE_COST_MICROUSD,
        transport: Transport = _post_openai_response,
    ) -> None:
        if not 1 <= timeout_seconds <= 600:
            raise ReproAssertError(
                "v021_openai_timeout", "OpenAI timeout must be between 1 and 600 seconds."
            )
        if (
            isinstance(max_case_cost_microusd, bool)
            or not isinstance(max_case_cost_microusd, int)
            or not 0 <= max_case_cost_microusd <= MAX_V021_CASE_COST_MICROUSD
        ):
            raise ReproAssertError(
                "v021_openai_cost_cap", "Per-case cost cap must be 0-250000 micro-USD."
            )
        self._pricing = pricing
        self._timeout_seconds = timeout_seconds
        self._max_case_cost_microusd = max_case_cost_microusd
        self._transport = transport

    def invoke(
        self, frozen_request_bytes: bytes, *, expected_request_sha256: str
    ) -> V021OpenAIProviderResult:
        """Call only after the controller has reserved this exact request digest."""

        if not isinstance(frozen_request_bytes, bytes) or not frozen_request_bytes:
            raise ReproAssertError(
                "v021_openai_request", "Frozen provider request must be non-empty bytes."
            )
        if len(frozen_request_bytes) > MAX_OPENAI_REQUEST_BYTES:
            raise ReproAssertError(
                "v021_openai_request_limit", "Frozen provider request exceeds 512 KiB."
            )
        if _SHA256.fullmatch(expected_request_sha256) is None:
            raise ReproAssertError(
                "v021_openai_request_hash", "Expected request SHA-256 is invalid."
            )
        request_sha256 = hashlib.sha256(frozen_request_bytes).hexdigest()
        if request_sha256 != expected_request_sha256:
            raise ReproAssertError(
                "v021_openai_request_hash", "Frozen provider request bytes changed before call."
            )

        # Deliberately read the credential only at the final provider call point.
        api_key = _read_openai_api_key()
        try:
            response_bytes = self._transport(
                frozen_request_bytes,
                api_key=api_key,
                timeout_seconds=self._timeout_seconds,
            )
        except ReproAssertError:
            raise
        except Exception as exc:
            raise ReproAssertError(
                "v021_openai_transport", "OpenAI transport failed before a valid response."
            ) from exc
        if not isinstance(response_bytes, bytes):
            raise ReproAssertError(
                "v021_openai_response", "OpenAI transport returned a non-bytes response."
            )
        if len(response_bytes) > MAX_OPENAI_RESPONSE_BYTES:
            raise ReproAssertError(
                "v021_openai_response_limit", "OpenAI response exceeded 128 KiB."
            )
        return _parse_provider_response(
            response_bytes,
            request_sha256=request_sha256,
            pricing=self._pricing,
            max_case_cost_microusd=self._max_case_cost_microusd,
        )


def parse_v021_candidate_output(
    output_text: str,
    *,
    issue_number: int,
    required_test_function: str | None = None,
) -> ValidatedCandidate:
    """Parse only output_text, never the raw provider response envelope, as a candidate."""

    if not isinstance(output_text, str):
        raise ReproAssertError("v021_candidate_json", "Candidate output must be text.")
    if len(output_text.encode("utf-8")) > MAX_V021_OUTPUT_BYTES:
        raise ReproAssertError("v021_candidate_output_limit", "Candidate output exceeded 64 KiB.")
    try:
        payload = json.loads(output_text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ReproAssertError(
            "v021_candidate_json", "Candidate output must be exactly one JSON object."
        ) from exc
    if not isinstance(payload, Mapping):
        raise ReproAssertError(
            "v021_candidate_json", "Candidate output must be exactly one JSON object."
        )
    return validate_candidate_payload(
        payload,
        issue_number=issue_number,
        required_test_function=required_test_function,
    )


def _parse_provider_response(
    response_bytes: bytes,
    *,
    request_sha256: str,
    pricing: FrozenOpenAIPricing,
    max_case_cost_microusd: int,
) -> V021OpenAIProviderResult:
    payload = _decode_openai_response(response_bytes)
    response_id = payload.get("id")
    if not isinstance(response_id, str) or _RESPONSE_ID.fullmatch(response_id) is None:
        raise ReproAssertError("v021_openai_response_id", "OpenAI response id is invalid.")
    response_model = payload.get("model")
    if not isinstance(response_model, str) or _MODEL_NAME.fullmatch(response_model) is None:
        raise ReproAssertError("v021_openai_model", "OpenAI response model is invalid.")
    output_text = _extract_openai_output_text(payload)
    if len(output_text.encode("utf-8")) > MAX_V021_OUTPUT_BYTES:
        raise ReproAssertError("v021_openai_output_limit", "OpenAI output_text exceeded 64 KiB.")
    usage = _parse_usage(payload.get("usage"))
    cost_microusd = _compute_cost_microusd(usage, pricing)
    if cost_microusd > max_case_cost_microusd:
        raise ReproAssertError(
            "v021_openai_cost_cap", "Reported OpenAI usage exceeds the authorized per-case cap."
        )
    response_sha256 = hashlib.sha256(response_bytes).hexdigest()
    output_sha256 = hashlib.sha256(output_text.encode("utf-8")).hexdigest()
    durable_metadata: Mapping[str, object] = MappingProxyType(
        {
            "cost_microusd": cost_microusd,
            "endpoint_host": OPENAI_API_HOST,
            "endpoint_path": OPENAI_RESPONSES_PATH,
            "output_text_sha256": output_sha256,
            "pricing_sha256": pricing.sha256,
            "provider": "openai",
            "request_sha256": request_sha256,
            "response_id_sha256": hashlib.sha256(response_id.encode("ascii")).hexdigest(),
            "response_model": response_model,
            "response_sha256": response_sha256,
            "usage": MappingProxyType(usage.to_dict()),
        }
    )
    return V021OpenAIProviderResult(
        response_id=response_id,
        output_text=output_text,
        usage=usage,
        cost_microusd=cost_microusd,
        durable_metadata=durable_metadata,
    )


def _parse_usage(value: object) -> OpenAIUsage:
    if not isinstance(value, Mapping):
        raise ReproAssertError("v021_openai_usage", "OpenAI usage metadata is required.")
    input_tokens = _token_count(value.get("input_tokens"), "input_tokens")
    output_tokens = _token_count(value.get("output_tokens"), "output_tokens")
    total_tokens = _token_count(value.get("total_tokens"), "total_tokens")
    details = value.get("input_tokens_details")
    if details is None:
        cached_input_tokens = 0
    elif isinstance(details, Mapping):
        cached_input_tokens = _token_count(details.get("cached_tokens", 0), "cached_tokens")
    else:
        raise ReproAssertError("v021_openai_usage", "OpenAI usage metadata is invalid.")
    if cached_input_tokens > input_tokens or total_tokens != input_tokens + output_tokens:
        raise ReproAssertError("v021_openai_usage", "OpenAI usage counts are inconsistent.")
    return OpenAIUsage(input_tokens, cached_input_tokens, output_tokens, total_tokens)


def _token_count(value: object, name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= MAX_OPENAI_REPORTED_TOKENS
    ):
        raise ReproAssertError("v021_openai_usage", f"OpenAI {name} is invalid.")
    return value


def _compute_cost_microusd(usage: OpenAIUsage, pricing: FrozenOpenAIPricing) -> int:
    uncached_input_tokens = usage.input_tokens - usage.cached_input_tokens
    numerator = (
        uncached_input_tokens * pricing.input_microusd_per_million_tokens
        + usage.cached_input_tokens * pricing.cached_input_microusd_per_million_tokens
        + usage.output_tokens * pricing.output_microusd_per_million_tokens
    )
    return (numerator + TOKENS_PER_MILLION - 1) // TOKENS_PER_MILLION


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
