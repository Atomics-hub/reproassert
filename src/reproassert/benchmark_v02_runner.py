from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import stat
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast

from reproassert import generator as generator_module
from reproassert.benchmark_v02_package import (
    BENCHMARK_VERSION,
    PreregisteredV02Case,
    V02CaseIdentity,
    VerifiedV02EvaluatorCapability,
    load_v02_preregistration,
    require_v02_evaluator_capability,
)
from reproassert.candidate import (
    MAX_TEST_BYTES,
    ValidatedCandidate,
    candidate_path,
    validate_candidate_payload,
)
from reproassert.context import SourceContext
from reproassert.differential import (
    DifferentialVerificationOutcome,
    verify_differential_candidate,
)
from reproassert.errors import PolicyRejection, ReproAssertError
from reproassert.generator import (
    OPENAI_MAX_OUTPUT_TOKENS,
    SYMPY_NATIVE_CANDIDATE_PROFILE,
    GenerationRequest,
)
from reproassert.intake import parse_issue_url
from reproassert.safeio import open_regular_file, require_private_directory
from reproassert.sandbox import DockerSandbox
from reproassert.semantic_issuer import (
    VerifiedV02GeneratorSourceContext,
    acquire_v02_evaluation_session,
    consume_v02_evaluation_session,
    require_v02_generator_source_context,
)

if TYPE_CHECKING:
    from reproassert.dependency_executor import DependencyVolumeHandle

SCHEMA_VERSION = "1.0.0"
RUNNER_ALGORITHM = "reproassert-v02-scored-runner-v1"
EVENT_ALGORITHM = "reproassert-v02-scored-event-chain-v1"
RESULT_ALGORITHM = "reproassert-v02-scored-result-v1"
EXECUTION_AUTHORIZATION_ALGORITHM = "reproassert-v02-execution-authorization-v1"
EXECUTION_AUTHORIZATION_CLAIM_ALGORITHM = "reproassert-v02-execution-authorization-claim-v1"
EXECUTION_REQUEST_SET_ALGORITHM = "reproassert-v02-execution-request-set-v1"
EXECUTION_REQUEST_BINDINGS_ALGORITHM = "reproassert-v02-execution-request-bindings-v1"
GENERATION_DISPOSITION_ALGORITHM = "reproassert-v02-generation-disposition-set-v1"
GENERATION_BARRIER_ALGORITHM = "reproassert-v02-campaign-generation-barrier-v1"
MAX_LEDGER_BYTES = 32 * 1024 * 1024
MAX_RESULT_BYTES = 2 * 1024 * 1024
MAX_PROJECTION_BYTES = 512 * 1024
MAX_EXECUTION_AUTHORIZATION_BYTES = 256 * 1024

_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}")
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_CALL_ID = re.compile(r"call_[0-9a-f]{32}")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z"
)
_ATTRIBUTABLE_COST_CATEGORIES = (
    "model_inference",
    "sandbox_compute",
    "artifact_transfer",
    "paid_storage",
)
_COST_CATEGORIES = (
    *_ATTRIBUTABLE_COST_CATEGORIES,
    "dependency_prep",
)
_PHASES = ("generation", "differential", "result_write")
_EVENT_TYPES = {
    "attempt_started",
    "phase_started",
    "phase_finished",
    "model_call_started",
    "model_call_finished",
    "cost_recorded",
    "candidate_submitted",
    "generation_disposition_frozen",
    "campaign_generation_barrier_frozen",
    "recovery_started",
    "attempt_finished",
    "attempt_crashed",
}
_EVENT_ENVELOPE_KEYS = {
    "schema_version",
    "benchmark_version",
    "algorithm",
    "sequence",
    "recorded_at",
    "previous_event_sha256",
    "campaign_id",
    "attempt_id",
    "case_id",
    "event_type",
    "payload",
    "event_sha256",
}
_PAYLOAD_KEYS = {
    "attempt_started": {
        "started_at",
        "preregistration_sha256",
        "cohort_sha256",
        "case",
        "configuration",
        "source_context",
        "runner_input_sha256",
        "reserved_worst_case_microusd",
    },
    "phase_started": {"phase", "started_at"},
    "phase_finished": {
        "phase",
        "status",
        "started_at",
        "completed_at",
        "duration_ms",
        "classification_code",
        "evidence",
    },
    "model_call_started": {
        "call_id",
        "started_at",
        "execution_authorization_sha256",
        "provider",
        "endpoint_host",
        "requested_model",
        "rendered_input_sha256",
        "config_sha256",
        "max_output_tokens",
        "pricing_snapshot_sha256",
        "reserved_worst_case_microusd",
        "runner_input_sha256",
    },
    "model_call_finished": {
        "call_id",
        "status",
        "started_at",
        "completed_at",
        "duration_ms",
        "response_model",
        "response_id_sha256",
        "classification_code",
        "usage",
        "generation_artifact_sha256",
        "generation_artifact_bytes",
    },
    "cost_recorded": {
        "entry_id",
        "category",
        "attribution",
        "status",
        "amount_microusd",
        "source_call_id",
        "observed_at",
        "evidence_sha256",
    },
    "candidate_submitted": {
        "candidate_index",
        "candidate_sha256",
        "candidate_bytes",
        "artifact_path",
        "generation_artifact_sha256",
        "generation_artifact_bytes",
        "test_function",
        "generation_call_id",
        "oracle_consulted",
        "submitted_at",
    },
    "generation_disposition_frozen": {
        "status",
        "candidate_sha256",
        "classification_code",
        "frozen_at",
    },
    "campaign_generation_barrier_frozen": {
        "barrier_algorithm",
        "configuration_sha256",
        "execution_authorization_sha256",
        "request_set_sha256",
        "pricing_snapshot_sha256",
        "run_provenance_sha256",
        "disposition_set_sha256",
        "generation_barrier_sha256",
        "disposition_count",
        "frozen_at",
    },
    "recovery_started": {
        "recovery_id",
        "started_at",
        "mode",
        "execution_authorization_sha256",
        "preregistration_sha256",
        "configuration_sha256",
        "source_context_sha256",
        "runner_input_sha256",
        "generation_call_id",
        "generation_artifact_sha256",
        "generation_artifact_bytes",
        "candidate_sha256",
        "provider_calls_permitted",
        "oracle_feedback_permitted",
    },
    "attempt_finished": {
        "completed_at",
        "status",
        "outcome",
        "claim_level",
        "cost_complete",
        "total_attributable_microusd",
        "private_result_sha256",
        "public_result_sha256",
    },
    "attempt_crashed": {
        "crashed_at",
        "classification_code",
        "exception_type",
        "cost_complete",
        "recovery_status",
    },
}


@dataclass(frozen=True)
class V02PricingSnapshot:
    """Frozen component prices used for reservation and measured-cost projection.

    Prices are integer micro-USD. Token and byte rates are per million units; sandbox compute is
    per second. The caller must preserve the canonical snapshot in the private campaign package.
    """

    provider: str
    requested_model: str
    effective_at: str
    source: str
    input_microusd_per_million_tokens: int
    cached_input_microusd_per_million_tokens: int
    output_microusd_per_million_tokens: int
    sandbox_microusd_per_second: int
    artifact_microusd_per_million_bytes: int
    paid_storage_microusd: int
    dependency_prep_microusd: int

    def __post_init__(self) -> None:
        if self.provider != "openai":
            raise _reject("v02_pricing", "The built-in scored adapter currently supports OpenAI.")
        _bounded_model(self.requested_model)
        _timestamp(self.effective_at, "pricing effective_at")
        if (
            not isinstance(self.source, str)
            or not 3 <= len(self.source) <= 300
            or not self.source.isprintable()
        ):
            raise _reject("v02_pricing", "Pricing source must be bounded printable text.")
        for name in (
            "input_microusd_per_million_tokens",
            "cached_input_microusd_per_million_tokens",
            "output_microusd_per_million_tokens",
            "sandbox_microusd_per_second",
            "artifact_microusd_per_million_bytes",
            "paid_storage_microusd",
            "dependency_prep_microusd",
        ):
            _nonnegative_int(getattr(self, name), name)
        if self.cached_input_microusd_per_million_tokens > self.input_microusd_per_million_tokens:
            raise _reject(
                "v02_pricing",
                "Cached-input pricing cannot exceed the normal input rate used for reservation.",
            )

    def record(self) -> dict[str, object]:
        return {
            "algorithm": "reproassert-v02-component-pricing-v1",
            **asdict(self),
        }

    @property
    def sha256(self) -> str:
        return _sha256_json(self.record())


@dataclass(frozen=True)
class V02ScoredRunPolicy:
    """Deny-by-default authorization and cost freeze for one scored campaign."""

    campaign_id: str | None = None
    campaign_freeze_sha256: str | None = None
    execution_authorization_sha256: str | None = None
    authorization_text_sha256: str | None = None
    authorized_at: str | None = None
    request_set_sha256: str | None = None
    tool_git_sha: str | None = None
    authorization_status: Literal[
        "not_authorized", "offline_zero_cost", "explicit_user_approval"
    ] = "not_authorized"
    authorization_ref: str | None = None
    generator_mode: Literal[
        "none", "trusted_builtin_provider_adapter", "sandboxed_generator_process"
    ] = "none"
    provider: str | None = None
    requested_model: str | None = None
    pricing: V02PricingSnapshot | None = None
    reserved_worst_case_microusd: int = 0
    max_case_attributable_microusd: int = 0
    max_campaign_attributable_microusd: int = 0
    max_case_wall_ms: int = 600_000
    provider_timeout_seconds: float = 120.0

    def configuration_record(self) -> dict[str, object]:
        pricing_record = self.pricing.record() if self.pricing is not None else None
        pricing_sha256 = self.pricing.sha256 if self.pricing is not None else None
        adapter_config_sha256 = (
            _openai_adapter_config_sha256(self.requested_model)
            if self.generator_mode == "trusted_builtin_provider_adapter"
            and self.requested_model is not None
            else None
        )
        authorization_ref_sha256 = (
            hashlib.sha256(self.authorization_ref.encode("utf-8")).hexdigest()
            if self.authorization_ref is not None
            else None
        )
        return {
            "algorithm": RUNNER_ALGORITHM,
            "campaign_freeze_sha256": self.campaign_freeze_sha256,
            "execution_authorization": {
                "sha256": self.execution_authorization_sha256,
                "kind": "explicit_user_approval",
                "authorized_at": self.authorized_at,
                "authorization_ref_sha256": authorization_ref_sha256,
                "authorization_text_sha256": self.authorization_text_sha256,
                "request_set_sha256": self.request_set_sha256,
            },
            "tool_git_sha": self.tool_git_sha,
            "authorization": {
                "status": self.authorization_status,
                "authorization_ref": self.authorization_ref,
            },
            "generator": {
                "mode": self.generator_mode,
                "provider": self.provider,
                "requested_model": self.requested_model,
                "adapter_config_sha256": adapter_config_sha256,
                "feedback_policy": "none_one_shot",
                "submitted_candidate_budget": 1,
            },
            "pricing_snapshot": pricing_record,
            "pricing_snapshot_sha256": pricing_sha256,
            "run_provenance": {
                "execution_authorization_sha256": self.execution_authorization_sha256,
                "authorized_at": self.authorized_at,
                "authorization_ref_sha256": authorization_ref_sha256,
                "authorization_text_sha256": self.authorization_text_sha256,
                "request_set_sha256": self.request_set_sha256,
                "provider": self.provider,
                "requested_model": self.requested_model,
                "adapter_config_sha256": adapter_config_sha256,
                "pricing_snapshot_sha256": pricing_sha256,
                "pricing_effective_at": (
                    self.pricing.effective_at if self.pricing is not None else None
                ),
                "pricing_source": self.pricing.source if self.pricing is not None else None,
            },
            "reserved_worst_case_microusd": self.reserved_worst_case_microusd,
            "max_case_attributable_microusd": self.max_case_attributable_microusd,
            "max_campaign_attributable_microusd": self.max_campaign_attributable_microusd,
            "max_case_wall_ms": self.max_case_wall_ms,
            "provider_timeout_ms": round(self.provider_timeout_seconds * 1_000),
        }

    @property
    def configuration_sha256(self) -> str:
        return _sha256_json(self.configuration_record())

    def require_executable(self) -> None:
        if self.authorization_status == "not_authorized" or self.generator_mode == "none":
            raise _reject(
                "v02_spend_not_authorized",
                "Scored generation defaults to no provider and requires explicit authorization.",
            )
        if self.campaign_id is None:
            raise _reject("v02_campaign", "An authorized run requires a bounded campaign ID.")
        _identifier(self.campaign_id, "campaign ID")
        if self.campaign_freeze_sha256 is None:
            raise _reject(
                "v02_campaign_freeze",
                "An authorized run requires the exact pre-inference campaign freeze SHA-256.",
            )
        _digest(self.campaign_freeze_sha256, "campaign freeze")
        for value, name in (
            (self.execution_authorization_sha256, "execution authorization"),
            (self.authorization_text_sha256, "authorization text"),
            (self.request_set_sha256, "execution request set"),
        ):
            _digest(value, name)
        authorized_at = _timestamp(self.authorized_at, "execution authorized_at")
        if datetime.fromisoformat(authorized_at[:-1] + "+00:00") > datetime.now(timezone.utc):
            raise _reject(
                "v02_execution_authorization",
                "Execution authorization cannot be dated in the future.",
            )
        if self.tool_git_sha is None or _GIT_SHA.fullmatch(self.tool_git_sha) is None:
            raise _reject("v02_campaign", "An authorized run requires the exact tool Git SHA.")
        for name in (
            "reserved_worst_case_microusd",
            "max_case_attributable_microusd",
            "max_campaign_attributable_microusd",
            "max_case_wall_ms",
        ):
            _positive_int(getattr(self, name), name)
        if (
            self.reserved_worst_case_microusd > self.max_case_attributable_microusd
            or self.reserved_worst_case_microusd > self.max_campaign_attributable_microusd
        ):
            raise _reject("v02_spend_cap", "The case reservation exceeds a frozen spend cap.")
        if not 1 <= self.provider_timeout_seconds <= min(600, self.max_case_wall_ms / 1_000):
            raise _reject("v02_time_cap", "Provider timeout must fit within the case wall cap.")
        if self.generator_mode == "trusted_builtin_provider_adapter":
            if self.authorization_status != "explicit_user_approval":
                raise _reject(
                    "v02_spend_not_authorized",
                    "The networked built-in provider requires explicit user approval.",
                )
            if (
                not isinstance(self.authorization_ref, str)
                or not 3 <= len(self.authorization_ref) <= 200
                or not self.authorization_ref.isprintable()
            ):
                raise _reject(
                    "v02_spend_not_authorized",
                    "Paid generation requires a bounded explicit authorization reference.",
                )
            if self.provider != "openai" or self.requested_model is None:
                raise _reject("v02_generator", "The built-in provider identity is not supported.")
            _bounded_model(self.requested_model)
            if self.pricing is None:
                raise _reject("v02_pricing", "Paid generation requires a frozen pricing snapshot.")
            if (
                self.pricing.provider != self.provider
                or self.pricing.requested_model != self.requested_model
            ):
                raise _reject("v02_pricing", "Pricing identity differs from the provider freeze.")
        elif self.generator_mode == "sandboxed_generator_process":
            if self.authorization_status != "offline_zero_cost":
                raise _reject(
                    "v02_sandboxed_generator",
                    "The sandboxed generator lane is currently restricted to offline zero cost.",
                )
            if self.authorization_ref is not None or self.reserved_worst_case_microusd != 0:
                raise _reject(
                    "v02_sandboxed_generator",
                    "Offline zero-cost generation cannot carry paid approval or reservation.",
                )
            raise _reject(
                "v02_sandboxed_generator_unavailable",
                "No production sandboxed generator process adapter is registered.",
            )
        else:
            raise _reject("v02_generator", "Scored generator mode is not executable.")


_EXECUTION_AUTHORIZATION_ISSUER = object()


@dataclass(frozen=True)
class VerifiedV02ExecutionAuthorization:
    """Nominal proof of one canonical, pre-inference, explicitly authorized spend record."""

    _issuer: object
    path: Path
    raw_sha256: str
    campaign_id: str
    campaign_freeze_sha256: str
    preregistration_sha256: str
    cohort_sha256: str
    tool_git_sha: str
    authorized_at: str
    authorization_ref: str
    authorization_text: str
    authorization_text_sha256: str
    provider: str
    requested_model: str
    adapter_config_sha256: str
    request_set_sha256: str
    requests: tuple[tuple[str, str], ...]
    pricing: V02PricingSnapshot
    reserved_worst_case_microusd: int
    max_case_attributable_microusd: int
    max_campaign_attributable_microusd: int
    max_case_wall_ms: int
    provider_timeout_ms: int

    def request_sha256(self, case_id: str) -> str:
        for frozen_case_id, digest in self.requests:
            if frozen_case_id == case_id:
                return digest
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization does not contain the requested case.",
        )

    def policy(self) -> V02ScoredRunPolicy:
        return V02ScoredRunPolicy(
            campaign_id=self.campaign_id,
            campaign_freeze_sha256=self.campaign_freeze_sha256,
            execution_authorization_sha256=self.raw_sha256,
            authorization_text_sha256=self.authorization_text_sha256,
            authorized_at=self.authorized_at,
            request_set_sha256=self.request_set_sha256,
            tool_git_sha=self.tool_git_sha,
            authorization_status="explicit_user_approval",
            authorization_ref=self.authorization_ref,
            generator_mode="trusted_builtin_provider_adapter",
            provider=self.provider,
            requested_model=self.requested_model,
            pricing=self.pricing,
            reserved_worst_case_microusd=self.reserved_worst_case_microusd,
            max_case_attributable_microusd=self.max_case_attributable_microusd,
            max_campaign_attributable_microusd=self.max_campaign_attributable_microusd,
            max_case_wall_ms=self.max_case_wall_ms,
            provider_timeout_seconds=self.provider_timeout_ms / 1_000,
        )


def load_v02_pricing_snapshot(path: Path) -> V02PricingSnapshot:
    """Load one bounded canonical full-price record without network or provider behavior."""

    _raw, value = _load_canonical_object(
        Path(path),
        limit=64 * 1024,
        label="pricing snapshot",
        code="v02_pricing",
    )
    pricing = _pricing_from_record(value)
    if value != pricing.record():
        raise _reject("v02_pricing", "Pricing snapshot is not canonical.")
    return pricing


def load_v02_request_bindings(path: Path, preregistration_path: Path) -> Mapping[str, str]:
    """Load the canonical 20-case rendered-input digest draft used by authorization tooling."""

    _raw, value = _load_canonical_object(
        Path(path),
        limit=128 * 1024,
        label="execution request bindings",
    )
    if set(value) != {
        "schema_version",
        "benchmark_version",
        "algorithm",
        "preregistration_sha256",
        "cohort_sha256",
        "requests",
    } or (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("benchmark_version") != BENCHMARK_VERSION
        or value.get("algorithm") != EXECUTION_REQUEST_BINDINGS_ALGORITHM
    ):
        raise _reject(
            "v02_execution_authorization",
            "Execution request-binding fields or version are not exact.",
        )
    preregistration = load_v02_preregistration(Path(preregistration_path))
    cohort_sha256 = cast(str, preregistration.decoded["cohort_sha256"])
    if (
        value.get("preregistration_sha256") != preregistration.raw_sha256
        or value.get("cohort_sha256") != cohort_sha256
    ):
        raise _reject(
            "v02_execution_authorization",
            "Execution request bindings differ from the preregistered cohort.",
        )
    request_values = value.get("requests")
    if not isinstance(request_values, list) or len(request_values) != 20:
        raise _reject(
            "v02_execution_authorization",
            "Execution request bindings require exactly 20 rows.",
        )
    bindings: dict[str, str] = {}
    for request in request_values:
        if not isinstance(request, Mapping) or set(request) != {
            "case_id",
            "rendered_input_sha256",
        }:
            raise _reject(
                "v02_execution_authorization",
                "Execution request-binding row fields are not exact.",
            )
        case_id = request.get("case_id")
        digest = request.get("rendered_input_sha256")
        if not isinstance(case_id, str) or case_id in bindings:
            raise _reject(
                "v02_execution_authorization",
                "Execution request-binding case IDs are invalid or duplicated.",
            )
        _digest(digest, f"rendered input for {case_id}")
        bindings[case_id] = cast(str, digest)
    normalized = _normalized_execution_requests(
        bindings,
        expected_case_ids=tuple(case.id for case in preregistration.cases),
    )
    expected_rows = [
        {"case_id": case_id, "rendered_input_sha256": digest} for case_id, digest in normalized
    ]
    if request_values != expected_rows:
        raise _reject(
            "v02_execution_authorization",
            "Execution request bindings are not sorted canonical cohort rows.",
        )
    return dict(normalized)


def write_v02_execution_authorization(
    *,
    output_path: Path,
    campaign_freeze_path: Path,
    preregistration_path: Path,
    request_bindings: Mapping[str, str],
    tool_git_sha: str,
    requested_model: str,
    pricing: V02PricingSnapshot,
    reserved_worst_case_microusd: int,
    max_case_attributable_microusd: int,
    max_campaign_attributable_microusd: int,
    max_case_wall_ms: int,
    provider_timeout_seconds: float,
    authorization_ref: str,
    authorization_text: str,
    authorized_at: str,
) -> Path:
    """Write one immutable explicit authorization for the exact 20-case request set."""

    from reproassert.benchmark_v02_campaign import verify_v02_campaign_freeze

    freeze = verify_v02_campaign_freeze(campaign_freeze_path, preregistration_path)
    preregistration = load_v02_preregistration(Path(preregistration_path))
    if not isinstance(tool_git_sha, str) or _GIT_SHA.fullmatch(tool_git_sha) is None:
        raise _reject("v02_execution_authorization", "Tool Git SHA is invalid.")
    freeze_tool = freeze.decoded.get("tool")
    if not isinstance(freeze_tool, Mapping) or freeze_tool.get("git_sha") != tool_git_sha:
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization tool differs from the campaign freeze.",
        )
    model = _bounded_model(requested_model)
    if pricing.provider != "openai" or pricing.requested_model != model:
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization pricing differs from its exact provider and model.",
        )
    requests = _normalized_execution_requests(
        request_bindings,
        expected_case_ids=tuple(case.id for case in preregistration.cases),
    )
    request_set_sha256 = _execution_request_set_sha256(
        campaign_id=freeze.campaign_id,
        preregistration_sha256=freeze.preregistration_sha256,
        cohort_sha256=freeze.cohort_sha256,
        requests=requests,
    )
    limits = _validated_execution_limits(
        reserved_worst_case_microusd=reserved_worst_case_microusd,
        max_case_attributable_microusd=max_case_attributable_microusd,
        max_campaign_attributable_microusd=max_campaign_attributable_microusd,
        max_case_wall_ms=max_case_wall_ms,
        provider_timeout_seconds=provider_timeout_seconds,
    )
    if (
        not isinstance(authorization_ref, str)
        or not 3 <= len(authorization_ref) <= 200
        or not authorization_ref.isprintable()
    ):
        raise _reject(
            "v02_execution_authorization",
            "Authorization reference must be bounded printable text.",
        )
    if (
        not isinstance(authorization_text, str)
        or not 10 <= len(authorization_text) <= 4_000
        or not authorization_text.isprintable()
    ):
        raise _reject(
            "v02_execution_authorization",
            "Explicit authorization text must be bounded printable text.",
        )
    authorized = _timestamp(authorized_at, "execution authorized_at")
    prepared = _timestamp(freeze.decoded.get("prepared_at"), "campaign preparation time")
    authorized_time = datetime.fromisoformat(authorized[:-1] + "+00:00")
    if authorized_time < datetime.fromisoformat(prepared[:-1] + "+00:00"):
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization cannot predate its exact campaign freeze.",
        )
    if authorized_time > datetime.now(timezone.utc):
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization cannot be dated in the future.",
        )
    pricing_time = datetime.fromisoformat(
        _timestamp(pricing.effective_at, "pricing effective_at")[:-1] + "+00:00"
    )
    if pricing_time > authorized_time:
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization cannot rely on pricing that was not yet effective.",
        )
    record: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "benchmark_version": BENCHMARK_VERSION,
        "algorithm": EXECUTION_AUTHORIZATION_ALGORITHM,
        "visibility": "private_controller_only",
        "authorization_kind": "explicit_user_approval",
        "authorized_at": authorized,
        "authorization_ref": authorization_ref,
        "authorization_text": authorization_text,
        "authorization_text_sha256": hashlib.sha256(authorization_text.encode("utf-8")).hexdigest(),
        "campaign": {
            "campaign_id": freeze.campaign_id,
            "campaign_freeze_sha256": freeze.raw_sha256,
            "preregistration_sha256": freeze.preregistration_sha256,
            "cohort_sha256": freeze.cohort_sha256,
            "tool_git_sha": tool_git_sha,
        },
        "provider": {
            "name": "openai",
            "endpoint_host": generator_module.OPENAI_API_HOST,
            "requested_model": model,
            "adapter_config_sha256": _openai_adapter_config_sha256(model),
        },
        "request_set": {
            "algorithm": EXECUTION_REQUEST_SET_ALGORITHM,
            "request_count": len(requests),
            "request_set_sha256": request_set_sha256,
            "requests": [
                {"case_id": case_id, "rendered_input_sha256": digest}
                for case_id, digest in requests
            ],
        },
        "pricing_snapshot": pricing.record(),
        "pricing_snapshot_sha256": pricing.sha256,
        "limits": limits,
    }
    _validate_execution_authorization_record(record)
    destination = Path(output_path)
    _require_private_parent(destination)
    _write_exclusive_fsync(destination, _canonical_json(record))
    verify_v02_execution_authorization(
        destination,
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
    )
    return destination


def verify_v02_execution_authorization(
    path: Path,
    *,
    campaign_freeze_path: Path,
    preregistration_path: Path,
) -> VerifiedV02ExecutionAuthorization:
    """Verify canonical bytes and rederive every campaign, pricing, request, and cap binding."""

    from reproassert.benchmark_v02_campaign import verify_v02_campaign_freeze

    raw, record = _load_execution_authorization(Path(path))
    _validate_execution_authorization_record(record)
    freeze = verify_v02_campaign_freeze(campaign_freeze_path, preregistration_path)
    preregistration = load_v02_preregistration(Path(preregistration_path))
    campaign = cast(Mapping[str, object], record["campaign"])
    if campaign != {
        "campaign_id": freeze.campaign_id,
        "campaign_freeze_sha256": freeze.raw_sha256,
        "preregistration_sha256": freeze.preregistration_sha256,
        "cohort_sha256": freeze.cohort_sha256,
        "tool_git_sha": cast(Mapping[str, object], freeze.decoded["tool"])["git_sha"],
    }:
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization campaign identity is not reproducible.",
        )
    pricing_record = cast(Mapping[str, object], record["pricing_snapshot"])
    pricing = _pricing_from_record(pricing_record)
    if pricing_record != pricing.record() or record["pricing_snapshot_sha256"] != pricing.sha256:
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization pricing snapshot is not canonical.",
        )
    provider = cast(Mapping[str, object], record["provider"])
    if (
        provider["name"] != pricing.provider
        or provider["requested_model"] != pricing.requested_model
        or provider["adapter_config_sha256"]
        != _openai_adapter_config_sha256(provider["requested_model"])
    ):
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization provider, model, adapter, and pricing differ.",
        )
    request_set = cast(Mapping[str, object], record["request_set"])
    request_values = cast(list[Mapping[str, object]], request_set["requests"])
    requests = _normalized_execution_requests(
        {
            cast(str, value["case_id"]): cast(str, value["rendered_input_sha256"])
            for value in request_values
        },
        expected_case_ids=tuple(case.id for case in preregistration.cases),
    )
    expected_request_set_sha256 = _execution_request_set_sha256(
        campaign_id=freeze.campaign_id,
        preregistration_sha256=freeze.preregistration_sha256,
        cohort_sha256=freeze.cohort_sha256,
        requests=requests,
    )
    if (
        request_set["request_count"] != len(requests)
        or request_values
        != [{"case_id": case_id, "rendered_input_sha256": digest} for case_id, digest in requests]
        or request_set["request_set_sha256"] != expected_request_set_sha256
    ):
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization request set is not canonical.",
        )
    limits = cast(Mapping[str, object], record["limits"])
    validated_limits = _validated_execution_limits(
        reserved_worst_case_microusd=cast(int, limits["reserved_worst_case_microusd"]),
        max_case_attributable_microusd=cast(int, limits["max_case_attributable_microusd"]),
        max_campaign_attributable_microusd=cast(int, limits["max_campaign_attributable_microusd"]),
        max_case_wall_ms=cast(int, limits["max_case_wall_ms"]),
        provider_timeout_seconds=cast(int, limits["provider_timeout_ms"]) / 1_000,
    )
    if dict(limits) != validated_limits:
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization limits are not canonical.",
        )
    authorized_at = cast(str, record["authorized_at"])
    prepared_at = _timestamp(freeze.decoded.get("prepared_at"), "campaign preparation time")
    authorized_time = datetime.fromisoformat(authorized_at[:-1] + "+00:00")
    pricing_time = datetime.fromisoformat(
        _timestamp(pricing.effective_at, "pricing effective_at")[:-1] + "+00:00"
    )
    if (
        authorized_time < datetime.fromisoformat(prepared_at[:-1] + "+00:00")
        or authorized_time > datetime.now(timezone.utc)
        or pricing_time > authorized_time
    ):
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization chronology is not pre-inference.",
        )
    return VerifiedV02ExecutionAuthorization(
        _issuer=_EXECUTION_AUTHORIZATION_ISSUER,
        path=Path(path),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        campaign_id=freeze.campaign_id,
        campaign_freeze_sha256=freeze.raw_sha256,
        preregistration_sha256=freeze.preregistration_sha256,
        cohort_sha256=freeze.cohort_sha256,
        tool_git_sha=cast(str, campaign["tool_git_sha"]),
        authorized_at=authorized_at,
        authorization_ref=cast(str, record["authorization_ref"]),
        authorization_text=cast(str, record["authorization_text"]),
        authorization_text_sha256=cast(str, record["authorization_text_sha256"]),
        provider=provider["name"],
        requested_model=provider["requested_model"],
        adapter_config_sha256=provider["adapter_config_sha256"],
        request_set_sha256=expected_request_set_sha256,
        requests=requests,
        pricing=pricing,
        reserved_worst_case_microusd=cast(int, limits["reserved_worst_case_microusd"]),
        max_case_attributable_microusd=cast(int, limits["max_case_attributable_microusd"]),
        max_campaign_attributable_microusd=cast(int, limits["max_campaign_attributable_microusd"]),
        max_case_wall_ms=cast(int, limits["max_case_wall_ms"]),
        provider_timeout_ms=cast(int, limits["provider_timeout_ms"]),
    )


def require_v02_execution_authorization(value: object) -> VerifiedV02ExecutionAuthorization:
    if (
        type(value) is not VerifiedV02ExecutionAuthorization
        or value._issuer is not _EXECUTION_AUTHORIZATION_ISSUER
    ):
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization proof is not application-issued.",
        )
    return value


def _claim_execution_authorization(
    authorization: VerifiedV02ExecutionAuthorization,
    ledger_path: Path,
) -> Path:
    """Bind one authorization file to one ledger, preventing accidental cap-multiplying replay."""

    verified = require_v02_execution_authorization(authorization)
    absolute_ledger = Path(os.path.abspath(os.fspath(ledger_path)))
    ledger_identity_sha256 = hashlib.sha256(os.fsencode(os.fspath(absolute_ledger))).hexdigest()
    claim_path = verified.path.with_name(f"{verified.path.name}.claim.json")
    require_private_directory(claim_path.parent)
    record = {
        "schema_version": SCHEMA_VERSION,
        "benchmark_version": BENCHMARK_VERSION,
        "algorithm": EXECUTION_AUTHORIZATION_CLAIM_ALGORITHM,
        "campaign_id": verified.campaign_id,
        "execution_authorization_sha256": verified.raw_sha256,
        "ledger_identity_sha256": ledger_identity_sha256,
        "claimed_at": _now(),
    }
    try:
        _write_exclusive_fsync(claim_path, _canonical_json(record))
    except PolicyRejection as exc:
        if exc.code != "v02_artifact_path" or not claim_path.exists():
            raise
    _raw, observed = _load_canonical_object(
        claim_path,
        limit=16 * 1024,
        label="execution authorization claim",
        code="v02_execution_authorization",
    )
    if set(observed) != set(record) or any(
        observed.get(name) != value for name, value in record.items() if name != "claimed_at"
    ):
        raise _reject(
            "v02_execution_authorization_replay",
            "Execution authorization is already claimed by a different campaign ledger.",
        )
    claimed_at = _timestamp(observed.get("claimed_at"), "execution authorization claimed_at")
    claimed_time = datetime.fromisoformat(claimed_at[:-1] + "+00:00")
    authorized_time = datetime.fromisoformat(verified.authorized_at[:-1] + "+00:00")
    if claimed_time < authorized_time or claimed_time > datetime.now(timezone.utc):
        raise _reject(
            "v02_execution_authorization_replay",
            "Execution authorization claim chronology is invalid.",
        )
    return claim_path


def _load_execution_authorization(path: Path) -> tuple[bytes, dict[str, object]]:
    return _load_canonical_object(
        path,
        limit=MAX_EXECUTION_AUTHORIZATION_BYTES,
        label="execution authorization",
        code="v02_execution_authorization",
    )


def _load_canonical_object(
    path: Path,
    *,
    limit: int,
    label: str,
    code: str = "v02_execution_authorization",
) -> tuple[bytes, dict[str, object]]:
    with open_regular_file(path) as stream:
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise _reject(
            code,
            f"{label.capitalize()} is empty or exceeds its byte limit.",
        )
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject(
            code,
            f"{label.capitalize()} is not strict JSON.",
        ) from exc
    if not isinstance(value, dict) or _canonical_json(value) != raw:
        raise _reject(
            code,
            f"{label.capitalize()} is not one canonical JSON object.",
        )
    return raw, cast(dict[str, object], value)


def _validate_execution_authorization_record(record: Mapping[str, object]) -> None:
    if set(record) != {
        "schema_version",
        "benchmark_version",
        "algorithm",
        "visibility",
        "authorization_kind",
        "authorized_at",
        "authorization_ref",
        "authorization_text",
        "authorization_text_sha256",
        "campaign",
        "provider",
        "request_set",
        "pricing_snapshot",
        "pricing_snapshot_sha256",
        "limits",
    }:
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization fields are not exact.",
        )
    if (
        record.get("schema_version") != SCHEMA_VERSION
        or record.get("benchmark_version") != BENCHMARK_VERSION
        or record.get("algorithm") != EXECUTION_AUTHORIZATION_ALGORITHM
        or record.get("visibility") != "private_controller_only"
        or record.get("authorization_kind") != "explicit_user_approval"
    ):
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization version or kind is invalid.",
        )
    _timestamp(record.get("authorized_at"), "execution authorized_at")
    reference = record.get("authorization_ref")
    if (
        not isinstance(reference, str)
        or not 3 <= len(reference) <= 200
        or not reference.isprintable()
    ):
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization reference is invalid.",
        )
    authorization_text = record.get("authorization_text")
    if (
        not isinstance(authorization_text, str)
        or not 10 <= len(authorization_text) <= 4_000
        or not authorization_text.isprintable()
        or record.get("authorization_text_sha256")
        != hashlib.sha256(authorization_text.encode("utf-8")).hexdigest()
    ):
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization text or its digest is invalid.",
        )
    _digest(record.get("authorization_text_sha256"), "authorization text")
    campaign = record.get("campaign")
    if not isinstance(campaign, Mapping) or set(campaign) != {
        "campaign_id",
        "campaign_freeze_sha256",
        "preregistration_sha256",
        "cohort_sha256",
        "tool_git_sha",
    }:
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization campaign fields are not exact.",
        )
    _identifier(campaign.get("campaign_id"), "campaign ID")
    for name in ("campaign_freeze_sha256", "preregistration_sha256", "cohort_sha256"):
        _digest(campaign.get(name), name)
    if (
        not isinstance(campaign.get("tool_git_sha"), str)
        or _GIT_SHA.fullmatch(cast(str, campaign["tool_git_sha"])) is None
    ):
        raise _reject("v02_execution_authorization", "Authorization tool Git SHA is invalid.")
    provider = record.get("provider")
    if not isinstance(provider, Mapping) or set(provider) != {
        "name",
        "endpoint_host",
        "requested_model",
        "adapter_config_sha256",
    }:
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization provider fields are not exact.",
        )
    if provider.get("name") != "openai" or provider.get("endpoint_host") != "api.openai.com":
        raise _reject("v02_execution_authorization", "Authorization provider is not allowlisted.")
    _bounded_model(provider.get("requested_model"))
    _digest(provider.get("adapter_config_sha256"), "adapter configuration")
    request_set = record.get("request_set")
    if not isinstance(request_set, Mapping) or set(request_set) != {
        "algorithm",
        "request_count",
        "request_set_sha256",
        "requests",
    }:
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization request-set fields are not exact.",
        )
    if request_set.get("algorithm") != EXECUTION_REQUEST_SET_ALGORITHM:
        raise _reject("v02_execution_authorization", "Request-set algorithm is invalid.")
    if request_set.get("request_count") != 20:
        raise _reject("v02_execution_authorization", "Authorization requires exactly 20 requests.")
    _digest(request_set.get("request_set_sha256"), "execution request set")
    requests = request_set.get("requests")
    if not isinstance(requests, list) or len(requests) != 20:
        raise _reject("v02_execution_authorization", "Authorization request set is incomplete.")
    for request in requests:
        if not isinstance(request, Mapping) or set(request) != {
            "case_id",
            "rendered_input_sha256",
        }:
            raise _reject(
                "v02_execution_authorization",
                "Execution authorization request fields are not exact.",
            )
        if (
            not isinstance(request.get("case_id"), str)
            or _CASE_ID.fullmatch(cast(str, request["case_id"])) is None
        ):
            raise _reject("v02_execution_authorization", "Authorized case ID is invalid.")
        _digest(request.get("rendered_input_sha256"), "rendered input")
    pricing = record.get("pricing_snapshot")
    if not isinstance(pricing, Mapping) or set(pricing) != set(
        V02PricingSnapshot.__dataclass_fields__
    ) | {"algorithm"}:
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization pricing fields are not exact.",
        )
    _digest(record.get("pricing_snapshot_sha256"), "pricing snapshot")
    limits = record.get("limits")
    if not isinstance(limits, Mapping) or set(limits) != {
        "reserved_worst_case_microusd",
        "max_case_attributable_microusd",
        "max_campaign_attributable_microusd",
        "max_case_wall_ms",
        "provider_timeout_ms",
        "max_output_tokens",
    }:
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization limit fields are not exact.",
        )
    for name in (
        "reserved_worst_case_microusd",
        "max_case_attributable_microusd",
        "max_campaign_attributable_microusd",
        "max_case_wall_ms",
        "provider_timeout_ms",
        "max_output_tokens",
    ):
        _positive_int(limits.get(name), name)
    if limits.get("max_output_tokens") != OPENAI_MAX_OUTPUT_TOKENS:
        raise _reject("v02_execution_authorization", "Authorized output-token cap changed.")


def _normalized_execution_requests(
    request_bindings: Mapping[str, str],
    *,
    expected_case_ids: tuple[str, ...],
) -> tuple[tuple[str, str], ...]:
    if set(request_bindings) != set(expected_case_ids):
        raise _reject(
            "v02_execution_authorization",
            "Execution authorization request IDs differ from the frozen cohort.",
        )
    requests: list[tuple[str, str]] = []
    for case_id in sorted(expected_case_ids):
        digest = request_bindings[case_id]
        _digest(digest, f"rendered input for {case_id}")
        requests.append((case_id, digest))
    return tuple(requests)


def _execution_request_set_sha256(
    *,
    campaign_id: str,
    preregistration_sha256: str,
    cohort_sha256: str,
    requests: tuple[tuple[str, str], ...],
) -> str:
    return _sha256_json(
        {
            "algorithm": EXECUTION_REQUEST_SET_ALGORITHM,
            "campaign_id": campaign_id,
            "preregistration_sha256": preregistration_sha256,
            "cohort_sha256": cohort_sha256,
            "requests": [
                {"case_id": case_id, "rendered_input_sha256": digest}
                for case_id, digest in requests
            ],
        }
    )


def _validated_execution_limits(
    *,
    reserved_worst_case_microusd: int,
    max_case_attributable_microusd: int,
    max_campaign_attributable_microusd: int,
    max_case_wall_ms: int,
    provider_timeout_seconds: float,
) -> dict[str, int]:
    for value, name in (
        (reserved_worst_case_microusd, "reserved_worst_case_microusd"),
        (max_case_attributable_microusd, "max_case_attributable_microusd"),
        (max_campaign_attributable_microusd, "max_campaign_attributable_microusd"),
        (max_case_wall_ms, "max_case_wall_ms"),
    ):
        _positive_int(value, name)
    if (
        reserved_worst_case_microusd > max_case_attributable_microusd
        or reserved_worst_case_microusd > max_campaign_attributable_microusd
    ):
        raise _reject(
            "v02_execution_authorization",
            "Authorized reservation exceeds an exact spend cap.",
        )
    if (
        isinstance(provider_timeout_seconds, bool)
        or not isinstance(provider_timeout_seconds, (int, float))
        or not math.isfinite(provider_timeout_seconds)
        or not 1 <= provider_timeout_seconds <= min(600, max_case_wall_ms / 1_000)
    ):
        raise _reject(
            "v02_execution_authorization",
            "Authorized provider timeout must fit the case wall cap.",
        )
    provider_timeout_ms = round(provider_timeout_seconds * 1_000)
    return {
        "reserved_worst_case_microusd": reserved_worst_case_microusd,
        "max_case_attributable_microusd": max_case_attributable_microusd,
        "max_campaign_attributable_microusd": max_campaign_attributable_microusd,
        "max_case_wall_ms": max_case_wall_ms,
        "provider_timeout_ms": provider_timeout_ms,
        "max_output_tokens": OPENAI_MAX_OUTPUT_TOKENS,
    }


@dataclass(frozen=True)
class V02LedgerSnapshot:
    events: tuple[dict[str, Any], ...]
    encoded: bytes
    sha256: str
    head_event_sha256: str | None


@dataclass(frozen=True)
class V02ScoredRunResult:
    campaign_id: str
    attempt_id: str
    case_id: str
    status: str
    outcome: str
    claim_level: str
    cost_complete: bool
    total_attributable_microusd: int | None
    candidate_sha256: str | None
    private_result_path: Path
    private_result_sha256: str
    public_result_path: Path
    public_result_sha256: str
    terminal_event_sha256: str


@dataclass(frozen=True)
class V02GenerationDisposition:
    """Durable, evaluator-blind terminal output of one case's generation phase."""

    campaign_id: str
    attempt_id: str
    case_id: str
    status: Literal["candidate_submitted", "no_candidate"]
    candidate_sha256: str | None
    classification_code: str | None
    ledger_head_event_sha256: str
    generation_artifact_path: Path | None


_BARRIER_ISSUER = object()


@dataclass(frozen=True)
class VerifiedV02CampaignGenerationBarrier:
    """Application-issued proof that every frozen case has a durable disposition."""

    _issuer: object
    algorithm: str
    campaign_id: str
    preregistration_sha256: str
    cohort_sha256: str
    configuration_sha256: str
    execution_authorization_sha256: str
    request_set_sha256: str
    pricing_snapshot_sha256: str
    run_provenance_sha256: str
    disposition_set_sha256: str
    disposition_count: int
    ledger_sequence: int
    ledger_head_event_sha256: str
    sha256: str


@dataclass
class _AttemptState:
    case_id: str
    campaign_id: str
    reservation: int
    configuration_sha256: str
    execution_authorization_sha256: str
    preregistration_sha256: str
    cohort_sha256: str
    source_context_sha256: str
    runner_input_sha256: str
    provider: str
    requested_model: str
    adapter_config_sha256: str
    pricing_snapshot_sha256: str
    request_set_sha256: str
    run_provenance_sha256: str
    active_phase: str | None = None
    phase_starts: dict[str, str] = field(default_factory=dict)
    completed_phases: set[str] = field(default_factory=set)
    model_call_id: str | None = None
    model_finished: bool = False
    costs: dict[str, int | None] = field(default_factory=dict)
    candidate_submitted: bool = False
    candidate_sha256: str | None = None
    generation_disposition_status: str | None = None
    generation_classification_code: str | None = None
    generation_disposition_event_sha256: str | None = None
    generation_disposition_sequence: int | None = None
    recovery_started: bool = False
    crashed: bool = False
    terminal: bool = False


@dataclass(frozen=True)
class _Projection:
    title: str
    body: str
    sha256: str


@dataclass(frozen=True)
class _RunContext:
    ledger_path: Path
    attempt_directory: Path
    policy: V02ScoredRunPolicy
    attempt_id: str
    case: PreregisteredV02Case
    preregistration_sha256: str
    cohort_sha256: str
    source_context: VerifiedV02GeneratorSourceContext
    request: GenerationRequest
    rendered_input_sha256: str
    runner_input_sha256: str


class _EventContext(Protocol):
    @property
    def ledger_path(self) -> Path: ...

    @property
    def policy(self) -> V02ScoredRunPolicy: ...

    @property
    def attempt_id(self) -> str: ...

    @property
    def case(self) -> PreregisteredV02Case: ...


@dataclass(frozen=True)
class _CampaignEventContext:
    ledger_path: Path
    policy: V02ScoredRunPolicy
    attempt_id: str
    case: PreregisteredV02Case


@dataclass(frozen=True)
class _GenerationTransaction:
    """Validated private recovery material for one already-paid model call.

    This type is constructed only after the canonical artifact is cross-bound to the attempt,
    call, runner input, preregistration-derived case, and candidate.  Recovery never accepts raw
    candidate bytes or provider output through its public API.
    """

    path: Path
    sha256: str
    bytes_count: int
    call_id: str
    candidate: ValidatedCandidate
    model_finish: dict[str, object]


class _ControlledFailure(Exception):
    def __init__(self, outcome: str, classification_code: str) -> None:
        super().__init__(classification_code)
        self.outcome = outcome
        self.classification_code = classification_code


class _PostExternalDurabilityCrash(BaseException):
    """Force crash semantics after paid or oracle-adjacent work cannot be committed."""


def read_v02_scored_ledger(path: Path) -> V02LedgerSnapshot:
    """Load and strictly validate a canonical v0.2 private event chain."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _reject("v02_ledger_path", "Cannot safely open the v0.2 scored ledger.") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise _reject("v02_ledger_path", "The v0.2 scored ledger is not a regular file.")
        encoded = _read_bounded_fd(descriptor, MAX_LEDGER_BYTES)
    finally:
        os.close(descriptor)
    return _decode_ledger(encoded)


def run_v02_scored_case(
    *,
    preregistration_path: Path,
    case_id: str,
    generator_projection_path: Path,
    generator_source_context: VerifiedV02GeneratorSourceContext,
    evaluator_capability: VerifiedV02EvaluatorCapability,
    sandbox: DockerSandbox,
    base_source: Path,
    fixed_source: Path,
    ledger_path: Path,
    attempt_directory: Path,
    policy: V02ScoredRunPolicy | None = None,
    dependency_handle: DependencyVolumeHandle | None = None,
) -> V02ScoredRunResult:
    """Reject the former combined path, which cannot satisfy the all-case generation barrier."""

    del (
        preregistration_path,
        case_id,
        generator_projection_path,
        generator_source_context,
        evaluator_capability,
        sandbox,
        base_source,
        fixed_source,
        ledger_path,
        attempt_directory,
        policy,
        dependency_handle,
    )
    raise _reject(
        "v02_two_phase_required",
        "Use generate_v02_scored_case for every case, freeze the campaign generation barrier, "
        "then evaluate_v02_frozen_case.",
    )


def generate_v02_scored_case(
    *,
    preregistration_path: Path,
    campaign_freeze_path: Path,
    execution_authorization_path: Path,
    case_id: str,
    generator_projection_path: Path,
    generator_source_context: VerifiedV02GeneratorSourceContext,
    ledger_path: Path,
    attempt_directory: Path,
    policy: V02ScoredRunPolicy | None = None,
) -> V02GenerationDisposition:
    """Freeze one candidate/no-candidate disposition without any evaluator authority.

    This is the only scored generation entry point.  Its signature deliberately contains no
    evaluator capability, fixed source, sandbox, oracle callback, or verifier feedback.  It makes
    at most the already-authorized one-shot provider call and fsyncs exactly one terminal generation
    disposition.  Unknown model spend hard-halts instead of becoming a no-candidate result.
    """

    policy = policy or V02ScoredRunPolicy()
    policy.require_executable()
    run = _start_new_scored_attempt(
        preregistration_path=Path(preregistration_path),
        campaign_freeze_path=Path(campaign_freeze_path),
        execution_authorization_path=Path(execution_authorization_path),
        case_id=case_id,
        generator_projection_path=Path(generator_projection_path),
        generator_source_context=generator_source_context,
        ledger_path=Path(ledger_path),
        attempt_directory=Path(attempt_directory),
        policy=policy,
    )
    candidate: ValidatedCandidate | None = None
    artifact_path: Path | None = None
    classification_code: str | None = None
    try:
        pricing = _require_pricing(policy)
        _record_cost(
            run,
            category="dependency_prep",
            attribution="cold_prep_excluded",
            status="measured" if pricing.dependency_prep_microusd else "zero_verified",
            amount=pricing.dependency_prep_microusd,
            source_call_id=None,
            evidence={
                "pricing_snapshot_sha256": pricing.sha256,
                "dependency_required": bool(
                    getattr(generator_source_context, "dependencies_required", False)
                ),
            },
        )
        candidate, artifact_path = _generation_phase(run)
        _assert_known_model_cost(run)
        _assert_total_within_reservation(run)
        _record_or_validate_recovery_artifact_cost(run, candidate)
        _assert_total_within_reservation(run)
        _revalidate_candidate_file(artifact_path, candidate)
    except _ControlledFailure as exc:
        classification_code = exc.classification_code
        _finish_open_phase(run, status="failed", classification_code=classification_code)
        _ensure_generation_costs(run, candidate=None)
    except (PolicyRejection, ReproAssertError) as exc:
        classification_code = _safe_code(exc.code)
        _finish_open_phase(run, status="failed", classification_code=classification_code)
        _ensure_generation_costs(run, candidate=None)
    except BaseException as exc:
        _append_crash(run, exc)
        raise

    costs = _attempt_costs(read_v02_scored_ledger(run.ledger_path), run.attempt_id)
    if costs.get("model_inference") is None:
        _append_crash(run, _PostExternalDurabilityCrash())
        raise _reject(
            "v02_generation_spend_unknown",
            "Generation usage is unknown; no disposition or evaluation is permitted.",
        )
    if costs.get("artifact_transfer") is None:
        _append_crash(run, _PostExternalDurabilityCrash())
        raise _reject(
            "v02_generation_spend_unknown",
            "Generation artifact spend is unknown; no disposition is permitted.",
        )
    status: Literal["candidate_submitted", "no_candidate"] = (
        "candidate_submitted" if candidate is not None else "no_candidate"
    )
    disposition = _append_event(
        run,
        "generation_disposition_frozen",
        {
            "status": status,
            "candidate_sha256": candidate.sha256 if candidate is not None else None,
            "classification_code": None if candidate is not None else classification_code,
            "frozen_at": _now(),
        },
    )
    return V02GenerationDisposition(
        campaign_id=cast(str, run.policy.campaign_id),
        attempt_id=run.attempt_id,
        case_id=run.case.id,
        status=status,
        candidate_sha256=candidate.sha256 if candidate is not None else None,
        classification_code=None if candidate is not None else classification_code,
        ledger_head_event_sha256=cast(str, disposition["event_sha256"]),
        generation_artifact_path=artifact_path,
    )


def _start_new_scored_attempt(
    *,
    preregistration_path: Path,
    campaign_freeze_path: Path,
    execution_authorization_path: Path,
    case_id: str,
    generator_projection_path: Path,
    generator_source_context: VerifiedV02GeneratorSourceContext,
    ledger_path: Path,
    attempt_directory: Path,
    policy: V02ScoredRunPolicy,
) -> _RunContext:
    campaign_prepared_at = _verify_campaign_freeze_binding(
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
        case_id=case_id,
        policy=policy,
    )
    preregistration = load_v02_preregistration(preregistration_path)
    case = _find_case(preregistration.cases, case_id)
    projection = _load_projection(generator_projection_path, case)
    context = require_v02_generator_source_context(generator_source_context)
    _validate_generator_context(context, case)
    request = _generation_request(case, projection, context)
    rendered_input_sha256 = _rendered_input_sha256(request)
    execution_authorization = _verify_execution_authorization_binding(
        execution_authorization_path=execution_authorization_path,
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
        case_id=case_id,
        rendered_input_sha256=rendered_input_sha256,
        policy=policy,
    )
    started_at = _now()
    prepared_time = datetime.fromisoformat(campaign_prepared_at[:-1] + "+00:00")
    authorized_time = datetime.fromisoformat(execution_authorization.authorized_at[:-1] + "+00:00")
    started_time = datetime.fromisoformat(started_at[:-1] + "+00:00")
    if prepared_time > authorized_time or authorized_time > started_time:
        raise _reject(
            "v02_execution_authorization",
            "Campaign freeze and execution authorization must precede attempt start.",
        )
    required_reserve = _required_reservation(policy, request)
    if policy.reserved_worst_case_microusd < required_reserve:
        raise _reject(
            "v02_spend_reservation",
            "The explicit reservation is below the deterministic worst-case component bound.",
        )
    ledger = Path(os.path.abspath(os.fspath(ledger_path)))
    _require_private_parent(ledger)
    _claim_execution_authorization(execution_authorization, ledger)
    private_root = _prepare_private_directory(attempt_directory)
    cohort_sha256 = cast(str, preregistration.decoded["cohort_sha256"])
    context_record = _source_context_record(context)
    runner_input_sha256 = _runner_input_digest(
        preregistration_sha256=preregistration.raw_sha256,
        cohort_sha256=cohort_sha256,
        case_record=asdict(case),
        generator_projection_sha256=projection.sha256,
        context_record=context_record,
        rendered_input_sha256=rendered_input_sha256,
        configuration_sha256=policy.configuration_sha256,
    )
    run = _RunContext(
        ledger_path=ledger,
        attempt_directory=private_root,
        policy=policy,
        attempt_id=f"attempt_{uuid.uuid4().hex}",
        case=case,
        preregistration_sha256=preregistration.raw_sha256,
        cohort_sha256=cohort_sha256,
        source_context=context,
        request=request,
        rendered_input_sha256=rendered_input_sha256,
        runner_input_sha256=runner_input_sha256,
    )
    _append_event(
        run,
        "attempt_started",
        {
            "started_at": started_at,
            "preregistration_sha256": run.preregistration_sha256,
            "cohort_sha256": run.cohort_sha256,
            "case": asdict(run.case),
            "configuration": policy.configuration_record(),
            "source_context": context_record,
            "runner_input_sha256": run.runner_input_sha256,
            "reserved_worst_case_microusd": policy.reserved_worst_case_microusd,
        },
        preflight=lambda snapshot: _preflight_attempt(snapshot, run),
    )
    return run


def _ensure_generation_costs(run: _RunContext, *, candidate: ValidatedCandidate | None) -> None:
    """Complete only pre-barrier cost categories; evaluator costs stay absent and sealed."""

    snapshot = read_v02_scored_ledger(run.ledger_path)
    events = [event for event in snapshot.events if event["attempt_id"] == run.attempt_id]
    existing = {
        cast(str, cast(Mapping[str, object], event["payload"])["category"])
        for event in events
        if event["event_type"] == "cost_recorded"
    }
    starts = [event for event in events if event["event_type"] == "model_call_started"]
    finishes = [event for event in events if event["event_type"] == "model_call_finished"]
    if "model_inference" not in existing:
        if finishes:
            payload = cast(Mapping[str, object], finishes[0]["payload"])
            _record_model_cost(
                run,
                call_id=cast(str, payload["call_id"]),
                usage=cast(Mapping[str, object], payload["usage"]),
            )
        elif starts:
            _record_cost(
                run,
                category="model_inference",
                attribution="scored",
                status="unknown",
                amount=None,
                source_call_id=cast(
                    str, cast(Mapping[str, object], starts[0]["payload"])["call_id"]
                ),
                evidence={"reason": "unmatched_provider_call"},
            )
        else:
            _record_cost(
                run,
                category="model_inference",
                attribution="scored",
                status="zero_verified",
                amount=0,
                source_call_id=None,
                evidence={"reason": "provider_not_invoked"},
            )
    if "artifact_transfer" not in existing:
        pricing = _require_pricing(run.policy)
        amount = _artifact_cost(pricing, candidate) if candidate is not None else 0
        _record_cost(
            run,
            category="artifact_transfer",
            attribution="scored",
            status="measured" if amount else "zero_verified",
            amount=amount,
            source_call_id=None,
            evidence={"candidate_present": candidate is not None},
        )


def freeze_v02_campaign_generation_barrier(
    *,
    preregistration_path: Path,
    ledger_path: Path,
    policy: V02ScoredRunPolicy,
) -> VerifiedV02CampaignGenerationBarrier:
    """Fsync and issue the all-case generation barrier without evaluator access.

    The barrier is independently reconstructed from the canonical event chain.  It requires one
    and only one candidate/no-candidate disposition for every preregistered case, exact generation
    costs, no unknown cases, and no prior differential phase.  Repeated calls return the same
    nominal proof; a racing second seal cannot create a duplicate event.
    """

    policy.require_executable()
    preregistration = load_v02_preregistration(Path(preregistration_path))
    ledger = Path(os.path.abspath(os.fspath(ledger_path)))
    _require_private_parent(ledger)
    snapshot = read_v02_scored_ledger(ledger)
    existing = _barrier_from_snapshot(snapshot, preregistration, policy)
    if existing is not None:
        return existing
    payload, anchor_attempt_id, anchor_case = _generation_barrier_payload(
        snapshot,
        preregistration,
        policy,
        frozen_at=_now(),
    )
    context = _CampaignEventContext(
        ledger_path=ledger,
        policy=policy,
        attempt_id=anchor_attempt_id,
        case=anchor_case,
    )

    def preflight(current: V02LedgerSnapshot) -> None:
        if _barrier_from_snapshot(current, preregistration, policy) is not None:
            raise _reject("v02_generation_barrier_exists", "Generation barrier already exists.")
        current_payload, current_attempt, _current_case = _generation_barrier_payload(
            current,
            preregistration,
            policy,
            frozen_at=cast(str, payload["frozen_at"]),
        )
        if current_payload != payload or current_attempt != anchor_attempt_id:
            raise _reject(
                "v02_generation_barrier_race", "Generation state changed before barrier fsync."
            )

    try:
        _append_event(
            context,
            "campaign_generation_barrier_frozen",
            payload,
            preflight=preflight,
        )
    except PolicyRejection as exc:
        if exc.code != "v02_generation_barrier_exists":
            raise
    sealed = _barrier_from_snapshot(read_v02_scored_ledger(ledger), preregistration, policy)
    if sealed is None:
        raise _reject("v02_generation_barrier", "Durable generation barrier was not observed.")
    return sealed


def require_v02_campaign_generation_barrier(
    value: object,
    *,
    preregistration_path: Path,
    ledger_path: Path,
    policy: V02ScoredRunPolicy,
) -> VerifiedV02CampaignGenerationBarrier:
    """Recompute a durable barrier and reject nominal or ledger tampering."""

    if type(value) is not VerifiedV02CampaignGenerationBarrier:
        raise _reject("v02_generation_barrier", "Generation barrier type is not application-owned.")
    barrier = value
    if barrier._issuer is not _BARRIER_ISSUER:
        raise _reject("v02_generation_barrier", "Generation barrier issuer is invalid.")
    preregistration = load_v02_preregistration(Path(preregistration_path))
    snapshot = read_v02_scored_ledger(Path(ledger_path))
    observed = _barrier_from_snapshot(snapshot, preregistration, policy)
    if observed is None or barrier != observed:
        raise _reject(
            "v02_generation_barrier", "Generation barrier differs from the durable event chain."
        )
    return barrier


def _barrier_from_snapshot(
    snapshot: V02LedgerSnapshot,
    preregistration: Any,
    policy: V02ScoredRunPolicy,
) -> VerifiedV02CampaignGenerationBarrier | None:
    barriers = [
        event
        for event in snapshot.events
        if event["event_type"] == "campaign_generation_barrier_frozen"
    ]
    if not barriers:
        return None
    if len(barriers) != 1:
        raise _reject("v02_generation_barrier", "Generation barrier is duplicated.")
    event = barriers[0]
    sequence = cast(int, event["sequence"])
    prefix_events = snapshot.events[: sequence - 1]
    payload = cast(Mapping[str, object], event["payload"])
    expected, anchor_attempt_id, _anchor_case = _generation_barrier_payload_from_events(
        prefix_events,
        preregistration,
        policy,
        frozen_at=cast(str, payload["frozen_at"]),
    )
    if event["attempt_id"] != anchor_attempt_id or dict(payload) != expected:
        raise _reject("v02_generation_barrier", "Generation barrier payload is not reproducible.")
    configuration = policy.configuration_record()
    execution_authorization = cast(Mapping[str, object], configuration["execution_authorization"])
    return VerifiedV02CampaignGenerationBarrier(
        _issuer=_BARRIER_ISSUER,
        algorithm=GENERATION_BARRIER_ALGORITHM,
        campaign_id=cast(str, policy.campaign_id),
        preregistration_sha256=preregistration.raw_sha256,
        cohort_sha256=cast(str, preregistration.decoded["cohort_sha256"]),
        configuration_sha256=policy.configuration_sha256,
        execution_authorization_sha256=cast(str, execution_authorization["sha256"]),
        request_set_sha256=cast(str, execution_authorization["request_set_sha256"]),
        pricing_snapshot_sha256=cast(str, configuration["pricing_snapshot_sha256"]),
        run_provenance_sha256=_sha256_json(configuration["run_provenance"]),
        disposition_set_sha256=cast(str, payload["disposition_set_sha256"]),
        disposition_count=cast(int, payload["disposition_count"]),
        ledger_sequence=sequence,
        ledger_head_event_sha256=cast(str, event["event_sha256"]),
        sha256=cast(str, payload["generation_barrier_sha256"]),
    )


def _generation_barrier_payload(
    snapshot: V02LedgerSnapshot,
    preregistration: Any,
    policy: V02ScoredRunPolicy,
    *,
    frozen_at: str,
) -> tuple[dict[str, object], str, PreregisteredV02Case]:
    return _generation_barrier_payload_from_events(
        snapshot.events,
        preregistration,
        policy,
        frozen_at=frozen_at,
    )


def _generation_barrier_payload_from_events(
    events: tuple[dict[str, Any], ...],
    preregistration: Any,
    policy: V02ScoredRunPolicy,
    *,
    frozen_at: str,
) -> tuple[dict[str, object], str, PreregisteredV02Case]:
    _timestamp(frozen_at, "generation barrier frozen_at")
    if any(event["event_type"] == "campaign_generation_barrier_frozen" for event in events):
        raise _reject("v02_generation_barrier", "Generation barrier input already contains a seal.")
    if any(
        event["event_type"] == "phase_started"
        and cast(Mapping[str, object], event["payload"])["phase"] == "differential"
        for event in events
    ):
        raise _reject(
            "v02_generation_barrier", "Differential evaluation began before the campaign barrier."
        )
    cases = {case.id: case for case in preregistration.cases}
    starts: dict[str, dict[str, Any]] = {}
    dispositions: dict[str, dict[str, Any]] = {}
    costs: dict[str, dict[str, int | None]] = {}
    candidate_hashes: dict[str, str] = {}
    for event in events:
        attempt_id = cast(str, event["attempt_id"])
        case_id = cast(str, event["case_id"])
        payload = cast(Mapping[str, object], event["payload"])
        if event["event_type"] == "attempt_started":
            if case_id not in cases or attempt_id in starts:
                raise _reject(
                    "v02_generation_barrier", "Barrier contains an unknown or duplicate attempt."
                )
            starts[attempt_id] = event
        elif event["event_type"] == "candidate_submitted":
            candidate_hashes[attempt_id] = cast(str, payload["candidate_sha256"])
        elif event["event_type"] == "cost_recorded":
            costs.setdefault(attempt_id, {})[cast(str, payload["category"])] = cast(
                int | None, payload["amount_microusd"]
            )
        elif event["event_type"] == "generation_disposition_frozen":
            if attempt_id in dispositions:
                raise _reject("v02_generation_barrier", "Case disposition is duplicated.")
            dispositions[attempt_id] = event
    if len(starts) != len(cases) or len(dispositions) != len(cases):
        raise _reject(
            "v02_generation_barrier_incomplete",
            "Every preregistered case must have exactly one durable generation disposition.",
        )
    cohort_sha256 = cast(str, preregistration.decoded["cohort_sha256"])
    records: list[dict[str, object]] = []
    seen_cases: set[str] = set()
    for attempt_id, start in starts.items():
        case_id = cast(str, start["case_id"])
        if case_id in seen_cases or attempt_id not in dispositions:
            raise _reject(
                "v02_generation_barrier", "Case-to-attempt disposition mapping is invalid."
            )
        seen_cases.add(case_id)
        case = cases[case_id]
        start_payload = cast(Mapping[str, object], start["payload"])
        if (
            start["campaign_id"] != policy.campaign_id
            or start_payload.get("preregistration_sha256") != preregistration.raw_sha256
            or start_payload.get("cohort_sha256") != cohort_sha256
            or start_payload.get("case") != asdict(case)
            or _sha256_json(start_payload.get("configuration")) != policy.configuration_sha256
        ):
            raise _reject(
                "v02_generation_barrier", "Attempt differs from campaign/preregistration freeze."
            )
        disposition = dispositions[attempt_id]
        disposition_payload = cast(Mapping[str, object], disposition["payload"])
        status = cast(str, disposition_payload["status"])
        candidate_sha256 = cast(str | None, disposition_payload["candidate_sha256"])
        classification_code = cast(str | None, disposition_payload["classification_code"])
        if status == "candidate_submitted":
            if (
                candidate_hashes.get(attempt_id) != candidate_sha256
                or classification_code is not None
            ):
                raise _reject("v02_generation_barrier", "Candidate disposition is not cross-bound.")
        elif status == "no_candidate":
            if (
                attempt_id in candidate_hashes
                or candidate_sha256 is not None
                or classification_code is None
            ):
                raise _reject(
                    "v02_generation_barrier", "No-candidate disposition is not cross-bound."
                )
        else:
            raise _reject("v02_generation_barrier", "Generation disposition status is invalid.")
        attempt_costs = costs.get(attempt_id, {})
        if (
            set(attempt_costs) != {"dependency_prep", "model_inference", "artifact_transfer"}
            or attempt_costs["dependency_prep"] is None
            or attempt_costs["model_inference"] is None
            or attempt_costs["artifact_transfer"] is None
        ):
            raise _reject(
                "v02_generation_barrier", "Generation disposition has incomplete or extra costs."
            )
        records.append(
            {
                "case_id": case_id,
                "attempt_id": attempt_id,
                "event_sha256": disposition["event_sha256"],
                "status": status,
                "candidate_sha256": candidate_sha256,
            }
        )
    records.sort(key=lambda record: cast(str, record["case_id"]))
    configuration = policy.configuration_record()
    execution_authorization = cast(Mapping[str, object], configuration["execution_authorization"])
    configuration_sha256 = policy.configuration_sha256
    execution_authorization_sha256 = cast(str, execution_authorization["sha256"])
    request_set_sha256 = cast(str, execution_authorization["request_set_sha256"])
    pricing_snapshot_sha256 = cast(str, configuration["pricing_snapshot_sha256"])
    run_provenance_sha256 = _sha256_json(configuration["run_provenance"])
    disposition_set_sha256 = _sha256_json(
        {
            "algorithm": GENERATION_DISPOSITION_ALGORITHM,
            "campaign_id": policy.campaign_id,
            "preregistration_sha256": preregistration.raw_sha256,
            "cohort_sha256": cohort_sha256,
            "dispositions": records,
        }
    )
    barrier_sha256 = _sha256_json(
        {
            "algorithm": GENERATION_BARRIER_ALGORITHM,
            "campaign_id": policy.campaign_id,
            "preregistration_sha256": preregistration.raw_sha256,
            "cohort_sha256": cohort_sha256,
            "disposition_count": len(records),
            "disposition_set_sha256": disposition_set_sha256,
            "configuration_sha256": configuration_sha256,
            "execution_authorization_sha256": execution_authorization_sha256,
            "request_set_sha256": request_set_sha256,
            "pricing_snapshot_sha256": pricing_snapshot_sha256,
            "run_provenance_sha256": run_provenance_sha256,
        }
    )
    anchor = max(dispositions.values(), key=lambda event: cast(int, event["sequence"]))
    anchor_case = cases[cast(str, anchor["case_id"])]
    return (
        {
            "barrier_algorithm": GENERATION_BARRIER_ALGORITHM,
            "configuration_sha256": configuration_sha256,
            "execution_authorization_sha256": execution_authorization_sha256,
            "request_set_sha256": request_set_sha256,
            "pricing_snapshot_sha256": pricing_snapshot_sha256,
            "run_provenance_sha256": run_provenance_sha256,
            "disposition_set_sha256": disposition_set_sha256,
            "generation_barrier_sha256": barrier_sha256,
            "disposition_count": len(records),
            "frozen_at": frozen_at,
        },
        cast(str, anchor["attempt_id"]),
        anchor_case,
    )


def evaluate_v02_frozen_case(
    *,
    preregistration_path: Path,
    case_id: str,
    generator_projection_path: Path,
    generator_source_context: VerifiedV02GeneratorSourceContext,
    campaign_barrier: VerifiedV02CampaignGenerationBarrier,
    evaluator_capability: VerifiedV02EvaluatorCapability | None,
    sandbox: DockerSandbox,
    base_source: Path,
    fixed_source: Path,
    ledger_path: Path,
    attempt_directory: Path,
    attempt_id: str,
    policy: V02ScoredRunPolicy,
    dependency_handle: DependencyVolumeHandle | None = None,
) -> V02ScoredRunResult:
    """Evaluate one frozen disposition only after the durable all-case barrier.

    Barrier verification and candidate/disposition reconciliation occur before the first evaluator
    capability operation.  Explicit no-candidate dispositions remain in the campaign denominator
    and finalize without accepting or inspecting any evaluator capability.
    """

    policy.require_executable()
    if type(sandbox) is not DockerSandbox:
        raise _reject(
            "v02_sandbox",
            "Scored evaluation requires the exact application-owned DockerSandbox type.",
        )
    run = _prepare_recovery_context(
        preregistration_path=Path(preregistration_path),
        case_id=case_id,
        generator_projection_path=Path(generator_projection_path),
        generator_source_context=generator_source_context,
        ledger_path=Path(ledger_path),
        attempt_directory=Path(attempt_directory),
        attempt_id=attempt_id,
        policy=policy,
    )
    lock_descriptor = _acquire_recovery_lock(run.attempt_directory)
    evaluation_mutated = False
    try:
        completed = _completed_recovery_result(run)
        if completed is not None:
            return completed
        require_v02_campaign_generation_barrier(
            campaign_barrier,
            preregistration_path=Path(preregistration_path),
            ledger_path=run.ledger_path,
            policy=policy,
        )
        snapshot = read_v02_scored_ledger(run.ledger_path)
        disposition = _attempt_generation_disposition(snapshot, run)
        _preflight_frozen_evaluation(snapshot, run)
        status = cast(str, disposition["status"])
        classification_code = cast(str | None, disposition["classification_code"])
        if status == "no_candidate":
            evaluation_mutated = True
            _fill_missing_costs(run, candidate=None)
            return _write_terminal_result(
                run,
                candidate=None,
                differential=None,
                outcome="no_output",
                claim_level="rejected",
                classification_code=cast(str, classification_code),
            )

        transaction = _load_generation_transaction(run)
        candidate = transaction.candidate
        if disposition["candidate_sha256"] != candidate.sha256:
            raise _reject(
                "v02_generation_disposition", "Frozen candidate differs from its transaction."
            )
        _revalidate_candidate_file(transaction.path, candidate)
        _assert_known_model_cost(run)
        _assert_total_within_reservation(run)

        # This is intentionally the first evaluator-capability touch in the two-phase path.
        evaluation_mutated = True
        capability = require_v02_evaluator_capability(evaluator_capability)
        _bind_capability(capability, run.case, run.source_context)
        session = acquire_v02_evaluation_session(
            capability,
            campaign_id=cast(str, run.policy.campaign_id),
            attempt_id=run.attempt_id,
            candidate=candidate,
            candidate_path=candidate_path(run.request.issue_number),
        )
        capability = consume_v02_evaluation_session(
            session,
            campaign_id=cast(str, run.policy.campaign_id),
            attempt_id=run.attempt_id,
            candidate=candidate,
            candidate_path=candidate_path(run.request.issue_number),
        )
        differential: DifferentialVerificationOutcome | None = None
        outcome = "benchmark_infrastructure_error"
        claim_level = "rejected"
        classification_code = "v02_evaluation_incomplete"
        try:
            differential, duration_ms = _differential_phase(
                run,
                capability=capability,
                sandbox=sandbox,
                base_source=Path(base_source),
                fixed_source=Path(fixed_source),
                candidate=candidate,
                dependency_handle=dependency_handle,
            )
            _revalidate_candidate_file(transaction.path, candidate)
            pricing = _require_pricing(run.policy)
            _record_cost(
                run,
                category="sandbox_compute",
                attribution="scored",
                status="measured" if pricing.sandbox_microusd_per_second else "zero_verified",
                amount=_sandbox_cost(pricing, duration_ms),
                source_call_id=None,
                evidence={
                    "duration_ms": duration_ms,
                    "evaluator_capability_sha256": differential.evaluator_capability_sha256,
                },
            )
            _assert_total_within_reservation(run)
            _record_cost(
                run,
                category="paid_storage",
                attribution="scored",
                status="measured" if pricing.paid_storage_microusd else "zero_verified",
                amount=pricing.paid_storage_microusd,
                source_call_id=None,
                evidence={"storage_policy": "private_local_attempt_artifacts"},
            )
            _assert_total_within_reservation(run)
            outcome = differential.outcome
            claim_level = _claim_level_value(differential.claim_level)
            classification_code = "completed"
        except _ControlledFailure as exc:
            outcome = exc.outcome
            classification_code = exc.classification_code
            _finish_open_phase(run, status="failed", classification_code=classification_code)
            _fill_missing_costs(run, candidate=candidate)
        except (PolicyRejection, ReproAssertError) as exc:
            classification_code = _safe_code(exc.code)
            _finish_open_phase(run, status="failed", classification_code=classification_code)
            _fill_missing_costs(run, candidate=candidate)
        return _write_terminal_result(
            run,
            candidate=candidate,
            differential=differential,
            outcome=outcome,
            claim_level=claim_level,
            classification_code=classification_code,
        )
    except BaseException as exc:
        if evaluation_mutated:
            _append_evaluation_crash_if_open(run, exc)
        raise
    finally:
        _release_recovery_lock(lock_descriptor)


def _attempt_generation_disposition(
    snapshot: V02LedgerSnapshot, run: _RunContext
) -> Mapping[str, object]:
    events = [
        event
        for event in snapshot.events
        if event["attempt_id"] == run.attempt_id
        and event["event_type"] == "generation_disposition_frozen"
    ]
    if len(events) != 1:
        raise _reject(
            "v02_generation_disposition", "Attempt lacks one exact generation disposition."
        )
    return cast(Mapping[str, object], events[0]["payload"])


def _preflight_frozen_evaluation(snapshot: V02LedgerSnapshot, run: _RunContext) -> None:
    """Reject any second or post-crash evaluator entry before capability access."""

    events = [event for event in snapshot.events if event["attempt_id"] == run.attempt_id]
    terminal = False
    for event in events:
        if event["event_type"] in {"attempt_finished", "attempt_crashed"}:
            terminal = True
        elif event["event_type"] == "recovery_started":
            terminal = False
    if terminal:
        raise _reject(
            "v02_evaluation_terminal", "Attempt is terminal and cannot access evaluator authority."
        )
    if any(
        event["event_type"] in {"phase_started", "phase_finished"}
        and cast(Mapping[str, object], event["payload"])["phase"]
        in {"differential", "result_write"}
        for event in events
    ):
        raise _reject(
            "v02_evaluation_replay", "Differential or result work already began for this attempt."
        )
    categories = {
        cast(str, cast(Mapping[str, object], event["payload"])["category"])
        for event in events
        if event["event_type"] == "cost_recorded"
    }
    if categories != {"dependency_prep", "model_inference", "artifact_transfer"}:
        raise _reject("v02_evaluation_cost_state", "Pre-evaluation cost categories are not exact.")


def _append_evaluation_crash_if_open(run: _RunContext, exc: BaseException) -> None:
    try:
        snapshot = read_v02_scored_ledger(run.ledger_path)
        events = [event for event in snapshot.events if event["attempt_id"] == run.attempt_id]
        if events and events[-1]["event_type"] not in {"attempt_finished", "attempt_crashed"}:
            _append_crash(run, exc)
    except Exception:
        return


def recover_v02_scored_case(
    *,
    preregistration_path: Path,
    campaign_freeze_path: Path,
    execution_authorization_path: Path,
    case_id: str,
    generator_projection_path: Path,
    generator_source_context: VerifiedV02GeneratorSourceContext,
    ledger_path: Path,
    attempt_directory: Path,
    attempt_id: str,
    policy: V02ScoredRunPolicy | None = None,
) -> V02GenerationDisposition:
    """Recover and freeze only the exact generation disposition, with zero provider calls.

    Recovery is deliberately narrower than a retry.  It accepts no generator, API response,
    replacement candidate, evaluator capability, fixed source, sandbox, verifier feedback, or
    provider credential.  Missing ledger commits are replayed idempotently from the exact private
    transaction, then one candidate disposition is fsynced.  Evaluation remains impossible until
    all 20 dispositions produce the separate durable campaign barrier.
    """

    policy = policy or V02ScoredRunPolicy()
    policy.require_executable()
    run = _prepare_recovery_context(
        preregistration_path=Path(preregistration_path),
        campaign_freeze_path=Path(campaign_freeze_path),
        execution_authorization_path=Path(execution_authorization_path),
        case_id=case_id,
        generator_projection_path=Path(generator_projection_path),
        generator_source_context=generator_source_context,
        ledger_path=Path(ledger_path),
        attempt_directory=Path(attempt_directory),
        attempt_id=attempt_id,
        policy=policy,
    )
    lock_descriptor = _acquire_recovery_lock(run.attempt_directory)
    try:
        candidate, candidate_file = _recover_generation_without_provider(run)
        _assert_known_model_cost(run)
        _assert_total_within_reservation(run)
        _record_or_validate_recovery_artifact_cost(run, candidate)
        _assert_total_within_reservation(run)
        _revalidate_candidate_file(candidate_file, candidate)
        snapshot = read_v02_scored_ledger(run.ledger_path)
        existing = [
            event
            for event in snapshot.events
            if event["attempt_id"] == run.attempt_id
            and event["event_type"] == "generation_disposition_frozen"
        ]
        if existing:
            payload = cast(Mapping[str, object], existing[0]["payload"])
            if (
                len(existing) != 1
                or payload.get("status") != "candidate_submitted"
                or payload.get("candidate_sha256") != candidate.sha256
                or payload.get("classification_code") is not None
            ):
                raise _reject(
                    "v02_generation_disposition", "Recovered disposition differs from candidate."
                )
            disposition_event = existing[0]
        else:
            disposition_event = _append_event(
                run,
                "generation_disposition_frozen",
                {
                    "status": "candidate_submitted",
                    "candidate_sha256": candidate.sha256,
                    "classification_code": None,
                    "frozen_at": _now(),
                },
            )
        return V02GenerationDisposition(
            campaign_id=cast(str, run.policy.campaign_id),
            attempt_id=run.attempt_id,
            case_id=run.case.id,
            status="candidate_submitted",
            candidate_sha256=candidate.sha256,
            classification_code=None,
            ledger_head_event_sha256=cast(str, disposition_event["event_sha256"]),
            generation_artifact_path=candidate_file,
        )
    except BaseException as exc:
        _append_recovery_crash_if_open(run, exc)
        raise
    finally:
        _release_recovery_lock(lock_descriptor)


def _prepare_recovery_context(
    *,
    preregistration_path: Path,
    campaign_freeze_path: Path | None = None,
    execution_authorization_path: Path | None = None,
    case_id: str,
    generator_projection_path: Path,
    generator_source_context: VerifiedV02GeneratorSourceContext,
    ledger_path: Path,
    attempt_directory: Path,
    attempt_id: str,
    policy: V02ScoredRunPolicy,
) -> _RunContext:
    """Rebuild and cross-check the immutable runner input for an existing attempt."""

    _identifier(attempt_id, "attempt ID")
    campaign_prepared_at = (
        _verify_campaign_freeze_binding(
            campaign_freeze_path=campaign_freeze_path,
            preregistration_path=preregistration_path,
            case_id=case_id,
            policy=policy,
        )
        if campaign_freeze_path is not None
        else None
    )
    preregistration = load_v02_preregistration(preregistration_path)
    case = _find_case(preregistration.cases, case_id)
    projection = _load_projection(generator_projection_path, case)
    context = require_v02_generator_source_context(generator_source_context)
    _validate_generator_context(context, case)
    request = _generation_request(case, projection, context)
    rendered_input_sha256 = _rendered_input_sha256(request)
    execution_authorization: VerifiedV02ExecutionAuthorization | None = None
    if (campaign_freeze_path is None) != (execution_authorization_path is None):
        raise _reject(
            "v02_execution_authorization",
            "Campaign freeze and execution authorization paths must be supplied together.",
        )
    if campaign_freeze_path is not None and execution_authorization_path is not None:
        execution_authorization = _verify_execution_authorization_binding(
            execution_authorization_path=execution_authorization_path,
            campaign_freeze_path=campaign_freeze_path,
            preregistration_path=preregistration_path,
            case_id=case_id,
            rendered_input_sha256=rendered_input_sha256,
            policy=policy,
        )
    required_reserve = _required_reservation(policy, request)
    if policy.reserved_worst_case_microusd < required_reserve:
        raise _reject(
            "v02_spend_reservation",
            "The recovery policy reservation is below the original deterministic bound.",
        )

    private_root = Path(os.path.abspath(os.fspath(attempt_directory)))
    require_private_directory(private_root)
    private_root = private_root.resolve(strict=True)
    ledger = Path(os.path.abspath(os.fspath(ledger_path)))
    _require_private_parent(ledger)
    if execution_authorization is not None:
        _claim_execution_authorization(execution_authorization, ledger)
    cohort_sha256 = cast(str, preregistration.decoded["cohort_sha256"])
    context_record = _source_context_record(context)
    runner_input_sha256 = _runner_input_digest(
        preregistration_sha256=preregistration.raw_sha256,
        cohort_sha256=cohort_sha256,
        case_record=asdict(case),
        generator_projection_sha256=projection.sha256,
        context_record=context_record,
        rendered_input_sha256=rendered_input_sha256,
        configuration_sha256=policy.configuration_sha256,
    )
    run = _RunContext(
        ledger_path=ledger,
        attempt_directory=private_root,
        policy=policy,
        attempt_id=attempt_id,
        case=case,
        preregistration_sha256=preregistration.raw_sha256,
        cohort_sha256=cohort_sha256,
        source_context=context,
        request=request,
        rendered_input_sha256=rendered_input_sha256,
        runner_input_sha256=runner_input_sha256,
    )
    _validate_recovery_attempt_freeze(
        read_v02_scored_ledger(ledger),
        run,
        campaign_prepared_at=campaign_prepared_at,
        execution_authorized_at=(
            execution_authorization.authorized_at if execution_authorization is not None else None
        ),
    )
    return run


def _verify_campaign_freeze_binding(
    *,
    campaign_freeze_path: Path,
    preregistration_path: Path,
    case_id: str,
    policy: V02ScoredRunPolicy,
) -> str:
    """Verify the preparation-only cohort freeze before any provider-capable operation."""

    # Imported lazily because the campaign verifier independently imports the ledger reader from
    # this module.  At invocation time both modules are fully initialized.
    from reproassert.benchmark_v02_campaign import verify_v02_campaign_freeze

    freeze = verify_v02_campaign_freeze(campaign_freeze_path, preregistration_path)
    tool = freeze.decoded.get("tool")
    if (
        policy.campaign_freeze_sha256 != freeze.raw_sha256
        or policy.campaign_id != freeze.campaign_id
        or case_id not in freeze.case_ids
        or not isinstance(tool, Mapping)
        or tool.get("git_sha") != policy.tool_git_sha
    ):
        raise _reject(
            "v02_campaign_freeze",
            "Run policy differs from the verified pre-inference campaign freeze.",
        )
    prepared_at = _timestamp(freeze.decoded.get("prepared_at"), "campaign preparation time")
    if datetime.fromisoformat(prepared_at[:-1] + "+00:00") > datetime.now(timezone.utc):
        raise _reject("v02_campaign_freeze", "Campaign preparation time cannot be in the future.")
    return prepared_at


def _verify_execution_authorization_binding(
    *,
    execution_authorization_path: Path,
    campaign_freeze_path: Path,
    preregistration_path: Path,
    case_id: str,
    rendered_input_sha256: str,
    policy: V02ScoredRunPolicy,
) -> VerifiedV02ExecutionAuthorization:
    authorization = verify_v02_execution_authorization(
        execution_authorization_path,
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
    )
    require_v02_execution_authorization(authorization)
    expected_policy = authorization.policy()
    if (
        policy.configuration_record() != expected_policy.configuration_record()
        or policy.execution_authorization_sha256 != authorization.raw_sha256
        or authorization.request_sha256(case_id) != rendered_input_sha256
    ):
        raise _reject(
            "v02_execution_authorization",
            "Run policy or rendered request differs from the exact execution authorization.",
        )
    return authorization


def _source_context_record(context: VerifiedV02GeneratorSourceContext) -> dict[str, object]:
    return {
        "algorithm": context.algorithm,
        "policy_sha256": context.policy_sha256,
        "sha256": context.context_sha256,
    }


def _runner_input_digest(
    *,
    preregistration_sha256: str,
    cohort_sha256: str,
    case_record: Mapping[str, object],
    generator_projection_sha256: str,
    context_record: Mapping[str, object],
    rendered_input_sha256: str,
    configuration_sha256: str,
) -> str:
    return _sha256_json(
        {
            "algorithm": "reproassert-v02-runner-input-v1",
            "preregistration_sha256": preregistration_sha256,
            "cohort_sha256": cohort_sha256,
            "case": dict(case_record),
            "generator_projection_sha256": generator_projection_sha256,
            "source_context": dict(context_record),
            "rendered_input_sha256": rendered_input_sha256,
            "configuration_sha256": configuration_sha256,
        }
    )


def _validate_recovery_attempt_freeze(
    snapshot: V02LedgerSnapshot,
    run: _RunContext,
    *,
    campaign_prepared_at: str | None = None,
    execution_authorized_at: str | None = None,
) -> None:
    starts = [
        event
        for event in snapshot.events
        if event["attempt_id"] == run.attempt_id and event["event_type"] == "attempt_started"
    ]
    if len(starts) != 1:
        raise _reject("v02_recovery_identity", "Recovery requires one exact attempt start.")
    start = starts[0]
    payload = cast(Mapping[str, object], start["payload"])
    if campaign_prepared_at is not None:
        attempt_started_at = _timestamp(payload.get("started_at"), "attempt start")
        if datetime.fromisoformat(attempt_started_at[:-1] + "+00:00") < datetime.fromisoformat(
            campaign_prepared_at[:-1] + "+00:00"
        ):
            raise _reject(
                "v02_campaign_freeze",
                "The verified campaign freeze was prepared after this attempt began.",
            )
    if execution_authorized_at is not None:
        attempt_started_at = _timestamp(payload.get("started_at"), "attempt start")
        if datetime.fromisoformat(execution_authorized_at[:-1] + "+00:00") > datetime.fromisoformat(
            attempt_started_at[:-1] + "+00:00"
        ):
            raise _reject(
                "v02_execution_authorization",
                "Execution authorization was issued after this attempt began.",
            )
    expected = {
        "preregistration_sha256": run.preregistration_sha256,
        "cohort_sha256": run.cohort_sha256,
        "case": asdict(run.case),
        "configuration": run.policy.configuration_record(),
        "source_context": _source_context_record(run.source_context),
        "runner_input_sha256": run.runner_input_sha256,
        "reserved_worst_case_microusd": run.policy.reserved_worst_case_microusd,
    }
    if (
        start["campaign_id"] != run.policy.campaign_id
        or start["case_id"] != run.case.id
        or any(payload.get(name) != value for name, value in expected.items())
    ):
        raise _reject(
            "v02_recovery_identity",
            "Recovery input differs from the durable attempt/preregistration/context freeze.",
        )


def _acquire_recovery_lock(attempt_directory: Path) -> int:
    """Take the private per-attempt recovery lock without waiting or following links."""

    path = attempt_directory / ".recovery.lock"
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise _reject("v02_recovery_lock", "Cannot safely open the recovery lock.") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise _reject("v02_recovery_lock", "Recovery lock identity or mode is unsafe.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise _reject(
                "v02_recovery_in_progress", "Another recovery owns this attempt lock."
            ) from exc
        os.fsync(descriptor)
        _fsync_directory(attempt_directory)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _release_recovery_lock(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _completed_recovery_result(run: _RunContext) -> V02ScoredRunResult | None:
    """Return an already-complete attempt only after revalidating both durable result files."""

    snapshot = read_v02_scored_ledger(run.ledger_path)
    terminals = [
        event
        for event in snapshot.events
        if event["attempt_id"] == run.attempt_id and event["event_type"] == "attempt_finished"
    ]
    if not terminals:
        return None
    if len(terminals) != 1:
        raise _reject("v02_recovery_terminal", "Attempt terminal state is ambiguous.")
    terminal = terminals[0]
    payload = cast(Mapping[str, object], terminal["payload"])
    private_path = run.attempt_directory / "reproassert-v02-private-result.json"
    public_path = run.attempt_directory / "reproassert-v02-public-embargoed-result.json"
    private_sha256 = _sha256_file(private_path, MAX_RESULT_BYTES)
    public_sha256 = _sha256_file(public_path, MAX_RESULT_BYTES)
    if private_sha256 != payload.get("private_result_sha256") or public_sha256 != payload.get(
        "public_result_sha256"
    ):
        raise _reject("v02_recovery_terminal", "Completed recovery result bytes changed.")
    private_record = _read_canonical_result(private_path)
    public_record = _read_canonical_result(public_path)
    for record in (private_record, public_record):
        if (
            record.get("campaign_id") != run.policy.campaign_id
            or record.get("attempt_id") != run.attempt_id
            or record.get("runner_input_sha256") != run.runner_input_sha256
        ):
            raise _reject("v02_recovery_terminal", "Completed result identity changed.")
    candidate = private_record.get("candidate")
    candidate_sha256 = (
        cast(str, candidate.get("sha256")) if isinstance(candidate, Mapping) else None
    )
    return V02ScoredRunResult(
        campaign_id=cast(str, run.policy.campaign_id),
        attempt_id=run.attempt_id,
        case_id=run.case.id,
        status=cast(str, payload["status"]),
        outcome=cast(str, payload["outcome"]),
        claim_level=cast(str, payload["claim_level"]),
        cost_complete=cast(bool, payload["cost_complete"]),
        total_attributable_microusd=cast(int | None, payload["total_attributable_microusd"]),
        candidate_sha256=candidate_sha256,
        private_result_path=private_path,
        private_result_sha256=private_sha256,
        public_result_path=public_path,
        public_result_sha256=public_sha256,
        terminal_event_sha256=cast(str, terminal["event_sha256"]),
    )


def _read_canonical_result(path: Path) -> Mapping[str, object]:
    with open_regular_file(path) as stream:
        encoded = stream.read(MAX_RESULT_BYTES + 1)
    if len(encoded) > MAX_RESULT_BYTES:
        raise _reject("v02_recovery_terminal", "Completed result exceeds its private limit.")
    try:
        value = json.loads(
            encoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject("v02_recovery_terminal", "Completed result is not valid JSON.") from exc
    if not isinstance(value, Mapping) or _canonical_json(value) + b"\n" != encoded:
        raise _reject("v02_recovery_terminal", "Completed result is not canonical.")
    return cast(Mapping[str, object], value)


def _load_generation_transaction(run: _RunContext) -> _GenerationTransaction:
    """Load the sole canonical candidate artifact and bind every recovery identity."""

    path = run.attempt_directory / "generation-transaction.json"
    with open_regular_file(path) as stream:
        encoded = stream.read(MAX_RESULT_BYTES + 1)
    if len(encoded) > MAX_RESULT_BYTES:
        raise _reject("v02_recovery_artifact", "Generation transaction exceeds its limit.")
    try:
        value = json.loads(
            encoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject("v02_recovery_artifact", "Generation transaction is invalid JSON.") from exc
    if not isinstance(value, Mapping) or _canonical_json(value) + b"\n" != encoded:
        raise _reject("v02_recovery_artifact", "Generation transaction is not canonical.")
    expected_keys = {
        "schema_version",
        "benchmark_version",
        "algorithm",
        "campaign_id",
        "attempt_id",
        "case_id",
        "preregistration_sha256",
        "configuration_sha256",
        "source_context_sha256",
        "runner_input_sha256",
        "call_id",
        "candidate",
        "model_finish",
    }
    if set(value) != expected_keys:
        raise _reject("v02_recovery_artifact", "Generation transaction fields are not exact.")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("benchmark_version") != BENCHMARK_VERSION
        or value.get("algorithm") != "reproassert-v02-generation-transaction-v1"
        or value.get("campaign_id") != run.policy.campaign_id
        or value.get("attempt_id") != run.attempt_id
        or value.get("case_id") != run.case.id
        or value.get("preregistration_sha256") != run.preregistration_sha256
        or value.get("configuration_sha256") != run.policy.configuration_sha256
        or value.get("source_context_sha256") != run.source_context.context_sha256
        or value.get("runner_input_sha256") != run.runner_input_sha256
    ):
        raise _reject(
            "v02_recovery_identity",
            "Generation transaction differs from the exact frozen runner identity.",
        )
    call_id = value.get("call_id")
    if not isinstance(call_id, str) or _CALL_ID.fullmatch(call_id) is None:
        raise _reject("v02_recovery_artifact", "Generation transaction call ID is invalid.")
    candidate_record = value.get("candidate")
    if not isinstance(candidate_record, Mapping) or set(candidate_record) != {
        "test_content",
        "expected_symptom",
        "rationale",
        "sha256",
        "bytes",
    }:
        raise _reject("v02_recovery_artifact", "Generation candidate fields are not exact.")
    candidate = validate_candidate_payload(
        {
            "test_content": candidate_record.get("test_content"),
            "expected_symptom": candidate_record.get("expected_symptom"),
            "rationale": candidate_record.get("rationale"),
        },
        issue_number=run.request.issue_number,
    )
    if candidate_record.get("sha256") != candidate.sha256 or candidate_record.get("bytes") != len(
        candidate.test_content.encode("utf-8")
    ):
        raise _reject("v02_recovery_artifact", "Generation candidate digest or size changed.")
    finish = value.get("model_finish")
    expected_finish_keys = _PAYLOAD_KEYS["model_call_finished"] - {
        "generation_artifact_sha256",
        "generation_artifact_bytes",
    }
    if not isinstance(finish, Mapping) or set(finish) != expected_finish_keys:
        raise _reject("v02_recovery_artifact", "Stored model terminal fields are not exact.")
    finish_record = dict(finish)
    if (
        finish_record.get("call_id") != call_id
        or finish_record.get("status") != "succeeded"
        or finish_record.get("classification_code") != "candidate_validated"
    ):
        raise _reject(
            "v02_recovery_artifact", "Only a successful candidate transaction is recoverable."
        )
    artifact_sha256 = hashlib.sha256(encoded).hexdigest()
    artifact_bytes = len(encoded)
    _validate_payload(
        "model_call_finished",
        {
            **finish_record,
            "generation_artifact_sha256": artifact_sha256,
            "generation_artifact_bytes": artifact_bytes,
        },
    )
    return _GenerationTransaction(
        path=path,
        sha256=artifact_sha256,
        bytes_count=artifact_bytes,
        call_id=call_id,
        candidate=candidate,
        model_finish=finish_record,
    )


def _candidate_commit_payload(
    run: _RunContext, transaction: _GenerationTransaction
) -> dict[str, object]:
    candidate = transaction.candidate
    return {
        "candidate_index": 1,
        "candidate_sha256": candidate.sha256,
        "candidate_bytes": len(candidate.test_content.encode("utf-8")),
        "artifact_path": transaction.path.name,
        "generation_artifact_sha256": transaction.sha256,
        "generation_artifact_bytes": transaction.bytes_count,
        "test_function": candidate.test_function,
        "generation_call_id": transaction.call_id,
        "oracle_consulted": False,
    }


def _model_finish_payload(transaction: _GenerationTransaction) -> dict[str, object]:
    return {
        **transaction.model_finish,
        "generation_artifact_sha256": transaction.sha256,
        "generation_artifact_bytes": transaction.bytes_count,
    }


def _recovery_started_payload(
    run: _RunContext, transaction: _GenerationTransaction
) -> dict[str, object]:
    identity = {
        "attempt_id": run.attempt_id,
        "runner_input_sha256": run.runner_input_sha256,
        "call_id": transaction.call_id,
        "artifact_sha256": transaction.sha256,
        "candidate_sha256": transaction.candidate.sha256,
    }
    return {
        "recovery_id": f"recovery_{_sha256_json(identity)[:32]}",
        "mode": "exact_candidate_zero_provider_calls",
        "execution_authorization_sha256": run.policy.execution_authorization_sha256,
        "preregistration_sha256": run.preregistration_sha256,
        "configuration_sha256": run.policy.configuration_sha256,
        "source_context_sha256": run.source_context.context_sha256,
        "runner_input_sha256": run.runner_input_sha256,
        "generation_call_id": transaction.call_id,
        "generation_artifact_sha256": transaction.sha256,
        "generation_artifact_bytes": transaction.bytes_count,
        "candidate_sha256": transaction.candidate.sha256,
        "provider_calls_permitted": 0,
        "oracle_feedback_permitted": False,
    }


def _recover_generation_without_provider(
    run: _RunContext,
) -> tuple[ValidatedCandidate, Path]:
    """Reconcile generation ledger commits from private bytes; never invoke a provider."""

    transaction = _load_generation_transaction(run)
    snapshot = read_v02_scored_ledger(run.ledger_path)
    recovery_payload = _recovery_started_payload(run, transaction)
    _preflight_recovery_state(snapshot, run, transaction, recovery_payload)
    recovery_events = [
        event
        for event in snapshot.events
        if event["attempt_id"] == run.attempt_id and event["event_type"] == "recovery_started"
    ]
    if not recovery_events:
        _append_event(
            run,
            "recovery_started",
            {**recovery_payload, "started_at": _now()},
            preflight=lambda current: _preflight_recovery_state(
                current, run, transaction, recovery_payload
            ),
        )
    else:
        _validate_existing_recovery_event(recovery_events[0], recovery_payload)

    snapshot = read_v02_scored_ledger(run.ledger_path)
    events = [event for event in snapshot.events if event["attempt_id"] == run.attempt_id]
    candidate_payload = _candidate_commit_payload(run, transaction)
    candidate_events = [event for event in events if event["event_type"] == "candidate_submitted"]
    if candidate_events:
        _validate_existing_event_payload(
            candidate_events[0], candidate_payload, ignored={"submitted_at"}
        )
    else:
        _append_event(
            run,
            "candidate_submitted",
            {**candidate_payload, "submitted_at": _now()},
        )

    finish_payload = _model_finish_payload(transaction)
    snapshot = read_v02_scored_ledger(run.ledger_path)
    events = [event for event in snapshot.events if event["attempt_id"] == run.attempt_id]
    finish_events = [event for event in events if event["event_type"] == "model_call_finished"]
    if finish_events:
        _validate_existing_event_payload(finish_events[0], finish_payload)
    else:
        _append_event(run, "model_call_finished", finish_payload)

    snapshot = read_v02_scored_ledger(run.ledger_path)
    model_costs = [
        event
        for event in snapshot.events
        if event["attempt_id"] == run.attempt_id
        and event["event_type"] == "cost_recorded"
        and cast(Mapping[str, object], event["payload"])["category"] == "model_inference"
    ]
    expected_cost = _model_cost_projection(run, cast(Mapping[str, object], finish_payload["usage"]))
    if model_costs:
        _validate_existing_cost(model_costs[0], expected_cost)
    else:
        _record_model_cost(
            run,
            call_id=transaction.call_id,
            usage=cast(Mapping[str, object], finish_payload["usage"]),
        )
    if expected_cost["amount_microusd"] is None:
        _halt_recovery_unknown_spend(run)
        raise _reject(
            "v02_recovery_spend_unknown",
            "Recovered model usage cannot be reconciled; evaluation remains sealed.",
        )

    snapshot = read_v02_scored_ledger(run.ledger_path)
    events = [event for event in snapshot.events if event["attempt_id"] == run.attempt_id]
    phase_starts = [
        event
        for event in events
        if event["event_type"] == "phase_started"
        and cast(Mapping[str, object], event["payload"])["phase"] == "generation"
    ]
    phase_finishes = [
        event
        for event in events
        if event["event_type"] == "phase_finished"
        and cast(Mapping[str, object], event["payload"])["phase"] == "generation"
    ]
    if len(phase_starts) != 1:
        raise _reject("v02_recovery_state", "Generation phase start is missing or ambiguous.")
    generation_evidence = {
        "candidate_sha256": transaction.candidate.sha256,
        "generation_artifact_sha256": transaction.sha256,
    }
    if phase_finishes:
        payload = cast(Mapping[str, object], phase_finishes[0]["payload"])
        if (
            payload.get("status") != "succeeded"
            or payload.get("classification_code") is not None
            or payload.get("evidence") != generation_evidence
        ):
            raise _reject("v02_recovery_state", "Generation phase terminal evidence changed.")
    else:
        started_at = cast(str, cast(Mapping[str, object], phase_starts[0]["payload"])["started_at"])
        _finish_phase(
            run,
            phase="generation",
            started_at=started_at,
            started_monotonic=time.monotonic(),
            status="succeeded",
            classification_code=None,
            evidence=generation_evidence,
        )
    _check_wall_budget(run)
    _revalidate_candidate_file(transaction.path, transaction.candidate)
    return transaction.candidate, transaction.path


def _preflight_recovery_state(
    snapshot: V02LedgerSnapshot,
    run: _RunContext,
    transaction: _GenerationTransaction,
    recovery_payload: Mapping[str, object],
) -> None:
    """Fail closed before any recovery mutation or evaluator-capability access."""

    _validate_recovery_attempt_freeze(snapshot, run)
    events = [event for event in snapshot.events if event["attempt_id"] == run.attempt_id]
    if any(
        event["event_type"] == "campaign_generation_barrier_frozen" for event in snapshot.events
    ):
        raise _reject(
            "v02_recovery_after_barrier",
            "Generation recovery is sealed after the durable campaign barrier.",
        )
    if any(event["event_type"] == "attempt_finished" for event in events):
        raise _reject("v02_recovery_terminal", "Completed attempts use idempotent result loading.")
    recovery_events = [event for event in events if event["event_type"] == "recovery_started"]
    if len(recovery_events) > 1:
        raise _reject("v02_recovery_state", "Recovery start is ambiguous.")
    if recovery_events:
        _validate_existing_recovery_event(recovery_events[0], recovery_payload)
        later_crashes = [
            event
            for event in events
            if event["event_type"] == "attempt_crashed"
            and cast(int, event["sequence"]) > cast(int, recovery_events[0]["sequence"])
        ]
        if later_crashes:
            raise _reject(
                "v02_recovery_halted", "A prior recovery hard-halted and cannot be retried."
            )
    if any(
        event["event_type"] in {"attempt_finished"}
        or (
            event["event_type"] in {"phase_started", "phase_finished"}
            and cast(Mapping[str, object], event["payload"])["phase"]
            in {"differential", "result_write"}
        )
        for event in events
    ):
        raise _reject(
            "v02_recovery_oracle_state",
            "Recovery is allowed only before differential evaluation begins.",
        )

    model_starts = [event for event in events if event["event_type"] == "model_call_started"]
    if len(model_starts) != 1:
        raise _reject("v02_recovery_call", "Recovery requires one exact original model call.")
    start_payload = cast(Mapping[str, object], model_starts[0]["payload"])
    expected_start = {
        "call_id": transaction.call_id,
        "provider": "openai",
        "endpoint_host": generator_module.OPENAI_API_HOST,
        "requested_model": run.policy.requested_model,
        "rendered_input_sha256": run.rendered_input_sha256,
        "config_sha256": _openai_adapter_config_sha256(run.policy.requested_model),
        "max_output_tokens": OPENAI_MAX_OUTPUT_TOKENS,
        "pricing_snapshot_sha256": _require_pricing(run.policy).sha256,
        "reserved_worst_case_microusd": run.policy.reserved_worst_case_microusd,
        "runner_input_sha256": run.runner_input_sha256,
    }
    if any(start_payload.get(name) != value for name, value in expected_start.items()):
        raise _reject(
            "v02_recovery_identity", "Original model call differs from the runner freeze."
        )
    if transaction.model_finish.get("started_at") != start_payload.get("started_at"):
        raise _reject("v02_recovery_call", "Stored model terminal has a different call origin.")

    candidate_events = [event for event in events if event["event_type"] == "candidate_submitted"]
    if len(candidate_events) > 1:
        raise _reject("v02_recovery_candidate", "Candidate budget was exceeded.")
    if candidate_events:
        _validate_existing_event_payload(
            candidate_events[0],
            _candidate_commit_payload(run, transaction),
            ignored={"submitted_at"},
        )
    finish_events = [event for event in events if event["event_type"] == "model_call_finished"]
    if len(finish_events) > 1:
        raise _reject("v02_recovery_call", "Model terminal is ambiguous.")
    if finish_events:
        _validate_existing_event_payload(finish_events[0], _model_finish_payload(transaction))

    costs = [event for event in events if event["event_type"] == "cost_recorded"]
    categories = [cast(Mapping[str, object], event["payload"])["category"] for event in costs]
    if len(categories) != len(set(categories)):
        raise _reject("v02_recovery_spend", "Recovery cost categories are ambiguous.")
    if any(category in {"sandbox_compute", "paid_storage"} for category in categories):
        raise _reject("v02_recovery_oracle_state", "Evaluator-attributable spend already exists.")
    model_costs = [
        event
        for event in costs
        if cast(Mapping[str, object], event["payload"])["category"] == "model_inference"
    ]
    if model_costs:
        _validate_existing_cost(
            model_costs[0],
            _model_cost_projection(
                run,
                cast(Mapping[str, object], transaction.model_finish["usage"]),
            ),
        )
    dependency_costs = [
        event
        for event in costs
        if cast(Mapping[str, object], event["payload"])["category"] == "dependency_prep"
    ]
    if len(dependency_costs) != 1:
        raise _reject(
            "v02_recovery_spend", "Original dependency-preparation cost is missing or ambiguous."
        )

    # A different attempt with unknown or unmatched paid work freezes this campaign as well.
    _require_other_attempt_spend_reconciled(snapshot, run)


def _validate_existing_recovery_event(
    event: Mapping[str, object], expected: Mapping[str, object]
) -> None:
    _validate_existing_event_payload(event, expected, ignored={"started_at"})


def _validate_existing_event_payload(
    event: Mapping[str, object],
    expected: Mapping[str, object],
    *,
    ignored: set[str] | None = None,
) -> None:
    payload = event.get("payload")
    if not isinstance(payload, Mapping):
        raise _reject("v02_recovery_state", "Recovery event payload is invalid.")
    omitted = ignored or set()
    if any(payload.get(name) != value for name, value in expected.items() if name not in omitted):
        raise _reject("v02_recovery_identity", "Durable recovery event differs from its artifact.")


def _model_cost_projection(run: _RunContext, usage: Mapping[str, object]) -> dict[str, object]:
    pricing = _require_pricing(run.policy)
    normalized = _validated_usage(usage)
    amount: int | None = None
    status = "unknown"
    if normalized["status"] == "reported":
        input_tokens = cast(int, normalized["input_tokens"])
        cached_tokens = cast(int, normalized["cached_input_tokens"])
        output_tokens = cast(int, normalized["output_tokens"])
        if cached_tokens > input_tokens:
            raise _reject("v02_model_usage", "Cached input tokens exceed total input tokens.")
        numerator = (
            (input_tokens - cached_tokens) * pricing.input_microusd_per_million_tokens
            + cached_tokens * pricing.cached_input_microusd_per_million_tokens
            + output_tokens * pricing.output_microusd_per_million_tokens
        )
        amount = _ceil_per_million(numerator)
        status = "measured" if amount else "zero_verified"
    evidence = {"usage": normalized, "pricing_snapshot_sha256": pricing.sha256}
    return {
        "category": "model_inference",
        "attribution": "scored",
        "status": status,
        "amount_microusd": amount,
        "source_call_id": _single_model_call_id(run),
        "evidence_sha256": _sha256_json(evidence),
    }


def _validate_existing_cost(event: Mapping[str, object], expected: Mapping[str, object]) -> None:
    payload = event.get("payload")
    if not isinstance(payload, Mapping) or any(
        payload.get(name) != value for name, value in expected.items()
    ):
        raise _reject("v02_recovery_spend", "Durable cost cannot be exactly reconciled.")


def _record_or_validate_recovery_artifact_cost(
    run: _RunContext, candidate: ValidatedCandidate
) -> None:
    pricing = _require_pricing(run.policy)
    amount = _artifact_cost(pricing, candidate)
    evidence = {"candidate_sha256": candidate.sha256}
    expected = {
        "category": "artifact_transfer",
        "attribution": "scored",
        "status": "measured" if pricing.artifact_microusd_per_million_bytes else "zero_verified",
        "amount_microusd": amount,
        "source_call_id": None,
        "evidence_sha256": _sha256_json(evidence),
    }
    snapshot = read_v02_scored_ledger(run.ledger_path)
    matches = [
        event
        for event in snapshot.events
        if event["attempt_id"] == run.attempt_id
        and event["event_type"] == "cost_recorded"
        and cast(Mapping[str, object], event["payload"])["category"] == "artifact_transfer"
    ]
    if matches:
        _validate_existing_cost(matches[0], expected)
    else:
        _record_cost(
            run,
            category="artifact_transfer",
            attribution="scored",
            status=cast(str, expected["status"]),
            amount=amount,
            source_call_id=None,
            evidence=evidence,
        )


def _halt_recovery_unknown_spend(run: _RunContext) -> None:
    snapshot = read_v02_scored_ledger(run.ledger_path)
    events = [event for event in snapshot.events if event["attempt_id"] == run.attempt_id]
    if events and events[-1]["event_type"] == "attempt_crashed":
        return
    _append_event(
        run,
        "attempt_crashed",
        {
            "crashed_at": _now(),
            "classification_code": "v02_recovery_spend_unknown",
            "exception_type": "RecoverySpendUnknown",
            "cost_complete": False,
            "recovery_status": "manual_reconciliation_required_no_new_provider_call",
        },
    )


def _append_recovery_crash_if_open(run: _RunContext, exc: BaseException) -> None:
    """Account an interrupted recovery without masking the authoritative exception."""

    try:
        snapshot = read_v02_scored_ledger(run.ledger_path)
        events = [event for event in snapshot.events if event["attempt_id"] == run.attempt_id]
        recoveries = [event for event in events if event["event_type"] == "recovery_started"]
        if not recoveries:
            return
        recovery_sequence = cast(int, recoveries[0]["sequence"])
        if any(
            cast(int, event["sequence"]) > recovery_sequence
            and event["event_type"] in {"attempt_finished", "attempt_crashed"}
            for event in events
        ):
            return
        _append_crash(run, exc)
    except Exception:
        return


def _require_other_attempt_spend_reconciled(snapshot: V02LedgerSnapshot, run: _RunContext) -> None:
    attempts: dict[str, dict[str, object]] = {}
    for event in snapshot.events:
        attempt_id = cast(str, event["attempt_id"])
        if attempt_id == run.attempt_id:
            continue
        state = attempts.setdefault(
            attempt_id,
            {
                "calls": set(),
                "finishes": set(),
                "costs": {},
                "reserve": 0,
                "terminal": False,
            },
        )
        payload = cast(Mapping[str, object], event["payload"])
        if event["event_type"] == "attempt_started":
            state["reserve"] = cast(int, payload["reserved_worst_case_microusd"])
        elif event["event_type"] == "model_call_started":
            cast(set[str], state["calls"]).add(cast(str, payload["call_id"]))
        elif event["event_type"] == "model_call_finished":
            cast(set[str], state["finishes"]).add(cast(str, payload["call_id"]))
        elif event["event_type"] == "cost_recorded":
            cast(dict[str, int | None], state["costs"])[cast(str, payload["category"])] = cast(
                int | None, payload["amount_microusd"]
            )
        elif event["event_type"] in {"attempt_finished", "attempt_crashed"}:
            state["terminal"] = True
        elif event["event_type"] == "recovery_started":
            state["terminal"] = False
    known_spend = 0
    active_reservations = run.policy.reserved_worst_case_microusd
    for state in attempts.values():
        calls = cast(set[str], state["calls"])
        finishes = cast(set[str], state["finishes"])
        costs = cast(dict[str, int | None], state["costs"])
        if calls != finishes:
            raise _reject("v02_recovery_spend", "Another campaign call remains unmatched.")
        if calls and ("model_inference" not in costs or costs["model_inference"] is None):
            raise _reject(
                "v02_recovery_spend", "Another finished call lacks reconciled model spend."
            )
        if state["terminal"]:
            if set(costs) != set(_COST_CATEGORIES) or any(
                costs[name] is None for name in _ATTRIBUTABLE_COST_CATEGORIES
            ):
                raise _reject(
                    "v02_recovery_spend", "Another terminal attempt lacks exact known costs."
                )
            known_spend += sum(cast(int, costs[name]) for name in _ATTRIBUTABLE_COST_CATEGORIES)
        else:
            active_reservations += cast(int, state["reserve"])
    if known_spend + active_reservations > run.policy.max_campaign_attributable_microusd:
        raise _reject(
            "v02_recovery_spend", "Campaign spend plus active reservations exceeds its cap."
        )


def _generation_phase(run: _RunContext) -> tuple[ValidatedCandidate, Path]:
    phase_started_at = _start_phase(run, "generation")
    started = time.monotonic()
    try:
        candidate, artifact_path = _run_transactional_openai_generation(run)
    except BaseException:
        raise
    _finish_phase(
        run,
        phase="generation",
        started_at=phase_started_at,
        started_monotonic=started,
        status="succeeded",
        classification_code=None,
        evidence={
            "candidate_sha256": candidate.sha256,
            "generation_artifact_sha256": _sha256_file(artifact_path, MAX_RESULT_BYTES),
        },
    )
    _check_wall_budget(run)
    return candidate, artifact_path


def _run_transactional_openai_generation(run: _RunContext) -> tuple[ValidatedCandidate, Path]:
    """Run the exact built-in adapter with candidate bytes durable before call closure."""

    policy = run.policy
    if policy.generator_mode != "trusted_builtin_provider_adapter":
        raise _reject("v02_generator", "Only the exact built-in scored adapter is executable.")
    model = policy.requested_model
    if model is None:
        raise _reject("v02_generator", "The scored model identity is missing.")
    request_payload = _openai_request_payload(run.request, model)
    encoded_request = json.dumps(request_payload, ensure_ascii=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(encoded_request) > generator_module.MAX_OPENAI_REQUEST_BYTES:
        raise _ControlledFailure("no_output", "openai_request_limit")

    api_key = generator_module._read_openai_api_key()
    call_id = f"call_{uuid.uuid4().hex}"
    started_at = _now()
    _append_event(
        run,
        "model_call_started",
        {
            "call_id": call_id,
            "started_at": started_at,
            "execution_authorization_sha256": policy.execution_authorization_sha256,
            "provider": "openai",
            "endpoint_host": generator_module.OPENAI_API_HOST,
            "requested_model": model,
            "rendered_input_sha256": run.rendered_input_sha256,
            "config_sha256": _openai_adapter_config_sha256(model),
            "max_output_tokens": OPENAI_MAX_OUTPUT_TOKENS,
            "pricing_snapshot_sha256": _require_pricing(policy).sha256,
            "reserved_worst_case_microusd": policy.reserved_worst_case_microusd,
            "runner_input_sha256": run.runner_input_sha256,
        },
        preflight=lambda snapshot: _preflight_model_call(snapshot, run),
    )
    call_started = time.monotonic()
    response_received = False
    observation = generator_module._OpenAIResponseObservation.unknown()
    try:
        encoded_response = generator_module._post_openai_response(
            encoded_request,
            api_key=api_key,
            timeout_seconds=min(
                policy.provider_timeout_seconds,
                _remaining_wall_seconds(run),
            ),
        )
        response_received = True
        if len(encoded_response) > generator_module.MAX_OPENAI_RESPONSE_BYTES:
            raise ReproAssertError(
                "openai_response_limit", "Provider response exceeded the private response limit."
            )
        observation = generator_module._observe_openai_response(encoded_response)
        response = generator_module._decode_openai_response(encoded_response)
        output_text = generator_module._extract_openai_output_text(response)
        if len(output_text.encode("utf-8")) > generator_module.MAX_OPENAI_OUTPUT_BYTES:
            raise ReproAssertError(
                "openai_output_limit", "Provider output exceeded the normalized output limit."
            )
        try:
            payload = json.loads(
                output_text,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constant,
            )
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise ReproAssertError(
                "openai_output_json", "Provider output was not one strict JSON object."
            ) from exc
        if not isinstance(payload, Mapping):
            raise ReproAssertError(
                "openai_output_json", "Provider output was not one strict JSON object."
            )
        candidate = validate_candidate_payload(
            payload,
            issue_number=run.request.issue_number,
            required_test_function=run.request.required_test_function,
        )
    except BaseException as exc:
        status, code = generator_module._classify_model_call_failure(
            exc, response_received=response_received
        )
        finish = dict(
            generator_module._model_call_finished_event(
                call_id=call_id,
                started_at=started_at,
                started_monotonic=call_started,
                status=status,
                classification_code=code,
                observation=observation,
            )
        )
        finish.update({"generation_artifact_sha256": None, "generation_artifact_bytes": None})
        try:
            _append_event(run, "model_call_finished", finish)
            _record_model_cost(
                run, call_id=call_id, usage=cast(Mapping[str, object], finish["usage"])
            )
        except Exception as durability_exc:
            raise _PostExternalDurabilityCrash() from durability_exc
        if not isinstance(exc, Exception):
            raise
        failure_outcome = (
            "policy_violation"
            if isinstance(exc, PolicyRejection) and exc.code.startswith("candidate_")
            else "no_output"
        )
        raise _ControlledFailure(failure_outcome, code) from exc

    finish = dict(
        generator_module._model_call_finished_event(
            call_id=call_id,
            started_at=started_at,
            started_monotonic=call_started,
            status="succeeded",
            classification_code="candidate_validated",
            observation=observation,
        )
    )
    artifact_path, artifact_sha256, artifact_bytes = _persist_generation_transaction(
        run,
        call_id=call_id,
        candidate=candidate,
        model_finish=finish,
    )
    finish.update(
        {
            "generation_artifact_sha256": artifact_sha256,
            "generation_artifact_bytes": artifact_bytes,
        }
    )
    try:
        _append_event(
            run,
            "candidate_submitted",
            {
                "candidate_index": 1,
                "candidate_sha256": candidate.sha256,
                "candidate_bytes": len(candidate.test_content.encode("utf-8")),
                "artifact_path": artifact_path.name,
                "generation_artifact_sha256": artifact_sha256,
                "generation_artifact_bytes": artifact_bytes,
                "test_function": candidate.test_function,
                "generation_call_id": call_id,
                "oracle_consulted": False,
                "submitted_at": _now(),
            },
        )
        _append_event(run, "model_call_finished", finish)
        _record_model_cost(run, call_id=call_id, usage=cast(Mapping[str, object], finish["usage"]))
    except Exception as durability_exc:
        raise _PostExternalDurabilityCrash() from durability_exc
    return candidate, artifact_path


def _differential_phase(
    run: _RunContext,
    *,
    capability: VerifiedV02EvaluatorCapability,
    sandbox: DockerSandbox,
    base_source: Path,
    fixed_source: Path,
    candidate: ValidatedCandidate,
    dependency_handle: DependencyVolumeHandle | None,
) -> tuple[DifferentialVerificationOutcome, int]:
    started_at = _start_phase(run, "differential")
    started = time.monotonic()
    try:
        result = verify_differential_candidate(
            sandbox=sandbox,
            base_source=base_source,
            fixed_source=fixed_source,
            relative_path=candidate_path(run.request.issue_number),
            candidate=candidate,
            evaluator_capability=capability,
            run_id=f"{run.policy.campaign_id}-{run.case.id}",
            dependency_handle=dependency_handle,
        )
    except BaseException:
        raise
    duration_ms = max(0, round((time.monotonic() - started) * 1_000))
    _finish_phase(
        run,
        phase="differential",
        started_at=started_at,
        started_monotonic=started,
        status="succeeded",
        classification_code=None,
        evidence={
            "accepted": result.accepted,
            "mechanical_claim_level": _claim_level_value(result.claim_level),
            "outcome": result.outcome,
            "evaluator_capability_sha256": result.evaluator_capability_sha256,
            "evaluator_commitment_sha256": result.evaluator_public_commitment_sha256,
        },
    )
    _check_wall_budget(run)
    return result, duration_ms


def _write_terminal_result(
    run: _RunContext,
    *,
    candidate: ValidatedCandidate | None,
    differential: DifferentialVerificationOutcome | None,
    outcome: str,
    claim_level: str,
    classification_code: str,
) -> V02ScoredRunResult:
    _fill_missing_costs(run, candidate=candidate)
    snapshot = read_v02_scored_ledger(run.ledger_path)
    costs = _attempt_costs(snapshot, run.attempt_id)
    cost_complete = all(costs.get(category) is not None for category in _COST_CATEGORIES)
    total_cost = (
        sum(cast(int, costs[category]) for category in _ATTRIBUTABLE_COST_CATEGORIES)
        if cost_complete
        else None
    )
    if not cost_complete:
        outcome = "benchmark_infrastructure_error"
        claim_level = "rejected"
    elif total_cost is not None and total_cost > run.policy.reserved_worst_case_microusd:
        outcome = "policy_violation"
        claim_level = "rejected"

    ledger_head = snapshot.head_event_sha256
    private_record = _private_result_record(
        run,
        candidate=candidate,
        differential=differential,
        outcome=outcome,
        claim_level=claim_level,
        costs=costs,
        cost_complete=cost_complete,
        total_cost=total_cost,
        ledger_head=ledger_head,
        classification_code=classification_code,
    )
    private_bytes = _bounded_result_bytes(private_record)
    private_sha256 = hashlib.sha256(private_bytes).hexdigest()
    public_record = _public_embargoed_result_record(
        run,
        candidate=candidate,
        costs=costs,
        cost_complete=cost_complete,
        total_cost=total_cost,
        ledger_head=ledger_head,
    )
    public_bytes = _bounded_result_bytes(public_record)
    public_sha256 = hashlib.sha256(public_bytes).hexdigest()

    _check_wall_budget(run)
    phase_started_at = _start_phase(run, "result_write")
    phase_started = time.monotonic()
    private_path = run.attempt_directory / "reproassert-v02-private-result.json"
    public_path = run.attempt_directory / "reproassert-v02-public-embargoed-result.json"
    _write_exclusive_fsync(private_path, private_bytes)
    _write_exclusive_fsync(public_path, public_bytes)
    _finish_phase(
        run,
        phase="result_write",
        started_at=phase_started_at,
        started_monotonic=phase_started,
        status="succeeded",
        classification_code=None,
        evidence={
            "private_result_sha256": private_sha256,
            "private_result_bytes": len(private_bytes),
            "public_result_sha256": public_sha256,
            "public_result_bytes": len(public_bytes),
            "public_embargoed": True,
        },
    )
    status = "complete" if cost_complete else "incomplete_unknown_cost"
    terminal = _append_event(
        run,
        "attempt_finished",
        {
            "completed_at": _now(),
            "status": status,
            "outcome": outcome,
            "claim_level": claim_level,
            "cost_complete": cost_complete,
            "total_attributable_microusd": total_cost,
            "private_result_sha256": private_sha256,
            "public_result_sha256": public_sha256,
        },
    )
    return V02ScoredRunResult(
        campaign_id=cast(str, run.policy.campaign_id),
        attempt_id=run.attempt_id,
        case_id=run.case.id,
        status=status,
        outcome=outcome,
        claim_level=claim_level,
        cost_complete=cost_complete,
        total_attributable_microusd=total_cost,
        candidate_sha256=candidate.sha256 if candidate is not None else None,
        private_result_path=private_path,
        private_result_sha256=private_sha256,
        public_result_path=public_path,
        public_result_sha256=public_sha256,
        terminal_event_sha256=cast(str, terminal["event_sha256"]),
    )


def _private_result_record(
    run: _RunContext,
    *,
    candidate: ValidatedCandidate | None,
    differential: DifferentialVerificationOutcome | None,
    outcome: str,
    claim_level: str,
    costs: Mapping[str, int | None],
    cost_complete: bool,
    total_cost: int | None,
    ledger_head: str | None,
    classification_code: str,
) -> dict[str, object]:
    evaluation: dict[str, object] | None = None
    if differential is not None:
        fixed_runs = sum(
            1
            for item in differential.scheduled_runs
            if getattr(item, "source_role", None) == "fixed"
        )
        base_runs = sum(
            1
            for item in differential.scheduled_runs
            if getattr(item, "source_role", None) == "base"
        )
        evaluation = {
            "accepted_mechanical_differential": differential.accepted,
            "mechanical_claim_level": _claim_level_value(differential.claim_level),
            "outcome": differential.outcome,
            "fingerprint": differential.fingerprint,
            "base_run_count": base_runs,
            "fixed_run_count": fixed_runs,
            "scheduled_runs": [
                {
                    "source_role": item.source_role,
                    "role_ordinal": item.role_ordinal,
                    "schedule_ordinal": item.schedule_ordinal,
                    "phase": item.result.phase,
                    "argv": list(item.result.argv),
                    "exit_code": item.result.exit_code,
                    "duration_seconds": item.result.duration_seconds,
                    "timed_out": item.result.timed_out,
                    "oom_killed": item.result.oom_killed,
                    "output_truncated": item.result.output_truncated,
                    "bounded_output": (
                        None if item.evaluator_output_redacted else item.result.output
                    ),
                    "output_sha256": item.output_sha256,
                    "junit_sha256": item.junit_sha256,
                    "evaluator_output_redacted": item.evaluator_output_redacted,
                }
                for item in differential.scheduled_runs
            ],
            "evaluator_capability_sha256": differential.evaluator_capability_sha256,
            "evaluator_package_sha256": differential.evaluator_package_sha256,
            "evaluator_commitment_sha256": differential.evaluator_public_commitment_sha256,
            "dependency": {
                "receipt_sha256": differential.dependency_receipt_sha256,
                "plan_sha256": differential.dependency_plan_sha256,
                "tree_sha256": differential.dependency_tree_sha256,
                "image_id": differential.dependency_image_id,
            },
            "semantic_status": "not_reviewed_mechanical_result_only",
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "benchmark_version": BENCHMARK_VERSION,
        "algorithm": RESULT_ALGORITHM,
        "visibility": "private_controller_only",
        "campaign_id": run.policy.campaign_id,
        "attempt_id": run.attempt_id,
        "case": asdict(run.case),
        "preregistration_sha256": run.preregistration_sha256,
        "cohort_sha256": run.cohort_sha256,
        "runner_input_sha256": run.runner_input_sha256,
        "configuration_sha256": run.policy.configuration_sha256,
        "source_context": {
            "algorithm": run.source_context.algorithm,
            "policy_sha256": run.source_context.policy_sha256,
            "sha256": run.source_context.context_sha256,
        },
        "candidate": (
            None
            if candidate is None
            else {
                "path": candidate_path(run.request.issue_number),
                "sha256": candidate.sha256,
                "bytes": len(candidate.test_content.encode("utf-8")),
                "test_content": candidate.test_content,
                "expected_symptom": candidate.expected_symptom,
                "rationale": candidate.rationale,
            }
        ),
        "evaluation": evaluation,
        "terminal_projection": {
            "outcome": outcome,
            "claim_level": claim_level,
            "classification_code": classification_code,
            "issue_faithful_or_semantic_valid": False,
            "limitation": (
                "Generated expected_symptom proves only mechanical assertion fingerprinting; "
                "issue fidelity requires later blinded semantic review and causal controls."
            ),
        },
        "cost": {
            "complete": cost_complete,
            "total_attributable_microusd": total_cost,
            "categories": dict(costs),
            "pricing_snapshot_sha256": _require_pricing(run.policy).sha256,
        },
        "ledger_head_before_result_sha256": ledger_head,
    }


def _public_embargoed_result_record(
    run: _RunContext,
    *,
    candidate: ValidatedCandidate | None,
    costs: Mapping[str, int | None],
    cost_complete: bool,
    total_cost: int | None,
    ledger_head: str | None,
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "benchmark_version": BENCHMARK_VERSION,
        "algorithm": RESULT_ALGORITHM,
        "visibility": "public_safe_embargoed",
        "publication_status": "embargoed_until_all_20_candidates_are_durably_frozen",
        "campaign_id": run.policy.campaign_id,
        "attempt_id": run.attempt_id,
        "case": asdict(run.case),
        "preregistration_sha256": run.preregistration_sha256,
        "cohort_sha256": run.cohort_sha256,
        "runner_input_sha256": run.runner_input_sha256,
        "configuration_sha256": run.policy.configuration_sha256,
        "candidate": (
            None
            if candidate is None
            else {
                "path": candidate_path(run.request.issue_number),
                "sha256": candidate.sha256,
                "bytes": len(candidate.test_content.encode("utf-8")),
                "test_content": candidate.test_content,
                "expected_symptom": candidate.expected_symptom,
                "rationale": candidate.rationale,
            }
        ),
        "evaluation": {
            "status": "sealed",
            "accepted": None,
            "outcome": None,
            "claim_level": None,
            "fixed_run_evidence": None,
            "evaluator_commitment_sha256": run.case.evaluator_commitment_sha256,
            "private_result_commitment": "withheld_until_campaign_terminal",
        },
        "cost": {
            "complete": cost_complete,
            "total_attributable_microusd": total_cost,
            "categories": dict(costs),
            "pricing_snapshot_sha256": _require_pricing(run.policy).sha256,
        },
        "ledger_head_before_result_sha256": ledger_head,
    }


def _append_event(
    run: _EventContext,
    event_type: str,
    payload: dict[str, Any],
    *,
    preflight: Callable[[V02LedgerSnapshot], None] | None = None,
) -> dict[str, Any]:
    path = run.ledger_path
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise _reject("v02_ledger_path", "Cannot safely open the v0.2 scored ledger.") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise _reject("v02_ledger_path", "The scored ledger must be one regular file.")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        os.lseek(descriptor, 0, os.SEEK_SET)
        snapshot = _decode_ledger(_read_bounded_fd(descriptor, MAX_LEDGER_BYTES))
        if preflight is not None:
            preflight(snapshot)
        event: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "benchmark_version": BENCHMARK_VERSION,
            "algorithm": EVENT_ALGORITHM,
            "sequence": len(snapshot.events) + 1,
            "recorded_at": _now(),
            "previous_event_sha256": snapshot.head_event_sha256,
            "campaign_id": run.policy.campaign_id,
            "attempt_id": run.attempt_id,
            "case_id": run.case.id,
            "event_type": event_type,
            "payload": payload,
        }
        event["event_sha256"] = _event_sha256(event)
        encoded = _canonical_json(event) + b"\n"
        candidate_chain = snapshot.encoded + encoded
        if len(candidate_chain) > MAX_LEDGER_BYTES:
            raise _reject("v02_ledger_limit", "The v0.2 scored ledger exceeds 32 MiB.")
        _decode_ledger(candidate_chain)
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
        _fsync_directory(path.parent)
        return event
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _decode_ledger(encoded: bytes) -> V02LedgerSnapshot:
    if len(encoded) > MAX_LEDGER_BYTES:
        raise _reject("v02_ledger_limit", "The v0.2 scored ledger exceeds 32 MiB.")
    if encoded and not encoded.endswith(b"\n"):
        raise _reject("v02_ledger_canonical", "The scored ledger has a truncated final event.")
    events: list[dict[str, Any]] = []
    previous: str | None = None
    for sequence, raw in enumerate(encoded.splitlines(), start=1):
        try:
            value = json.loads(
                raw,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise _reject("v02_ledger_json", "The scored ledger contains invalid JSON.") from exc
        if not isinstance(value, dict):
            raise _reject("v02_ledger_json", "Every scored event must be one JSON object.")
        event = cast(dict[str, Any], value)
        if _canonical_json(event) != raw:
            raise _reject("v02_ledger_canonical", "A scored event is not canonical JSON.")
        _validate_envelope(event, sequence=sequence, previous=previous)
        previous = cast(str, event["event_sha256"])
        events.append(event)
    _validate_transitions(events)
    return V02LedgerSnapshot(
        events=tuple(events),
        encoded=encoded,
        sha256=hashlib.sha256(encoded).hexdigest(),
        head_event_sha256=previous,
    )


def _validate_envelope(event: Mapping[str, Any], *, sequence: int, previous: str | None) -> None:
    if set(event) != _EVENT_ENVELOPE_KEYS:
        raise _reject("v02_event_schema", "Scored event envelope fields are not exact.")
    if (
        event.get("schema_version") != SCHEMA_VERSION
        or event.get("benchmark_version") != BENCHMARK_VERSION
        or event.get("algorithm") != EVENT_ALGORITHM
    ):
        raise _reject("v02_event_version", "Scored event version or algorithm is invalid.")
    if event.get("sequence") != sequence or event.get("previous_event_sha256") != previous:
        raise _reject("v02_event_chain", "Scored event sequence or predecessor is invalid.")
    _timestamp(event.get("recorded_at"), "event recorded_at")
    _identifier(event.get("campaign_id"), "campaign ID")
    _identifier(event.get("attempt_id"), "attempt ID")
    if not isinstance(event.get("case_id"), str) or _CASE_ID.fullmatch(event["case_id"]) is None:
        raise _reject("v02_event_identity", "Scored event case ID is invalid.")
    event_type = event.get("event_type")
    if event_type not in _EVENT_TYPES:
        raise _reject("v02_event_schema", "Scored event type is invalid.")
    payload = event.get("payload")
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS[event_type]:
        raise _reject("v02_event_schema", "Scored event payload fields are not exact.")
    digest = event.get("event_sha256")
    if not isinstance(digest, str) or digest != _event_sha256(dict(event)):
        raise _reject("v02_event_chain", "Scored event hash is invalid.")
    _validate_payload(cast(str, event_type), cast(Mapping[str, Any], payload))
    if event_type == "attempt_started":
        case = cast(Mapping[str, object], payload["case"])
        if case.get("id") != event["case_id"]:
            raise _reject("v02_event_identity", "Attempt case payload differs from its envelope.")


def _validate_payload(event_type: str, payload: Mapping[str, Any]) -> None:
    timestamp_names = {
        "attempt_started": ("started_at",),
        "phase_started": ("started_at",),
        "phase_finished": ("started_at", "completed_at"),
        "model_call_started": ("started_at",),
        "model_call_finished": ("started_at", "completed_at"),
        "cost_recorded": ("observed_at",),
        "candidate_submitted": ("submitted_at",),
        "generation_disposition_frozen": ("frozen_at",),
        "campaign_generation_barrier_frozen": ("frozen_at",),
        "recovery_started": ("started_at",),
        "attempt_finished": ("completed_at",),
        "attempt_crashed": ("crashed_at",),
    }
    for name in timestamp_names[event_type]:
        _timestamp(payload.get(name), name)
    if event_type == "attempt_started":
        _validate_attempt_started_payload(payload)
    elif event_type in {"phase_started", "phase_finished"} and payload.get("phase") not in _PHASES:
        raise _reject("v02_event_schema", "Scored phase is invalid.")
    if event_type == "phase_finished":
        if payload.get("status") not in {"succeeded", "failed"}:
            raise _reject("v02_event_schema", "Scored phase status is invalid.")
        _nonnegative_int(payload.get("duration_ms"), "phase duration")
        _nullable_code(payload.get("classification_code"))
        if not isinstance(payload.get("evidence"), dict):
            raise _reject("v02_event_schema", "Scored phase evidence must be an object.")
    elif event_type == "model_call_started":
        if _CALL_ID.fullmatch(str(payload.get("call_id"))) is None:
            raise _reject("v02_model_event", "Model call ID is invalid.")
        if payload.get("provider") != "openai" or payload.get("endpoint_host") != "api.openai.com":
            raise _reject("v02_model_event", "Model provider endpoint is not allowlisted.")
        _bounded_model(payload.get("requested_model"))
        for name in (
            "execution_authorization_sha256",
            "rendered_input_sha256",
            "config_sha256",
            "pricing_snapshot_sha256",
            "runner_input_sha256",
        ):
            _digest(payload.get(name), name)
        _positive_int(payload.get("max_output_tokens"), "max output tokens")
        _positive_int(payload.get("reserved_worst_case_microusd"), "model reservation")
    elif event_type == "model_call_finished":
        if _CALL_ID.fullmatch(str(payload.get("call_id"))) is None:
            raise _reject("v02_model_event", "Model call ID is invalid.")
        if payload.get("status") not in {
            "succeeded",
            "provider_error",
            "timeout",
            "invalid_response",
            "refusal",
            "cancelled",
        }:
            raise _reject("v02_model_event", "Model terminal status is invalid.")
        _nonnegative_int(payload.get("duration_ms"), "model duration")
        _nullable_digest(payload.get("response_id_sha256"), "response ID hash")
        _nullable_digest(payload.get("generation_artifact_sha256"), "generation artifact hash")
        artifact_bytes = payload.get("generation_artifact_bytes")
        if artifact_bytes is not None:
            _positive_int(artifact_bytes, "generation artifact bytes")
        if (payload.get("generation_artifact_sha256") is None) != (artifact_bytes is None):
            raise _reject("v02_model_event", "Generation artifact identity is incomplete.")
        if payload.get("status") == "succeeded" and artifact_bytes is None:
            raise _reject("v02_model_event", "Successful model calls require a durable candidate.")
        _nullable_code(payload.get("classification_code"), nullable=False)
        _validated_usage(payload.get("usage"))
    elif event_type == "cost_recorded":
        _identifier(payload.get("entry_id"), "cost entry ID")
        category = payload.get("category")
        if category not in _COST_CATEGORIES:
            raise _reject("v02_cost_event", "Cost category is invalid.")
        expected_attribution = "cold_prep_excluded" if category == "dependency_prep" else "scored"
        if payload.get("attribution") != expected_attribution:
            raise _reject("v02_cost_event", "Cost attribution is invalid.")
        status = payload.get("status")
        if status not in {"measured", "zero_verified", "unknown"}:
            raise _reject("v02_cost_event", "Cost status is invalid.")
        amount = payload.get("amount_microusd")
        if status == "unknown":
            if amount is not None:
                raise _reject("v02_cost_event", "Unknown cost cannot carry an amount.")
        else:
            _nonnegative_int(amount, "cost amount")
            if status == "zero_verified" and amount != 0:
                raise _reject("v02_cost_event", "Zero-verified cost must be zero.")
        source_call_id = payload.get("source_call_id")
        if source_call_id is not None and _CALL_ID.fullmatch(str(source_call_id)) is None:
            raise _reject("v02_cost_event", "Cost source call ID is invalid.")
        _digest(payload.get("evidence_sha256"), "cost evidence hash")
    elif event_type == "candidate_submitted":
        if payload.get("candidate_index") != 1 or payload.get("oracle_consulted") is not False:
            raise _reject("v02_candidate_event", "Candidate budget or oracle policy is invalid.")
        _digest(payload.get("candidate_sha256"), "candidate hash")
        bytes_count = payload.get("candidate_bytes")
        _positive_int(bytes_count, "candidate bytes")
        if cast(int, bytes_count) > MAX_TEST_BYTES:
            raise _reject("v02_candidate_event", "Candidate exceeds its test byte limit.")
        artifact_path = payload.get("artifact_path")
        if artifact_path != "generation-transaction.json":
            raise _reject("v02_candidate_event", "Candidate artifact path is not fixed.")
        _digest(payload.get("generation_artifact_sha256"), "generation artifact hash")
        _positive_int(payload.get("generation_artifact_bytes"), "generation artifact bytes")
        _identifier(payload.get("test_function"), "test function")
        if _CALL_ID.fullmatch(str(payload.get("generation_call_id"))) is None:
            raise _reject("v02_candidate_event", "Candidate call binding is invalid.")
    elif event_type == "generation_disposition_frozen":
        status = payload.get("status")
        candidate_sha256 = payload.get("candidate_sha256")
        classification_code = payload.get("classification_code")
        if status == "candidate_submitted":
            _digest(candidate_sha256, "generation disposition candidate")
            if classification_code is not None:
                raise _reject(
                    "v02_generation_disposition", "Candidate disposition cannot be classified."
                )
        elif status == "no_candidate":
            if candidate_sha256 is not None:
                raise _reject(
                    "v02_generation_disposition", "No-candidate disposition carries a candidate."
                )
            _nullable_code(classification_code, nullable=False)
        else:
            raise _reject("v02_generation_disposition", "Generation disposition status is invalid.")
    elif event_type == "campaign_generation_barrier_frozen":
        if payload.get("barrier_algorithm") != GENERATION_BARRIER_ALGORITHM:
            raise _reject("v02_generation_barrier", "Generation barrier algorithm is invalid.")
        for name in (
            "configuration_sha256",
            "execution_authorization_sha256",
            "request_set_sha256",
            "pricing_snapshot_sha256",
            "run_provenance_sha256",
            "disposition_set_sha256",
            "generation_barrier_sha256",
        ):
            _digest(payload.get(name), name)
        if payload.get("disposition_count") != 20:
            raise _reject("v02_generation_barrier", "Generation barrier must contain 20 cases.")
    elif event_type == "recovery_started":
        _identifier(payload.get("recovery_id"), "recovery ID")
        if payload.get("mode") != "exact_candidate_zero_provider_calls":
            raise _reject("v02_recovery_event", "Recovery mode is not fail-closed.")
        for name in (
            "execution_authorization_sha256",
            "preregistration_sha256",
            "configuration_sha256",
            "source_context_sha256",
            "runner_input_sha256",
            "generation_artifact_sha256",
            "candidate_sha256",
        ):
            _digest(payload.get(name), name)
        if _CALL_ID.fullmatch(str(payload.get("generation_call_id"))) is None:
            raise _reject("v02_recovery_event", "Recovery call binding is invalid.")
        _positive_int(payload.get("generation_artifact_bytes"), "generation artifact bytes")
        if (
            payload.get("provider_calls_permitted") != 0
            or payload.get("oracle_feedback_permitted") is not False
        ):
            raise _reject("v02_recovery_event", "Recovery permits provider or oracle feedback.")
    elif event_type == "attempt_finished":
        if payload.get("status") not in {
            "complete",
            "incomplete_unknown_cost",
        }:
            raise _reject("v02_event_schema", "Attempt terminal status is invalid.")
        _nullable_digest(payload.get("private_result_sha256"), "private result hash")
        _nullable_digest(payload.get("public_result_sha256"), "public result hash")
        amount = payload.get("total_attributable_microusd")
        if payload.get("cost_complete") is True:
            _nonnegative_int(amount, "total attributable cost")
        elif payload.get("cost_complete") is False and amount is not None:
            raise _reject("v02_cost_event", "Incomplete cost cannot carry a total.")
    elif event_type == "attempt_crashed":
        _nullable_code(payload.get("classification_code"), nullable=False)
        exception_type = payload.get("exception_type")
        if not isinstance(exception_type, str) or not 1 <= len(exception_type) <= 100:
            raise _reject("v02_event_schema", "Crash exception type is invalid.")
        if payload.get("cost_complete") is not False:
            raise _reject("v02_event_schema", "Crash events cannot claim complete cost.")
        if payload.get("recovery_status") != "manual_reconciliation_required_no_new_provider_call":
            raise _reject("v02_event_schema", "Crash recovery status is not fail-closed.")


def _validate_attempt_started_payload(payload: Mapping[str, Any]) -> None:
    for name in (
        "preregistration_sha256",
        "cohort_sha256",
        "runner_input_sha256",
    ):
        _digest(payload.get(name), name)
    reservation = _positive_int(payload.get("reserved_worst_case_microusd"), "attempt reservation")
    case = payload.get("case")
    if not isinstance(case, Mapping) or set(case) != {
        "id",
        "repo",
        "issue_url",
        "base_sha",
        "difficulty",
        "smoke",
        "generator_projection_sha256",
        "evaluator_commitment_sha256",
        "source_context_sha256",
    }:
        raise _reject("v02_event_schema", "Attempt case freeze fields are not exact.")
    if not isinstance(case.get("id"), str) or _CASE_ID.fullmatch(cast(str, case["id"])) is None:
        raise _reject("v02_event_identity", "Attempt case ID is invalid.")
    if not isinstance(case.get("repo"), str) or not isinstance(case.get("issue_url"), str):
        raise _reject("v02_event_identity", "Attempt repository identity is invalid.")
    if (
        not isinstance(case.get("base_sha"), str)
        or _GIT_SHA.fullmatch(cast(str, case["base_sha"])) is None
    ):
        raise _reject("v02_event_identity", "Attempt base SHA is invalid.")
    for name in (
        "generator_projection_sha256",
        "evaluator_commitment_sha256",
        "source_context_sha256",
    ):
        _digest(case.get(name), name)
    if case.get("difficulty") not in {"lt_15m", "15m_to_1h"} or not isinstance(
        case.get("smoke"), bool
    ):
        raise _reject("v02_event_identity", "Attempt case strata are invalid.")

    source_context = payload.get("source_context")
    if not isinstance(source_context, Mapping) or set(source_context) != {
        "algorithm",
        "policy_sha256",
        "sha256",
    }:
        raise _reject("v02_event_schema", "Attempt source-context fields are not exact.")
    _identifier(source_context.get("algorithm"), "source-context algorithm")
    _digest(source_context.get("policy_sha256"), "source-context policy")
    _digest(source_context.get("sha256"), "source-context hash")
    if source_context.get("sha256") != case.get("source_context_sha256"):
        raise _reject("v02_event_identity", "Attempt source context differs from case freeze.")

    configuration = payload.get("configuration")
    if not isinstance(configuration, Mapping) or set(configuration) != {
        "algorithm",
        "campaign_freeze_sha256",
        "execution_authorization",
        "tool_git_sha",
        "authorization",
        "generator",
        "pricing_snapshot",
        "pricing_snapshot_sha256",
        "run_provenance",
        "reserved_worst_case_microusd",
        "max_case_attributable_microusd",
        "max_campaign_attributable_microusd",
        "max_case_wall_ms",
        "provider_timeout_ms",
    }:
        raise _reject("v02_event_schema", "Attempt configuration fields are not exact.")
    if configuration.get("algorithm") != RUNNER_ALGORITHM:
        raise _reject("v02_event_version", "Attempt runner algorithm is invalid.")
    _digest(configuration.get("campaign_freeze_sha256"), "campaign freeze")
    execution_authorization = configuration.get("execution_authorization")
    if not isinstance(execution_authorization, Mapping) or set(execution_authorization) != {
        "sha256",
        "kind",
        "authorized_at",
        "authorization_ref_sha256",
        "authorization_text_sha256",
        "request_set_sha256",
    }:
        raise _reject("v02_event_schema", "Execution-authorization freeze fields are not exact.")
    if execution_authorization.get("kind") != "explicit_user_approval":
        raise _reject("v02_spend_not_authorized", "Attempt lacks explicit execution authorization.")
    for name in (
        "sha256",
        "authorization_ref_sha256",
        "authorization_text_sha256",
        "request_set_sha256",
    ):
        _digest(execution_authorization.get(name), name)
    authorized_at = _timestamp(
        execution_authorization.get("authorized_at"), "execution authorized_at"
    )
    if datetime.fromisoformat(authorized_at[:-1] + "+00:00") > datetime.fromisoformat(
        cast(str, payload["started_at"])[:-1] + "+00:00"
    ):
        raise _reject(
            "v02_execution_authorization", "Attempt predates its execution authorization."
        )
    if (
        not isinstance(configuration.get("tool_git_sha"), str)
        or _GIT_SHA.fullmatch(cast(str, configuration["tool_git_sha"])) is None
    ):
        raise _reject("v02_event_identity", "Attempt tool Git SHA is invalid.")
    if configuration.get("reserved_worst_case_microusd") != reservation:
        raise _reject("v02_campaign_freeze", "Attempt reservation fields disagree.")
    for name in (
        "max_case_attributable_microusd",
        "max_campaign_attributable_microusd",
        "max_case_wall_ms",
        "provider_timeout_ms",
    ):
        _positive_int(configuration.get(name), name)
    _digest(configuration.get("pricing_snapshot_sha256"), "pricing snapshot")
    pricing_record = configuration.get("pricing_snapshot")
    if not isinstance(pricing_record, Mapping):
        raise _reject("v02_event_schema", "Attempt pricing snapshot is missing.")
    pricing = _pricing_from_record(pricing_record)
    if (
        dict(pricing_record) != pricing.record()
        or configuration.get("pricing_snapshot_sha256") != pricing.sha256
    ):
        raise _reject("v02_pricing", "Attempt pricing record and digest disagree.")
    authorization = configuration.get("authorization")
    if not isinstance(authorization, Mapping) or set(authorization) != {
        "status",
        "authorization_ref",
    }:
        raise _reject("v02_event_schema", "Spend authorization fields are not exact.")
    if authorization.get("status") != "explicit_user_approval" or not isinstance(
        authorization.get("authorization_ref"), str
    ):
        raise _reject("v02_spend_not_authorized", "Attempt lacks explicit paid authorization.")
    generator = configuration.get("generator")
    if not isinstance(generator, Mapping) or set(generator) != {
        "mode",
        "provider",
        "requested_model",
        "adapter_config_sha256",
        "feedback_policy",
        "submitted_candidate_budget",
    }:
        raise _reject("v02_event_schema", "Generator freeze fields are not exact.")
    if (
        generator.get("mode") != "trusted_builtin_provider_adapter"
        or generator.get("provider") != "openai"
        or generator.get("feedback_policy") != "none_one_shot"
        or generator.get("submitted_candidate_budget") != 1
    ):
        raise _reject("v02_generator", "Attempt generator freeze is not one-shot built-in mode.")
    _bounded_model(generator.get("requested_model"))
    _digest(generator.get("adapter_config_sha256"), "adapter configuration")
    if (
        generator.get("provider") != pricing.provider
        or generator.get("requested_model") != pricing.requested_model
    ):
        raise _reject("v02_pricing", "Attempt provider and pricing identities differ.")
    reference_sha256 = hashlib.sha256(
        cast(str, authorization["authorization_ref"]).encode("utf-8")
    ).hexdigest()
    if execution_authorization.get("authorization_ref_sha256") != reference_sha256:
        raise _reject(
            "v02_execution_authorization", "Attempt authorization reference hash differs."
        )
    provenance = configuration.get("run_provenance")
    expected_provenance = {
        "execution_authorization_sha256": execution_authorization["sha256"],
        "authorized_at": execution_authorization["authorized_at"],
        "authorization_ref_sha256": execution_authorization["authorization_ref_sha256"],
        "authorization_text_sha256": execution_authorization["authorization_text_sha256"],
        "request_set_sha256": execution_authorization["request_set_sha256"],
        "provider": generator["provider"],
        "requested_model": generator["requested_model"],
        "adapter_config_sha256": generator["adapter_config_sha256"],
        "pricing_snapshot_sha256": configuration["pricing_snapshot_sha256"],
        "pricing_effective_at": pricing.effective_at,
        "pricing_source": pricing.source,
    }
    if provenance != expected_provenance:
        raise _reject(
            "v02_execution_authorization", "Safe run provenance differs from its exact inputs."
        )


def _validate_transitions(events: list[dict[str, Any]]) -> None:
    attempts: dict[str, _AttemptState] = {}
    campaign_id: str | None = None
    campaign_config: str | None = None
    case_attempt: dict[str, str] = {}
    generation_barrier_frozen = False
    for event in events:
        event_campaign = cast(str, event["campaign_id"])
        if campaign_id is None:
            campaign_id = event_campaign
        elif event_campaign != campaign_id:
            raise _reject("v02_campaign_freeze", "One ledger cannot mix campaigns.")
        attempt_id = cast(str, event["attempt_id"])
        case_id = cast(str, event["case_id"])
        event_type = cast(str, event["event_type"])
        payload = cast(dict[str, Any], event["payload"])
        state = attempts.get(attempt_id)
        if event_type == "attempt_started":
            if generation_barrier_frozen:
                raise _reject(
                    "v02_generation_barrier", "Attempt cannot start after the generation barrier."
                )
            if state is not None or case_id in case_attempt:
                raise _reject("v02_attempt_transition", "A case already has a scored attempt.")
            configuration = cast(Mapping[str, Any], payload["configuration"])
            generator = cast(Mapping[str, Any], configuration["generator"])
            execution_authorization = cast(
                Mapping[str, Any], configuration["execution_authorization"]
            )
            configuration_sha256 = _sha256_json(configuration)
            if campaign_config is None:
                campaign_config = configuration_sha256
            elif configuration_sha256 != campaign_config:
                raise _reject("v02_campaign_freeze", "Campaign configuration changed.")
            state = _AttemptState(
                case_id=case_id,
                campaign_id=event_campaign,
                reservation=cast(int, payload["reserved_worst_case_microusd"]),
                configuration_sha256=configuration_sha256,
                execution_authorization_sha256=cast(str, execution_authorization["sha256"]),
                preregistration_sha256=cast(str, payload["preregistration_sha256"]),
                cohort_sha256=cast(str, payload["cohort_sha256"]),
                source_context_sha256=cast(
                    str, cast(Mapping[str, object], payload["source_context"])["sha256"]
                ),
                runner_input_sha256=cast(str, payload["runner_input_sha256"]),
                provider=cast(str, generator["provider"]),
                requested_model=cast(str, generator["requested_model"]),
                adapter_config_sha256=cast(str, generator["adapter_config_sha256"]),
                pricing_snapshot_sha256=cast(str, configuration["pricing_snapshot_sha256"]),
                request_set_sha256=cast(str, execution_authorization["request_set_sha256"]),
                run_provenance_sha256=_sha256_json(configuration["run_provenance"]),
            )
            attempts[attempt_id] = state
            case_attempt[case_id] = attempt_id
            continue
        if state is None:
            raise _reject("v02_attempt_transition", "Attempt event precedes attempt_started.")
        if event_type == "campaign_generation_barrier_frozen":
            if generation_barrier_frozen or len(attempts) != 20:
                raise _reject(
                    "v02_generation_barrier", "Generation barrier is duplicate or incomplete."
                )
            if any(item.generation_disposition_status is None for item in attempts.values()):
                raise _reject(
                    "v02_generation_barrier", "Generation barrier precedes a case disposition."
                )
            records = [
                {
                    "case_id": item.case_id,
                    "attempt_id": item_id,
                    "event_sha256": item.generation_disposition_event_sha256,
                    "status": item.generation_disposition_status,
                    "candidate_sha256": item.candidate_sha256,
                }
                for item_id, item in attempts.items()
            ]
            records.sort(key=lambda record: cast(str, record["case_id"]))
            preregistrations = {item.preregistration_sha256 for item in attempts.values()}
            cohorts = {item.cohort_sha256 for item in attempts.values()}
            execution_authorizations = {
                item.execution_authorization_sha256 for item in attempts.values()
            }
            request_sets = {item.request_set_sha256 for item in attempts.values()}
            pricings = {item.pricing_snapshot_sha256 for item in attempts.values()}
            provenance_records = {item.run_provenance_sha256 for item in attempts.values()}
            if (
                len(preregistrations) != 1
                or len(cohorts) != 1
                or len(execution_authorizations) != 1
                or len(request_sets) != 1
                or len(pricings) != 1
                or len(provenance_records) != 1
                or campaign_config is None
            ):
                raise _reject(
                    "v02_generation_barrier", "Campaign freeze identities are inconsistent."
                )
            disposition_set_sha256 = _sha256_json(
                {
                    "algorithm": GENERATION_DISPOSITION_ALGORITHM,
                    "campaign_id": event_campaign,
                    "preregistration_sha256": next(iter(preregistrations)),
                    "cohort_sha256": next(iter(cohorts)),
                    "dispositions": records,
                }
            )
            barrier_sha256 = _sha256_json(
                {
                    "algorithm": GENERATION_BARRIER_ALGORITHM,
                    "campaign_id": event_campaign,
                    "preregistration_sha256": next(iter(preregistrations)),
                    "cohort_sha256": next(iter(cohorts)),
                    "disposition_count": len(records),
                    "disposition_set_sha256": disposition_set_sha256,
                    "configuration_sha256": campaign_config,
                    "execution_authorization_sha256": next(iter(execution_authorizations)),
                    "request_set_sha256": next(iter(request_sets)),
                    "pricing_snapshot_sha256": next(iter(pricings)),
                    "run_provenance_sha256": next(iter(provenance_records)),
                }
            )
            anchor_attempt_id, anchor_state = max(
                attempts.items(),
                key=lambda item: cast(int, item[1].generation_disposition_sequence),
            )
            if (
                attempt_id != anchor_attempt_id
                or case_id != anchor_state.case_id
                or payload["barrier_algorithm"] != GENERATION_BARRIER_ALGORITHM
                or payload["configuration_sha256"] != campaign_config
                or payload["execution_authorization_sha256"] != next(iter(execution_authorizations))
                or payload["request_set_sha256"] != next(iter(request_sets))
                or payload["pricing_snapshot_sha256"] != next(iter(pricings))
                or payload["run_provenance_sha256"] != next(iter(provenance_records))
                or payload["disposition_set_sha256"] != disposition_set_sha256
                or payload["generation_barrier_sha256"] != barrier_sha256
                or payload["disposition_count"] != len(records)
            ):
                raise _reject(
                    "v02_generation_barrier", "Generation barrier does not match dispositions."
                )
            generation_barrier_frozen = True
            continue
        if event_type == "recovery_started":
            if state.recovery_started or state.model_call_id is None:
                raise _reject(
                    "v02_recovery_transition", "Recovery is duplicate or lacks its original call."
                )
            if state.terminal and not state.crashed:
                raise _reject("v02_recovery_transition", "Only a crashed attempt may be reopened.")
            if state.active_phase != "generation" and "generation" not in state.completed_phases:
                raise _reject(
                    "v02_recovery_transition", "Recovery requires an interrupted generation phase."
                )
            if (
                payload["execution_authorization_sha256"] != state.execution_authorization_sha256
                or payload["preregistration_sha256"] != state.preregistration_sha256
                or payload["configuration_sha256"] != state.configuration_sha256
                or payload["source_context_sha256"] != state.source_context_sha256
                or payload["runner_input_sha256"] != state.runner_input_sha256
                or payload["generation_call_id"] != state.model_call_id
            ):
                raise _reject(
                    "v02_recovery_transition", "Recovery differs from the attempt freeze."
                )
            state.recovery_started = True
            state.crashed = False
            state.terminal = False
            continue
        if state.terminal:
            raise _reject("v02_attempt_transition", "Event follows a terminal attempt event.")
        if event_type == "phase_started":
            phase = cast(str, payload["phase"])
            if state.active_phase is not None or phase in state.phase_starts:
                raise _reject("v02_phase_transition", "Phase start is duplicate or overlapping.")
            if phase == "generation" and state.completed_phases:
                raise _reject("v02_phase_transition", "Generation must be the first phase.")
            if phase == "differential" and not state.candidate_submitted:
                raise _reject("v02_phase_transition", "Differential requires the frozen candidate.")
            if phase == "differential" and not generation_barrier_frozen:
                raise _reject(
                    "v02_generation_barrier", "Differential requires the durable campaign barrier."
                )
            if phase == "result_write" and not set(_COST_CATEGORIES) <= set(state.costs):
                raise _reject("v02_phase_transition", "Results require all cost categories.")
            state.active_phase = phase
            state.phase_starts[phase] = cast(str, payload["started_at"])
        elif event_type == "phase_finished":
            phase = cast(str, payload["phase"])
            if (
                state.active_phase != phase
                or state.phase_starts.get(phase) != payload["started_at"]
            ):
                raise _reject("v02_phase_transition", "Phase finish has no exact open start.")
            if (
                phase == "generation"
                and payload["status"] == "succeeded"
                and (not state.model_finished or not state.candidate_submitted)
            ):
                raise _reject(
                    "v02_phase_transition",
                    "Successful generation requires model terminal, cost, and candidate commit.",
                )
            state.active_phase = None
            state.completed_phases.add(phase)
        elif event_type == "model_call_started":
            if state.active_phase != "generation" or state.model_call_id is not None:
                raise _reject("v02_model_transition", "Model start is outside one-shot generation.")
            if (
                payload["execution_authorization_sha256"] != state.execution_authorization_sha256
                or payload["provider"] != state.provider
                or payload["requested_model"] != state.requested_model
                or payload["config_sha256"] != state.adapter_config_sha256
                or payload["pricing_snapshot_sha256"] != state.pricing_snapshot_sha256
                or payload["runner_input_sha256"] != state.runner_input_sha256
                or payload["reserved_worst_case_microusd"] != state.reservation
            ):
                raise _reject("v02_campaign_freeze", "Model call differs from attempt freeze.")
            state.model_call_id = cast(str, payload["call_id"])
        elif event_type == "model_call_finished":
            if (
                state.active_phase != "generation"
                or state.model_call_id != payload["call_id"]
                or state.model_finished
            ):
                raise _reject("v02_model_transition", "Model finish has no exact unmatched start.")
            if payload["status"] == "succeeded" and not state.candidate_submitted:
                raise _reject(
                    "v02_model_transition", "Successful model finish precedes candidate commit."
                )
            state.model_finished = True
        elif event_type == "cost_recorded":
            category = cast(str, payload["category"])
            if category in state.costs:
                raise _reject("v02_cost_transition", "Cost category is already recorded.")
            if category == "model_inference" and (
                payload["source_call_id"] != state.model_call_id
                or (
                    not state.model_finished
                    and not (
                        (
                            state.model_call_id is None
                            and payload["status"] == "zero_verified"
                            and payload["amount_microusd"] == 0
                        )
                        or (
                            state.model_call_id is not None
                            and payload["status"] == "unknown"
                            and payload["amount_microusd"] is None
                        )
                    )
                )
            ):
                raise _reject(
                    "v02_cost_transition",
                    "Model cost lacks its exact terminal call or fail-closed unknown binding.",
                )
            state.costs[category] = cast(int | None, payload["amount_microusd"])
        elif event_type == "candidate_submitted":
            if (
                state.active_phase != "generation"
                or state.model_call_id is None
                or state.model_finished
                or state.candidate_submitted
                or payload["generation_call_id"] != state.model_call_id
            ):
                raise _reject("v02_candidate_transition", "Candidate commit is not one-shot.")
            state.candidate_submitted = True
            state.candidate_sha256 = cast(str, payload["candidate_sha256"])
        elif event_type == "generation_disposition_frozen":
            if generation_barrier_frozen or state.generation_disposition_status is not None:
                raise _reject(
                    "v02_generation_disposition", "Generation disposition is late or duplicate."
                )
            if (
                state.active_phase is not None
                or "generation" not in state.completed_phases
                or set(state.costs) != {"dependency_prep", "model_inference", "artifact_transfer"}
                or state.costs["model_inference"] is None
                or state.costs["artifact_transfer"] is None
            ):
                raise _reject(
                    "v02_generation_disposition", "Generation is not durably cost-complete."
                )
            disposition_status = cast(str, payload["status"])
            disposition_candidate = cast(str | None, payload["candidate_sha256"])
            disposition_code = cast(str | None, payload["classification_code"])
            if disposition_status == "candidate_submitted":
                if (
                    not state.candidate_submitted
                    or disposition_candidate != state.candidate_sha256
                    or disposition_code is not None
                ):
                    raise _reject(
                        "v02_generation_disposition", "Candidate disposition is not cross-bound."
                    )
            elif (
                disposition_status != "no_candidate"
                or state.candidate_submitted
                or disposition_candidate is not None
                or disposition_code is None
            ):
                raise _reject(
                    "v02_generation_disposition", "No-candidate disposition is not cross-bound."
                )
            state.generation_disposition_status = disposition_status
            state.generation_classification_code = disposition_code
            state.generation_disposition_event_sha256 = cast(str, event["event_sha256"])
            state.generation_disposition_sequence = cast(int, event["sequence"])
        elif event_type == "attempt_finished":
            if state.active_phase is not None or "result_write" not in state.completed_phases:
                raise _reject("v02_attempt_transition", "Attempt finished before durable results.")
            if set(state.costs) != set(_COST_CATEGORIES):
                raise _reject("v02_cost_transition", "Attempt lacks an exact cost category set.")
            known = all(value is not None for value in state.costs.values())
            total = (
                sum(cast(int, state.costs[name]) for name in _ATTRIBUTABLE_COST_CATEGORIES)
                if known
                else None
            )
            if payload["cost_complete"] != known or payload["total_attributable_microusd"] != total:
                raise _reject("v02_cost_transition", "Attempt cost total does not reconcile.")
            state.terminal = True
        elif event_type == "attempt_crashed":
            state.crashed = True
            state.terminal = True


def _preflight_attempt(snapshot: V02LedgerSnapshot, run: _RunContext) -> None:
    known_spend = 0
    active_reservations = 0
    attempts: dict[str, dict[str, object]] = {}
    for event in snapshot.events:
        attempt_id = cast(str, event["attempt_id"])
        event_type = cast(str, event["event_type"])
        payload = cast(Mapping[str, object], event["payload"])
        state = attempts.setdefault(attempt_id, {"costs": {}, "terminal": False, "reserve": 0})
        if event_type == "attempt_started":
            state["reserve"] = cast(int, payload["reserved_worst_case_microusd"])
        elif event_type == "cost_recorded":
            costs = cast(dict[str, int | None], state["costs"])
            costs[cast(str, payload["category"])] = cast(int | None, payload["amount_microusd"])
        elif event_type in {"attempt_finished", "attempt_crashed"}:
            state["terminal"] = True
        elif event_type == "recovery_started":
            state["terminal"] = False
    for state in attempts.values():
        if state["terminal"]:
            costs = cast(dict[str, int | None], state["costs"])
            if set(costs) != set(_COST_CATEGORIES) or any(
                costs.get(name) is None for name in _ATTRIBUTABLE_COST_CATEGORIES
            ):
                raise _reject("v02_spend_unknown", "A prior attempt has unknown attributable cost.")
            known_spend += sum(
                cast(int, costs.get(name, 0)) for name in _ATTRIBUTABLE_COST_CATEGORIES
            )
        else:
            active_reservations += cast(int, state["reserve"])
    if (
        known_spend + active_reservations + run.policy.reserved_worst_case_microusd
        > run.policy.max_campaign_attributable_microusd
    ):
        raise _reject("v02_spend_cap", "Campaign known spend plus reservations exceeds its cap.")


def _preflight_model_call(snapshot: V02LedgerSnapshot, run: _RunContext) -> None:
    for event in snapshot.events:
        if event["event_type"] != "model_call_started":
            continue
        call_id = cast(Mapping[str, object], event["payload"])["call_id"]
        if not any(
            later["event_type"] == "model_call_finished"
            and cast(Mapping[str, object], later["payload"])["call_id"] == call_id
            for later in snapshot.events
        ):
            raise _reject("v02_spend_unknown", "A campaign model call remains unmatched.")
    starts = [
        event
        for event in snapshot.events
        if event["attempt_id"] == run.attempt_id and event["event_type"] == "attempt_started"
    ]
    if len(starts) != 1:
        raise _reject("v02_model_transition", "Model start requires one durable attempt start.")


def _record_model_cost(run: _RunContext, *, call_id: str, usage: Mapping[str, object]) -> None:
    projection = _model_cost_projection(run, usage)
    if projection["source_call_id"] != call_id:
        raise _reject("v02_model_transition", "Model cost call differs from the one-shot call.")
    pricing = _require_pricing(run.policy)
    _record_cost(
        run,
        category="model_inference",
        attribution="scored",
        status=cast(str, projection["status"]),
        amount=cast(int | None, projection["amount_microusd"]),
        source_call_id=call_id,
        evidence={
            "usage": _validated_usage(usage),
            "pricing_snapshot_sha256": pricing.sha256,
        },
    )


def _record_cost(
    run: _RunContext,
    *,
    category: str,
    attribution: str,
    status: str,
    amount: int | None,
    source_call_id: str | None,
    evidence: Mapping[str, object],
) -> None:
    _append_event(
        run,
        "cost_recorded",
        {
            "entry_id": f"cost_{uuid.uuid4().hex}",
            "category": category,
            "attribution": attribution,
            "status": status,
            "amount_microusd": amount,
            "source_call_id": source_call_id,
            "observed_at": _now(),
            "evidence_sha256": _sha256_json(evidence),
        },
    )


def _fill_missing_costs(run: _RunContext, *, candidate: ValidatedCandidate | None) -> None:
    snapshot = read_v02_scored_ledger(run.ledger_path)
    events = [event for event in snapshot.events if event["attempt_id"] == run.attempt_id]
    existing = {
        cast(str, cast(Mapping[str, object], event["payload"])["category"])
        for event in events
        if event["event_type"] == "cost_recorded"
    }
    starts = [event for event in events if event["event_type"] == "model_call_started"]
    if "model_inference" not in existing:
        if starts:
            call_id = cast(str, cast(Mapping[str, object], starts[-1]["payload"])["call_id"])
            # Never silently turn an unmatched transmitted call into zero spend.
            _record_cost(
                run,
                category="model_inference",
                attribution="scored",
                status="unknown",
                amount=None,
                source_call_id=call_id,
                evidence={"reason": "missing_terminal_or_cost"},
            )
        else:
            _record_cost(
                run,
                category="model_inference",
                attribution="scored",
                status="zero_verified",
                amount=0,
                source_call_id=None,
                evidence={"reason": "provider_not_invoked"},
            )
    pricing = _require_pricing(run.policy)
    if "artifact_transfer" not in existing:
        amount = _artifact_cost(pricing, candidate) if candidate is not None else 0
        _record_cost(
            run,
            category="artifact_transfer",
            attribution="scored",
            status="measured" if amount else "zero_verified",
            amount=amount,
            source_call_id=None,
            evidence={"candidate_present": candidate is not None},
        )
    if "sandbox_compute" not in existing:
        _record_cost(
            run,
            category="sandbox_compute",
            attribution="scored",
            status="zero_verified",
            amount=0,
            source_call_id=None,
            evidence={"reason": "differential_not_completed"},
        )
    if "paid_storage" not in existing:
        _record_cost(
            run,
            category="paid_storage",
            attribution="scored",
            status="measured" if pricing.paid_storage_microusd else "zero_verified",
            amount=pricing.paid_storage_microusd,
            source_call_id=None,
            evidence={"storage_policy": "private_local_attempt_artifacts"},
        )
    if "dependency_prep" not in existing:
        _record_cost(
            run,
            category="dependency_prep",
            attribution="cold_prep_excluded",
            status="measured" if pricing.dependency_prep_microusd else "zero_verified",
            amount=pricing.dependency_prep_microusd,
            source_call_id=None,
            evidence={"reason": "predeclared_cold_prep"},
        )


def _attempt_costs(snapshot: V02LedgerSnapshot, attempt_id: str) -> dict[str, int | None]:
    return {
        cast(str, payload["category"]): cast(int | None, payload["amount_microusd"])
        for event in snapshot.events
        if event["attempt_id"] == attempt_id and event["event_type"] == "cost_recorded"
        for payload in [cast(Mapping[str, object], event["payload"])]
    }


def _assert_known_model_cost(run: _RunContext) -> None:
    costs = _attempt_costs(read_v02_scored_ledger(run.ledger_path), run.attempt_id)
    if costs.get("model_inference") is None:
        raise _ControlledFailure("benchmark_infrastructure_error", "v02_model_cost_unknown")


def _assert_total_within_reservation(run: _RunContext) -> None:
    costs = _attempt_costs(read_v02_scored_ledger(run.ledger_path), run.attempt_id)
    known = [costs.get(name) for name in _ATTRIBUTABLE_COST_CATEGORIES if name in costs]
    if any(value is None for value in known):
        raise _ControlledFailure("benchmark_infrastructure_error", "v02_cost_unknown")
    total = sum(cast(int, value) for value in known)
    if total > run.policy.reserved_worst_case_microusd:
        raise _ControlledFailure("policy_violation", "v02_spend_reservation_exceeded")


def _start_phase(run: _RunContext, phase: str) -> str:
    _check_wall_budget(run)
    started_at = _now()
    _append_event(run, "phase_started", {"phase": phase, "started_at": started_at})
    return started_at


def _finish_phase(
    run: _RunContext,
    *,
    phase: str,
    started_at: str,
    started_monotonic: float,
    status: str,
    classification_code: str | None,
    evidence: Mapping[str, object],
) -> None:
    _append_event(
        run,
        "phase_finished",
        {
            "phase": phase,
            "status": status,
            "started_at": started_at,
            "completed_at": _now(),
            "duration_ms": max(0, round((time.monotonic() - started_monotonic) * 1_000)),
            "classification_code": classification_code,
            "evidence": dict(evidence),
        },
    )


def _finish_open_phase(run: _RunContext, *, status: str, classification_code: str) -> None:
    snapshot = read_v02_scored_ledger(run.ledger_path)
    events = [event for event in snapshot.events if event["attempt_id"] == run.attempt_id]
    open_phase: tuple[str, str] | None = None
    for event in events:
        payload = cast(Mapping[str, object], event["payload"])
        if event["event_type"] == "phase_started":
            open_phase = (cast(str, payload["phase"]), cast(str, payload["started_at"]))
        elif event["event_type"] == "phase_finished":
            open_phase = None
    if open_phase is not None:
        phase, started_at = open_phase
        _append_event(
            run,
            "phase_finished",
            {
                "phase": phase,
                "status": status,
                "started_at": started_at,
                "completed_at": _now(),
                "duration_ms": 0,
                "classification_code": classification_code,
                "evidence": {},
            },
        )


def _append_crash(run: _RunContext, exc: BaseException) -> None:
    try:
        _append_event(
            run,
            "attempt_crashed",
            {
                "crashed_at": _now(),
                "classification_code": "v02_runner_crash",
                "exception_type": type(exc).__name__[:100] or "BaseException",
                "cost_complete": False,
                "recovery_status": "manual_reconciliation_required_no_new_provider_call",
            },
        )
    except Exception:
        # The original exception remains authoritative if the ledger itself is unavailable.
        return


def _check_wall_budget(run: _RunContext) -> None:
    if _remaining_wall_seconds(run) <= 0:
        raise _ControlledFailure("benchmark_infrastructure_error", "v02_case_wall_cap")


def _remaining_wall_seconds(run: _RunContext) -> float:
    snapshot = read_v02_scored_ledger(run.ledger_path)
    starts = [
        cast(str, cast(Mapping[str, object], event["payload"])["started_at"])
        for event in snapshot.events
        if event["attempt_id"] == run.attempt_id and event["event_type"] == "attempt_started"
    ]
    if len(starts) != 1:
        raise _reject("v02_time_cap", "Attempt wall-clock origin is missing or ambiguous.")
    origin = datetime.fromisoformat(starts[0][:-1] + "+00:00")
    elapsed = (datetime.now(timezone.utc) - origin).total_seconds()
    return max(0.0, run.policy.max_case_wall_ms / 1_000 - elapsed)


def _persist_generation_transaction(
    run: _RunContext,
    *,
    call_id: str,
    candidate: ValidatedCandidate,
    model_finish: Mapping[str, object],
) -> tuple[Path, str, int]:
    transaction = {
        "schema_version": SCHEMA_VERSION,
        "benchmark_version": BENCHMARK_VERSION,
        "algorithm": "reproassert-v02-generation-transaction-v1",
        "campaign_id": run.policy.campaign_id,
        "attempt_id": run.attempt_id,
        "case_id": run.case.id,
        "preregistration_sha256": run.preregistration_sha256,
        "configuration_sha256": run.policy.configuration_sha256,
        "source_context_sha256": run.source_context.context_sha256,
        "runner_input_sha256": run.runner_input_sha256,
        "call_id": call_id,
        "candidate": {
            "test_content": candidate.test_content,
            "expected_symptom": candidate.expected_symptom,
            "rationale": candidate.rationale,
            "sha256": candidate.sha256,
            "bytes": len(candidate.test_content.encode("utf-8")),
        },
        "model_finish": dict(model_finish),
    }
    encoded = _bounded_result_bytes(transaction)
    path = run.attempt_directory / "generation-transaction.json"
    _write_exclusive_fsync(path, encoded)
    return path, hashlib.sha256(encoded).hexdigest(), len(encoded)


def _revalidate_candidate_file(path: Path, expected: ValidatedCandidate) -> None:
    with open_regular_file(path) as stream:
        encoded = stream.read(MAX_RESULT_BYTES + 1)
    if len(encoded) > MAX_RESULT_BYTES:
        raise _reject("v02_candidate_artifact", "Generation transaction exceeds its limit.")
    try:
        decoded = json.loads(
            encoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject("v02_candidate_artifact", "Generation transaction is invalid.") from exc
    if not isinstance(decoded, Mapping) or _canonical_json(decoded) + b"\n" != encoded:
        raise _reject("v02_candidate_artifact", "Generation transaction is not canonical.")
    value = decoded.get("candidate")
    if not isinstance(value, Mapping):
        raise _reject("v02_candidate_artifact", "Generation transaction lacks a candidate.")
    candidate = validate_candidate_payload(
        {
            "test_content": value.get("test_content"),
            "expected_symptom": value.get("expected_symptom"),
            "rationale": value.get("rationale"),
        },
        issue_number=int(expected.test_function.split("_")[2]),
    )
    if (
        candidate != expected
        or value.get("sha256") != expected.sha256
        or value.get("bytes") != len(expected.test_content.encode("utf-8"))
    ):
        raise _reject("v02_candidate_artifact", "Durable candidate bytes changed.")


def _load_projection(path: Path, case: PreregisteredV02Case) -> _Projection:
    with open_regular_file(path) as stream:
        encoded = stream.read(MAX_PROJECTION_BYTES + 1)
    if len(encoded) > MAX_PROJECTION_BYTES:
        raise _reject("v02_generator_projection", "Generator projection exceeds its limit.")
    if hashlib.sha256(encoded).hexdigest() != case.generator_projection_sha256:
        raise _reject(
            "v02_generator_projection", "Generator projection differs from preregistration."
        )
    try:
        decoded = json.loads(
            encoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject("v02_generator_projection", "Generator projection is invalid JSON.") from exc
    if not isinstance(decoded, Mapping) or _canonical_json(decoded) + b"\n" != encoded:
        raise _reject("v02_generator_projection", "Generator projection is not canonical.")
    if set(decoded) != {
        "schema_version",
        "benchmark_version",
        "case_id",
        "repo",
        "issue_url",
        "base_sha",
        "issue_snapshot",
    }:
        raise _reject("v02_generator_projection", "Generator projection fields are not exact.")
    if (
        decoded.get("schema_version") != SCHEMA_VERSION
        or decoded.get("benchmark_version") != BENCHMARK_VERSION
        or decoded.get("case_id") != case.id
        or decoded.get("repo") != case.repo
        or decoded.get("issue_url") != case.issue_url
        or decoded.get("base_sha") != case.base_sha
    ):
        raise _reject("v02_generator_projection", "Generator projection identity changed.")
    issue = decoded.get("issue_snapshot")
    if not isinstance(issue, Mapping) or set(issue) != {"title", "body", "snapshot_sha256"}:
        raise _reject("v02_generator_projection", "Issue projection fields are not exact.")
    title = issue.get("title")
    body = issue.get("body")
    if not isinstance(title, str) or not isinstance(body, str):
        raise _reject("v02_generator_projection", "Issue projection text is invalid.")
    return _Projection(title=title, body=body, sha256=hashlib.sha256(encoded).hexdigest())


def _generation_request(
    case: PreregisteredV02Case,
    projection: _Projection,
    context: VerifiedV02GeneratorSourceContext,
) -> GenerationRequest:
    issue = parse_issue_url(case.issue_url)
    suffix = case.id.rsplit("-", 1)[1]
    sympy_native = case.id in {"rk-v0.2-016", "rk-v0.2-017"}
    return GenerationRequest(
        issue_url=case.issue_url,
        issue_number=issue.number,
        issue_title=projection.title,
        issue_body=projection.body,
        source_sha=case.base_sha,
        source_context=context.source_context,
        candidate_profile=(SYMPY_NATIVE_CANDIDATE_PROFILE if sympy_native else "pytest-v1"),
        required_test_function=(f"test_reproassert_issue_{suffix}" if sympy_native else None),
        attempt=1,
        feedback="",
    )


def _validate_generator_context(
    context: VerifiedV02GeneratorSourceContext, case: PreregisteredV02Case
) -> None:
    if context.case != V02CaseIdentity(case.id, case.repo, case.issue_url, case.base_sha):
        raise _reject("v02_source_context", "Generator context case differs from preregistration.")
    if context.context_sha256 != case.source_context_sha256:
        raise _reject(
            "v02_source_context", "Generator context digest differs from preregistration."
        )


def _bind_capability(
    capability: VerifiedV02EvaluatorCapability,
    case: PreregisteredV02Case,
    context: VerifiedV02GeneratorSourceContext,
) -> None:
    if capability.case != V02CaseIdentity(case.id, case.repo, case.issue_url, case.base_sha):
        raise _reject("v02_evaluator_binding", "Evaluator capability case differs from the freeze.")
    if capability.public_commitment_sha256 != case.evaluator_commitment_sha256:
        raise _reject("v02_evaluator_binding", "Evaluator commitment differs from preregistration.")
    if (
        capability.source_context_algorithm != context.algorithm
        or capability.source_context_policy_sha256 != context.policy_sha256
        or capability.source_context_sha256 != context.context_sha256
    ):
        raise _reject("v02_evaluator_binding", "Evaluator and generator source contexts differ.")


def _find_case(cases: tuple[PreregisteredV02Case, ...], case_id: str) -> PreregisteredV02Case:
    if _CASE_ID.fullmatch(case_id) is None:
        raise _reject("v02_case", "Scored case ID is invalid.")
    matches = [case for case in cases if case.id == case_id]
    if len(matches) != 1:
        raise _reject("v02_case", "Scored case is not uniquely preregistered.")
    return matches[0]


def _required_reservation(policy: V02ScoredRunPolicy, request: GenerationRequest) -> int:
    pricing = _require_pricing(policy)
    rendered_bytes = len(_rendered_input_text(request).encode("utf-8"))
    # UTF-8 bytes are a conservative upper bound for tokenizer units in the fixed request.
    token_numerator = (
        rendered_bytes * pricing.input_microusd_per_million_tokens
        + OPENAI_MAX_OUTPUT_TOKENS * pricing.output_microusd_per_million_tokens
    )
    sandbox = math.ceil(policy.max_case_wall_ms * pricing.sandbox_microusd_per_second / 1_000)
    artifact = _ceil_per_million(MAX_TEST_BYTES * pricing.artifact_microusd_per_million_bytes)
    return _ceil_per_million(token_numerator) + sandbox + artifact + pricing.paid_storage_microusd


def _artifact_cost(pricing: V02PricingSnapshot, candidate: ValidatedCandidate) -> int:
    return _ceil_per_million(
        len(candidate.test_content.encode("utf-8")) * pricing.artifact_microusd_per_million_bytes
    )


def _sandbox_cost(pricing: V02PricingSnapshot, duration_ms: int) -> int:
    return math.ceil(duration_ms * pricing.sandbox_microusd_per_second / 1_000)


def _ceil_per_million(numerator: int) -> int:
    return (numerator + 999_999) // 1_000_000


def _require_pricing(policy: V02ScoredRunPolicy) -> V02PricingSnapshot:
    if policy.pricing is None:
        raise _reject("v02_pricing", "The scored campaign lacks a pricing snapshot.")
    return policy.pricing


def _pricing_from_record(value: Mapping[str, object]) -> V02PricingSnapshot:
    if set(value) != set(V02PricingSnapshot.__dataclass_fields__) | {"algorithm"}:
        raise _reject("v02_pricing", "Pricing snapshot fields are not exact.")
    if value.get("algorithm") != "reproassert-v02-component-pricing-v1":
        raise _reject("v02_pricing", "Pricing snapshot algorithm is invalid.")
    try:
        return V02PricingSnapshot(
            **{key: item for key, item in value.items() if key != "algorithm"}  # type: ignore[arg-type]
        )
    except TypeError as exc:
        raise _reject("v02_pricing", "Pricing snapshot field types are invalid.") from exc


def _openai_request_payload(request: GenerationRequest, model: str) -> dict[str, object]:
    return {
        "model": model,
        "store": False,
        "instructions": generator_module.openai_instructions(request),
        "input": _rendered_input_text(request),
        "max_output_tokens": OPENAI_MAX_OUTPUT_TOKENS,
        "text": {
            "format": {
                "type": "json_schema",
                "name": "reproassert_candidate",
                "strict": True,
                "schema": generator_module._OPENAI_CANDIDATE_SCHEMA,
            }
        },
    }


def _openai_adapter_config_sha256(model: object) -> str:
    bounded = _bounded_model(model)
    profiles: list[dict[str, object]] = []
    for profile, required_function in (
        ("pytest-v1", None),
        (SYMPY_NATIVE_CANDIDATE_PROFILE, "test_reproassert_issue_016"),
    ):
        payload = _openai_request_payload(
            GenerationRequest(
                issue_url="https://github.com/placeholder/repository/issues/1",
                issue_number=1,
                issue_title="placeholder",
                issue_body="placeholder",
                source_sha="0" * 40,
                source_context=SourceContext((), (), 0),
                candidate_profile=profile,
                required_test_function=required_function,
            ),
            bounded,
        )
        del payload["input"]
        profiles.append(payload)
    return _sha256_json({"profiles": profiles})


def _rendered_input_text(request: GenerationRequest) -> str:
    return json.dumps(request.to_dict(), ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _rendered_input_sha256(request: GenerationRequest) -> str:
    return hashlib.sha256(_rendered_input_text(request).encode("utf-8")).hexdigest()


def _prepare_private_directory(path: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        absolute.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError:
        raise _reject("v02_attempt_directory", "Attempt directory must be newly created.") from None
    require_private_directory(absolute)
    return absolute.resolve(strict=True)


def _require_private_parent(path: Path) -> None:
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require_private_directory(parent)


def _write_exclusive_fsync(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise _reject("v02_artifact_path", "Cannot exclusively create private artifact.") from exc
    try:
        _write_all(descriptor, content)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise _reject("v02_artifact_path", "Private artifact identity is unsafe.")
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sha256_file(path: Path, limit: int) -> str:
    with open_regular_file(path) as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise _reject("v02_artifact_limit", "Private artifact exceeds its byte limit.")
    return hashlib.sha256(content).hexdigest()


def _bounded_result_bytes(value: Mapping[str, object]) -> bytes:
    encoded = _canonical_json(value) + b"\n"
    if len(encoded) > MAX_RESULT_BYTES:
        raise _reject("v02_result_limit", "Canonical v0.2 result exceeds 2 MiB.")
    return encoded


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise _reject("v02_json", "Value is not bounded canonical JSON data.") from exc


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _event_sha256(event: dict[str, Any]) -> str:
    unsigned = dict(event)
    unsigned.pop("event_sha256", None)
    return _sha256_json(unsigned)


def _read_bounded_fd(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    content = b"".join(chunks)
    if len(content) > limit:
        raise _reject("v02_ledger_limit", "The v0.2 scored ledger exceeds its byte limit.")
    return content


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise _reject("v02_io", "Private durable write made no progress.")
        offset += written


def _validated_usage(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {
        "status",
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "total_tokens",
    }:
        raise _reject("v02_model_usage", "Model usage fields are not exact.")
    status = value.get("status")
    counts = {
        name: value.get(name)
        for name in ("input_tokens", "cached_input_tokens", "output_tokens", "total_tokens")
    }
    if status == "reported":
        for name, count in counts.items():
            _nonnegative_int(count, name)
        if counts["total_tokens"] != cast(int, counts["input_tokens"]) + cast(
            int, counts["output_tokens"]
        ):
            raise _reject("v02_model_usage", "Model token total does not reconcile.")
    elif status == "unknown":
        if any(count is not None for count in counts.values()):
            raise _reject("v02_model_usage", "Unknown usage cannot carry token counts.")
    else:
        raise _reject("v02_model_usage", "Only reported or unknown scored usage is allowed.")
    return {"status": status, **counts}


def _claim_level_value(value: object) -> str:
    candidate = getattr(value, "value", value)
    if candidate not in {
        "rejected",
        "collected",
        "repeatable_base_failure",
        "differential_reproduction",
    }:
        raise _reject("v02_claim", "Mechanical differential claim level is invalid.")
    return candidate


def _single_model_call_id(run: _RunContext) -> str:
    snapshot = read_v02_scored_ledger(run.ledger_path)
    calls = [
        cast(str, cast(Mapping[str, object], event["payload"])["call_id"])
        for event in snapshot.events
        if event["attempt_id"] == run.attempt_id and event["event_type"] == "model_call_started"
    ]
    if len(calls) != 1:
        raise _reject("v02_model_transition", "Attempt does not have exactly one model call.")
    return calls[0]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _timestamp(value: object, name: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject("v02_timestamp", f"{name} must be an RFC 3339 UTC timestamp.")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _reject("v02_timestamp", f"{name} is not a real timestamp.") from exc
    return value


def _identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise _reject("v02_identifier", f"{name} is invalid.")
    return value


def _bounded_model(value: object) -> str:
    if not isinstance(value, str) or _MODEL.fullmatch(value) is None:
        raise _reject("v02_model", "Model identifier is invalid.")
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _reject("v02_digest", f"{name} is invalid.")
    return value


def _nullable_digest(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _digest(value, name)


def _positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise _reject("v02_integer", f"{name} must be a positive integer.")
    return value


def _nonnegative_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _reject("v02_integer", f"{name} must be a nonnegative integer.")
    return value


def _nullable_code(value: object, *, nullable: bool = True) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,99}", value) is None:
        raise _reject("v02_code", "Classification code is invalid.")
    return value


def _safe_code(value: object) -> str:
    if isinstance(value, str) and re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,99}", value):
        return value
    return "v02_failure"


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"invalid JSON constant: {value}")


def _reject(code: str, message: str) -> PolicyRejection:
    return PolicyRejection(code, message)
