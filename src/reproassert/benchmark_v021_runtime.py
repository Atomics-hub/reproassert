"""Fail-closed v0.2.1 generation runtime with durable one-shot recovery."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, cast

from reproassert.benchmark_v021_authorization import (
    VerifiedV021ExecutionAuthorization,
    require_v021_execution_authorization,
)
from reproassert.benchmark_v021_preregistration_authority import (
    require_v021_execution_preregistration,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

PLAN_ALGORITHM = "reproassert-v021-runtime-plan-v1"
RESPONSE_ALGORITHM = "reproassert-v021-durable-provider-response-v1"
RESULT_ALGORITHM = "reproassert-v021-generation-result-v1"
SCHEMA_VERSION = "1.0.0"
CASE_COUNT = 20
REQUEST_SET_ALGORITHM = "reproassert-v021-provider-request-envelope-set-v1"
MAX_PLAN_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RESULT_BYTES = 2 * 1024 * 1024
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PLAN_ISSUER = object()
_RESULT_ISSUER = object()


ExecutionAuthorization = VerifiedV021ExecutionAuthorization


@dataclass(frozen=True)
class V021LedgerCaseState:
    """The only ledger state the runtime is allowed to observe."""

    status: str
    response_sha256: str | None = None
    result_sha256: str | None = None


class V021LedgerPort(Protocol):
    """Authorization-bound append-only ledger operations used by this runtime."""

    def state(self, case_id: str, request_sha256: str) -> V021LedgerCaseState: ...

    def reserve(self, case_id: str, request_sha256: str, call_id: str) -> None: ...

    def record_response(
        self, case_id: str, request_sha256: str, response_sha256: str, cost_microusd: int
    ) -> None: ...

    def record_result(
        self, case_id: str, request_sha256: str, response_sha256: str, result_sha256: str
    ) -> None: ...

    def record_unknown_spend_halt(
        self, case_id: str, request_sha256: str, call_id: str
    ) -> None: ...


@dataclass(frozen=True)
class V021ProviderRequest:
    case_id: str
    request_sha256: str
    input_sha256: str
    call_id: str
    request: Mapping[str, object] = field(repr=False)


@dataclass(frozen=True)
class V021ProviderResponse:
    response_id: str
    output: str
    cost_microusd: int


ProviderAdapter = Callable[[V021ProviderRequest], V021ProviderResponse]


@dataclass(frozen=True, init=False)
class VerifiedV021RuntimePlan:
    path: Path
    sha256: str
    authorization_sha256: str
    preregistration_sha256: str
    lineage_commitment_sha256: str
    request_set_sha256: str
    cases: tuple[Mapping[str, object], ...] = field(repr=False)
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV021RuntimePlan is verifier-issued only")


@dataclass(frozen=True, init=False)
class V021GenerationResult:
    path: Path
    sha256: str
    case_id: str
    outcome: str
    response_sha256: str | None
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("V021GenerationResult is runtime-issued only")


def prepare_v021_runtime_plan(
    *,
    preregistration: object,
    authorization: ExecutionAuthorization,
    capability_index_path: Path,
    request_envelope_paths: Mapping[str, Path],
    output_path: Path,
) -> VerifiedV021RuntimePlan:
    """Build the exact all-20 plan, then reverify it before issuing authority."""

    authority = require_v021_execution_authorization(authorization)
    destination = Path(output_path)
    require_private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise _reject("Refusing to overwrite a v0.2.1 runtime plan.")
    expected_ids = tuple(f"rk-v0.2-{index:03d}" for index in range(1, CASE_COUNT + 1))
    if tuple(request_envelope_paths) != expected_ids:
        raise _reject("Runtime plan requires the exact sorted 20 request paths.")

    capability_raw = _read(Path(capability_index_path), MAX_PLAN_BYTES, "capability index")
    capability_record = _decode_canonical(capability_raw, "capability index")
    capability_values = capability_record.get("cases")
    if not isinstance(capability_values, list) or len(capability_values) != CASE_COUNT:
        raise _reject("Capability index must contain exactly 20 cases.")

    rows: list[dict[str, object]] = []
    for case_id, capability_value in zip(expected_ids, capability_values, strict=True):
        capability = _mapping(capability_value, "capability row")
        evidence = _mapping(capability.get("evidence"), "capability evidence")
        request_raw = _read(
            Path(request_envelope_paths[case_id]), MAX_PLAN_BYTES, "request envelope"
        )
        request = _decode_canonical(request_raw, "request envelope")
        rows.append(
            {
                "capability_sha256": capability.get("evaluator_public_commitment_sha256"),
                "capability_status": "semantic_valid",
                "case_id": case_id,
                "input_sha256": request.get("rendered_input_sha256"),
                "request": request,
                "request_sha256": hashlib.sha256(request_raw).hexdigest(),
                "runtime_manifest_sha256": evidence.get("runtime_manifest_sha256"),
            }
        )

    record = {
        "algorithm": PLAN_ALGORITHM,
        "authorization_sha256": authority.sha256,
        "benchmark_version": "0.2.1",
        "cases": rows,
        "lineage_commitment_sha256": authority.lineage_commitment_sha256,
        "preregistration_sha256": authority.preregistration_sha256,
        "request_set_sha256": authority.request_set_sha256,
        "schema_version": SCHEMA_VERSION,
    }
    write_bytes_exclusive(destination, _canonical(record) + b"\n")
    return verify_v021_runtime_plan(
        destination,
        preregistration=preregistration,
        authorization=authority,
        capability_index_path=capability_index_path,
    )


def verify_v021_runtime_plan(
    path: Path,
    *,
    preregistration: object,
    authorization: ExecutionAuthorization,
    capability_index_path: Path,
) -> VerifiedV021RuntimePlan:
    """Verify every case capability and request before issuing runtime authority."""

    preregistration = require_v021_execution_preregistration(preregistration)
    prereg_sha = _digest(preregistration.sha256, "preregistration")
    lineage = _digest(getattr(preregistration, "lineage_commitment_sha256", None), "lineage")
    authorization = require_v021_execution_authorization(authorization)
    auth_sha = _digest(authorization.sha256, "authorization")
    prereg_raw = _read(preregistration.path, MAX_PLAN_BYTES, "v0.2.1 preregistration")
    if hashlib.sha256(prereg_raw).hexdigest() != prereg_sha:
        raise _reject("Preregistration authority differs from its current bytes.")
    prereg_record = _decode_canonical(prereg_raw, "v0.2.1 preregistration")
    evidence = _mapping(prereg_record.get("evidence"), "preregistration evidence")
    capability_raw = _read(Path(capability_index_path), MAX_PLAN_BYTES, "capability index")
    if hashlib.sha256(capability_raw).hexdigest() != evidence.get("capability_index_raw_sha256"):
        raise _reject("Capability index differs from the preregistered raw artifact.")
    capability_record = _decode_canonical(capability_raw, "capability index")
    capability_rows = capability_record.get("cases")
    if not isinstance(capability_rows, list) or len(capability_rows) != CASE_COUNT:
        raise _reject("Capability index must contain exactly 20 cases.")
    capability_by_case: dict[str, Mapping[str, object]] = {}
    for expected_id, value in zip(
        (f"rk-v0.2-{index:03d}" for index in range(1, CASE_COUNT + 1)),
        capability_rows,
        strict=True,
    ):
        capability = _mapping(value, "capability row")
        capability_evidence = _mapping(capability.get("evidence"), "capability evidence")
        if (
            capability.get("case_id") != expected_id
            or capability.get("status") != "runtime_attested_evaluator_preflight_ready"
            or capability_evidence.get("case_id") != expected_id
            or capability_evidence.get("runtime_manifest_sha256")
            != evidence.get("runtime_manifest_sha256")
        ):
            raise _reject("Every actual capability must be uniformly ready and lineage-bound.")
        _digest(capability.get("evaluator_public_commitment_sha256"), "evaluator commitment")
        capability_by_case[expected_id] = capability
    if (
        authorization.preregistration_sha256 != prereg_sha
        or authorization.lineage_commitment_sha256 != lineage
    ):
        raise _reject("Authorization is not bound to the exact v0.2.1 preregistration.")
    raw = _read(Path(path), MAX_PLAN_BYTES, "runtime plan")
    record = _decode_canonical(raw, "runtime plan")
    if (
        set(record)
        != {
            "algorithm",
            "authorization_sha256",
            "benchmark_version",
            "cases",
            "lineage_commitment_sha256",
            "preregistration_sha256",
            "request_set_sha256",
            "schema_version",
        }
        or record.get("algorithm") != PLAN_ALGORITHM
        or record.get("schema_version") != SCHEMA_VERSION
    ):
        raise _reject("v0.2.1 runtime plan fields or identity are invalid.")
    if record.get("benchmark_version") != "0.2.1":
        raise _reject("Runtime plan is not the v0.2.1 protocol.")
    if (
        record.get("authorization_sha256") != auth_sha
        or record.get("preregistration_sha256") != prereg_sha
        or record.get("lineage_commitment_sha256") != lineage
        or record.get("request_set_sha256") != authorization.request_set_sha256
    ):
        raise _reject("Runtime plan lineage differs from verifier-issued authorities.")
    rows = record.get("cases")
    expected_ids = tuple(f"rk-v0.2-{index:03d}" for index in range(1, CASE_COUNT + 1))
    if not isinstance(rows, list) or len(rows) != CASE_COUNT:
        raise _reject("Runtime plan requires exactly 20 cases.")
    normalized: list[Mapping[str, object]] = []
    for expected_id, value in zip(expected_ids, rows, strict=True):
        row = _mapping(value, "runtime case")
        if set(row) != {
            "capability_sha256",
            "capability_status",
            "case_id",
            "input_sha256",
            "request",
            "request_sha256",
            "runtime_manifest_sha256",
        }:
            raise _reject("Runtime case fields are invalid.")
        request = _mapping(row["request"], "provider request")
        request_sha = hashlib.sha256(_canonical(request) + b"\n").hexdigest()
        if set(request) != {
            "algorithm",
            "case_id",
            "execution",
            "generator_input",
            "model",
            "outbound_request_sha256",
            "provider_request",
            "rendered_input_sha256",
            "status",
            "tool_git_sha",
        }:
            raise _reject("Frozen provider request envelope fields are invalid.")
        execution = _mapping(request.get("execution"), "request execution policy")
        model = _mapping(request.get("model"), "request model")
        provider_request = _mapping(request.get("provider_request"), "nested provider request")
        if (
            request.get("algorithm") != "reproassert-v02-provider-disabled-request-envelope-v1"
            or request.get("case_id") != expected_id
            or request.get("status")
            != "frozen_not_executable_pending_preregistration_and_authorization"
            or request.get("tool_git_sha") != authorization.tool_git_sha
            or request.get("rendered_input_sha256") != row.get("input_sha256")
            or execution
            != {
                "authorization_status": "not_authorized",
                "provider_calls": 0,
                "provider_execution_enabled": False,
            }
            or model
            != {
                "provider": "openai",
                "requested_model": authorization.model,
                "pricing_snapshot_sha256": authorization.pricing_snapshot_sha256,
            }
            or hashlib.sha256(_canonical(provider_request)).hexdigest()
            != request.get("outbound_request_sha256")
        ):
            raise _reject("Frozen provider request envelope bindings are invalid.")
        capability = capability_by_case[expected_id]
        if (
            row.get("case_id") != expected_id
            or row.get("capability_status") != "semantic_valid"
            or row.get("request_sha256") != request_sha
            or row.get("capability_sha256") != capability.get("evaluator_public_commitment_sha256")
            or row.get("runtime_manifest_sha256") != evidence.get("runtime_manifest_sha256")
        ):
            raise _reject("Every v0.2.1 case must be uniformly semantic-valid and exact-bound.")
        for key in (
            "capability_sha256",
            "input_sha256",
            "request_sha256",
            "runtime_manifest_sha256",
        ):
            _digest(row.get(key), key)
        normalized.append(dict(row))
    if tuple(authorization.case_ids) != expected_ids:
        raise _reject("Authorization does not contain the canonical 20-case cohort.")
    request_rows = [
        {
            "case_id": row["case_id"],
            "request_envelope_sha256": row["request_sha256"],
        }
        for row in normalized
    ]
    derived_set = hashlib.sha256(
        _canonical({"algorithm": REQUEST_SET_ALGORITHM, "requests": request_rows})
    ).hexdigest()
    authorized_requests = getattr(authorization, "request_sha256_by_case", None)
    if not isinstance(authorized_requests, Mapping) or dict(authorized_requests) != {
        cast(str, row["case_id"]): cast(str, row["request_envelope_sha256"]) for row in request_rows
    }:
        raise _reject("Runtime request envelopes differ from authorization.")
    if derived_set != authorization.request_set_sha256:
        raise _reject("Runtime request set differs from authorization.")
    authority = object.__new__(VerifiedV021RuntimePlan)
    for name, value in {
        "path": Path(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "authorization_sha256": auth_sha,
        "preregistration_sha256": prereg_sha,
        "lineage_commitment_sha256": lineage,
        "request_set_sha256": derived_set,
        "cases": tuple(normalized),
        "_issuer": _PLAN_ISSUER,
    }.items():
        object.__setattr__(authority, name, value)
    return authority


def require_v021_runtime_plan(value: object) -> VerifiedV021RuntimePlan:
    if type(value) is not VerifiedV021RuntimePlan or value._issuer is not _PLAN_ISSUER:
        raise _reject("Fresh verifier-issued v0.2.1 runtime plan is required.")
    return value


def require_v021_generation_result(value: object) -> V021GenerationResult:
    """Revalidate a runtime-issued result and its current durable bytes."""

    if type(value) is not V021GenerationResult or value._issuer is not _RESULT_ISSUER:
        raise _reject("Runtime-issued v0.2.1 generation result is required.")
    case_ids = {f"rk-v0.2-{index:03d}" for index in range(1, CASE_COUNT + 1)}
    if value.case_id not in case_ids or value.outcome not in {
        "provider_response_durable_unparsed",
        "unknown_spend_halt",
    }:
        raise _reject("Generation result identity is invalid.")
    raw = _read(value.path, MAX_RESULT_BYTES, "generation result")
    if hashlib.sha256(raw).hexdigest() != _digest(value.sha256, "result SHA"):
        raise _reject("Generation result changed after runtime issuance.")
    record = _decode_canonical(raw, "generation result")
    if (
        record.get("algorithm") != RESULT_ALGORITHM
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("benchmark_version") != "0.2.1"
        or record.get("case_id") != value.case_id
        or record.get("outcome") != value.outcome
        or record.get("response_sha256") != value.response_sha256
    ):
        raise _reject("Generation result durable identity is invalid.")
    if value.response_sha256 is not None:
        _digest(value.response_sha256, "response SHA")
    return value


def execute_v021_case(
    *,
    plan: VerifiedV021RuntimePlan,
    authorization: ExecutionAuthorization,
    ledger: V021LedgerPort,
    case_id: str,
    provider: ProviderAdapter,
    response_directory: Path,
    result_directory: Path,
) -> V021GenerationResult:
    """Execute or resume one case; the provider can be called at most once."""

    verified = require_v021_runtime_plan(plan)
    authorization = require_v021_execution_authorization(authorization)
    if authorization.sha256 != verified.authorization_sha256:
        raise _reject("Runtime authorization changed after preflight.")
    row = next((item for item in verified.cases if item["case_id"] == case_id), None)
    if row is None:
        raise _reject("Case is outside the verified 20-case plan.")
    request_sha = cast(str, row["request_sha256"])
    call_id = hashlib.sha256(
        _canonical(
            {
                "authorization_sha256": authorization.sha256,
                "case_id": case_id,
                "request_sha256": request_sha,
            }
        )
    ).hexdigest()
    response_root, result_root = Path(response_directory), Path(result_directory)
    require_private_directory(response_root)
    require_private_directory(result_root)
    response_path = response_root / f"{case_id}.json"
    result_path = result_root / f"{case_id}.json"
    state = ledger.state(case_id, request_sha)
    if state.status == "result_recorded":
        return _load_result(result_path, verified, authorization, row, state.result_sha256)
    if state.status == "unknown_spend_halt":
        return _unknown_result(result_path, verified, authorization, row, call_id)
    if state.status == "unreserved":
        ledger.reserve(case_id, request_sha, call_id)
        state = V021LedgerCaseState("reserved")
        request = V021ProviderRequest(
            case_id=case_id,
            request_sha256=request_sha,
            input_sha256=cast(str, row["input_sha256"]),
            call_id=call_id,
            request=_mapping(
                _mapping(row["request"], "provider request")["provider_request"],
                "nested provider request",
            ),
        )
        try:
            response = _call_provider_once(provider, request)
        except Exception:
            ledger.record_unknown_spend_halt(case_id, request_sha, call_id)
            return _unknown_result(result_path, verified, authorization, row, call_id)
        envelope = _response_record(verified, authorization, row, call_id, response)
        write_bytes_exclusive(response_path, _canonical(envelope) + b"\n")
    elif state.status == "reserved" and not response_path.exists():
        ledger.record_unknown_spend_halt(case_id, request_sha, call_id)
        return _unknown_result(result_path, verified, authorization, row, call_id)
    elif state.status not in {"reserved", "response_recorded"}:
        raise _reject("Ledger contains an unsupported case state.")

    response_record, response_sha = _load_response(
        response_path, verified, authorization, row, call_id
    )
    if state.status == "reserved":
        ledger.record_response(
            case_id,
            request_sha,
            response_sha,
            cast(int, response_record["cost_microusd"]),
        )
    result = _success_result_record(verified, authorization, row, call_id, response_sha)
    result_raw = _canonical(result) + b"\n"
    if result_path.exists():
        existing = _read(result_path, MAX_RESULT_BYTES, "generation result")
        if existing != result_raw:
            raise _reject("Durable result conflicts with recovered response.")
    else:
        write_bytes_exclusive(result_path, result_raw)
    result_sha = hashlib.sha256(result_raw).hexdigest()
    ledger.record_result(case_id, request_sha, response_sha, result_sha)
    return _issue_result(
        result_path, result_sha, case_id, "provider_response_durable_unparsed", response_sha
    )


def _call_provider_once(
    adapter: ProviderAdapter, request: V021ProviderRequest
) -> V021ProviderResponse:
    """The sole provider-capable call site in the v0.2.1 runtime."""

    response = adapter(request)
    if not isinstance(response, V021ProviderResponse):
        raise _reject("Provider adapter returned an invalid response type.")
    if (
        type(response.response_id) is not str
        or type(response.output) is not str
        or not response.response_id
        or len(response.response_id) > 500
        or len(response.output) > 1_000_000
    ):
        raise _reject("Provider response fields exceed their bounds.")
    if type(response.cost_microusd) is not int or not 0 <= response.cost_microusd <= 250_000:
        raise _reject("Provider response cost exceeds the hard per-case cap.")
    return response


def _response_record(
    plan: VerifiedV021RuntimePlan,
    authorization: ExecutionAuthorization,
    row: Mapping[str, object],
    call_id: str,
    response: V021ProviderResponse,
) -> dict[str, object]:
    return {
        "algorithm": RESPONSE_ALGORITHM,
        "authorization_sha256": authorization.sha256,
        "call_id": call_id,
        "case_id": row["case_id"],
        "cost_microusd": response.cost_microusd,
        "input_sha256": row["input_sha256"],
        "lineage_commitment_sha256": plan.lineage_commitment_sha256,
        "output": response.output,
        "preregistration_sha256": plan.preregistration_sha256,
        "request_sha256": row["request_sha256"],
        "response_id": response.response_id,
        "schema_version": SCHEMA_VERSION,
    }


def _load_response(
    path: Path,
    plan: VerifiedV021RuntimePlan,
    authorization: ExecutionAuthorization,
    row: Mapping[str, object],
    call_id: str,
) -> tuple[dict[str, object], str]:
    raw = _read(path, MAX_RESPONSE_BYTES, "provider response")
    record = _decode_canonical(raw, "provider response")
    expected_keys = set(
        _response_record(plan, authorization, row, call_id, V021ProviderResponse("x", "", 0))
    )
    if set(record) != expected_keys:
        raise _reject("Durable provider response fields are invalid.")
    for key, expected in {
        "algorithm": RESPONSE_ALGORITHM,
        "schema_version": SCHEMA_VERSION,
        "authorization_sha256": authorization.sha256,
        "preregistration_sha256": plan.preregistration_sha256,
        "lineage_commitment_sha256": plan.lineage_commitment_sha256,
        "case_id": row["case_id"],
        "request_sha256": row["request_sha256"],
        "input_sha256": row["input_sha256"],
        "call_id": call_id,
    }.items():
        if record.get(key) != expected:
            raise _reject("Durable provider response has stale or cross-case bindings.")
    if (
        type(record.get("cost_microusd")) is not int
        or not 0 <= cast(int, record["cost_microusd"]) <= 250_000
    ):
        raise _reject("Durable provider response cost is invalid.")
    return record, hashlib.sha256(raw).hexdigest()


def _success_result_record(
    plan: VerifiedV021RuntimePlan,
    authorization: ExecutionAuthorization,
    row: Mapping[str, object],
    call_id: str,
    response_sha: str,
) -> dict[str, object]:
    return {
        "algorithm": RESULT_ALGORITHM,
        "authorization_sha256": authorization.sha256,
        "benchmark_version": "0.2.1",
        "call_id": call_id,
        "case_id": row["case_id"],
        "claim_level": "generation_only_unreviewed",
        "input_sha256": row["input_sha256"],
        "lineage_commitment_sha256": plan.lineage_commitment_sha256,
        "outcome": "provider_response_durable_unparsed",
        "preregistration_sha256": plan.preregistration_sha256,
        "request_sha256": row["request_sha256"],
        "response_sha256": response_sha,
        "schema_version": SCHEMA_VERSION,
    }


def _unknown_result(
    path: Path,
    plan: VerifiedV021RuntimePlan,
    authorization: ExecutionAuthorization,
    row: Mapping[str, object],
    call_id: str,
) -> V021GenerationResult:
    record = _success_result_record(plan, authorization, row, call_id, "0" * 64)
    record.update(
        outcome="unknown_spend_halt",
        claim_level="rejected",
        response_sha256=None,
    )
    raw = _canonical(record) + b"\n"
    if path.exists():
        if _read(path, MAX_RESULT_BYTES, "generation result") != raw:
            raise _reject("Unknown-spend result conflicts with durable bytes.")
    else:
        write_bytes_exclusive(path, raw)
    return _issue_result(
        path, hashlib.sha256(raw).hexdigest(), cast(str, row["case_id"]), "unknown_spend_halt", None
    )


def _load_result(
    path: Path,
    plan: VerifiedV021RuntimePlan,
    authorization: ExecutionAuthorization,
    row: Mapping[str, object],
    expected_sha: str | None,
) -> V021GenerationResult:
    raw = _read(path, MAX_RESULT_BYTES, "generation result")
    if expected_sha is None or hashlib.sha256(raw).hexdigest() != expected_sha:
        raise _reject("Recorded result differs from durable bytes.")
    record = _decode_canonical(raw, "generation result")
    response_sha = record.get("response_sha256")
    call_id = hashlib.sha256(
        _canonical(
            {
                "authorization_sha256": authorization.sha256,
                "case_id": row["case_id"],
                "request_sha256": row["request_sha256"],
            }
        )
    ).hexdigest()
    expected = _success_result_record(plan, authorization, row, call_id, cast(str, response_sha))
    if record != expected:
        raise _reject("Recorded result bindings are invalid.")
    return _issue_result(
        path,
        expected_sha,
        cast(str, row["case_id"]),
        "provider_response_durable_unparsed",
        cast(str, response_sha),
    )


def _issue_result(
    path: Path, sha: str, case_id: str, outcome: str, response_sha: str | None
) -> V021GenerationResult:
    result = object.__new__(V021GenerationResult)
    for name, value in {
        "path": path,
        "sha256": sha,
        "case_id": case_id,
        "outcome": outcome,
        "response_sha256": response_sha,
        "_issuer": _RESULT_ISSUER,
    }.items():
        object.__setattr__(result, name, value)
    return result


def _read(path: Path, limit: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as stream:
            raw = stream.read(limit + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"Cannot safely read {label}.") from exc
    if len(raw) > limit:
        raise _reject(f"{label} exceeds its size bound.")
    return raw


def _decode_canonical(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject(f"{label} is invalid JSON.") from exc
    if not isinstance(value, dict) or raw != _canonical(value) + b"\n":
        raise _reject(f"{label} is not exact canonical JSON.")
    return cast(dict[str, object], value)


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise _reject(f"{label} must be an object.")
    return cast(Mapping[str, object], value)


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise _reject(f"{label} must be a SHA-256 digest.")
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v021_runtime", message)
