from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from reproassert import benchmark_v021_authorization as auth_module
from reproassert import benchmark_v021_preregistration as prereg_module
from reproassert import benchmark_v021_runtime as runtime
from reproassert.errors import PolicyRejection


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _prereg(tmp_path: Path, *, capability_raw: bytes) -> prereg_module.VerifiedV021Preregistration:
    record = {
        "evidence": {
            "capability_index_raw_sha256": hashlib.sha256(capability_raw).hexdigest(),
            "runtime_manifest_sha256": "c" * 64,
        }
    }
    raw = _canonical(record) + b"\n"
    path = tmp_path / "prereg.json"
    path.write_bytes(raw)
    prereg = object.__new__(prereg_module.VerifiedV021Preregistration)
    for name, value in {
        "path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "lineage_commitment_sha256": "b" * 64,
        "approval_statement": "approved",
        "approval_statement_sha256": "e" * 64,
        "case_count": 20,
        "dependency_ready_count": 20,
        "provider_calls": 0,
        "execution_enabled": False,
        "_issuer": prereg_module._ISSUER,
    }.items():
        object.__setattr__(prereg, name, value)
    return prereg


def _fixture(
    tmp_path: Path,
) -> tuple[
    runtime.VerifiedV021RuntimePlan,
    auth_module.VerifiedV021ExecutionAuthorization,
    list[dict[str, object]],
]:
    rows: list[dict[str, object]] = []
    capability_rows: list[dict[str, object]] = []
    for index in range(1, 21):
        capability_sha = hashlib.sha256(f"cap-{index}".encode()).hexdigest()
        case_id = f"rk-v0.2-{index:03d}"
        provider_request = {"input": f"bounded-{index}", "model": auth_module.MODEL}
        rendered_sha = hashlib.sha256(f"input-{index}".encode()).hexdigest()
        request = {
            "algorithm": "reproassert-v02-provider-disabled-request-envelope-v1",
            "case_id": case_id,
            "execution": {
                "authorization_status": "not_authorized",
                "provider_calls": 0,
                "provider_execution_enabled": False,
            },
            "generator_input": {
                "issue_projection_sha256": "3" * 64,
                "source_archive_sha256": "4" * 64,
                "source_tree_sha256": "5" * 64,
            },
            "model": {
                "provider": "openai",
                "requested_model": auth_module.MODEL,
                "pricing_snapshot_sha256": "f" * 64,
            },
            "provider_request": provider_request,
            "rendered_input_sha256": rendered_sha,
            "outbound_request_sha256": hashlib.sha256(_canonical(provider_request)).hexdigest(),
            "status": "frozen_not_executable_pending_preregistration_and_authorization",
            "tool_git_sha": "f" * 40,
        }
        rows.append(
            {
                "capability_sha256": capability_sha,
                "capability_status": "semantic_valid",
                "case_id": case_id,
                "input_sha256": rendered_sha,
                "request": request,
                "request_sha256": hashlib.sha256(_canonical(request) + b"\n").hexdigest(),
                "runtime_manifest_sha256": "c" * 64,
            }
        )
        capability_rows.append(
            {
                "case_id": case_id,
                "evaluator_public_commitment_sha256": capability_sha,
                "evidence": {
                    "case_id": case_id,
                    "runtime_manifest_sha256": "c" * 64,
                },
                "status": "runtime_attested_evaluator_preflight_ready",
            }
        )
    capability_raw = _canonical({"cases": capability_rows}) + b"\n"
    capability_path = tmp_path / "capability-index.json"
    capability_path.write_bytes(capability_raw)
    prereg = _prereg(tmp_path, capability_raw=capability_raw)
    request_rows = [
        {
            "case_id": row["case_id"],
            "request_envelope_sha256": row["request_sha256"],
        }
        for row in rows
    ]
    request_set = hashlib.sha256(
        _canonical({"algorithm": runtime.REQUEST_SET_ALGORITHM, "requests": request_rows})
    ).hexdigest()
    authorization = object.__new__(auth_module.VerifiedV021ExecutionAuthorization)
    authorization_ref = "operator:test-runtime"
    operator_nonce = "7" * 64
    authorized_at = "2026-07-11T00:00:00Z"
    ledger_path = tmp_path / "ledger.jsonl"
    ledger_identity = "1" * 64
    execution_statement = auth_module.required_v021_execution_statement(
        preregistration_raw_sha256=prereg.sha256,
        request_set_sha256=request_set,
        ledger_absolute_path=ledger_path,
        ledger_identity_sha256=ledger_identity,
        model=auth_module.MODEL,
        total_cap_usd=auth_module.TOTAL_CAP_USD,
        per_case_cap_usd=auth_module.PER_CASE_CAP_USD,
        overage_allowed=False,
        authorized_at=authorized_at,
        authorization_ref=authorization_ref,
        operator_nonce=operator_nonce,
    )
    for name, value in {
        "path": tmp_path / "authorization.json",
        "sha256": "d" * 64,
        "preregistration_sha256": prereg.sha256,
        "lineage_commitment_sha256": prereg.lineage_commitment_sha256,
        "request_set_sha256": request_set,
        "tool_git_sha": "f" * 40,
        "model": auth_module.MODEL,
        "pricing_snapshot_sha256": "f" * 64,
        "case_ids": tuple(row["case_id"] for row in rows),
        "preregistration_request_set_sha256": "2" * 64,
        "request_sha256_by_case": {
            str(row["case_id"]): str(row["request_envelope_sha256"]) for row in request_rows
        },
        "ledger_path": ledger_path,
        "ledger_identity_sha256": ledger_identity,
        "total_cap_usd": auth_module.TOTAL_CAP_USD,
        "per_case_cap_usd": auth_module.PER_CASE_CAP_USD,
        "authorized_at": authorized_at,
        "authorization_ref": authorization_ref,
        "operator_nonce": operator_nonce,
        "execution_statement": execution_statement,
        "execution_statement_sha256": hashlib.sha256(execution_statement.encode()).hexdigest(),
        "_issuer": auth_module._ISSUER,
    }.items():
        object.__setattr__(authorization, name, value)
    record = {
        "algorithm": runtime.PLAN_ALGORITHM,
        "authorization_sha256": authorization.sha256,
        "benchmark_version": "0.2.1",
        "cases": rows,
        "lineage_commitment_sha256": prereg.lineage_commitment_sha256,
        "preregistration_sha256": prereg.sha256,
        "request_set_sha256": request_set,
        "schema_version": runtime.SCHEMA_VERSION,
    }
    path = tmp_path / "plan.json"
    path.write_bytes(_canonical(record) + b"\n")
    return (
        runtime.verify_v021_runtime_plan(
            path,
            preregistration=prereg,
            authorization=authorization,
            capability_index_path=capability_path,
        ),
        authorization,
        rows,
    )


class _Ledger:
    def __init__(self) -> None:
        self.states: dict[str, runtime.V021LedgerCaseState] = {}
        self.events: list[tuple[str, str]] = []
        self.fail_response_once = False

    def state(self, case_id: str, request_sha256: str) -> runtime.V021LedgerCaseState:
        return self.states.get(case_id, runtime.V021LedgerCaseState("unreserved"))

    def reserve(self, case_id: str, request_sha256: str, call_id: str) -> None:
        self.events.append(("reserve", case_id))
        self.states[case_id] = runtime.V021LedgerCaseState("reserved")

    def record_response(
        self, case_id: str, request_sha256: str, response_sha256: str, cost_microusd: int
    ) -> None:
        self.events.append(("response", case_id))
        if self.fail_response_once:
            self.fail_response_once = False
            raise RuntimeError("simulated crash after durable response")
        self.states[case_id] = runtime.V021LedgerCaseState(
            "response_recorded", response_sha256=response_sha256
        )

    def record_result(
        self, case_id: str, request_sha256: str, response_sha256: str, result_sha256: str
    ) -> None:
        self.events.append(("result", case_id))
        self.states[case_id] = runtime.V021LedgerCaseState(
            "result_recorded", response_sha256, result_sha256
        )

    def record_unknown_spend_halt(self, case_id: str, request_sha256: str, call_id: str) -> None:
        self.events.append(("unknown", case_id))
        self.states[case_id] = runtime.V021LedgerCaseState("unknown_spend_halt")


def _private_dirs(tmp_path: Path) -> tuple[Path, Path]:
    responses = tmp_path / "responses"
    results = tmp_path / "results"
    responses.mkdir(mode=0o700)
    results.mkdir(mode=0o700)
    return responses, results


def test_prepare_runtime_plan_rederives_all_twenty_request_bindings(tmp_path: Path) -> None:
    plan, authorization, rows = _fixture(tmp_path)
    capability_path = tmp_path / "capability-index.json"
    prereg = _prereg(tmp_path, capability_raw=capability_path.read_bytes())
    request_paths: dict[str, Path] = {}
    for row in rows:
        case_id = str(row["case_id"])
        path = tmp_path / f"{case_id}-request.json"
        path.write_bytes(_canonical(row["request"]) + b"\n")
        request_paths[case_id] = path

    prepared = runtime.prepare_v021_runtime_plan(
        preregistration=prereg,
        authorization=authorization,
        capability_index_path=capability_path,
        request_envelope_paths=request_paths,
        output_path=tmp_path / "prepared-plan.json",
    )

    assert prepared.request_set_sha256 == plan.request_set_sha256
    assert tuple(row["case_id"] for row in prepared.cases) == tuple(request_paths)


def test_prepare_runtime_plan_rejects_request_path_order_before_write(tmp_path: Path) -> None:
    _, authorization, rows = _fixture(tmp_path)
    capability_path = tmp_path / "capability-index.json"
    prereg = _prereg(tmp_path, capability_raw=capability_path.read_bytes())
    request_paths: dict[str, Path] = {}
    for row in reversed(rows):
        case_id = str(row["case_id"])
        path = tmp_path / f"{case_id}-request.json"
        path.write_bytes(_canonical(row["request"]) + b"\n")
        request_paths[case_id] = path
    output = tmp_path / "prepared-plan.json"

    with pytest.raises(PolicyRejection, match="exact sorted 20 request paths"):
        runtime.prepare_v021_runtime_plan(
            preregistration=prereg,
            authorization=authorization,
            capability_index_path=capability_path,
            request_envelope_paths=request_paths,
            output_path=output,
        )
    assert not output.exists()


def test_preflight_rejects_case014_waiver_before_provider(tmp_path: Path) -> None:
    plan, authorization, rows = _fixture(tmp_path)
    record = json.loads(plan.path.read_text())
    record["cases"][13]["capability_status"] = "infrastructure_failure"
    plan.path.write_bytes(_canonical(record) + b"\n")
    calls = 0

    with pytest.raises(PolicyRejection, match="uniformly semantic-valid"):
        runtime.verify_v021_runtime_plan(
            plan.path,
            preregistration=_prereg(
                tmp_path, capability_raw=(tmp_path / "capability-index.json").read_bytes()
            ),
            authorization=authorization,
            capability_index_path=tmp_path / "capability-index.json",
        )
    assert calls == 0
    assert rows[13]["case_id"] == "rk-v0.2-014"


def test_preflight_rejects_mutated_preregistered_capability_index(tmp_path: Path) -> None:
    plan, authorization, _ = _fixture(tmp_path)
    capability_path = tmp_path / "capability-index.json"
    original = capability_path.read_bytes()
    prereg = _prereg(tmp_path, capability_raw=original)
    record = json.loads(original)
    record["cases"][0]["status"] = "runtime_attested_gold_smoke_infrastructure_failure"
    capability_path.write_bytes(_canonical(record) + b"\n")
    with pytest.raises(PolicyRejection, match="preregistered raw artifact"):
        runtime.verify_v021_runtime_plan(
            plan.path,
            preregistration=prereg,
            authorization=authorization,
            capability_index_path=capability_path,
        )


def test_preflight_rejects_fabricated_plan_capability_commitment(tmp_path: Path) -> None:
    plan, authorization, _ = _fixture(tmp_path)
    capability_path = tmp_path / "capability-index.json"
    prereg = _prereg(tmp_path, capability_raw=capability_path.read_bytes())
    record = json.loads(plan.path.read_text())
    record["cases"][13]["capability_sha256"] = "9" * 64
    plan.path.write_bytes(_canonical(record) + b"\n")
    with pytest.raises(PolicyRejection, match="uniformly semantic-valid and exact-bound"):
        runtime.verify_v021_runtime_plan(
            plan.path,
            preregistration=prereg,
            authorization=authorization,
            capability_index_path=capability_path,
        )


def test_preflight_has_no_actual_case014_infrastructure_waiver(tmp_path: Path) -> None:
    plan, authorization, _ = _fixture(tmp_path)
    capability_path = tmp_path / "capability-index.json"
    capability = json.loads(capability_path.read_text())
    capability["cases"][13]["status"] = "runtime_attested_gold_smoke_infrastructure_failure"
    capability_raw = _canonical(capability) + b"\n"
    capability_path.write_bytes(capability_raw)
    prereg = _prereg(tmp_path, capability_raw=capability_raw)
    object.__setattr__(authorization, "preregistration_sha256", prereg.sha256)
    execution_statement = auth_module.required_v021_execution_statement(
        preregistration_raw_sha256=prereg.sha256,
        request_set_sha256=authorization.request_set_sha256,
        ledger_absolute_path=authorization.ledger_path,
        ledger_identity_sha256=authorization.ledger_identity_sha256,
        model=authorization.model,
        total_cap_usd=authorization.total_cap_usd,
        per_case_cap_usd=authorization.per_case_cap_usd,
        overage_allowed=False,
        authorized_at=authorization.authorized_at,
        authorization_ref=authorization.authorization_ref,
        operator_nonce=authorization.operator_nonce,
    )
    object.__setattr__(authorization, "execution_statement", execution_statement)
    object.__setattr__(
        authorization,
        "execution_statement_sha256",
        hashlib.sha256(execution_statement.encode()).hexdigest(),
    )
    plan_record = json.loads(plan.path.read_text())
    plan_record["preregistration_sha256"] = prereg.sha256
    plan.path.write_bytes(_canonical(plan_record) + b"\n")
    with pytest.raises(PolicyRejection, match="actual capability must be uniformly ready"):
        runtime.verify_v021_runtime_plan(
            plan.path,
            preregistration=prereg,
            authorization=authorization,
            capability_index_path=capability_path,
        )


def test_reservation_precedes_the_only_provider_call(tmp_path: Path) -> None:
    plan, authorization, _ = _fixture(tmp_path)
    ledger = _Ledger()
    responses, results = _private_dirs(tmp_path)

    def provider(request: runtime.V021ProviderRequest) -> runtime.V021ProviderResponse:
        assert ledger.events == [("reserve", request.case_id)]
        return runtime.V021ProviderResponse("response-1", "candidate", 10_000)

    result = runtime.execute_v021_case(
        plan=plan,
        authorization=authorization,
        ledger=ledger,
        case_id="rk-v0.2-014",
        provider=provider,
        response_directory=responses,
        result_directory=results,
    )
    assert result.outcome == "provider_response_durable_unparsed"
    assert ledger.events == [
        ("reserve", "rk-v0.2-014"),
        ("response", "rk-v0.2-014"),
        ("result", "rk-v0.2-014"),
    ]


def test_reserved_without_durable_response_halts_and_never_recalls(tmp_path: Path) -> None:
    plan, authorization, rows = _fixture(tmp_path)
    ledger = _Ledger()
    case_id = "rk-v0.2-001"
    ledger.states[case_id] = runtime.V021LedgerCaseState("reserved")
    responses, results = _private_dirs(tmp_path)
    calls = 0

    def forbidden(_request: runtime.V021ProviderRequest) -> runtime.V021ProviderResponse:
        nonlocal calls
        calls += 1
        raise AssertionError("provider must not be recalled")

    result = runtime.execute_v021_case(
        plan=plan,
        authorization=authorization,
        ledger=ledger,
        case_id=case_id,
        provider=forbidden,
        response_directory=responses,
        result_directory=results,
    )
    assert result.outcome == "unknown_spend_halt"
    assert calls == 0
    assert rows[0]["case_id"] == case_id


def test_durable_response_recovery_never_recalls_provider(tmp_path: Path) -> None:
    plan, authorization, _ = _fixture(tmp_path)
    ledger = _Ledger()
    ledger.fail_response_once = True
    responses, results = _private_dirs(tmp_path)
    calls = 0

    def provider(_request: runtime.V021ProviderRequest) -> runtime.V021ProviderResponse:
        nonlocal calls
        calls += 1
        return runtime.V021ProviderResponse("response-1", "candidate", 12_500)

    with pytest.raises(RuntimeError, match="simulated crash"):
        runtime.execute_v021_case(
            plan=plan,
            authorization=authorization,
            ledger=ledger,
            case_id="rk-v0.2-002",
            provider=provider,
            response_directory=responses,
            result_directory=results,
        )
    recovered = runtime.execute_v021_case(
        plan=plan,
        authorization=authorization,
        ledger=ledger,
        case_id="rk-v0.2-002",
        provider=lambda _request: (_ for _ in ()).throw(AssertionError("provider recalled")),
        response_directory=responses,
        result_directory=results,
    )
    assert recovered.outcome == "provider_response_durable_unparsed"
    assert calls == 1


def test_tampered_durable_response_cross_binding_is_rejected(tmp_path: Path) -> None:
    plan, authorization, _ = _fixture(tmp_path)
    ledger = _Ledger()
    ledger.fail_response_once = True
    responses, results = _private_dirs(tmp_path)
    with pytest.raises(RuntimeError):
        runtime.execute_v021_case(
            plan=plan,
            authorization=authorization,
            ledger=ledger,
            case_id="rk-v0.2-003",
            provider=lambda _request: runtime.V021ProviderResponse("response", "candidate", 1),
            response_directory=responses,
            result_directory=results,
        )
    path = responses / "rk-v0.2-003.json"
    record = json.loads(path.read_text())
    record["case_id"] = "rk-v0.2-014"
    path.write_bytes(_canonical(record) + b"\n")
    with pytest.raises(PolicyRejection, match="stale or cross-case"):
        runtime.execute_v021_case(
            plan=plan,
            authorization=authorization,
            ledger=ledger,
            case_id="rk-v0.2-003",
            provider=lambda _request: (_ for _ in ()).throw(AssertionError("provider recalled")),
            response_directory=responses,
            result_directory=results,
        )


def test_provider_response_runtime_types_are_enforced() -> None:
    request = runtime.V021ProviderRequest(
        case_id="rk-v0.2-001",
        request_sha256="1" * 64,
        input_sha256="2" * 64,
        call_id="3" * 64,
        request={},
    )
    with pytest.raises(PolicyRejection, match="fields exceed"):
        runtime._call_provider_once(
            lambda _request: runtime.V021ProviderResponse("response", ["not", "text"], 1),  # type: ignore[arg-type]
            request,
        )


def test_generation_result_schema_is_mirrored_and_accepts_runtime_output(tmp_path: Path) -> None:
    plan, authorization, _ = _fixture(tmp_path)
    ledger = _Ledger()
    responses, results = _private_dirs(tmp_path)
    result = runtime.execute_v021_case(
        plan=plan,
        authorization=authorization,
        ledger=ledger,
        case_id="rk-v0.2-020",
        provider=lambda _request: runtime.V021ProviderResponse("response", "candidate", 1),
        response_directory=responses,
        result_directory=results,
    )
    public_schema = json.loads(
        (
            Path(__file__).parents[1] / "schemas/benchmark-v021-generation-result.schema.json"
        ).read_text()
    )
    package_schema = json.loads(
        (
            Path(__file__).parents[1]
            / "src/reproassert/schemas/benchmark-v021-generation-result.schema.json"
        ).read_text()
    )
    assert public_schema == package_schema
    Draft202012Validator(public_schema).validate(json.loads(result.path.read_text()))
