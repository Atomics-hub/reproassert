from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import jsonschema
import pytest

import reproassert.benchmark_v02_execution_freeze as execution_freeze
from reproassert import benchmark_v02_campaign as campaign_module
from reproassert import benchmark_v02_exact_preregistration as exact_preregistration
from reproassert import benchmark_v02_runner as runner
from reproassert.benchmark_v02_candidate_contract import v02_candidate_contract
from reproassert.benchmark_v02_execution_freeze import (
    MAX_CASE_MICROUSD,
    _preparation_requests,
    _required_reservation,
    exact_approval_statement,
)
from reproassert.benchmark_v02_runner import V02PricingSnapshot
from reproassert.benchmark_v02_scored_preregistration import load_v02_scored_preregistration
from reproassert.errors import PolicyRejection


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    )


def _pricing() -> V02PricingSnapshot:
    return V02PricingSnapshot(
        provider="openai",
        requested_model="gpt-5.4-mini-2026-03-17",
        effective_at="2026-07-10T00:00:00Z",
        source="official pricing fixture",
        input_microusd_per_million_tokens=750_000,
        cached_input_microusd_per_million_tokens=75_000,
        output_microusd_per_million_tokens=4_500_000,
        sandbox_microusd_per_second=0,
        artifact_microusd_per_million_bytes=0,
        paid_storage_microusd=0,
        dependency_prep_microusd=0,
    )


def _request_preparation(
    root: Path, *, tool_git_sha: str, rendered_bytes: int
) -> dict[str, object]:
    packages: list[dict[str, object]] = []
    for position in range(1, 21):
        case_id = f"rk-v0.2-{position:03d}"
        request_path = Path("cases") / case_id / "request-envelope.json"
        package_path = Path("cases") / case_id / "package.json"
        (root / request_path).parent.mkdir(parents=True)
        rendered = "x" * rendered_bytes
        provider_request = {"input": rendered, "instructions": "fixed", "model": "fixture"}
        request = {
            "case_id": case_id,
            "provider_request": provider_request,
            "outbound_request_sha256": hashlib.sha256(
                json.dumps(
                    provider_request, sort_keys=True, separators=(",", ":"), allow_nan=False
                ).encode()
            ).hexdigest(),
            "rendered_input_sha256": hashlib.sha256(rendered.encode()).hexdigest(),
            "tool_git_sha": tool_git_sha,
        }
        request_raw = _canonical(request)
        (root / request_path).write_bytes(request_raw)
        package = {
            "request_envelope": {
                "path": request_path.as_posix(),
                "sha256": hashlib.sha256(request_raw).hexdigest(),
            }
        }
        (root / package_path).write_bytes(_canonical(package))
        packages.append({"case_id": case_id, "path": package_path.as_posix()})
    return {"packages": packages}


def test_preparation_requests_bind_exact_rendered_bytes_and_controller_sha(tmp_path: Path) -> None:
    tool_sha = "9" * 40
    preparation = _request_preparation(tmp_path, tool_git_sha=tool_sha, rendered_bytes=100)
    case_ids = tuple(f"rk-v0.2-{position:03d}" for position in range(1, 21))

    rows = _preparation_requests(tmp_path, preparation, case_ids, controller_git_sha=tool_sha)

    assert len(rows) == 20
    assert all(outbound_bytes > 100 for _, _, _, outbound_bytes in rows)
    assert all(
        outbound_digest != rendered_digest for _, rendered_digest, outbound_digest, _ in rows
    )
    with pytest.raises(PolicyRejection, match="controller SHA"):
        _preparation_requests(tmp_path, preparation, case_ids, controller_git_sha="8" * 40)


def test_reservation_audit_rejects_known_oversize_requests() -> None:
    pricing = _pricing()

    assert _required_reservation(pricing, 374_714) == 299_468
    assert _required_reservation(pricing, 380_607) == 303_888
    assert _required_reservation(pricing, 300_000) <= MAX_CASE_MICROUSD
    assert _required_reservation(pricing, 374_714) > MAX_CASE_MICROUSD


def test_preparation_prices_full_outbound_body_and_rejects_overhead_tampering(
    tmp_path: Path,
) -> None:
    tool_sha = "9" * 40
    preparation = _request_preparation(tmp_path, tool_git_sha=tool_sha, rendered_bytes=100)
    case_ids = tuple(f"rk-v0.2-{position:03d}" for position in range(1, 21))
    rows = _preparation_requests(tmp_path, preparation, case_ids, controller_git_sha=tool_sha)

    assert all(outbound_bytes > 100 for _, _, _, outbound_bytes in rows)

    first_package = json.loads((tmp_path / "cases/rk-v0.2-001/package.json").read_text())
    request_path = tmp_path / first_package["request_envelope"]["path"]
    request = json.loads(request_path.read_text())
    request["provider_request"]["instructions"] = "tampered instructions"
    tampered = _canonical(request)
    request_path.write_bytes(tampered)
    first_package["request_envelope"]["sha256"] = hashlib.sha256(tampered).hexdigest()
    (tmp_path / "cases/rk-v0.2-001/package.json").write_bytes(_canonical(first_package))

    with pytest.raises(PolicyRejection, match="Outbound request hash"):
        _preparation_requests(tmp_path, preparation, case_ids, controller_git_sha=tool_sha)


def test_approval_statement_binds_final_freeze_hash_and_exact_caps() -> None:
    digest = "a" * 64
    statement = exact_approval_statement(digest)
    assert digest in statement
    assert "USD 5.00 total" in statement
    assert "USD 0.25 per-case" in statement
    assert "zero overage" in statement


def test_prepare_and_authorize_exact_freeze_end_to_end_without_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool_sha = "9" * 40
    case_ids = tuple(f"rk-v0.2-{position:03d}" for position in range(1, 21))
    preparation = _request_preparation(tmp_path, tool_git_sha=tool_sha, rendered_bytes=100)
    pricing_path = tmp_path / "pricing.json"
    pricing_raw = _canonical(_pricing().record())
    pricing_path.write_bytes(pricing_raw)
    preparation.update(
        {
            "inputs": {
                "pricing_snapshot": {
                    "path": pricing_path.name,
                    "sha256": hashlib.sha256(pricing_raw).hexdigest(),
                }
            },
            "request_set_sha256": "7" * 64,
        }
    )
    preparation_path = tmp_path / "preparation.json"
    preparation_path.write_bytes(_canonical(preparation))
    exact_rows: list[dict[str, object]] = []
    for position in range(1, 21):
        case_id = f"rk-v0.2-{position:03d}"
        request = json.loads((tmp_path / f"cases/{case_id}/request-envelope.json").read_text())
        contract = v02_candidate_contract(case_id=case_id, issue_number=position)
        row: dict[str, object] = {
            "base_sha": f"{position:040x}",
            "candidate_profile": contract.profile,
            "case_id": case_id,
            "difficulty": "lt_15m" if position <= 14 else "15m_to_1h",
            "evaluator_commitment_sha256": f"{position + 100:064x}",
            "evaluator_status": (
                "runtime_attested_gold_smoke_infrastructure_failure"
                if position == 14
                else "runtime_attested_evaluator_preflight_ready"
            ),
            "generator_projection_sha256": f"{position + 200:064x}",
            "instance_id": f"instance-{position}",
            "issue_url": f"https://github.com/owner/repo/issues/{position}",
            "mapping_selected_hunks_sha256": f"{position + 400:064x}",
            "outbound_request_sha256": request["outbound_request_sha256"],
            "rendered_input_sha256": request["rendered_input_sha256"],
            "repo": "owner/repo",
            "request_envelope_sha256": f"{position + 500:064x}",
            "smoke": position in {4, 6, 10, 11, 18},
            "source_projection_commitment_sha256": f"{position + 300:064x}",
            "test_command_profile": (
                "sympy-bin-test-v1" if contract.profile == "sympy-native-v1" else "pytest-v1"
            ),
        }
        row["case_commitment_sha256"] = runner._sha256_json(row)
        exact_rows.append(row)
    exact_record: dict[str, object] = {
        "algorithm": exact_preregistration.ALGORITHM,
        "benchmark_version": "0.2",
        "case_count": 20,
        "case_set_sha256": runner._sha256_json(
            {
                "algorithm": "reproassert-v02-exact-preregistered-case-set-v1",
                "case_commitments": [row["case_commitment_sha256"] for row in exact_rows],
            }
        ),
        "cases": exact_rows,
        "claims": {},
        "cohort_sha256": "2" * 64,
        "evidence": {},
        "frozen_at": "2026-07-11T07:30:00Z",
        "policy": {},
        "request_set_sha256": "7" * 64,
        "schema_version": "1.0.0",
        "status": "frozen_preinference_exact_image",
        "tool_git_sha": tool_sha,
    }
    exact_record["preregistration_sha256"] = exact_preregistration._self_hash(exact_record)
    exact_path = tmp_path / "preregistration.json"
    exact_path.write_bytes(exact_preregistration._canonical(exact_record) + b"\n")
    loaded_exact = load_v02_scored_preregistration(exact_path)
    campaign = SimpleNamespace(
        campaign_id="campaign-v02-test",
        case_ids=case_ids,
        preregistration_sha256=loaded_exact.raw_sha256,
        cohort_sha256="2" * 64,
        raw_sha256="3" * 64,
        decoded={"prepared_at": "2026-07-11T07:00:00Z"},
    )
    prepared = SimpleNamespace(
        root=tmp_path,
        receipt_path=preparation_path,
        receipt_sha256=hashlib.sha256(preparation_path.read_bytes()).hexdigest(),
    )
    runtime = SimpleNamespace(
        entries=tuple(SimpleNamespace(case_id=case_id) for case_id in case_ids),
        sha256="4" * 64,
    )
    smoke = SimpleNamespace(selected_case_count=20, sha256="5" * 64)
    preregistration = SimpleNamespace(
        cases=tuple(SimpleNamespace(id=case_id) for case_id in case_ids)
    )
    monkeypatch.setattr(execution_freeze, "verify_v02_campaign_freeze", lambda *_: campaign)
    monkeypatch.setattr(execution_freeze, "verify_v02_cases", lambda *_: prepared)
    monkeypatch.setattr(execution_freeze, "load_instance_runtime_manifest", lambda *_: runtime)
    monkeypatch.setattr(execution_freeze, "verify_instance_gold_smoke_receipt", lambda *_: smoke)
    monkeypatch.setattr(execution_freeze, "load_v02_preregistration", lambda *_: preregistration)
    placeholders = {
        name: tmp_path / name
        for name in (
            "campaign-freeze.json",
            "runtime.json",
            "gold-smoke.json",
        )
    }
    placeholders["preregistration.json"] = exact_path
    output_path = tmp_path / "execution-freeze.json"

    verified = execution_freeze.prepare_v02_exact_image_execution_freeze(
        campaign_freeze_path=placeholders["campaign-freeze.json"],
        preregistration_path=placeholders["preregistration.json"],
        cases_preparation_receipt=preparation_path,
        instance_runtime_manifest_path=placeholders["runtime.json"],
        gold_smoke_receipt_path=placeholders["gold-smoke.json"],
        prepared_at="2026-07-11T08:00:00Z",
        controller_git_sha=tool_sha,
        requested_model=_pricing().requested_model,
        output_path=output_path,
    )

    assert verified.campaign_id == campaign.campaign_id
    assert verified.max_campaign_microusd == 5_000_000
    assert verified.max_case_microusd == 250_000
    freeze_record = cast(dict[str, Any], json.loads(output_path.read_text()))
    assert freeze_record["claims"]["provider_calls"] == 0
    assert freeze_record["execution"]["reservation_total_microusd"] < 5_000_000
    assert len(freeze_record["request_set"]["requests"]) == 20

    approval_path = tmp_path / "approval.txt"
    approval_path.write_text(exact_approval_statement(verified.sha256) + "\n")
    authorization_path = tmp_path / "authorization.json"
    authorization = execution_freeze.authorize_v02_exact_image_execution(
        execution_freeze_path=output_path,
        campaign_freeze_path=placeholders["campaign-freeze.json"],
        preregistration_path=placeholders["preregistration.json"],
        cases_preparation_receipt=preparation_path,
        instance_runtime_manifest_path=placeholders["runtime.json"],
        gold_smoke_receipt_path=placeholders["gold-smoke.json"],
        approval_file=approval_path,
        approval_ref="user:test-fixture",
        authorized_at="2026-07-11T08:01:00Z",
        output_path=authorization_path,
    )

    assert authorization.execution_freeze_sha256 == verified.sha256
    assert authorization.campaign_id == campaign.campaign_id
    assert authorization.authorized_at == "2026-07-11T08:01:00Z"
    assert authorization.provider_calls == 0

    monkeypatch.setattr(campaign_module, "verify_v02_campaign_freeze", lambda *_: campaign)
    approval_text = exact_approval_statement(verified.sha256)
    reservations = freeze_record["execution"]["reservations"]
    policy = runner.V02ScoredRunPolicy(
        campaign_id=campaign.campaign_id,
        campaign_freeze_sha256=campaign.raw_sha256,
        execution_authorization_sha256=authorization.sha256,
        authorization_text_sha256=hashlib.sha256(approval_text.encode()).hexdigest(),
        authorized_at=authorization.authorized_at,
        request_set_sha256=verified.request_set_sha256,
        tool_git_sha=tool_sha,
        authorization_status="explicit_user_approval",
        authorization_ref="user:test-fixture",
        generator_mode="trusted_builtin_provider_adapter",
        provider="openai",
        requested_model=_pricing().requested_model,
        pricing=_pricing(),
        reserved_worst_case_microusd=max(
            cast(int, item["worst_case_microusd"]) for item in reservations
        ),
        max_case_attributable_microusd=250_000,
        max_campaign_attributable_microusd=5_000_000,
        max_case_wall_ms=600_000,
        provider_timeout_seconds=120.0,
    )
    bound = runner._verify_execution_authorization_binding(
        execution_authorization_path=authorization_path,
        exact_execution_freeze_path=output_path,
        campaign_freeze_path=placeholders["campaign-freeze.json"],
        preregistration_path=exact_path,
        case_id="rk-v0.2-001",
        rendered_input_sha256=cast(str, exact_rows[0]["rendered_input_sha256"]),
        policy=policy,
    )
    assert bound.raw_sha256 == authorization.sha256
    assert bound.request_sha256("rk-v0.2-001") == exact_rows[0]["rendered_input_sha256"]

    verification_paths = {
        "campaign_freeze_path": placeholders["campaign-freeze.json"],
        "preregistration_path": placeholders["preregistration.json"],
        "cases_preparation_receipt": preparation_path,
        "instance_runtime_manifest_path": placeholders["runtime.json"],
        "gold_smoke_receipt_path": placeholders["gold-smoke.json"],
    }
    prepare_paths = {
        **verification_paths,
        "requested_model": _pricing().requested_model,
        "controller_git_sha": tool_sha,
    }

    with pytest.raises(PolicyRejection, match="future"):
        execution_freeze.prepare_v02_exact_image_execution_freeze(
            prepared_at="2099-01-01T00:00:00Z",
            output_path=tmp_path / "rejected-future-freeze.json",
            **prepare_paths,
        )
    campaign.case_ids = tuple(reversed(case_ids))
    with pytest.raises(PolicyRejection, match="20-case preregistration"):
        execution_freeze.prepare_v02_exact_image_execution_freeze(
            prepared_at="2026-07-11T08:02:00Z",
            output_path=tmp_path / "rejected-campaign-order.json",
            **prepare_paths,
        )
    campaign.case_ids = case_ids
    runtime.entries = tuple(reversed(runtime.entries))
    with pytest.raises(PolicyRejection, match="campaign cohort"):
        execution_freeze.prepare_v02_exact_image_execution_freeze(
            prepared_at="2026-07-11T08:02:00Z",
            output_path=tmp_path / "rejected-runtime-order.json",
            **prepare_paths,
        )
    runtime.entries = tuple(SimpleNamespace(case_id=case_id) for case_id in case_ids)
    smoke.selected_case_count = 19
    with pytest.raises(PolicyRejection, match="complete 20-case denominator"):
        execution_freeze.prepare_v02_exact_image_execution_freeze(
            prepared_at="2026-07-11T08:02:00Z",
            output_path=tmp_path / "rejected-incomplete-smoke.json",
            **prepare_paths,
        )
    smoke.selected_case_count = 20
    with pytest.raises(PolicyRejection, match="Requested model differs"):
        execution_freeze.prepare_v02_exact_image_execution_freeze(
            prepared_at="2026-07-11T08:02:00Z",
            output_path=tmp_path / "rejected-model.json",
            **{**prepare_paths, "requested_model": "gpt-not-frozen"},
        )
    with pytest.raises(PolicyRejection, match="cannot predate the campaign"):
        execution_freeze.prepare_v02_exact_image_execution_freeze(
            prepared_at="2026-07-11T06:59:00Z",
            output_path=tmp_path / "rejected-campaign-chronology.json",
            **prepare_paths,
        )
    campaign.decoded["prepared_at"] = "2026-07-09T07:00:00Z"
    with pytest.raises(PolicyRejection, match="cannot predate its pricing"):
        execution_freeze.prepare_v02_exact_image_execution_freeze(
            prepared_at="2026-07-09T08:00:00Z",
            output_path=tmp_path / "rejected-pricing-chronology.json",
            **prepare_paths,
        )
    campaign.decoded["prepared_at"] = "2026-07-11T07:00:00Z"

    def replace(record: dict[str, Any], keys: tuple[str, ...], value: object) -> None:
        target = record
        for key in keys[:-1]:
            target = cast(dict[str, Any], target[key])
        target[keys[-1]] = value

    freeze_tampering = (
        ("identity", ("status",), "provider_started"),
        ("evidence", ("evidence", "gold_smoke_receipt_sha256"), "6" * 64),
        ("campaign", ("campaign", "campaign_id"), "campaign-v02-tampered"),
        ("pricing", ("pricing_snapshot", "paid_storage_microusd"), 1),
        ("request-set", ("request_set", "request_count"), 19),
        ("limits", ("execution", "max_case_attributable_microusd"), 250_001),
        ("provider", ("provider", "endpoint_host"), "example.invalid"),
        ("claims", ("claims", "provider_calls"), 1),
        ("chronology", ("prepared_at",), "2099-01-01T00:00:00Z"),
    )
    original_freeze = cast(dict[str, Any], json.loads(output_path.read_text()))
    for label, keys, value in freeze_tampering:
        tampered = cast(dict[str, Any], json.loads(json.dumps(original_freeze)))
        replace(tampered, keys, value)
        tampered["execution_freeze_sha256"] = execution_freeze._self_hash(tampered)
        tampered_path = tmp_path / f"tampered-freeze-{label}.json"
        tampered_path.write_bytes(_canonical(tampered))
        with pytest.raises(PolicyRejection):
            execution_freeze.verify_v02_exact_image_execution_freeze(
                tampered_path, **verification_paths
            )

    wrong_approval = tmp_path / "wrong-approval.txt"
    wrong_approval.write_text(exact_approval_statement("0" * 64) + "\n")
    with pytest.raises(PolicyRejection, match="exact execution-freeze hash"):
        execution_freeze.authorize_v02_exact_image_execution(
            execution_freeze_path=output_path,
            approval_file=wrong_approval,
            approval_ref="user:test-fixture",
            authorized_at="2026-07-11T08:01:00Z",
            output_path=tmp_path / "rejected-wrong-approval.json",
            **verification_paths,
        )
    with pytest.raises(PolicyRejection, match="after the exact execution freeze"):
        execution_freeze.authorize_v02_exact_image_execution(
            execution_freeze_path=output_path,
            approval_file=approval_path,
            approval_ref="user:test-fixture",
            authorized_at="2026-07-11T08:00:00Z",
            output_path=tmp_path / "rejected-same-time.json",
            **verification_paths,
        )

    authorization_path = tmp_path / "authorization.json"
    original_authorization = cast(dict[str, Any], json.loads(authorization_path.read_text()))
    authorization_tampering = (
        ("identity", ("status",), "provider_started"),
        ("binding", ("request_set_sha256",), "0" * 64),
        ("limits", ("limits", "overage_permitted"), True),
        ("statement", ("authorization", "approval_statement"), "not approved"),
        ("chronology", ("authorization", "authorized_at"), "2026-07-11T08:00:00Z"),
    )
    for label, keys, value in authorization_tampering:
        tampered = cast(dict[str, Any], json.loads(json.dumps(original_authorization)))
        replace(tampered, keys, value)
        tampered["execution_authorization_sha256"] = execution_freeze._self_hash_named(
            tampered, "execution_authorization_sha256"
        )
        tampered_path = tmp_path / f"tampered-authorization-{label}.json"
        tampered_path.write_bytes(_canonical(tampered))
        with pytest.raises(PolicyRejection):
            execution_freeze.verify_v02_exact_image_authorization(
                tampered_path,
                execution_freeze_path=output_path,
                **verification_paths,
            )


def test_schema_is_bundled_strict_and_provider_code_reads_no_key() -> None:
    root = Path(__file__).parents[1]
    for filename in (
        "benchmark-v02-execution-freeze.schema.json",
        "benchmark-v02-exact-image-authorization.schema.json",
    ):
        public = root / "schemas" / filename
        bundled = root / "src/reproassert/schemas" / filename
        assert public.read_bytes() == bundled.read_bytes()
        jsonschema.Draft202012Validator.check_schema(json.loads(public.read_text()))
    source = (root / "src/reproassert/benchmark_v02_execution_freeze.py").read_text()
    assert "OPENAI_API_KEY" not in source
    assert "os.environ" not in source
    assert "exact_approval_statement" in source


def test_freeze_parser_helpers_fail_closed_on_hostile_artifacts(tmp_path: Path) -> None:
    with pytest.raises(PolicyRejection, match="escapes"):
        execution_freeze._safe_relative("/tmp/escape.json")
    with pytest.raises(PolicyRejection, match="escapes"):
        execution_freeze._safe_relative("../escape.json")
    with pytest.raises(PolicyRejection, match="must be an object"):
        execution_freeze._mapping([], "hostile mapping")
    with pytest.raises(PolicyRejection, match="invalid"):
        execution_freeze._digest("not-a-digest", "digest")
    with pytest.raises(PolicyRejection, match="invalid"):
        execution_freeze._git_sha("not-a-git-sha", "Git SHA")
    with pytest.raises(PolicyRejection, match="invalid"):
        execution_freeze._bounded_text("x\n", "reference", 1, 20)
    with pytest.raises(PolicyRejection, match="invalid JSON"):
        execution_freeze._decode_canonical(b"{broken\n", "artifact")
    with pytest.raises(PolicyRejection, match="not canonical JSON"):
        execution_freeze._decode_canonical(b'{"value": 1}\n', "artifact")
    with pytest.raises(PolicyRejection, match="invalid JSON"):
        execution_freeze._decode_canonical(b'{"value":1,"value":2}\n', "artifact")
    with pytest.raises(PolicyRejection, match="invalid JSON"):
        execution_freeze._decode_canonical(b'{"value":NaN}\n', "artifact")

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * 9)
    with pytest.raises(PolicyRejection, match="size limit"):
        execution_freeze._read_regular(oversized, 8, "artifact")


def test_preparation_request_index_rejects_every_binding_break(tmp_path: Path) -> None:
    tool_sha = "9" * 40
    case_ids = tuple(f"rk-v0.2-{position:03d}" for position in range(1, 21))

    short_root = tmp_path / "short"
    short = _request_preparation(short_root, tool_git_sha=tool_sha, rendered_bytes=8)
    cast(list[object], short["packages"]).pop()
    with pytest.raises(PolicyRejection, match="package index"):
        _preparation_requests(short_root, short, case_ids, controller_git_sha=tool_sha)

    order_root = tmp_path / "order"
    wrong_order = _request_preparation(order_root, tool_git_sha=tool_sha, rendered_bytes=8)
    cast(dict[str, object], cast(list[object], wrong_order["packages"])[0])["case_id"] = (
        "rk-v0.2-020"
    )
    with pytest.raises(PolicyRejection, match="ordering"):
        _preparation_requests(order_root, wrong_order, case_ids, controller_git_sha=tool_sha)

    def mutate_request(name: str, mutation: str) -> tuple[Path, dict[str, object]]:
        root = tmp_path / name
        preparation = _request_preparation(root, tool_git_sha=tool_sha, rendered_bytes=8)
        request_path = root / "cases/rk-v0.2-001/request-envelope.json"
        package_path = root / "cases/rk-v0.2-001/package.json"
        request = cast(dict[str, Any], json.loads(request_path.read_text()))
        if mutation == "case":
            request["case_id"] = "rk-v0.2-999"
        elif mutation == "input":
            request["provider_request"]["input"] = 7
        elif mutation == "rendered-hash":
            request["rendered_input_sha256"] = "0" * 64
        request_raw = _canonical(request)
        request_path.write_bytes(request_raw)
        package = cast(dict[str, Any], json.loads(package_path.read_text()))
        package["request_envelope"]["sha256"] = hashlib.sha256(request_raw).hexdigest()
        package_path.write_bytes(_canonical(package))
        return root, preparation

    digest_root = tmp_path / "digest"
    bad_digest = _request_preparation(digest_root, tool_git_sha=tool_sha, rendered_bytes=8)
    package_path = digest_root / "cases/rk-v0.2-001/package.json"
    package = cast(dict[str, Any], json.loads(package_path.read_text()))
    package["request_envelope"]["sha256"] = "0" * 64
    package_path.write_bytes(_canonical(package))
    with pytest.raises(PolicyRejection, match="reference digest"):
        _preparation_requests(digest_root, bad_digest, case_ids, controller_git_sha=tool_sha)

    for name, mutation, message in (
        ("case", "case", "case identity"),
        ("input", "input", "rendered input"),
        ("rendered-hash", "rendered-hash", "Rendered input hash"),
    ):
        root, preparation = mutate_request(name, mutation)
        with pytest.raises(PolicyRejection, match=message):
            _preparation_requests(root, preparation, case_ids, controller_git_sha=tool_sha)

    pricing_root = tmp_path / "pricing"
    pricing_root.mkdir()
    pricing_path = pricing_root / "pricing.json"
    pricing_path.write_bytes(_canonical(_pricing().record()))
    bad_pricing_ref = {"inputs": {"pricing_snapshot": {"path": "pricing.json", "sha256": "0" * 64}}}
    with pytest.raises(PolicyRejection, match="reference digest"):
        execution_freeze._preparation_pricing(pricing_root, bad_pricing_ref)
