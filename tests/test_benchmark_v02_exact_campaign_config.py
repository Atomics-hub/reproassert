from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from reproassert import benchmark_v02_exact_campaign_config as config_builder
from reproassert import benchmark_v02_exact_campaign_controller as controller
from reproassert.benchmark_v02_exact_campaign_controller import (
    ExactCampaignCase,
    ExactCampaignPaths,
    load_v02_exact_campaign_config,
)
from reproassert.cli import main
from reproassert.errors import PolicyRejection

SHA = "a" * 64
GIT_SHA = "b" * 40
AUTHORIZED_AT = "2026-07-11T00:00:00Z"
PREPARED_AT = "2026-07-11T00:00:01Z"
EXECUTED_AT = "2026-07-11T00:00:02Z"


@pytest.mark.parametrize(
    ("value", "microsecond"),
    [
        ("2026-07-11T00:00:01.5Z", 500_000),
        ("2026-07-11T00:00:01.1234567Z", 123_456),
    ],
)
def test_timestamp_fraction_is_interpreter_independent(value: str, microsecond: int) -> None:
    assert config_builder._timestamp_value(value).microsecond == microsecond


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _preparation(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "preparation"
    root.mkdir(mode=0o700)
    inputs = root / "inputs"
    inputs.mkdir(mode=0o700)
    plan = inputs / "cohort-plan.json"
    plan.write_text("plan\n")
    object_sources = tmp_path / "object-sources"
    object_sources.mkdir(mode=0o700)
    packages: list[dict[str, object]] = []
    for index in range(1, 21):
        case_id = f"rk-v0.2-{index:03d}"
        case_root = root / "cases" / case_id
        case_root.mkdir(parents=True, mode=0o700)
        projection = case_root / "generator-projection.json"
        projection.write_text(f"{case_id}\n")
        source_root = object_sources / f"{case_id}-object-v2"
        source_root.mkdir(mode=0o700)
        receipt = source_root / "benchmark-object-source-receipt.json"
        receipt.write_text(f"{case_id}-receipt\n")
        package = {
            "case_id": case_id,
            "generator_projection": {
                "bytes": projection.stat().st_size,
                "path": f"cases/{case_id}/generator-projection.json",
                "sha256": _sha(projection),
            },
            "source": {"receipt_path": str(receipt), "receipt_sha256": _sha(receipt)},
        }
        package_path = case_root / "package.json"
        _write_json(package_path, package)
        packages.append(
            {
                "case_id": case_id,
                "path": f"cases/{case_id}/package.json",
                "sha256": _sha(package_path),
                "status": "pre_review_preparation_blocked",
            }
        )
    receipt_path = root / "benchmark-v02-cases-preparation.json"
    _write_json(
        receipt_path,
        {
            "inputs": {
                "cohort_plan": {
                    "bytes": plan.stat().st_size,
                    "path": "inputs/cohort-plan.json",
                    "sha256": _sha(plan),
                },
                "object_sources_root": {
                    "path": str(object_sources),
                    "storage": "evaluator_private_external_directory",
                },
            },
            "packages": packages,
        },
    )
    return root, receipt_path


def test_case_paths_are_canonically_derived_for_all_twenty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, receipt = _preparation(tmp_path)
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    calls: list[str] = []

    def issue(_receipt: Path, **kwargs: object) -> object:
        case_id = str(kwargs["expected_case_id"])
        path = Path(str(kwargs["source_evidence_receipt_path"]))
        path.write_text(f"{case_id}-evidence\n")
        calls.append(case_id)
        return object()

    monkeypatch.setattr(config_builder, "issue_v02_source_evidence_from_object_receipt", issue)
    cases = config_builder._derive_cases(
        preparation_root=root,
        preparation_receipt=receipt,
        cohort_plan=tmp_path / "ignored-plan.json",
        source_evidence_write_root=evidence,
        source_evidence_config_root=evidence,
    )

    assert [case.case_id for case in cases] == [f"rk-v0.2-{i:03d}" for i in range(1, 21)]
    assert calls == [case.case_id for case in cases]
    assert all(case.object_source_receipt_sha256 is not None for case in cases)
    assert all(case.object_source_plan == root / "inputs" / "cohort-plan.json" for case in cases)
    assert all(case.generator_projection.parent.name == case.case_id for case in cases)


@pytest.mark.parametrize("mutation", ["null_receipt_sha", "swapped_receipt", "projection_escape"])
def test_case_derivation_rejects_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    root, receipt = _preparation(tmp_path)
    record = json.loads(receipt.read_text())
    first_path = root / record["packages"][0]["path"]
    first = json.loads(first_path.read_text())
    if mutation == "null_receipt_sha":
        first["source"]["receipt_sha256"] = None
    elif mutation == "swapped_receipt":
        second_path = root / record["packages"][1]["path"]
        second = json.loads(second_path.read_text())
        first["source"]["receipt_path"] = second["source"]["receipt_path"]
    else:
        first["generator_projection"]["path"] = "../escape.json"
    _write_json(first_path, first)
    record["packages"][0]["sha256"] = _sha(first_path)
    _write_json(receipt, record)
    monkeypatch.setattr(
        config_builder, "issue_v02_source_evidence_from_object_receipt", lambda *_a, **_k: object()
    )

    with pytest.raises(PolicyRejection):
        config_builder._derive_cases(
            preparation_root=root,
            preparation_receipt=receipt,
            cohort_plan=tmp_path / "ignored.json",
            source_evidence_write_root=tmp_path / "evidence",
            source_evidence_config_root=tmp_path / "evidence",
        )


def _inputs(tmp_path: Path) -> config_builder.ExactCampaignConfigInputs:
    values: dict[str, Any] = {}
    for name in config_builder.ExactCampaignConfigInputs.__dataclass_fields__:
        if name == "runtime_manifest_sha256":
            values[name] = SHA
        elif name == "issue_responses_root":
            path = tmp_path / name
            path.mkdir(mode=0o700)
            values[name] = path
        else:
            path = tmp_path / f"{name}.json"
            path.write_text(f"{name}\n")
            values[name] = path
    return config_builder.ExactCampaignConfigInputs(**values)


def _fake_derive(
    inputs: config_builder.ExactCampaignConfigInputs,
) -> Callable[..., tuple[ExactCampaignPaths, tuple[ExactCampaignCase, ...], dict[str, object]]]:
    def derive(
        *,
        campaign_root: Path,
        source_evidence_write_root: Path | None,
        source_evidence_config_root: Path,
        **_kwargs: object,
    ) -> tuple[ExactCampaignPaths, tuple[ExactCampaignCase, ...], dict[str, object]]:
        if source_evidence_write_root is not None:
            for index in range(1, 21):
                (source_evidence_write_root / f"rk-v0.2-{index:03d}.json").write_text("evidence\n")
        cases = tuple(
            ExactCampaignCase(
                case_id=f"rk-v0.2-{index:03d}",
                generator_projection=inputs.cases_preparation,
                object_source_receipt=inputs.cases_preparation,
                object_source_plan=inputs.cohort_plan,
                source_evidence_receipt=source_evidence_config_root / f"rk-v0.2-{index:03d}.json",
                object_source_receipt_sha256=SHA,
            )
            for index in range(1, 21)
        )
        paths = ExactCampaignPaths(
            **{
                **vars(inputs),
                "ledger": campaign_root / "ledger" / "scored-events.jsonl",
                "attempts_root": campaign_root / "attempts",
                "progress": campaign_root / "controller" / "progress.json",
            }
        )
        return (
            paths,
            cases,
            {
                "artifact_sha256": {"execution_authorization": SHA},
                "authorization_at": AUTHORIZED_AT,
                "campaign_id": "campaign_test",
                "case_binding_set_sha256": SHA,
                "execution_freeze_sha256": SHA,
                "max_campaign_microusd": 5_000_000,
                "max_case_microusd": 250_000,
                "overage_permitted": False,
                "provider": "openai",
                "requested_model": "gpt-test",
                "request_set_sha256": SHA,
            },
        )

    return derive


def test_prepare_is_atomic_private_idempotent_and_provider_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    inputs = _inputs(parent)
    monkeypatch.setattr(config_builder, "_derive", _fake_derive(inputs))
    getenv_calls: list[str] = []
    monkeypatch.setattr(os, "getenv", lambda key, *_a: getenv_calls.append(key))
    output = parent / "run"

    first = config_builder.prepare_v02_exact_campaign_config(
        inputs=inputs,
        output_root=output,
        prepared_at=PREPARED_AT,
        executed_at=EXECUTED_AT,
        tool_git_sha=GIT_SHA,
    )
    before = (output / "controller" / "config.json").read_bytes()
    second = config_builder.prepare_v02_exact_campaign_config(
        inputs=inputs,
        output_root=output,
        prepared_at=PREPARED_AT,
        executed_at=EXECUTED_AT,
        tool_git_sha=GIT_SHA,
    )

    assert first.config_sha256 == second.config_sha256
    assert (output / "controller" / "config.json").read_bytes() == before
    assert getenv_calls == []
    assert first.summary()["provider_calls"] == 0
    schema = json.loads(Path("schemas/benchmark-v02-exact-campaign-config.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(json.loads(before))
    assert (
        Path("src/reproassert/schemas/benchmark-v02-exact-campaign-config.schema.json").read_bytes()
        == Path("schemas/benchmark-v02-exact-campaign-config.schema.json").read_bytes()
    )
    for name in ("run", "run/attempts", "run/controller", "run/ledger", "run/source-evidence"):
        assert (parent / name).stat().st_mode & 0o777 == 0o700


def test_atomic_failure_leaves_no_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    inputs = _inputs(parent)
    output = parent / "run"
    monkeypatch.setattr(
        config_builder,
        "_derive",
        lambda **_kwargs: (_ for _ in ()).throw(PolicyRejection("test", "mid-write")),
    )
    with pytest.raises(PolicyRejection, match="mid-write"):
        config_builder.prepare_v02_exact_campaign_config(
            inputs=inputs,
            output_root=output,
            prepared_at=PREPARED_AT,
            executed_at=EXECUTED_AT,
            tool_git_sha=GIT_SHA,
        )
    assert not output.exists()


def test_output_root_symlink_is_rejected_without_mutating_target(tmp_path: Path) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    target = parent / "target"
    target.mkdir(mode=0o700)
    marker = target / "marker"
    marker.write_text("unchanged")
    link = parent / "run"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(PolicyRejection, match="symlink"):
        config_builder.prepare_v02_exact_campaign_config(
            inputs=_inputs(parent),
            output_root=link,
            prepared_at=PREPARED_AT,
            executed_at=EXECUTED_AT,
            tool_git_sha=GIT_SHA,
        )
    assert marker.read_text() == "unchanged"


def _authority_inputs(tmp_path: Path) -> config_builder.ExactCampaignConfigInputs:
    inputs = _inputs(tmp_path)
    gold = b"gold specs\n"
    inputs.gold_specs.write_bytes(gold)
    records: dict[Path, object] = {
        inputs.cases_preparation: {"tool": {"git_sha": GIT_SHA}},
        inputs.chronology: {"tool_git_sha": GIT_SHA},
        inputs.mapping_preparation: {"tool": {"git_sha": GIT_SHA}},
        inputs.capability_index: {"tool_git_sha": GIT_SHA},
        inputs.exact_preregistration: {"tool_git_sha": GIT_SHA},
        inputs.campaign_freeze: {"tool": {"git_sha": GIT_SHA}},
        inputs.execution_freeze: {"controller_git_sha": GIT_SHA},
        inputs.gold_smoke_receipt: {
            "inputs": {"gold_specs_sha256": hashlib.sha256(gold).hexdigest()},
            "tool_git_sha": GIT_SHA,
        },
    }
    for path, record in records.items():
        _write_json(path, record)
    return inputs


def _mock_exact_authorities(
    monkeypatch: pytest.MonkeyPatch,
    inputs: config_builder.ExactCampaignConfigInputs,
    *,
    authorization_at: str = AUTHORIZED_AT,
    campaign_cap: int = 5_000_000,
) -> None:
    monkeypatch.setattr(
        config_builder,
        "verify_v02_cases",
        lambda _path: SimpleNamespace(
            root=inputs.cases_preparation.parent, case_count=20, provider_calls=0
        ),
    )
    monkeypatch.setattr(
        config_builder,
        "verify_v02_exact_preregistration",
        lambda *_a, **_k: SimpleNamespace(case_count=20, provider_calls=0),
    )
    monkeypatch.setattr(
        config_builder,
        "verify_v02_campaign_freeze",
        lambda *_a, **_k: SimpleNamespace(campaign_id="campaign_test", case_ids=tuple(range(20))),
    )
    monkeypatch.setattr(
        config_builder,
        "verify_v02_exact_image_capability_index",
        lambda *_a, **_k: SimpleNamespace(case_count=20, provider_calls=0),
    )
    monkeypatch.setattr(
        config_builder,
        "verify_v02_exact_image_execution_freeze",
        lambda *_a, **_k: SimpleNamespace(
            campaign_id="campaign_test",
            max_campaign_microusd=campaign_cap,
            max_case_microusd=250_000,
            provider_calls=0,
            requested_model="gpt-test",
            request_set_sha256=SHA,
            sha256=SHA,
        ),
    )
    monkeypatch.setattr(
        config_builder,
        "verify_v02_exact_image_authorization",
        lambda *_a, **_k: SimpleNamespace(
            campaign_id="campaign_test",
            provider_calls=0,
            authorized_at=authorization_at,
        ),
    )
    evidence = inputs.cases_preparation.parent / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    for index in range(1, 21):
        (evidence / f"rk-v0.2-{index:03d}.json").write_text("evidence\n")
    cases = tuple(
        ExactCampaignCase(
            case_id=f"rk-v0.2-{index:03d}",
            generator_projection=inputs.cases_preparation,
            object_source_receipt=inputs.cases_preparation,
            object_source_plan=inputs.cohort_plan,
            source_evidence_receipt=evidence / f"rk-v0.2-{index:03d}.json",
            object_source_receipt_sha256=SHA,
        )
        for index in range(1, 21)
    )
    monkeypatch.setattr(config_builder, "_derive_cases", lambda **_kwargs: cases)


@pytest.mark.parametrize("failure", ["gold", "tool", "cap", "chronology"])
def test_fresh_authority_derivation_rejects_critical_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    inputs = _authority_inputs(tmp_path)
    _mock_exact_authorities(
        monkeypatch,
        inputs,
        authorization_at=("2026-07-11T00:00:02Z" if failure == "chronology" else AUTHORIZED_AT),
        campaign_cap=(5_000_001 if failure == "cap" else 5_000_000),
    )
    if failure == "gold":
        inputs.gold_specs.write_text("tampered gold\n")
    elif failure == "tool":
        record = json.loads(inputs.gold_smoke_receipt.read_text())
        record["tool_git_sha"] = "c" * 40
        _write_json(inputs.gold_smoke_receipt, record)

    with pytest.raises(PolicyRejection):
        config_builder._derive(
            inputs=inputs,
            campaign_root=tmp_path / "run",
            source_evidence_write_root=None,
            source_evidence_config_root=tmp_path / "evidence",
            prepared_at=PREPARED_AT,
            executed_at=EXECUTED_AT,
            tool_git_sha=GIT_SHA,
        )


def test_existing_workspace_drift_rejects_without_changing_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    inputs = _inputs(parent)
    monkeypatch.setattr(config_builder, "_derive", _fake_derive(inputs))
    output = parent / "run"
    config_builder.prepare_v02_exact_campaign_config(
        inputs=inputs,
        output_root=output,
        prepared_at=PREPARED_AT,
        executed_at=EXECUTED_AT,
        tool_git_sha=GIT_SHA,
    )
    path = output / "controller" / "config.json"
    before = path.read_bytes()
    with pytest.raises(PolicyRejection, match="differs"):
        config_builder.prepare_v02_exact_campaign_config(
            inputs=inputs,
            output_root=output,
            prepared_at="2026-07-11T00:00:01.5Z",
            executed_at=EXECUTED_AT,
            tool_git_sha=GIT_SHA,
        )
    assert path.read_bytes() == before


def test_config_self_hash_tamper_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    inputs = _inputs(parent)
    monkeypatch.setattr(config_builder, "_derive", _fake_derive(inputs))
    output = parent / "run"
    config_builder.prepare_v02_exact_campaign_config(
        inputs=inputs,
        output_root=output,
        prepared_at=PREPARED_AT,
        executed_at=EXECUTED_AT,
        tool_git_sha=GIT_SHA,
    )
    path = output / "controller" / "config.json"
    record = json.loads(path.read_text())
    record["tool_git_sha"] = "c" * 40
    path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(PolicyRejection, match="identity"):
        load_v02_exact_campaign_config(path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_campaign_microusd", 5_000_001),
        ("max_case_microusd", 250_001),
        ("overage_permitted", True),
        ("case_binding_set_sha256", "0" * 63),
    ],
)
def test_binding_validation_rejects_cap_and_denominator_tamper(field: str, value: object) -> None:
    binding = {
        "artifact_sha256": {"authorization": SHA},
        "authorization_at": AUTHORIZED_AT,
        "campaign_id": "campaign_test",
        "case_binding_set_sha256": SHA,
        "execution_freeze_sha256": SHA,
        "max_campaign_microusd": 5_000_000,
        "max_case_microusd": 250_000,
        "overage_permitted": False,
        "provider": "openai",
        "requested_model": "gpt-test",
        "request_set_sha256": SHA,
    }
    binding[field] = value
    with pytest.raises(PolicyRejection):
        config_builder.validate_config_bindings(binding)


def test_loaded_config_rejects_19_case_denominator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    inputs = _inputs(parent)
    monkeypatch.setattr(config_builder, "_derive", _fake_derive(inputs))
    output = parent / "run"
    config_builder.prepare_v02_exact_campaign_config(
        inputs=inputs,
        output_root=output,
        prepared_at=PREPARED_AT,
        executed_at=EXECUTED_AT,
        tool_git_sha=GIT_SHA,
    )
    path = output / "controller" / "config.json"
    record = json.loads(path.read_text())
    record["cases"].pop()
    record["config_sha256"] = config_builder.config_self_hash(record)
    path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(PolicyRejection, match="exactly 20"):
        load_v02_exact_campaign_config(path)


def test_cli_exposes_prepare_and_verify_commands() -> None:
    prepare = CliRunner().invoke(main, ["benchmark", "prepare-v02-exact-campaign-config", "--help"])
    verify = CliRunner().invoke(main, ["benchmark", "verify-v02-exact-campaign-config", "--help"])
    assert prepare.exit_code == 0
    assert "provider-free exact 20-case" in prepare.output
    assert verify.exit_code == 0
    assert "every upstream authority" in verify.output


def test_run_rejects_fresh_config_verifier_failure_before_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        config_builder,
        "verify_v02_exact_campaign_config",
        lambda _path: (_ for _ in ()).throw(PolicyRejection("test", "fresh authority failed")),
    )
    monkeypatch.setattr(
        controller,
        "_ProductionRuntime",
        lambda: (_ for _ in ()).throw(AssertionError("runtime constructed before verification")),
    )
    with pytest.raises(PolicyRejection, match="fresh authority failed"):
        controller.run_v02_exact_campaign(tmp_path / "config.json")


def test_run_rejects_canonical_config_swap_after_fresh_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    inputs = _inputs(parent)
    monkeypatch.setattr(config_builder, "_derive", _fake_derive(inputs))
    output = parent / "run"
    config_builder.prepare_v02_exact_campaign_config(
        inputs=inputs,
        output_root=output,
        prepared_at=PREPARED_AT,
        executed_at=EXECUTED_AT,
        tool_git_sha=GIT_SHA,
    )
    path = output / "controller" / "config.json"
    original_verify = config_builder.verify_v02_exact_campaign_config

    def verify_then_swap(config_path: Path) -> object:
        authority = original_verify(config_path)
        record = json.loads(config_path.read_text())
        record["prepared_at"] = "2026-07-11T00:00:01.5Z"
        record["config_sha256"] = config_builder.config_self_hash(record)
        config_path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        return authority

    monkeypatch.setattr(config_builder, "verify_v02_exact_campaign_config", verify_then_swap)
    monkeypatch.setattr(
        controller,
        "_ProductionRuntime",
        lambda: (_ for _ in ()).throw(AssertionError("runtime constructed after config swap")),
    )
    with pytest.raises(PolicyRejection, match="changed after fresh verification"):
        controller.run_v02_exact_campaign(path)
