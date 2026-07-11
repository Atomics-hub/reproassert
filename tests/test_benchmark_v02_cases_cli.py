from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator, ValidationError  # type: ignore[import-untyped]

from reproassert import cli
from reproassert.benchmark_v02_cases import V02CasesPreparation
from reproassert.schema import schema_text

ROOT_SCHEMA = Path("schemas/benchmark-v02-cases-preparation.schema.json")
HEX64 = "a" * 64


def _inputs(tmp_path: Path) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for name in ("cohort", "dataset", "hidden", "pricing"):
        path = tmp_path / f"{name}.json"
        path.write_text("{}\n")
        paths[name] = path
    sources = tmp_path / "sources"
    sources.mkdir()
    paths["sources"] = sources
    return paths


def _prepared(tmp_path: Path) -> V02CasesPreparation:
    private = tmp_path / "evaluator-private" / "v02-case-preparation"
    private.mkdir(parents=True)
    receipt = private / "benchmark-v02-cases-preparation.json"
    receipt.write_text("{}\n")
    return V02CasesPreparation(
        root=private,
        receipt_path=receipt,
        receipt_sha256=HEX64,
        case_count=20,
        dependency_ready_count=0,
        campaign_ready_count=0,
    )


def test_prepare_cases_cli_emits_only_safe_zero_spend_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    prepared = _prepared(tmp_path)
    observed: dict[str, object] = {}

    def fake_prepare(**kwargs: object) -> V02CasesPreparation:
        observed.update(kwargs)
        return prepared

    monkeypatch.setattr(cli, "prepare_v02_cases", fake_prepare)
    output_root = tmp_path / "output"
    result = CliRunner().invoke(
        cli.main,
        [
            "benchmark",
            "prepare-v02-cases",
            "--cohort-plan",
            str(inputs["cohort"]),
            "--dataset-preparation-receipt",
            str(inputs["dataset"]),
            "--hidden-extraction-receipt",
            str(inputs["hidden"]),
            "--object-sources-root",
            str(inputs["sources"]),
            "--pricing-snapshot",
            str(inputs["pricing"]),
            "--tool-git-sha",
            "b" * 40,
            "--prepared-at",
            "2026-07-10T12:00:00Z",
            "--output-root",
            str(output_root),
        ],
    )

    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary == {
        "campaign_ready_count": 0,
        "case_count": 20,
        "dependency_ready_count": 0,
        "preparation_receipt_sha256": HEX64,
        "provider_calls": 0,
        "provider_execution_enabled": False,
        "status": "prepared_review_required_provider_disabled",
    }
    assert str(prepared.root) not in result.output
    assert str(inputs["hidden"]) not in result.output
    assert observed["hidden_extraction_receipt"] == inputs["hidden"]
    assert observed["dependency_plans_root"] is None


def test_verify_cases_cli_never_emits_evaluator_private_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepared(tmp_path)
    monkeypatch.setattr(cli, "verify_v02_cases", lambda _: prepared)

    result = CliRunner().invoke(
        cli.main,
        ["benchmark", "verify-v02-cases", str(prepared.receipt_path)],
    )

    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary["verified"] is True
    assert summary["provider_calls"] == 0
    assert summary["provider_execution_enabled"] is False
    assert str(prepared.root) not in result.output
    assert prepared.receipt_path.name not in result.output


def test_cases_preparation_schema_is_bundled_and_rejects_provider_enablement() -> None:
    root_text = ROOT_SCHEMA.read_text()
    assert schema_text("benchmark-v02-cases-preparation") == root_text
    schema = json.loads(root_text)
    Draft202012Validator.check_schema(schema)
    record = {
        "algorithm": "reproassert-v02-cases-preparation-v1",
        "benchmark_version": "0.2",
        "case_count": 20,
        "claims": {
            "campaign_ready_count": 0,
            "chronology": "unproven",
            "model_or_provider_invoked": False,
            "provider_calls": 0,
            "reviewer_approvals_fabricated": False,
        },
        "dependency_ready_count": 0,
        "inputs": {
            "cohort_plan": {"bytes": 1, "path": "inputs/cohort.json", "sha256": HEX64},
            "dataset_preparation": {
                "bytes": 1,
                "path": "/private/dataset.json",
                "sha256": HEX64,
                "storage": "evaluator_private_external",
            },
            "dependency_plans_root": None,
            "hidden_extraction": {
                "bytes": 1,
                "path": "/private/hidden.json",
                "sha256": HEX64,
                "storage": "evaluator_private_external",
            },
            "object_sources_root": {
                "path": "/private/sources",
                "storage": "evaluator_private_external_directory",
            },
            "pricing_snapshot": {
                "bytes": 1,
                "path": "inputs/pricing.json",
                "sha256": HEX64,
            },
        },
        "packages": [
            {
                "bytes": 1,
                "case_id": f"rk-v0.2-{position:03d}",
                "path": f"cases/rk-v0.2-{position:03d}/package.json",
                "sha256": HEX64,
                "status": "pre_review_preparation_blocked",
            }
            for position in range(1, 21)
        ],
        "prepared_at": "2026-07-10T12:00:00Z",
        "preparation_set_sha256": HEX64,
        "provider_execution_enabled": False,
        "request_set_sha256": HEX64,
        "receipt_sha256": HEX64,
        "schema_version": "1.0.0",
        "spend_gate": {"bytes": 1, "path": "spend-gate.json", "sha256": HEX64},
        "status": "prepared_review_required_provider_disabled",
        "tool": {"git_sha": "b" * 40, "provenance": "publisher_declared_revision"},
    }
    validator = Draft202012Validator(schema)
    validator.validate(record)

    record["provider_execution_enabled"] = True
    with pytest.raises(ValidationError):
        validator.validate(record)
