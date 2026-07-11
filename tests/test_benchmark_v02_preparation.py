from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

import reproassert.benchmark_v02_preparation as preparation
import reproassert.cli as cli
import reproassert.semantic_issuer as semantic_issuer
from reproassert.errors import PolicyRejection


def _plan() -> dict[str, object]:
    return {
        "cases": [
            {
                "case_id": f"rk-v0.2-{ordinal:03d}",
                "instance_id": f"owner__repo-{ordinal}",
                "repo": "owner/repo",
                "issue_url": f"https://github.com/owner/repo/issues/{ordinal}",
                "base_sha": f"{ordinal:040x}",
            }
            for ordinal in range(1, 21)
        ]
    }


def _projection(case_id: str) -> bytes:
    value = {
        "case_id": case_id,
        "issue_text": f"bounded issue text for {case_id}",
        "issue_text_chronology": "chronology_unproven",
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _boundary_attestation(*, image_digest: str | None = None) -> bytes:
    value = {
        "algorithm": "reproassert-v02-dataset-container-attestation-v1",
        "container_inspection_sha256": "1" * 64,
        "image_digest": image_digest or preparation.FROZEN_V02_DATASET_PARSER_IMAGE_ID,
        "inputs": {"fixture": True},
        "parser_output_bytes": 10,
        "parser_output_sha256": "2" * 64,
        "parser_receipt_sha256": hashlib.sha256(b'{"parser":"receipt"}\n').hexdigest(),
        "policy": {"network_mode": "none"},
        "production_eligible": True,
        "upstream_evidence_sha256": "3" * 64,
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _install_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preparation, "load_v02_leak_audited_cohort_plan", lambda _path: _plan())
    monkeypatch.setattr(
        preparation,
        "render_prepared_v02_issue_snapshot_projection",
        lambda _receipt, _plan_path, *, case_id: _projection(case_id),
    )
    monkeypatch.setattr(preparation, "load_prepared_v02_dataset_receipt", lambda _path: {})
    monkeypatch.setattr(
        preparation,
        "run_attested_v02_dataset_parser",
        lambda **_kwargs: SimpleNamespace(
            parser_receipt=b'{"parser":"receipt"}\n',
            boundary_attestation=_boundary_attestation(),
            production_eligible=True,
        ),
    )


def _inputs(tmp_path: Path) -> dict[str, Path]:
    values = {
        "tdd_id_list_path": tmp_path / "id-list.txt",
        "source_dataset_path": tmp_path / "dataset.parquet",
        "upstream_object_witness_path": tmp_path / "witness.json",
        "cohort_plan_path": tmp_path / "plan.json",
    }
    for name, path in values.items():
        path.write_bytes(f"fixture:{name}\n".encode())
    return values


def test_prepares_and_freshly_verifies_twenty_provider_free_projections(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install_fakes(monkeypatch)
    inputs = _inputs(tmp_path)
    output = tmp_path / "private"
    output.mkdir(mode=0o700)

    result = preparation.prepare_v02_dataset_inputs(
        output_root=output,
        image_digest=preparation.FROZEN_V02_DATASET_PARSER_IMAGE_ID,
        prepared_at="2026-07-10T23:59:59Z",
        **inputs,
    )

    assert result.case_count == 20
    assert result.provider_calls == 0
    assert result.parser_receipt_sha256 == hashlib.sha256(b'{"parser":"receipt"}\n').hexdigest()
    record = json.loads(result.receipt_path.read_text())
    schema = json.loads(Path("schemas/benchmark-v02-dataset-preparation.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(record)
    assert record["claims"] == {
        "campaign_readiness_changed": False,
        "issue_text_chronology": "chronology_unproven",
        "model_or_provider_invoked": False,
        "provider_calls": 0,
    }
    assert len(cast(dict[str, object], record["outputs"])["projections"]) == 20  # type: ignore[arg-type]
    assert preparation.verify_v02_dataset_preparation(result.receipt_path) == result
    marker = object()
    monkeypatch.setattr(
        semantic_issuer,
        "issue_v02_dataset_evidence_from_attested_parse",
        lambda **_kwargs: marker,
    )
    assert (
        preparation.issue_v02_dataset_evidence_from_preparation(
            result.receipt_path, case_id="rk-v0.2-001"
        )
        is marker
    )


def test_preparation_rejects_overwrite_tampering_and_duplicate_keys(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install_fakes(monkeypatch)
    inputs = _inputs(tmp_path)
    output = tmp_path / "private"
    output.mkdir(mode=0o700)
    with pytest.raises(PolicyRejection, match="trusted image"):
        preparation.prepare_v02_dataset_inputs(
            output_root=output,
            image_digest=f"sha256:{'b' * 64}",
            prepared_at="2026-07-10T23:59:59Z",
            **inputs,
        )
    result = preparation.prepare_v02_dataset_inputs(
        output_root=output,
        image_digest=preparation.FROZEN_V02_DATASET_PARSER_IMAGE_ID,
        prepared_at="2026-07-10T23:59:59Z",
        **inputs,
    )
    with pytest.raises(PolicyRejection, match="overwrite"):
        preparation.prepare_v02_dataset_inputs(
            output_root=output,
            image_digest=preparation.FROZEN_V02_DATASET_PARSER_IMAGE_ID,
            prepared_at="2026-07-10T23:59:59Z",
            **inputs,
        )

    projection = result.root / "generator-projections/rk-v0.2-001.json"
    projection.write_text("tampered\n")
    with pytest.raises(PolicyRejection, match="commitment"):
        preparation.verify_v02_dataset_preparation(result.receipt_path)

    projection.write_bytes(_projection("rk-v0.2-001"))
    record = json.loads(result.receipt_path.read_text())
    outputs = cast(dict[str, object], record["outputs"])
    attestation_ref = cast(dict[str, object], outputs["boundary_attestation"])
    attestation = result.root / cast(str, attestation_ref["path"])
    forged_attestation = _boundary_attestation(image_digest=f"sha256:{'f' * 64}")
    attestation.write_bytes(forged_attestation)
    attestation_ref["bytes"] = len(forged_attestation)
    attestation_ref["sha256"] = hashlib.sha256(forged_attestation).hexdigest()
    record["preparation_sha256"] = preparation._self_hash(record)
    result.receipt_path.write_bytes(preparation._canonical(record) + b"\n")
    with pytest.raises(PolicyRejection, match="boundary attestation"):
        preparation.verify_v02_dataset_preparation(result.receipt_path)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"1.0.0","schema_version":"1.0.0"}\n')
    duplicate.parent.chmod(0o700)
    with pytest.raises(PolicyRejection, match="invalid JSON"):
        preparation.load_v02_dataset_preparation(duplicate)


def test_schema_copies_are_identical() -> None:
    assert (
        Path("schemas/benchmark-v02-dataset-preparation.schema.json").read_bytes()
        == Path(
            "src/reproassert/schemas/benchmark-v02-dataset-preparation.schema.json"
        ).read_bytes()
    )


def test_dataset_preparation_cli_is_bounded_and_reports_zero_provider_calls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    inputs = _inputs(tmp_path)
    output = tmp_path / "private"
    output.mkdir(mode=0o700)
    receipt = output / "receipt.json"
    receipt.write_text("{}\n")
    value = preparation.V02DatasetPreparation(
        root=output,
        receipt_path=receipt,
        receipt_sha256="a" * 64,
        parser_receipt_sha256="b" * 64,
        case_count=20,
        provider_calls=0,
    )
    monkeypatch.setattr(cli, "prepare_v02_dataset_inputs", lambda **_kwargs: value)
    result = CliRunner().invoke(
        cli.main,
        [
            "benchmark",
            "prepare-v02-dataset",
            "--tdd-id-list",
            str(inputs["tdd_id_list_path"]),
            "--source-dataset",
            str(inputs["source_dataset_path"]),
            "--upstream-object-witness",
            str(inputs["upstream_object_witness_path"]),
            "--cohort-plan",
            str(inputs["cohort_plan_path"]),
            "--image-digest",
            preparation.FROZEN_V02_DATASET_PARSER_IMAGE_ID,
            "--prepared-at",
            "2026-07-10T23:59:59Z",
            "--output-root",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["case_count"] == 20
    assert payload["provider_calls"] == 0
    assert "issue_text" not in result.output

    monkeypatch.setattr(cli, "verify_v02_dataset_preparation", lambda _path: value)
    result = CliRunner().invoke(
        cli.main,
        ["benchmark", "verify-v02-dataset", str(receipt)],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["verified"] is True
