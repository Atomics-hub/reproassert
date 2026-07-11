from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest
from click.testing import CliRunner

import reproassert.benchmark_v02_exact_capability as capability
import reproassert.cli as cli
from reproassert.benchmark_v02_instance_controller import GoldSmokeReceipt
from reproassert.benchmark_v02_instance_runtime import (
    InstanceRuntime,
    instance_runtime_manifest_bytes,
    load_instance_runtime_manifest,
)
from reproassert.benchmark_v02_package import VerifiedV02EvaluatorCapability
from reproassert.cli import main
from reproassert.errors import PolicyRejection


def _inputs(tmp_path: Path) -> tuple[Path, str, Path, object]:
    entries = tuple(_runtime(number) for number in range(1, 21))
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(
        instance_runtime_manifest_bytes(
            harness_git_sha="a" * 40,
            harness_specs_sha256="b" * 64,
            entries=entries,
        )
    )
    manifest_sha = load_instance_runtime_manifest(manifest_path).sha256
    rows = []
    for entry in entries:
        is_network_case = entry.case_id == "rk-v0.2-014"
        rows.append(
            {
                "case_id": entry.case_id,
                "classification": (
                    "infrastructure_failure" if is_network_case else "semantic_valid"
                ),
                "hidden_inputs": {
                    "developer_tests_bytes": 5,
                    "developer_tests_sha256": hashlib.sha256(b"tests").hexdigest(),
                    "production_patch_bytes": 3,
                    "production_patch_sha256": hashlib.sha256(b"fix").hexdigest(),
                },
                "instance_id": entry.instance_id,
                "reason": (
                    "network_dependency" if is_network_case else "fails_on_base_passes_on_fixed"
                ),
                "test_command_profile": entry.test_command_profile,
            }
        )
    gold = {
        "counts": {
            "infrastructure_failure": 1,
            "not_run": 0,
            "selected": 20,
            "semantic_failure": 0,
            "semantic_valid": 19,
        },
        "inputs": {
            "hidden_extraction_receipt_sha256": "7" * 64,
            "instance_runtime_manifest_sha256": manifest_sha,
        },
        "receipt_sha256": "9" * 64,
        "results": rows,
        "selection": "all",
        "status": "complete",
    }
    gold_path = tmp_path / "gold.json"
    gold_path.write_bytes(capability._canonical(gold) + b"\n")
    hidden = SimpleNamespace(prepared=SimpleNamespace(receipt_sha256="7" * 64))
    return manifest_path, manifest_sha, gold_path, hidden


def _runtime(number: int) -> InstanceRuntime:
    sympy = number in {16, 17}
    instance_id = f"sympy__sympy-{15000 + number}" if sympy else f"project__repo-{1000 + number}"
    return InstanceRuntime(
        case_id=f"rk-v0.2-{number:03d}",
        instance_id=instance_id,
        base_sha="c" * 40,
        base_tree_oid="d" * 40,
        spec_sha256=f"{number:064x}",
        image_tag=f"swebench/sweb.eval.x86_64.case_{number}:v1",
        image_digest=f"sha256:{number:064x}",
        image_id=f"sha256:{number + 20:064x}",
        test_command_profile="sympy-bin-test-v1" if sympy else "pytest-v1",
    )


def _install_verifiers(monkeypatch: pytest.MonkeyPatch, gold_path: Path) -> None:
    raw = gold_path.read_bytes()
    monkeypatch.setattr(
        capability,
        "verify_instance_gold_smoke_receipt",
        lambda path: GoldSmokeReceipt(path, hashlib.sha256(raw).hexdigest(), 20, 19, 1),
    )
    monkeypatch.setattr(
        capability,
        "hidden_case_artifacts",
        lambda _verified, _case: {
            "developer_tests": {
                "bytes": 5,
                "path": Path("private-tests"),
                "sha256": hashlib.sha256(b"tests").hexdigest(),
            },
            "production_patch": {
                "bytes": 3,
                "path": Path("private-fix"),
                "sha256": hashlib.sha256(b"fix").hexdigest(),
            },
        },
    )


def test_issuer_binds_exact_runtime_gold_and_hidden_commitments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, manifest_sha, gold, hidden = _inputs(tmp_path)
    _install_verifiers(monkeypatch, gold)

    issued = capability.issue_verified_v02_exact_image_evaluator_capability(
        manifest_path=manifest,
        expected_manifest_sha256=manifest_sha,
        gold_smoke_receipt_path=gold,
        verified_hidden=hidden,  # type: ignore[arg-type]
        case_id="rk-v0.2-014",
    )

    assert issued.gold_smoke_classification == "infrastructure_failure"
    assert issued.gold_smoke_reason == "network_dependency"
    assert issued.runtime.image_id == f"sha256:{34:064x}"
    assert (
        hashlib.sha256(capability._canonical(issued.public_record())).hexdigest()
        == issued.evaluator_public_commitment_sha256
    )
    assert capability.require_v02_exact_image_evaluator_capability(issued) is issued
    assert "path" not in json.dumps(issued.public_record())


def test_capability_rejects_direct_construction_and_legacy_authority() -> None:
    with pytest.raises(TypeError, match="verifier-issued only"):
        capability.VerifiedV02ExactImageEvaluatorCapability()
    legacy = object.__new__(VerifiedV02EvaluatorCapability)
    with pytest.raises(PolicyRejection, match="exact-image evaluator capability"):
        capability.require_v02_exact_image_evaluator_capability(legacy)


def test_issuer_rejects_tampered_denominator_and_hidden_commitment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, manifest_sha, gold, hidden = _inputs(tmp_path)
    record = json.loads(gold.read_bytes())
    record["counts"]["semantic_valid"] = 20
    gold.write_bytes(capability._canonical(record) + b"\n")
    _install_verifiers(monkeypatch, gold)
    with pytest.raises(PolicyRejection, match="denominator"):
        capability.issue_verified_v02_exact_image_evaluator_capability(
            manifest_path=manifest,
            expected_manifest_sha256=manifest_sha,
            gold_smoke_receipt_path=gold,
            verified_hidden=hidden,  # type: ignore[arg-type]
            case_id="rk-v0.2-001",
        )

    record["counts"]["semantic_valid"] = 19
    record["results"][0]["hidden_inputs"]["production_patch_sha256"] = "0" * 64
    gold.write_bytes(capability._canonical(record) + b"\n")
    _install_verifiers(monkeypatch, gold)
    with pytest.raises(PolicyRejection, match="hidden commitments"):
        capability.issue_verified_v02_exact_image_evaluator_capability(
            manifest_path=manifest,
            expected_manifest_sha256=manifest_sha,
            gold_smoke_receipt_path=gold,
            verified_hidden=hidden,  # type: ignore[arg-type]
            case_id="rk-v0.2-001",
        )


def test_capability_index_persists_20_redacted_commitments_not_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, manifest_sha, gold, hidden = _inputs(tmp_path)
    _install_verifiers(monkeypatch, gold)
    hidden_receipt = tmp_path / "hidden.json"
    hidden_receipt.write_text("{}")
    monkeypatch.setattr(capability, "verify_v02_hidden_gold", lambda _path: hidden)
    output = tmp_path / "capability-index.json"

    verified = capability.prepare_v02_exact_image_capability_index(
        manifest_path=manifest,
        expected_manifest_sha256=manifest_sha,
        gold_smoke_receipt_path=gold,
        hidden_extraction_receipt=hidden_receipt,
        prepared_at="2026-07-11T09:00:00Z",
        tool_git_sha="a" * 40,
        output_path=output,
    )

    assert verified.runtime_attested_count == 20
    assert verified.evaluator_preflight_ready_count == 19
    assert verified.infrastructure_failure_count == 1
    record = json.loads(output.read_text())
    assert record["claims"]["nominal_authority_serialized"] is False
    assert record["cases"][13]["status"] == ("runtime_attested_gold_smoke_infrastructure_failure")
    assert len({row["evaluator_public_commitment_sha256"] for row in record["cases"]}) == 20
    public_schema = Path("schemas/benchmark-v02-exact-image-capability-index.schema.json")
    packaged_schema = Path(
        "src/reproassert/schemas/benchmark-v02-exact-image-capability-index.schema.json"
    )
    assert public_schema.read_bytes() == packaged_schema.read_bytes()
    jsonschema.validate(record, json.loads(public_schema.read_text()))

    record["cases"][0]["evaluator_public_commitment_sha256"] = "0" * 64
    record["index_sha256"] = capability._index_hash(record)
    output.write_bytes(capability._canonical(record) + b"\n")
    with pytest.raises(PolicyRejection, match="freshly verified"):
        capability.verify_v02_exact_image_capability_index(
            output,
            manifest_path=manifest,
            expected_manifest_sha256=manifest_sha,
            gold_smoke_receipt_path=gold,
            hidden_extraction_receipt=hidden_receipt,
        )


def test_capability_index_cli_prepares_and_verifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = []
    for name in ("manifest.json", "gold.json", "hidden.json", "index.json"):
        path = tmp_path / name
        path.write_text("{}")
        inputs.append(path)
    manifest, gold, hidden, index = inputs
    verified = capability.VerifiedV02ExactImageCapabilityIndex(
        path=index,
        sha256="a" * 64,
        case_count=20,
        runtime_attested_count=20,
        evaluator_preflight_ready_count=19,
        infrastructure_failure_count=1,
    )
    monkeypatch.setattr(cli, "prepare_v02_exact_image_capability_index", lambda **_kwargs: verified)
    monkeypatch.setattr(
        cli, "verify_v02_exact_image_capability_index", lambda *_args, **_kwargs: verified
    )
    common = [
        "--instance-runtime-manifest",
        str(manifest),
        "--expected-manifest-sha256",
        "b" * 64,
        "--gold-smoke-receipt",
        str(gold),
        "--hidden-extraction-receipt",
        str(hidden),
    ]
    runner = CliRunner()
    prepared = runner.invoke(
        main,
        [
            "benchmark",
            "prepare-v02-exact-capabilities",
            *common,
            "--prepared-at",
            "2026-07-11T09:00:00Z",
            "--tool-git-sha",
            "a" * 40,
            "--output",
            str(tmp_path / "output.json"),
        ],
    )
    assert prepared.exit_code == 0, prepared.output
    assert json.loads(prepared.output)["runtime_attested_count"] == 20

    checked = runner.invoke(
        main,
        ["benchmark", "verify-v02-exact-capabilities", str(index), *common],
    )
    assert checked.exit_code == 0, checked.output
    assert json.loads(checked.output)["verified"] is True


def _verify_index_with_dummy_evidence(path: Path) -> None:
    capability.verify_v02_exact_image_capability_index(
        path,
        manifest_path=Path("manifest.json"),
        expected_manifest_sha256="a" * 64,
        gold_smoke_receipt_path=Path("gold.json"),
        hidden_extraction_receipt=Path("hidden.json"),
    )


def test_capability_index_rejects_overwrite_future_date_and_bad_producer_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, manifest_sha, gold, hidden = _inputs(tmp_path)
    hidden_receipt = tmp_path / "hidden.json"
    hidden_receipt.write_text("{}")
    monkeypatch.setattr(capability, "verify_v02_hidden_gold", lambda _path: hidden)
    output = tmp_path / "existing.json"
    output.write_text("do not replace")

    with pytest.raises(PolicyRejection, match="overwrite"):
        capability.prepare_v02_exact_image_capability_index(
            manifest_path=manifest,
            expected_manifest_sha256=manifest_sha,
            gold_smoke_receipt_path=gold,
            hidden_extraction_receipt=hidden_receipt,
            prepared_at="2026-07-11T09:00:00Z",
            tool_git_sha="a" * 40,
            output_path=output,
        )
    assert output.read_text() == "do not replace"

    with pytest.raises(PolicyRejection, match="future-dated"):
        capability._derive_index(
            manifest_path=manifest,
            expected_manifest_sha256=manifest_sha,
            gold_smoke_receipt_path=gold,
            hidden_extraction_receipt=hidden_receipt,
            prepared_at="2999-01-01T00:00:00Z",
            tool_git_sha="a" * 40,
        )
    with pytest.raises(PolicyRejection, match="tool Git SHA"):
        capability._derive_index(
            manifest_path=manifest,
            expected_manifest_sha256=manifest_sha,
            gold_smoke_receipt_path=gold,
            hidden_extraction_receipt=hidden_receipt,
            prepared_at="2026-07-11T09:00:00Z",
            tool_git_sha="not-a-sha",
        )


def test_capability_index_rejects_unsafe_encoding_shape_identity_and_size(tmp_path: Path) -> None:
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_bytes(b"{")
    with pytest.raises(PolicyRejection, match="invalid JSON"):
        _verify_index_with_dummy_evidence(invalid_json)

    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_bytes(b"{}")
    with pytest.raises(PolicyRejection, match="not canonical"):
        _verify_index_with_dummy_evidence(noncanonical)

    wrong_fields = tmp_path / "wrong-fields.json"
    wrong_fields.write_bytes(capability._canonical({"unexpected": True}) + b"\n")
    with pytest.raises(PolicyRejection, match="fields"):
        _verify_index_with_dummy_evidence(wrong_fields)

    identity = {
        "algorithm": "wrong",
        "benchmark_version": "0.2",
        "case_count": 20,
        "cases": [],
        "claims": {},
        "index_sha256": "0" * 64,
        "prepared_at": "2026-07-11T09:00:00Z",
        "schema_version": "1.0.0",
        "status": "runtime_attested_20_evaluator_preflight_19",
        "tool_git_sha": "a" * 40,
    }
    identity_path = tmp_path / "identity.json"
    identity_path.write_bytes(capability._canonical(identity) + b"\n")
    with pytest.raises(PolicyRejection, match="identity"):
        _verify_index_with_dummy_evidence(identity_path)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(PolicyRejection, match="size limit"):
        _verify_index_with_dummy_evidence(oversized)
    with pytest.raises(PolicyRejection, match="read safely"):
        _verify_index_with_dummy_evidence(tmp_path / "missing.json")


@pytest.mark.parametrize("value", [None, "", "2026-02-30T00:00:00Z"])
def test_capability_index_rejects_invalid_timestamps(value: object) -> None:
    with pytest.raises(PolicyRejection, match="timestamp"):
        capability._timestamp(value)


def _rewrite_gold(gold: Path, mutation: object) -> None:
    record = json.loads(gold.read_bytes())
    assert callable(mutation)
    mutation(record)
    gold.write_bytes(capability._canonical(record) + b"\n")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda record: record.update(selection="rk-v0.2-001"), "complete all-case"),
        (
            lambda record: record["inputs"].update(instance_runtime_manifest_sha256="0" * 64),
            "exact runtime manifest",
        ),
        (
            lambda record: record["inputs"].update(hidden_extraction_receipt_sha256="0" * 64),
            "hidden extraction",
        ),
        (
            lambda record: record["results"][0].update(instance_id="wrong__instance-1"),
            "exact runtime entry",
        ),
        (
            lambda record: record["results"][0].update(classification="semantic_failure"),
            "Non-014",
        ),
        (
            lambda record: record["results"][13].update(reason="setup_failure"),
            "Case 014",
        ),
    ],
)
def test_capability_issuer_rejects_cross_evidence_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: object,
    message: str,
) -> None:
    manifest, manifest_sha, gold, hidden = _inputs(tmp_path)
    _rewrite_gold(gold, mutation)
    _install_verifiers(monkeypatch, gold)
    case_id = "rk-v0.2-014" if message == "Case 014" else "rk-v0.2-001"
    with pytest.raises(PolicyRejection, match=message):
        capability.issue_verified_v02_exact_image_evaluator_capability(
            manifest_path=manifest,
            expected_manifest_sha256=manifest_sha,
            gold_smoke_receipt_path=gold,
            verified_hidden=hidden,  # type: ignore[arg-type]
            case_id=case_id,
        )


def test_capability_issuer_rejects_manifest_gold_toctou_and_forged_commitment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, manifest_sha, gold, hidden = _inputs(tmp_path)
    _install_verifiers(monkeypatch, gold)
    with pytest.raises(PolicyRejection, match="explicit commitment"):
        capability.issue_verified_v02_exact_image_evaluator_capability(
            manifest_path=manifest,
            expected_manifest_sha256="0" * 64,
            gold_smoke_receipt_path=gold,
            verified_hidden=hidden,  # type: ignore[arg-type]
            case_id="rk-v0.2-001",
        )

    short_manifest = tmp_path / "short-manifest.json"
    short_manifest.write_bytes(
        instance_runtime_manifest_bytes(
            harness_git_sha="a" * 40,
            harness_specs_sha256="b" * 64,
            entries=(_runtime(1),),
        )
    )
    short_sha = load_instance_runtime_manifest(short_manifest).sha256
    with pytest.raises(PolicyRejection, match="complete 20-case"):
        capability.issue_verified_v02_exact_image_evaluator_capability(
            manifest_path=short_manifest,
            expected_manifest_sha256=short_sha,
            gold_smoke_receipt_path=gold,
            verified_hidden=hidden,  # type: ignore[arg-type]
            case_id="rk-v0.2-001",
        )

    monkeypatch.setattr(
        capability,
        "verify_instance_gold_smoke_receipt",
        lambda path: GoldSmokeReceipt(path, "0" * 64, 20, 19, 1),
    )
    with pytest.raises(PolicyRejection, match="changed after verification"):
        capability.issue_verified_v02_exact_image_evaluator_capability(
            manifest_path=manifest,
            expected_manifest_sha256=manifest_sha,
            gold_smoke_receipt_path=gold,
            verified_hidden=hidden,  # type: ignore[arg-type]
            case_id="rk-v0.2-001",
        )

    _install_verifiers(monkeypatch, gold)
    issued = capability.issue_verified_v02_exact_image_evaluator_capability(
        manifest_path=manifest,
        expected_manifest_sha256=manifest_sha,
        gold_smoke_receipt_path=gold,
        verified_hidden=hidden,  # type: ignore[arg-type]
        case_id="rk-v0.2-001",
    )
    object.__setattr__(issued, "evaluator_public_commitment_sha256", "0" * 64)
    with pytest.raises(PolicyRejection, match="public commitment"):
        capability.require_v02_exact_image_evaluator_capability(issued)


def test_capability_rejects_invalid_case_and_oversized_gold(tmp_path: Path) -> None:
    with pytest.raises(PolicyRejection, match="case ID"):
        capability._case("rk-v0.2-../../secret")
    oversized = tmp_path / "gold.json"
    oversized.write_bytes(b"x" * (capability.MAX_GOLD_SMOKE_RECEIPT_BYTES + 1))
    with pytest.raises(PolicyRejection, match="verifier limit"):
        capability._read_gold(oversized)
