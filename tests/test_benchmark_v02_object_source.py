from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jsonschema  # type: ignore[import-untyped]
import pytest
from click.testing import CliRunner

import reproassert.benchmark_v02_object_source as v02_source
import reproassert.cli as cli
import reproassert.semantic_issuer as semantic_issuer
from reproassert.benchmark_object_source import OBJECT_SOURCE_POLICY_SHA256
from reproassert.benchmark_source import SOURCE_ARCHIVE_FILENAME
from reproassert.errors import PolicyRejection
from reproassert.git_objects import GIT_OBJECT_SNAPSHOT_ALGORITHM

ROOT = Path(__file__).parents[1]
PLAN = ROOT / "benchmarks" / "v0.2-draft" / "leak-audited-cohort-plan.json"
SCHEMA = ROOT / "schemas" / "benchmark-v02-object-source-receipt.schema.json"
BUNDLED_SCHEMA = (
    ROOT / "src" / "reproassert" / "schemas" / "benchmark-v02-object-source-receipt.schema.json"
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _rewrite_plan(path: Path, mutate: Any) -> None:
    root = json.loads(PLAN.read_bytes())
    mutate(root)
    for case in root["cases"]:
        envelope = {key: value for key, value in case.items() if key != "case_plan_sha256"}
        case["case_plan_sha256"] = hashlib.sha256(_canonical(envelope)).hexdigest()
    envelope = {key: value for key, value in root.items() if key != "cohort_plan_sha256"}
    root["cohort_plan_sha256"] = hashlib.sha256(_canonical(envelope)).hexdigest()
    path.write_bytes(_canonical(root) + b"\n")


def _evidence(archive_path: Path, workspace_path: Path) -> tuple[object, ...]:
    archive_bytes = archive_path.read_bytes()
    tree_oid = "1" * 40
    snapshot = SimpleNamespace(
        algorithm=GIT_OBJECT_SNAPSHOT_ALGORITHM,
        manifest_sha256="2" * 64,
        entry_count=1,
        blob_count=1,
        regular_file_count=1,
        directory_count=0,
        symlink_count=0,
        gitlink_count=0,
        total_blob_bytes=7,
    )
    repair_plan = SimpleNamespace(
        archive_member_count=1,
        archive_regular_count=1,
        archive_directory_count=0,
        archive_symlink_count=0,
        exact_blobs=("blob",),
        repairs=(),
        repair_oids=(),
        archive_sha256=hashlib.sha256(archive_bytes).hexdigest(),
        archive_bytes=len(archive_bytes),
    )
    verified_plan = SimpleNamespace(tree_sha256="3" * 64)
    acquisition = SimpleNamespace(verified_plan=verified_plan)
    materialized = SimpleNamespace(
        path=workspace_path,
        root_tree_oid=tree_oid,
        manifest_sha256=snapshot.manifest_sha256,
        regular_file_count=1,
        directory_count=0,
        symlink_count=0,
        gitlink_count=0,
    )
    archive = SimpleNamespace(
        path=archive_path,
        sha256=repair_plan.archive_sha256,
        size_bytes=repair_plan.archive_bytes,
    )
    return (
        SimpleNamespace(tree_sha=tree_oid),
        snapshot,
        archive,
        repair_plan,
        acquisition,
        materialized,
    )


def _install_source_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_acquire(case: Any, case_dir: Path, **_kwargs: object) -> tuple[object, ...]:
        assert case.id == "rk-v0.2-001"
        archive = case_dir / SOURCE_ARCHIVE_FILENAME
        archive.write_bytes(b"fixed archive\n")
        workspace = case_dir / "workspace"
        workspace.mkdir()
        return _evidence(archive, workspace)

    def fake_verify(
        case: Any, archive: Any, scratch: Path, **_kwargs: object
    ) -> tuple[object, ...]:
        assert case.base_sha == "cdb66059a2feb44ee49021874605ba90801f9986"
        workspace = scratch / "workspace"
        workspace.mkdir()
        evidence = _evidence(archive.path, workspace)
        commit, snapshot, _archive, repair, acquisition, materialized = evidence
        return commit, snapshot, repair, acquisition, materialized

    monkeypatch.setattr(v02_source, "_acquire_and_materialize", fake_acquire)
    monkeypatch.setattr(v02_source, "_verify_staged_archive", fake_verify)


def test_v02_plan_loader_preserves_order_and_exact_identity() -> None:
    plan = v02_source.load_v02_object_source_plan(PLAN)

    assert plan.benchmark_version == "0.2.0"
    assert plan.raw_sha256 == hashlib.sha256(PLAN.read_bytes()).hexdigest()
    assert [case.id for case in plan.cases] == [f"rk-v0.2-{i:03d}" for i in range(1, 21)]
    first = plan.require_case("rk-v0.2-001")
    assert first.repository == "astropy/astropy"
    assert first.issue_number == 14305
    assert first.base_sha == "cdb66059a2feb44ee49021874605ba90801f9986"
    assert (
        first.case_entry_sha256
        == "f693e7ce826d424148764ac7935c2268ad5393c330c9a0b96ee9751c62216046"
    )


@pytest.mark.parametrize("failure", ["tamper", "order", "identity"])
def test_v02_plan_loader_rejects_rehashed_semantic_tampering(tmp_path: Path, failure: str) -> None:
    path = tmp_path / "plan.json"

    def mutate(root: dict[str, object]) -> None:
        cases = root["cases"]
        assert isinstance(cases, list)
        if failure == "tamper":
            cases[0]["base_sha"] = "f" * 40
        elif failure == "order":
            cases[0], cases[1] = cases[1], cases[0]
        else:
            cases[0]["repo"] = "other/astropy"

    _rewrite_plan(path, mutate)
    with pytest.raises(PolicyRejection):
        v02_source.load_v02_object_source_plan(path)


def test_v02_prepare_verify_schema_and_plan_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_source_fakes(monkeypatch)
    output_root = tmp_path / "sources"
    output_root.mkdir(mode=0o700)
    os.chmod(output_root, 0o700)

    receipt_path = v02_source.prepare_v02_object_source_case(
        PLAN,
        "rk-v0.2-001",
        output_root,
        tool_git_sha="a" * 40,
    )
    receipt_bytes = receipt_path.read_bytes()
    receipt = json.loads(receipt_bytes)
    jsonschema.Draft202012Validator(json.loads(SCHEMA.read_bytes())).validate(receipt)
    assert receipt["benchmark_version"] == "0.2.0"
    assert receipt["case"]["id"] == "rk-v0.2-001"
    assert receipt["manifest"]["raw_sha256"] == hashlib.sha256(PLAN.read_bytes()).hexdigest()
    assert receipt["manifest"]["case_entry_sha256"] == (
        "f693e7ce826d424148764ac7935c2268ad5393c330c9a0b96ee9751c62216046"
    )
    assert receipt["acquisition"]["policy_sha256"] == OBJECT_SOURCE_POLICY_SHA256
    assert receipt["campaign_readiness_changed"] is False
    assert receipt_bytes == _canonical(receipt) + b"\n"

    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    os.chmod(scratch, 0o700)
    verified = v02_source.verify_v02_object_source_receipt(
        receipt_path,
        plan_path=PLAN,
        expected_case_id="rk-v0.2-001",
        expected_receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        scratch_root=scratch,
    )
    assert verified == receipt
    assert list(scratch.iterdir()) == []

    marker = object()
    monkeypatch.setattr(
        semantic_issuer,
        "render_v02_source_evidence_receipt",
        lambda _case, _plan: b'{"source":"evidence"}\n',
    )
    monkeypatch.setattr(
        semantic_issuer,
        "verify_v02_source_evidence",
        lambda _path, **_kwargs: marker,
    )
    source_evidence_path = receipt_path.parent / "benchmark-v02-source-evidence.json"
    issued = v02_source.issue_v02_source_evidence_from_object_receipt(
        receipt_path,
        plan_path=PLAN,
        expected_case_id="rk-v0.2-001",
        source_evidence_receipt_path=source_evidence_path,
        scratch_root=scratch,
    )
    assert issued is marker
    assert source_evidence_path.read_bytes() == b'{"source":"evidence"}\n'

    tampered = json.loads(receipt_bytes)
    tampered["manifest"]["case_entry_sha256"] = "f" * 64
    receipt_path.write_bytes(_canonical(tampered) + b"\n")
    with pytest.raises(PolicyRejection, match="frozen manifest"):
        v02_source.verify_v02_object_source_receipt(
            receipt_path,
            plan_path=PLAN,
            expected_case_id="rk-v0.2-001",
            scratch_root=scratch,
        )


def test_v02_schema_bundle_and_cli_are_preparation_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert SCHEMA.read_bytes() == BUNDLED_SCHEMA.read_bytes()
    jsonschema.Draft202012Validator.check_schema(json.loads(SCHEMA.read_bytes()))
    schema_result = CliRunner().invoke(
        cli.main, ["schema", "--name", "benchmark-v02-object-source-receipt"]
    )
    assert schema_result.exit_code == 0, schema_result.output
    assert schema_result.output.encode() == SCHEMA.read_bytes()

    output_root = tmp_path / "sources"
    receipt = output_root / "rk-v0.2-001-object-v2" / "benchmark-object-source-receipt.json"

    def fake_prepare(*_args: object, **_kwargs: object) -> Path:
        receipt.parent.mkdir(mode=0o700)
        receipt.write_text("{}")
        return receipt

    monkeypatch.setattr(cli, "prepare_v02_object_source_case", fake_prepare)
    prepared = CliRunner().invoke(
        cli.main,
        [
            "benchmark",
            "prepare-v02-object-source",
            "rk-v0.2-001",
            "--cohort-plan",
            str(PLAN),
            "--output-root",
            str(output_root),
            "--tool-git-sha",
            "a" * 40,
        ],
    )
    assert prepared.exit_code == 0, prepared.output
    assert json.loads(prepared.output)["campaign_readiness_changed"] is False

    monkeypatch.setattr(
        cli,
        "verify_v02_object_source_receipt",
        lambda *_args, **_kwargs: {
            "source": {
                "github_root_tree_oid": "b" * 40,
                "transport": {"sha256": "c" * 64},
                "verified_workspace": {"tree_sha256": "d" * 64},
            }
        },
    )
    verified = CliRunner().invoke(
        cli.main,
        [
            "benchmark",
            "verify-v02-object-source",
            str(receipt),
            "--cohort-plan",
            str(PLAN),
            "--case-id",
            "rk-v0.2-001",
        ],
    )
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.output)["verified"] is True
