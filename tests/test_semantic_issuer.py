from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import reproassert.benchmark_v02_package as package_module
import reproassert.semantic_issuer as issuer
from reproassert.benchmark_snapshot import canonical_snapshot_content_bytes
from reproassert.benchmark_v02_package import (
    ArtifactReference,
    V02CaseIdentity,
    V02SemanticVerificationContext,
    generator_projection_bytes,
)
from reproassert.candidate import validate_candidate_payload
from reproassert.dependency_execution_receipt import VerifiedDependencyExecutionReceipt
from reproassert.errors import PolicyRejection
from reproassert.git_objects import (
    VerifiedGitObjectPlan,
    materialize_git_workspace,
    parse_recursive_git_tree,
    verify_git_object_blobs,
)
from reproassert.isolation_canary import IsolationCanaryResult
from reproassert.source_attestation import attest_source_tree

CASE = V02CaseIdentity(
    id="rk-v0.2-007",
    repo="owner/repo",
    issue_url="https://github.com/owner/repo/issues/7",
    base_sha="a" * 40,
)


def _blob_oid(content: bytes) -> str:
    digest = hashlib.sha1(f"blob {len(content)}\0".encode(), usedforsecurity=False)
    digest.update(content)
    return digest.hexdigest()


def _tree_oid(files: dict[str, tuple[str, bytes]]) -> str:
    body = bytearray()
    for name, (mode, content) in sorted(files.items(), key=lambda item: item[0].encode()):
        body.extend(mode.encode())
        body.extend(b" ")
        body.extend(name.encode())
        body.extend(b"\0")
        body.extend(bytes.fromhex(_blob_oid(content)))
    digest = hashlib.sha1(f"tree {len(body)}\0".encode(), usedforsecurity=False)
    digest.update(body)
    return digest.hexdigest()


def _source_plan() -> VerifiedGitObjectPlan:
    files = {
        ".env.secret": ("100644", b"TOKEN=never-forward\n"),
        "parser.py": ("100644", b"def normalize(value):\n    return value\n"),
        "pyproject.toml": ("100644", b"[tool.pytest.ini_options]\naddopts='-q'\n"),
        "test_parser.py": (
            "100644",
            b"from parser import normalize\n\n"
            b"def test_existing():\n"
            b"    assert normalize('x') == 'x'\n",
        ),
    }
    root_oid = _tree_oid(files)
    entries = [
        {
            "path": path,
            "mode": mode,
            "type": "blob",
            "sha": _blob_oid(content),
            "size": len(content),
        }
        for path, (mode, content) in files.items()
    ]
    snapshot = parse_recursive_git_tree(
        {"sha": root_oid, "tree": entries, "truncated": False},
        expected_root_tree_oid=root_oid,
    )
    blobs = {_blob_oid(content): content for _, content in files.values()}
    return verify_git_object_blobs(snapshot, lambda entry: blobs[entry.oid])


def _source_evidence(tmp_path: Path) -> issuer.VerifiedV02SourceEvidence:
    plan = _source_plan()
    receipt = tmp_path / "source-evidence.json"
    receipt.write_bytes(issuer.render_v02_source_evidence_receipt(CASE, plan))
    receipt.chmod(0o600)
    return issuer.verify_v02_source_evidence(receipt, case=CASE, exact_object_plan=plan)


def _dataset_evidence() -> issuer.VerifiedV02DatasetEvidence:
    value = object.__new__(issuer.VerifiedV02DatasetEvidence)
    fields: dict[str, object] = {
        "case": CASE,
        "tdd_bench_git_sha": issuer.OFFICIAL_TDD_BENCH_GIT_SHA,
        "tdd_bench_root_tree_oid": issuer.OFFICIAL_TDD_BENCH_ROOT_TREE_OID,
        "tdd_id_list_blob_oid": issuer.OFFICIAL_TDD_ID_LIST_BLOB_OID,
        "tdd_id_list_sha256": issuer.OFFICIAL_TDD_ID_LIST_SHA256,
        "tdd_membership_ordinal": 7,
        "source_dataset_git_sha": issuer.OFFICIAL_SOURCE_DATASET_GIT_SHA,
        "source_dataset_root_tree_oid": issuer.OFFICIAL_SOURCE_DATASET_ROOT_TREE_OID,
        "source_dataset_artifact_git_blob_oid": issuer.OFFICIAL_SOURCE_DATASET_GIT_BLOB_OID,
        "source_dataset_artifact_lfs_sha256": issuer.OFFICIAL_SOURCE_DATASET_LFS_SHA256,
        "source_dataset_artifact_lfs_bytes": issuer.OFFICIAL_SOURCE_DATASET_BYTES,
        "source_dataset_artifact_xet_sha256": issuer.OFFICIAL_SOURCE_DATASET_XET_SHA256,
        "source_dataset_row_ordinal": 6,
        "source_dataset_row_sha256": "1" * 64,
        "source_dataset_transform": package_module.SOURCE_DATASET_TRANSFORM,
        "parser_receipt_sha256": "2" * 64,
        "dataset_parser_image_digest": f"sha256:{'3' * 64}",
        "boundary_attestation_sha256": "4" * 64,
        "upstream_evidence_sha256": "5" * 64,
    }
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    object.__setattr__(value, "_issuer", issuer._DATASET_EVIDENCE_ISSUER)
    record = issuer._dataset_evidence_record(value, CASE)
    object.__setattr__(value, "evidence_sha256", issuer._json_sha256(record))
    return issuer.require_v02_dataset_evidence(value)


def _dependency(source_tree_sha256: str) -> VerifiedDependencyExecutionReceipt:
    return VerifiedDependencyExecutionReceipt(
        receipt_sha256="3" * 64,
        case_id=CASE.id,
        base_sha=CASE.base_sha,
        source_tree_sha256=source_tree_sha256,
        plan_raw_sha256="4" * 64,
        plan_sha256="5" * 64,
        requirements_sha256="6" * 64,
        image_id="sha256:" + "7" * 64,
        policy_sha256="8" * 64,
        wheelhouse_sha256="9" * 64,
        dependency_tree_sha256="a" * 64,
        evaluator_package_sha256="b" * 64,
        sequence_sha256="c" * 64,
        tool_name="reproassert-test",
        tool_version="1.0.0",
        tool_git_sha="d" * 40,
    )


def _isolation(policy_sha256: str, image_id: str) -> IsolationCanaryResult:
    return IsolationCanaryResult(
        version=issuer.CANARY_VERSION,
        tool_version="1.0.0",
        tool_git_sha="e" * 40,
        policy_sha256=policy_sha256,
        config_sha256="f" * 64,
        image_id=image_id,
        sentinel_sha256="0" * 64,
        positive_control_passed=True,
        negative_control_passed=True,
        positive_mount_destinations=(issuer.EVALUATOR_DESTINATION,),
        generator_mount_destinations=(issuer.GENERATOR_DESTINATION,),
        process_env_names=("HOME", "PATH"),
        image_env_names_cleared=("TOKEN",),
        cleanup_succeeded=True,
    )


def _projection(tmp_path: Path, *, body: str = "normalize keeps duplicate separators") -> Path:
    snapshot_bytes = canonical_snapshot_content_bytes(title="Normalizer bug", body=body)
    path = tmp_path / f"projection-{hashlib.sha256(body.encode()).hexdigest()[:8]}.json"
    path.write_bytes(
        generator_projection_bytes(
            CASE,
            {
                "title": "Normalizer bug",
                "body": body,
                "snapshot_sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
            },
        )
    )
    path.chmod(0o600)
    return path


def _capability() -> package_module.VerifiedV02EvaluatorCapability:
    return package_module.VerifiedV02EvaluatorCapability(
        package_module._CAPABILITY_ISSUER,
        case=CASE,
        preregistration_sha256="1" * 64,
        cohort_sha256="2" * 64,
        preregistered_case_sha256="3" * 64,
        package_identity_sha256="4" * 64,
        public_commitment_sha256="5" * 64,
        generator_projection_sha256="6" * 64,
        dataset_evidence_sha256="7" * 64,
        base_commit_sha=CASE.base_sha,
        base_root_tree_oid="8" * 40,
        source_receipt_sha256="9" * 64,
        source_tree_sha256="a" * 64,
        source_context_algorithm=issuer.V02_SOURCE_CONTEXT_ALGORITHM,
        source_context_policy_sha256=issuer.V02_SOURCE_CONTEXT_POLICY_SHA256,
        source_context_sha256="b" * 64,
        hidden_fixed_root_tree_oid="c" * 40,
        fixing_head_commit_sha="d" * 40,
        fixing_head_root_tree_oid="e" * 40,
        production_patch_sha256="c" * 64,
        developer_tests_sha256="d" * 64,
        dependencies_required=False,
        dependency_receipt_sha256=None,
        dependency_plan_sha256=None,
        dependency_tree_sha256=None,
        dependency_runner_image_id=None,
        isolation_receipt_sha256="e" * 64,
        isolation_policy_sha256="f" * 64,
        reviewer_role_seal_sha256="0" * 64,
        semantic_verification_receipt_sha256="1" * 64,
    )


def _candidate(symptom: str = "duplicate separators") -> object:
    return validate_candidate_payload(
        {
            "test_content": (
                "from parser import normalize\n\n"
                "def test_issue_7_reproduction():\n"
                f"    assert normalize('a--b') == 'a-b', '{symptom}'\n"
            ),
            "expected_symptom": symptom,
            "rationale": "Calls the reported public behavior.",
        },
        issue_number=7,
    )


def test_exact_object_source_receipt_round_trips_and_rejects_v01_alias(tmp_path: Path) -> None:
    evidence = _source_evidence(tmp_path)

    assert issuer.require_v02_source_evidence(evidence) is evidence
    assert evidence.base_root_tree_oid == _source_plan().snapshot.root_tree_oid
    assert len(evidence.source_tree_sha256) == 64

    v01_alias = V02CaseIdentity(
        id="rk-v0.1-007",
        repo=CASE.repo,
        issue_url=CASE.issue_url,
        base_sha=CASE.base_sha,
    )
    with pytest.raises(PolicyRejection, match=r"v0\.2 case"):
        issuer.render_v02_source_evidence_receipt(v01_alias, _source_plan())


def test_source_context_is_exact_deterministic_and_generator_safe(tmp_path: Path) -> None:
    evidence = _source_evidence(tmp_path)
    projection = _projection(tmp_path)

    first = issuer.derive_v02_generator_source_context(evidence, projection)
    second = issuer.derive_v02_generator_source_context(evidence, projection)

    assert issuer.require_v02_generator_source_context(first) is first
    assert first.context_sha256 == second.context_sha256
    assert first.algorithm == issuer.V02_SOURCE_CONTEXT_ALGORITHM
    assert first.policy_sha256 == issuer.V02_SOURCE_CONTEXT_POLICY_SHA256
    assert ".env.secret" in first.source_context.manifest
    assert all(item.path != ".env.secret" for item in first.source_context.files)
    public_shape = json.dumps(
        {
            "case": first.case.id,
            "source_context": first.source_context.to_dict(),
            "context_sha256": first.context_sha256,
        }
    )
    assert "hidden_fixed" not in public_shape
    assert "evaluator_package" not in public_shape
    assert "never-forward" not in public_shape

    changed = issuer.derive_v02_generator_source_context(
        evidence, _projection(tmp_path, body="a distinct issue symptom")
    )
    assert changed.context_sha256 != first.context_sha256


def test_source_and_context_nominal_objects_reject_forgery_and_mutation(tmp_path: Path) -> None:
    evidence = _source_evidence(tmp_path)
    context = issuer.derive_v02_generator_source_context(evidence, _projection(tmp_path))
    forged_source = object.__new__(issuer.VerifiedV02SourceEvidence)
    forged_context = object.__new__(issuer.VerifiedV02GeneratorSourceContext)

    with pytest.raises(PolicyRejection, match=r"fields|issuer"):
        issuer.require_v02_source_evidence(forged_source)
    with pytest.raises(PolicyRejection, match=r"fields|issuer"):
        issuer.require_v02_generator_source_context(forged_context)

    object.__setattr__(context, "context_sha256", "0" * 64)
    with pytest.raises(PolicyRejection, match="digest"):
        issuer.require_v02_generator_source_context(context)


def test_dataset_evidence_has_no_public_raw_hash_or_boolean_mint() -> None:
    with pytest.raises(TypeError, match="trusted pinned parser"):
        issuer.VerifiedV02DatasetEvidence()  # type: ignore[call-arg]
    forged = object.__new__(issuer.VerifiedV02DatasetEvidence)
    with pytest.raises(PolicyRejection, match=r"issuer|fields"):
        issuer.require_v02_dataset_evidence(forged)

    with pytest.raises(PolicyRejection, match="Attested production dataset parse"):
        issuer.issue_v02_dataset_evidence_from_attested_parse(
            attested_parse=SimpleNamespace(parser_receipt=b"{}"),
            case=CASE,
            instance_id="owner__repo-1",
        )


def test_dataset_evidence_promotes_only_attested_bound_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reproassert.benchmark_v02_dataset as dataset_module
    import reproassert.benchmark_v02_dataset_sandbox as sandbox_module

    instance_id = "owner__repo-1"
    identity = {"base_commit": CASE.base_sha, "instance_id": instance_id, "repo": CASE.repo}
    attested = SimpleNamespace(
        parser_receipt=b"private-canonical-receipt",
        parser_receipt_sha256="2" * 64,
        image_digest=f"sha256:{'3' * 64}",
        boundary_attestation_sha256="4" * 64,
        upstream_evidence_sha256="5" * 64,
    )
    receipt = {
        "dataset": {
            "joined_tdd_rows": [
                {
                    "identity_sha256": issuer._json_sha256(identity),
                    "instance_id": instance_id,
                    "source_dataset_row_ordinal": 6,
                    "source_dataset_row_sha256": "1" * 64,
                    "tdd_membership_ordinal": 7,
                }
            ],
            "source_dataset_transform": package_module.SOURCE_DATASET_TRANSFORM,
        },
        "upstream": {
            "source_dataset": {
                "artifact_bytes": issuer.OFFICIAL_SOURCE_DATASET_BYTES,
                "artifact_git_blob_oid": issuer.OFFICIAL_SOURCE_DATASET_GIT_BLOB_OID,
                "artifact_lfs_sha256": issuer.OFFICIAL_SOURCE_DATASET_LFS_SHA256,
                "artifact_xet_sha256": issuer.OFFICIAL_SOURCE_DATASET_XET_SHA256,
                "git_sha": issuer.OFFICIAL_SOURCE_DATASET_GIT_SHA,
                "root_tree_oid": issuer.OFFICIAL_SOURCE_DATASET_ROOT_TREE_OID,
            },
            "tdd_bench": {
                "git_sha": issuer.OFFICIAL_TDD_BENCH_GIT_SHA,
                "id_list_blob_oid": issuer.OFFICIAL_TDD_ID_LIST_BLOB_OID,
                "id_list_sha256": issuer.OFFICIAL_TDD_ID_LIST_SHA256,
                "root_tree_oid": issuer.OFFICIAL_TDD_BENCH_ROOT_TREE_OID,
            },
            "verification": {"upstream_evidence_sha256": attested.upstream_evidence_sha256},
        },
    }
    monkeypatch.setattr(sandbox_module, "require_attested_v02_dataset_parse", lambda value: value)
    monkeypatch.setattr(dataset_module, "_validate_private_receipt", lambda value: receipt)

    evidence = issuer.issue_v02_dataset_evidence_from_attested_parse(
        attested_parse=attested,
        case=CASE,
        instance_id=instance_id,
    )

    assert issuer.require_v02_dataset_evidence(evidence) is evidence
    assert evidence.dataset_parser_image_digest == attested.image_digest
    assert evidence.boundary_attestation_sha256 == attested.boundary_attestation_sha256
    assert evidence.upstream_evidence_sha256 == attested.upstream_evidence_sha256


def test_semantic_projection_cross_binds_official_dataset_source_and_dependency(
    tmp_path: Path,
) -> None:
    source = _source_evidence(tmp_path)
    source_context = issuer.derive_v02_generator_source_context(source, _projection(tmp_path))
    dataset = _dataset_evidence()
    dependency = _dependency(source.source_tree_sha256)
    policy_sha256 = "f" * 64
    isolation = _isolation(policy_sha256, dependency.image_id)
    mapping = SimpleNamespace(
        case=CASE,
        base_root_tree_oid=source.base_root_tree_oid,
        tdd_bench_git_sha=dataset.tdd_bench_git_sha,
        tdd_bench_root_tree_oid=dataset.tdd_bench_root_tree_oid,
        tdd_id_list_blob_oid=dataset.tdd_id_list_blob_oid,
        tdd_id_list_sha256=dataset.tdd_id_list_sha256,
        tdd_membership_ordinal=dataset.tdd_membership_ordinal,
        source_dataset_git_sha=dataset.source_dataset_git_sha,
        source_dataset_root_tree_oid=dataset.source_dataset_root_tree_oid,
        source_dataset_artifact_git_blob_oid=dataset.source_dataset_artifact_git_blob_oid,
        source_dataset_lfs_pointer_sha256="3" * 64,
        source_dataset_artifact_lfs_sha256=dataset.source_dataset_artifact_lfs_sha256,
        source_dataset_artifact_lfs_bytes=dataset.source_dataset_artifact_lfs_bytes,
        source_dataset_artifact_xet_sha256=dataset.source_dataset_artifact_xet_sha256,
        source_dataset_artifact_sha256=issuer.OFFICIAL_SOURCE_DATASET_LFS_SHA256,
        source_dataset_row_ordinal=dataset.source_dataset_row_ordinal,
        upstream_record_sha256=dataset.source_dataset_row_sha256,
        production_patch_sha256="4" * 64,
        developer_tests_sha256="5" * 64,
        fixed_commit_sha="6" * 40,
        head_root_tree_oid="7" * 40,
        environment_setup_commit="8" * 40,
    )
    supporting = {
        "isolation_canary_receipt": ArtifactReference("isolation.json", "9" * 64, 100),
        "reviewer_role_seal": ArtifactReference("reviewers.json", "a" * 64, 100),
    }
    context = V02SemanticVerificationContext(
        case=CASE,
        package_root=tmp_path,
        mapping=cast(Any, mapping),
        supporting_inputs=supporting,
        generator_projection=ArtifactReference("projection.json", "b" * 64, 100),
        isolation_policy_sha256=policy_sha256,
    )

    issuer._bind_source_to_mapping(source, cast(Any, mapping))
    issuer._bind_dataset_to_mapping(dataset, cast(Any, mapping))
    verification = issuer._semantic_verification(
        context,
        source=source,
        dataset=dataset,
        source_context=source_context,
        dependency=dependency,
        isolation_result=isolation,
        semantic_reviewer_ids=("semantic-1", "semantic-2"),
        completed_at="2026-07-10T15:00:00Z",
        scored_generator_mode="trusted_builtin_provider_adapter",
        hidden_fixed_oid="c" * 40,
        head_oid=mapping.head_root_tree_oid,
    )

    assert verification.dataset_evidence_sha256 == dataset.evidence_sha256
    assert verification.source_context_sha256 == source_context.context_sha256
    assert verification.dependency_receipt_sha256 == dependency.receipt_sha256
    assert verification.production_isolation_accepted is True
    assert verification.gold_hidden_until_verdict is True
    changed = SimpleNamespace(**{**vars(mapping), "upstream_record_sha256": "0" * 64})
    with pytest.raises(PolicyRejection, match="dataset evidence"):
        issuer._bind_dataset_to_mapping(dataset, cast(Any, changed))


def test_application_receipts_require_exact_isolation_and_independent_reviewer_bytes(
    tmp_path: Path,
) -> None:
    policy_sha256 = "1" * 64
    image_id = "sha256:" + "2" * 64
    isolation = _isolation(policy_sha256, image_id)
    isolation_record = {**asdict(isolation), "accepted": True}
    isolation_bytes = issuer._canonical_json(isolation_record) + b"\n"
    isolation_path = tmp_path / "isolation.json"
    isolation_path.write_bytes(isolation_bytes)
    isolation_ref = ArtifactReference(
        isolation_path.name,
        hashlib.sha256(isolation_bytes).hexdigest(),
        len(isolation_bytes),
    )
    issuer._verify_isolation_receipt(
        isolation_path,
        isolation_ref,
        isolation,
        expected_policy_sha256=policy_sha256,
        expected_image_id=image_id,
    )
    with pytest.raises(PolicyRejection, match="production policy"):
        issuer._verify_isolation_receipt(
            isolation_path,
            isolation_ref,
            isolation,
            expected_policy_sha256="0" * 64,
            expected_image_id=image_id,
        )

    mapping = SimpleNamespace(
        receipt_sha256="3" * 64,
        mapping_reviewer_ids=("mapping-1", "mapping-2"),
        reviewed_at="2026-07-10T12:00:00Z",
    )
    role_bytes = issuer.render_v02_reviewer_role_seal(
        case=CASE,
        mapping_receipt_sha256=mapping.receipt_sha256,
        mapping_reviewer_ids=mapping.mapping_reviewer_ids,
        semantic_reviewer_ids=("semantic-1", "semantic-2"),
        sealed_at="2026-07-10T13:00:00Z",
    )
    role_path = tmp_path / "reviewers.json"
    role_path.write_bytes(role_bytes)
    role_ref = ArtifactReference(
        role_path.name,
        hashlib.sha256(role_bytes).hexdigest(),
        len(role_bytes),
    )
    issuer._verify_reviewer_role_seal(
        role_path,
        role_ref,
        mapping=cast(Any, mapping),
        case=CASE,
        semantic_reviewer_ids=("semantic-1", "semantic-2"),
        completed_at="2026-07-10T14:00:00Z",
    )
    with pytest.raises(PolicyRejection, match="review interval"):
        issuer._verify_reviewer_role_seal(
            role_path,
            role_ref,
            mapping=cast(Any, mapping),
            case=CASE,
            semantic_reviewer_ids=("semantic-1", "semantic-2"),
            completed_at="2026-07-10T12:30:00Z",
        )


def test_application_semantic_issuer_composes_one_nominal_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _source_evidence(tmp_path)
    projection_path = _projection(tmp_path)
    projection_bytes = projection_path.read_bytes()
    projection_ref = ArtifactReference(
        projection_path.name,
        hashlib.sha256(projection_bytes).hexdigest(),
        len(projection_bytes),
    )
    source_context = issuer.derive_v02_generator_source_context(source, projection_path)
    dataset = _dataset_evidence()
    dependency = _dependency(source.source_tree_sha256)
    policy_sha256 = "f" * 64
    isolation = _isolation(policy_sha256, dependency.image_id)

    source_path = tmp_path / "source-evidence.json"
    source_ref = ArtifactReference(
        source_path.name, source.receipt_sha256, source_path.stat().st_size
    )
    dependency_path = tmp_path / "dependency.json"
    dependency_path.write_bytes(b'{"dependency":"fixture"}\n')
    dependency_ref = ArtifactReference(
        dependency_path.name,
        hashlib.sha256(dependency_path.read_bytes()).hexdigest(),
        dependency_path.stat().st_size,
    )
    isolation_record = {**asdict(isolation), "accepted": True}
    isolation_path = tmp_path / "isolation.json"
    isolation_path.write_bytes(issuer._canonical_json(isolation_record) + b"\n")
    isolation_ref = ArtifactReference(
        isolation_path.name,
        hashlib.sha256(isolation_path.read_bytes()).hexdigest(),
        isolation_path.stat().st_size,
    )
    production_path = tmp_path / "production.patch"
    production_path.write_bytes(b"production patch fixture\n")
    developer_path = tmp_path / "developer.patch"
    developer_path.write_bytes(b"developer tests fixture\n")
    production_ref = ArtifactReference(
        production_path.name,
        hashlib.sha256(production_path.read_bytes()).hexdigest(),
        production_path.stat().st_size,
    )
    developer_ref = ArtifactReference(
        developer_path.name,
        hashlib.sha256(developer_path.read_bytes()).hexdigest(),
        developer_path.stat().st_size,
    )
    mapping = SimpleNamespace(
        case=CASE,
        receipt_sha256="3" * 64,
        mapping_reviewer_ids=("mapping-1", "mapping-2"),
        reviewed_at="2026-07-10T12:00:00Z",
        base_root_tree_oid=source.base_root_tree_oid,
        tdd_bench_git_sha=dataset.tdd_bench_git_sha,
        tdd_bench_root_tree_oid=dataset.tdd_bench_root_tree_oid,
        tdd_id_list_blob_oid=dataset.tdd_id_list_blob_oid,
        tdd_id_list_sha256=dataset.tdd_id_list_sha256,
        tdd_membership_ordinal=dataset.tdd_membership_ordinal,
        source_dataset_git_sha=dataset.source_dataset_git_sha,
        source_dataset_root_tree_oid=dataset.source_dataset_root_tree_oid,
        source_dataset_artifact_git_blob_oid=dataset.source_dataset_artifact_git_blob_oid,
        source_dataset_lfs_pointer_sha256="4" * 64,
        source_dataset_artifact_lfs_sha256=dataset.source_dataset_artifact_lfs_sha256,
        source_dataset_artifact_lfs_bytes=dataset.source_dataset_artifact_lfs_bytes,
        source_dataset_artifact_xet_sha256=dataset.source_dataset_artifact_xet_sha256,
        source_dataset_artifact_sha256=issuer.OFFICIAL_SOURCE_DATASET_LFS_SHA256,
        source_dataset_row_ordinal=dataset.source_dataset_row_ordinal,
        upstream_record_sha256=dataset.source_dataset_row_sha256,
        production_patch=production_ref,
        production_patch_sha256=production_ref.sha256,
        developer_tests=developer_ref,
        developer_tests_sha256=developer_ref.sha256,
        fixed_commit_sha="5" * 40,
        head_root_tree_oid="6" * 40,
        environment_setup_commit="7" * 40,
    )
    role_bytes = issuer.render_v02_reviewer_role_seal(
        case=CASE,
        mapping_receipt_sha256=mapping.receipt_sha256,
        mapping_reviewer_ids=mapping.mapping_reviewer_ids,
        semantic_reviewer_ids=("semantic-1", "semantic-2"),
        sealed_at="2026-07-10T13:00:00Z",
    )
    role_path = tmp_path / "reviewers.json"
    role_path.write_bytes(role_bytes)
    role_ref = ArtifactReference(
        role_path.name,
        hashlib.sha256(role_bytes).hexdigest(),
        len(role_bytes),
    )
    supporting = {
        "source_receipt": source_ref,
        "dependency_receipt": dependency_ref,
        "isolation_canary_receipt": isolation_ref,
        "reviewer_role_seal": role_ref,
    }
    preliminary_context = V02SemanticVerificationContext(
        case=CASE,
        package_root=tmp_path,
        mapping=cast(Any, mapping),
        supporting_inputs=supporting,
        generator_projection=projection_ref,
        isolation_policy_sha256=policy_sha256,
    )
    expected = issuer._semantic_verification(
        preliminary_context,
        source=source,
        dataset=dataset,
        source_context=source_context,
        dependency=dependency,
        isolation_result=isolation,
        semantic_reviewer_ids=("semantic-1", "semantic-2"),
        completed_at="2026-07-10T14:00:00Z",
        scored_generator_mode="trusted_builtin_provider_adapter",
        hidden_fixed_oid="8" * 40,
        head_oid=mapping.head_root_tree_oid,
    )
    semantic_path = tmp_path / "semantic.json"
    semantic_path.write_bytes(issuer._canonical_json(asdict(expected)) + b"\n")
    semantic_ref = ArtifactReference(
        semantic_path.name,
        hashlib.sha256(semantic_path.read_bytes()).hexdigest(),
        semantic_path.stat().st_size,
    )
    context = V02SemanticVerificationContext(
        case=CASE,
        package_root=tmp_path,
        mapping=cast(Any, mapping),
        supporting_inputs={**supporting, "semantic_verification_receipt": semantic_ref},
        generator_projection=projection_ref,
        isolation_policy_sha256=policy_sha256,
    )
    load_calls = 0

    def load_dependency(*_args: object, **_kwargs: object) -> VerifiedDependencyExecutionReceipt:
        nonlocal load_calls
        load_calls += 1
        return dependency

    monkeypatch.setattr(issuer, "load_dependency_execution_receipt", load_dependency)
    monkeypatch.setattr(
        issuer,
        "_rederive_patch_causality",
        lambda *_args: (
            "8" * 40,
            mapping.head_root_tree_oid,
            (production_path, developer_path),
        ),
    )
    application = issuer._ApplicationSemanticIssuer(
        source=source,
        dataset=dataset,
        dependency_plan_path=tmp_path / "dependency-plan.json",
        isolation_result=isolation,
        semantic_reviewer_ids=("semantic-1", "semantic-2"),
        completed_at="2026-07-10T14:00:00Z",
        scored_generator_mode="trusted_builtin_provider_adapter",
    )

    observed = application.verify(context)
    assert observed == expected
    package = package_module.VerifiedV02CasePackage(
        case=CASE,
        generator_projection_sha256=projection_ref.sha256,
        evaluator_package_sha256="9" * 64,
        evaluator_commitment_sha256="a" * 64,
        snapshot_sha256=source_context.snapshot_sha256,
        difficulty="lt_15m",
        upstream_instance_id="owner__repo-7",
        fixing_pr_number=7,
        fixed_commit_sha=mapping.fixed_commit_sha,
        hidden_fixed_root_tree_oid="8" * 40,
        evaluator_commitment_nonce="b" * 64,
        verification_completed_at="2026-07-10T14:00:00Z",
        evaluator_capability=None,
    )
    capability = application.issue_capability(
        package,
        preregistration_sha256="c" * 64,
        cohort_sha256="d" * 64,
        preregistered_case_sha256="e" * 64,
    )

    assert package_module.require_v02_evaluator_capability(capability) is capability
    assert capability.source_context_sha256 == source_context.context_sha256
    assert capability.dataset_evidence_sha256 == dataset.evidence_sha256
    assert capability.dependency_receipt_sha256 == dependency.receipt_sha256
    assert load_calls == 2
    with pytest.raises(PolicyRejection, match="lifecycle"):
        application.verify(context)


def test_reviewer_role_seal_is_canonical_and_enforces_independence() -> None:
    first = issuer.render_v02_reviewer_role_seal(
        case=CASE,
        mapping_receipt_sha256="1" * 64,
        mapping_reviewer_ids=("mapping-1", "mapping-2"),
        semantic_reviewer_ids=("semantic-1", "semantic-2"),
        sealed_at="2026-07-10T12:00:00Z",
    )
    second = issuer.render_v02_reviewer_role_seal(
        case=CASE,
        mapping_receipt_sha256="1" * 64,
        mapping_reviewer_ids=("mapping-1", "mapping-2"),
        semantic_reviewer_ids=("semantic-1", "semantic-2"),
        sealed_at="2026-07-10T12:00:00Z",
    )
    assert first == second
    assert json.loads(first)["gold_hidden_until_verdict"] is True

    with pytest.raises(PolicyRejection, match="overlap"):
        issuer.render_v02_reviewer_role_seal(
            case=CASE,
            mapping_receipt_sha256="1" * 64,
            mapping_reviewer_ids=("reviewer-1", "reviewer-2"),
            semantic_reviewer_ids=("reviewer-1", "reviewer-3"),
            sealed_at="2026-07-10T12:00:00Z",
        )


def test_evaluation_session_is_candidate_bound_one_use_and_tamper_evident() -> None:
    candidate = _candidate()
    assert hasattr(candidate, "sha256")
    session = issuer.acquire_v02_evaluation_session(
        _capability(),
        campaign_id="campaign-v02",
        attempt_id="attempt-007",
        candidate=candidate,  # type: ignore[arg-type]
        candidate_path="tests/reproassert/test_issue_7.py",
    )
    assert issuer.require_v02_evaluation_session(session) is session

    with pytest.raises(PolicyRejection, match="exact attempt and candidate"):
        issuer.consume_v02_evaluation_session(
            session,
            campaign_id="campaign-v02",
            attempt_id="attempt-008",
            candidate=candidate,  # type: ignore[arg-type]
            candidate_path="tests/reproassert/test_issue_7.py",
        )

    capability = issuer.consume_v02_evaluation_session(
        session,
        campaign_id="campaign-v02",
        attempt_id="attempt-007",
        candidate=candidate,  # type: ignore[arg-type]
        candidate_path="tests/reproassert/test_issue_7.py",
    )
    assert capability.capability_sha256 == session.capability_sha256
    with pytest.raises(PolicyRejection, match=r"consumed|expired|unknown"):
        issuer.consume_v02_evaluation_session(
            session,
            campaign_id="campaign-v02",
            attempt_id="attempt-007",
            candidate=candidate,  # type: ignore[arg-type]
            candidate_path="tests/reproassert/test_issue_7.py",
        )


def test_evaluation_session_rejects_cross_candidate_and_object_new() -> None:
    candidate = _candidate()
    other = _candidate("a different symptom")
    session = issuer.acquire_v02_evaluation_session(
        _capability(),
        campaign_id="campaign-v02",
        attempt_id="attempt-007",
        candidate=candidate,  # type: ignore[arg-type]
        candidate_path="tests/reproassert/test_issue_7.py",
    )
    with pytest.raises(PolicyRejection, match="exact attempt and candidate"):
        issuer.consume_v02_evaluation_session(
            session,
            campaign_id="campaign-v02",
            attempt_id="attempt-007",
            candidate=other,  # type: ignore[arg-type]
            candidate_path="tests/reproassert/test_issue_7.py",
        )
    forged = object.__new__(issuer.V02EvaluationSession)
    with pytest.raises(PolicyRejection, match=r"issuer|fields"):
        issuer.require_v02_evaluation_session(forged)


def test_private_package_seal_rejects_external_hardlink(tmp_path: Path) -> None:
    package_root = tmp_path / "private-package"
    package_root.mkdir(mode=0o700)
    package_root.chmod(0o700)
    package = package_root / "benchmark-v02-case-package.json"
    package.write_text("{}\n", encoding="utf-8")
    package.chmod(0o600)
    os.link(package, tmp_path / "external-alias.json")

    with pytest.raises(PolicyRejection, match=r"link count|unsafe"):
        issuer._seal_private_package(package, tmp_path / "sealed")


def test_private_package_seal_rejects_symlinked_entrypoint(tmp_path: Path) -> None:
    package_root = tmp_path / "private-package"
    package_root.mkdir(mode=0o700)
    package_root.chmod(0o700)
    target = package_root / "actual.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    package = package_root / "benchmark-v02-case-package.json"
    package.symlink_to(target.name)

    with pytest.raises(PolicyRejection, match=r"regular file"):
        issuer._seal_private_package(package, tmp_path / "sealed")


def test_private_package_seal_completes_short_writes_durably(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package_root = tmp_path / "private-package"
    package_root.mkdir(mode=0o700)
    package_root.chmod(0o700)
    package = package_root / "benchmark-v02-case-package.json"
    content = b'{"schema_version":"1.0.0"}\n'
    package.write_bytes(content)
    package.chmod(0o600)
    real_write = os.write
    write_calls = 0

    def short_write(descriptor: int, value: bytes | memoryview) -> int:
        nonlocal write_calls
        write_calls += 1
        return real_write(descriptor, value[:3])

    monkeypatch.setattr(issuer.os, "write", short_write)
    sealed = issuer._seal_private_package(package, tmp_path / "sealed")

    assert sealed.read_bytes() == content
    assert write_calls > 1


def test_patch_causality_reconstructs_distinct_base_fixed_and_head_trees(tmp_path: Path) -> None:
    source = _source_evidence(tmp_path)
    generator = tmp_path / "causality-patch-generator"
    generator.mkdir()
    subprocess.run(["/usr/bin/git", "init", "-q"], cwd=generator, check=True)
    (generator / "parser.py").write_text(
        "def normalize(value):\n    return value\n", encoding="utf-8"
    )
    subprocess.run(["/usr/bin/git", "add", "parser.py"], cwd=generator, check=True)
    subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "base",
        ],
        cwd=generator,
        check=True,
    )
    (generator / "parser.py").write_text(
        "def normalize(value):\n    return value.replace('--', '-')\n", encoding="utf-8"
    )
    production = subprocess.run(
        ["/usr/bin/git", "diff", "--binary", "HEAD", "--", "parser.py"],
        cwd=generator,
        check=True,
        capture_output=True,
    ).stdout
    subprocess.run(["/usr/bin/git", "add", "parser.py"], cwd=generator, check=True)
    subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "production",
        ],
        cwd=generator,
        check=True,
    )
    (generator / "test_regression.py").write_text(
        "from parser import normalize\n\n"
        "def test_duplicate_separator():\n"
        "    assert normalize('a--b') == 'a-b'\n",
        encoding="utf-8",
    )
    developer = subprocess.run(
        [
            "/usr/bin/git",
            "diff",
            "--binary",
            "--no-index",
            "/dev/null",
            "test_regression.py",
        ],
        cwd=generator,
        check=False,
        capture_output=True,
    ).stdout
    production_path = tmp_path / "production.patch"
    production_path.write_bytes(production)
    developer_path = tmp_path / "developer.patch"
    developer_path.write_bytes(developer)

    expected_base = materialize_git_workspace(source._plan, tmp_path / "expected-base").path
    expected_head = tmp_path / "expected-head"
    shutil.copytree(expected_base, expected_head, symlinks=True, copy_function=shutil.copy2)
    issuer._apply_patch(expected_head, production)
    fixed_oid = attest_source_tree(expected_head).reconstructed_git_tree_oid
    issuer._apply_patch(expected_head, developer)
    head_oid = attest_source_tree(expected_head).reconstructed_git_tree_oid
    mapping = SimpleNamespace(
        production_patch=ArtifactReference(
            production_path.name, hashlib.sha256(production).hexdigest(), len(production)
        ),
        production_patch_sha256=hashlib.sha256(production).hexdigest(),
        developer_tests=ArtifactReference(
            developer_path.name, hashlib.sha256(developer).hexdigest(), len(developer)
        ),
        developer_tests_sha256=hashlib.sha256(developer).hexdigest(),
        head_root_tree_oid=head_oid,
    )

    observed_fixed, observed_head, paths = issuer._rederive_patch_causality(
        source, tmp_path, cast(Any, mapping)
    )

    assert observed_fixed == fixed_oid
    assert observed_head == head_oid
    assert observed_fixed not in {source.base_root_tree_oid, observed_head}
    assert paths == (production_path, developer_path)


def test_patch_applicator_supports_rename_and_mode_but_rejects_special_modes(
    tmp_path: Path,
) -> None:
    generator = tmp_path / "patch-generator"
    generator.mkdir()
    subprocess.run(["/usr/bin/git", "init", "-q"], cwd=generator, check=True)
    (generator / "old.py").write_text("print('hello')\n", encoding="utf-8")
    subprocess.run(["/usr/bin/git", "add", "old.py"], cwd=generator, check=True)
    subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "base",
        ],
        cwd=generator,
        check=True,
    )
    (generator / "old.py").rename(generator / "new.py")
    (generator / "new.py").chmod(0o755)
    subprocess.run(["/usr/bin/git", "add", "-A"], cwd=generator, check=True)
    patch = subprocess.run(
        ["/usr/bin/git", "diff", "--cached", "--binary", "--find-renames=50%"],
        cwd=generator,
        check=True,
        capture_output=True,
    ).stdout

    root = tmp_path / "source"
    root.mkdir()
    (root / "old.py").write_text("print('hello')\n", encoding="utf-8")
    issuer._apply_patch(root, patch)
    assert not (root / "old.py").exists()
    assert (root / "new.py").read_text(encoding="utf-8") == "print('hello')\n"
    assert (root / "new.py").stat().st_mode & 0o111

    special = b"""diff --git a/link b/link
new file mode 120000
index 0000000..0123456
--- /dev/null
+++ b/link
@@ -0,0 +1 @@
+../escape
"""
    with pytest.raises(PolicyRejection, match="symlinks or Gitlinks"):
        issuer._apply_patch(root, special)
