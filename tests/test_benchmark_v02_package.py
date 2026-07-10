from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

import reproassert.benchmark_v02_package as package_module
from reproassert.benchmark_snapshot_producer import (
    GRAPHQL_CAPTURE_FORMAT,
    ISSUE_HISTORY_QUERY_SHA256,
    SOLUTION_CUTOFF_QUERY_SHA256,
    SnapshotIdentity,
    SnapshotPrivacyReview,
    SnapshotProducerMetadata,
    produce_snapshot_receipt,
)
from reproassert.benchmark_v02_package import (
    BENCHMARK_VERSION,
    CASE_PACKAGE_FILENAME,
    EVALUATOR_COMMITMENT_ALGORITHM,
    EVALUATOR_PACKAGE_ALGORITHM,
    FIXING_PR_IDENTITY_QUERY_SHA256,
    ArtifactReference,
    PreregisteredV02Case,
    V02CaseIdentity,
    V02SemanticVerification,
    V02SemanticVerificationContext,
    VerifiedV02CasePackage,
    audit_v02_cohort_packages,
    build_v02_preregistration,
    canonical_preregistration_bytes,
    generator_projection_bytes,
    load_fix_mapping_receipt,
    load_v02_preregistration,
    new_evaluator_commitment_nonce,
    scan_v02_publication_tree,
    verify_v02_case_package,
)
from reproassert.errors import PolicyRejection

ROOT = Path(__file__).resolve().parents[1]
CASE = V02CaseIdentity(
    id="rk-v0.2-001",
    repo="owner/repo",
    issue_url="https://github.com/owner/repo/issues/7",
    base_sha="a" * 40,
)
CREATED_AT = "2024-01-01T00:00:00Z"
PR_CREATED_AT = "2024-02-20T00:00:00Z"
CUTOFF_AT = "2024-03-01T00:00:00Z"
TITLE = "Duplicate separators survive normalization"
BODY = "normalize('a--b') keeps duplicate separators; see #9."
PRODUCTION_PATCH = "production fix\n"
DEVELOPER_TESTS = "gold tests\n"
BASE_TREE_OID = "1" * 40
HEAD_TREE_OID = "2" * 40
HIDDEN_FIXED_TREE_OID = "3" * 40
SOURCE_TREE_SHA256 = "4" * 64


def _fixture_semantic_verification(
    context: V02SemanticVerificationContext,
) -> V02SemanticVerification:
    mapping = context.mapping
    supporting = context.supporting_inputs
    return V02SemanticVerification(
        algorithm="reproassert-v02-semantic-verification-v1",
        case=context.case,
        completed_at="2026-07-10T15:00:00Z",
        tdd_bench_git_sha=mapping.tdd_bench_git_sha,
        tdd_bench_root_tree_oid=mapping.tdd_bench_root_tree_oid,
        tdd_id_list_path=mapping.tdd_id_list_path,
        tdd_id_list_blob_oid=mapping.tdd_id_list_blob_oid,
        tdd_id_list_sha256=mapping.tdd_id_list_sha256,
        tdd_membership_ordinal=mapping.tdd_membership_ordinal,
        source_dataset_git_sha=mapping.source_dataset_git_sha,
        source_dataset_root_tree_oid=mapping.source_dataset_root_tree_oid,
        source_dataset_split=mapping.source_dataset_split,
        source_dataset_artifact_path=mapping.source_dataset_artifact_path,
        source_dataset_artifact_git_blob_oid=mapping.source_dataset_artifact_git_blob_oid,
        source_dataset_lfs_pointer_sha256=mapping.source_dataset_lfs_pointer_sha256,
        source_dataset_artifact_lfs_sha256=mapping.source_dataset_artifact_lfs_sha256,
        source_dataset_artifact_lfs_bytes=mapping.source_dataset_artifact_lfs_bytes,
        source_dataset_artifact_xet_sha256=mapping.source_dataset_artifact_xet_sha256,
        source_dataset_artifact_sha256=mapping.source_dataset_artifact_sha256,
        source_dataset_row_ordinal=mapping.source_dataset_row_ordinal,
        source_dataset_row_sha256=mapping.upstream_record_sha256,
        source_dataset_transform="drop_PASS_TO_PASS_and_FAIL_TO_PASS_v1",
        dataset_evidence_sha256="a" * 64,
        source_receipt_sha256=supporting["source_receipt"].sha256,
        source_base_commit_sha=context.case.base_sha,
        source_base_root_tree_oid=mapping.base_root_tree_oid,
        source_tree_sha256=SOURCE_TREE_SHA256,
        source_context_algorithm="reproassert-v02-source-context-v1",
        source_context_policy_sha256="b" * 64,
        source_context_sha256="c" * 64,
        production_patch_sha256=mapping.production_patch_sha256,
        developer_tests_sha256=mapping.developer_tests_sha256,
        hidden_fixed_root_tree_oid=HIDDEN_FIXED_TREE_OID,
        reconstructed_pr_head_root_tree_oid=mapping.head_root_tree_oid,
        fixing_head_commit_sha=mapping.fixed_commit_sha,
        fixing_head_root_tree_oid=mapping.head_root_tree_oid,
        dependency_receipt_sha256=supporting["dependency_receipt"].sha256,
        dependency_case_id=context.case.id,
        dependency_base_sha=context.case.base_sha,
        dependency_source_tree_sha256=SOURCE_TREE_SHA256,
        dependency_environment_setup_commit=mapping.environment_setup_commit,
        dependency_runner_image_id="sha256:" + "5" * 64,
        isolation_receipt_sha256=supporting["isolation_canary_receipt"].sha256,
        isolation_policy_sha256=context.isolation_policy_sha256,
        scored_generator_mode="sandboxed_generator_process",
        arbitrary_host_command_generator_allowed=False,
        evaluator_paths_exposed=False,
        host_credentials_forwarded=False,
        network_after_dependency_prep="disabled",
        production_isolation_accepted=True,
        reviewer_role_seal_sha256=supporting["reviewer_role_seal"].sha256,
        reviewer_roles_sealed=True,
        semantic_reviewer_ids=("semantic-reviewer-1", "semantic-reviewer-2"),
        gold_hidden_until_verdict=True,
    )


class _FixtureSemanticVerifier:
    def verify(self, context: V02SemanticVerificationContext) -> V02SemanticVerification:
        return _fixture_semantic_verification(context)


SEMANTIC_VERIFIER = _FixtureSemanticVerifier()


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def _page(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "totalCount": len(nodes),
        "pageInfo": {
            "hasNextPage": False,
            "hasPreviousPage": False,
            "startCursor": "start" if nodes else None,
            "endCursor": "end" if nodes else None,
        },
        "nodes": nodes,
    }


def _issue_artifact() -> dict[str, Any]:
    return {
        "format": GRAPHQL_CAPTURE_FORMAT,
        "query_sha256": ISSUE_HISTORY_QUERY_SHA256,
        "response": {
            "data": {
                "repository": {
                    "nameWithOwner": CASE.repo,
                    "issue": {
                        "number": 7,
                        "url": CASE.issue_url,
                        "title": TITLE,
                        "body": BODY,
                        "createdAt": CREATED_AT,
                        "lastEditedAt": None,
                        "includesCreatedEdit": True,
                        "userContentEdits": _page(
                            [
                                {
                                    "id": "creation",
                                    "createdAt": CREATED_AT,
                                    "editedAt": CREATED_AT,
                                    "deletedAt": None,
                                    "diff": BODY,
                                }
                            ]
                        ),
                        "timelineItems": _page([]),
                    },
                }
            }
        },
    }


def _cutoff_artifact() -> dict[str, Any]:
    return {
        "format": GRAPHQL_CAPTURE_FORMAT,
        "query_sha256": SOLUTION_CUTOFF_QUERY_SHA256,
        "response": {
            "data": {
                "repository": {
                    "nameWithOwner": CASE.repo,
                    "pullRequest": {
                        "number": 9,
                        "url": "https://github.com/owner/repo/pull/9",
                        "createdAt": PR_CREATED_AT,
                        "publishedAt": CUTOFF_AT,
                        "mergedAt": "2024-03-02T00:00:00Z",
                        "isDraft": False,
                        "baseRepository": {"nameWithOwner": CASE.repo},
                    },
                }
            }
        },
    }


def _write(root: Path, relative: str, content: bytes) -> dict[str, object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return {
        "path": relative,
        "sha256": hashlib.sha256(content).hexdigest(),
        "bytes": len(content),
    }


def _target_sha256() -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "number": 9,
                "repository": CASE.repo,
                "url": "https://github.com/owner/repo/pull/9",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _build_case_package(tmp_path: Path) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    root = tmp_path / CASE.id
    root.mkdir(mode=0o700)
    raw_bytes = _canonical(_issue_artifact())
    cutoff_bytes = _canonical(_cutoff_artifact())
    privacy_bytes = b"privacy and oracle review completed\n"
    raw_ref = _write(root, "snapshot/issue-history.json", raw_bytes)
    cutoff_ref = _write(root, "snapshot/cutoff-basis.json", cutoff_bytes)
    privacy_ref = _write(root, "reviews/privacy-review.txt", privacy_bytes)
    snapshot_receipt = produce_snapshot_receipt(
        identity=SnapshotIdentity(
            case_id=CASE.id,
            repository=CASE.repo,
            issue_url=CASE.issue_url,
            base_sha=CASE.base_sha,
        ),
        raw_issue_evidence_bytes=raw_bytes,
        cutoff_basis_bytes=cutoff_bytes,
        producer=SnapshotProducerMetadata(
            captured_at="2026-07-10T12:00:00Z",
            tool_git_sha="b" * 40,
        ),
        privacy_review=SnapshotPrivacyReview(
            reviewed_at="2026-07-10T13:00:00Z",
            reviewer_id="privacy-reviewer",
            checklist_sha256=str(privacy_ref["sha256"]),
        ),
    )
    snapshot_ref = _write(
        root, "snapshot/benchmark-snapshot-receipt.json", _canonical(snapshot_receipt)
    )
    snapshot_content = cast(dict[str, Any], snapshot_receipt["content"])
    safe_snapshot = {
        "title": snapshot_content["title"],
        "body": snapshot_content["body"],
        "snapshot_sha256": snapshot_content["snapshot_sha256"],
    }
    projection_ref = _write(
        root,
        "generator/generator-case.json",
        generator_projection_bytes(CASE, safe_snapshot),
    )

    tdd_members = [f"fixture__repo-{index}" for index in range(1, 450)]
    tdd_members[8] = "owner__repo-9"
    tdd_id_list_bytes = ("\n".join(tdd_members) + "\n").encode("ascii")
    tdd_id_list_ref = _write(root, "evaluator/id_list.txt", tdd_id_list_bytes)
    tdd_id_list_blob_oid = hashlib.sha1(
        f"blob {len(tdd_id_list_bytes)}\0".encode() + tdd_id_list_bytes,
        usedforsecurity=False,
    ).hexdigest()
    source_dataset_bytes = b"pinned split fixture\n"
    source_dataset_lfs_sha256 = hashlib.sha256(source_dataset_bytes).hexdigest()
    source_dataset_pointer_bytes = (
        "version https://git-lfs.github.com/spec/v1\n"
        f"oid sha256:{source_dataset_lfs_sha256}\n"
        f"size {len(source_dataset_bytes)}\n"
    ).encode("ascii")
    source_dataset_pointer_ref = _write(
        root, "evaluator/swe-bench-verified-test.parquet.pointer", source_dataset_pointer_bytes
    )
    source_dataset_pointer_oid = hashlib.sha1(
        f"blob {len(source_dataset_pointer_bytes)}\0".encode() + source_dataset_pointer_bytes,
        usedforsecurity=False,
    ).hexdigest()
    source_dataset_ref = _write(
        root, "evaluator/swe-bench-verified-test.parquet", source_dataset_bytes
    )
    upstream_record = {
        "repo": CASE.repo,
        "instance_id": "owner__repo-9",
        "base_commit": CASE.base_sha,
        "patch": PRODUCTION_PATCH,
        "test_patch": DEVELOPER_TESTS,
        "problem_statement": f"{TITLE}\n{BODY}",
        "hints_text": "",
        "created_at": PR_CREATED_AT,
        "version": "1.0",
        "environment_setup_commit": "9" * 40,
        "difficulty": "<15 min fix",
    }
    upstream_ref = _write(root, "evaluator/upstream-record.json", _canonical(upstream_record))
    fixing_pr_evidence = {
        "format": GRAPHQL_CAPTURE_FORMAT,
        "query_sha256": FIXING_PR_IDENTITY_QUERY_SHA256,
        "captured_at": "2026-07-10T12:30:00Z",
        "response": {
            "data": {
                "repository": {
                    "nameWithOwner": CASE.repo,
                    "baseCommit": {"oid": CASE.base_sha, "tree": {"oid": BASE_TREE_OID}},
                    "pullRequest": {
                        "number": 9,
                        "url": "https://github.com/owner/repo/pull/9",
                        "createdAt": PR_CREATED_AT,
                        "publishedAt": CUTOFF_AT,
                        "mergedAt": "2024-03-02T00:00:00Z",
                        "isDraft": False,
                        "headRefOid": "d" * 40,
                        "baseRepository": {"nameWithOwner": CASE.repo},
                        "commits": {
                            "totalCount": 2,
                            "nodes": [
                                {
                                    "commit": {
                                        "oid": "d" * 40,
                                        "tree": {"oid": HEAD_TREE_OID},
                                    }
                                }
                            ],
                        },
                    },
                }
            }
        },
    }
    fixing_evidence_ref = _write(
        root, "evaluator/fixing-pr-evidence.json", _canonical(fixing_pr_evidence)
    )
    hidden = {
        "production_patch": _write(root, "evaluator/production.patch", PRODUCTION_PATCH.encode()),
        "developer_tests": _write(
            root, "evaluator/developer-tests.patch", DEVELOPER_TESTS.encode()
        ),
        "oracle_rubric": _write(root, "evaluator/oracle-rubric.json", b'{"rubric":true}\n'),
        "causal_controls": _write(
            root, "evaluator/causal-controls.json", b'{"status":"planned"}\n'
        ),
        "reviewer_packet": _write(root, "evaluator/reviewer-packet.json", b'{"blinded":true}\n'),
    }
    mapping_checklist = _write(root, "reviews/fix-mapping-review.txt", b"mapping reviewed\n")
    fix_mapping = {
        "schema_version": "1.0.0",
        "benchmark_version": BENCHMARK_VERSION,
        "case": asdict(CASE),
        "provenance": {
            "tdd_bench_repository_url": "https://github.com/IBM/TDD-Bench-Verified",
            "tdd_bench_git_sha": "c" * 40,
            "tdd_bench_root_tree_oid": "7" * 40,
            "tdd_id_list_path": "id_list.txt",
            "tdd_id_list_blob_oid": tdd_id_list_blob_oid,
            "tdd_id_list": tdd_id_list_ref,
            "tdd_membership_ordinal": 9,
            "source_dataset_repository_url": (
                "https://huggingface.co/datasets/princeton-nlp/SWE-bench_Verified"
            ),
            "source_dataset_git_sha": "8" * 40,
            "source_dataset_root_tree_oid": "6" * 40,
            "source_dataset_split": "test",
            "source_dataset_artifact_path": "default/test/0000.parquet",
            "source_dataset_artifact_git_blob_oid": source_dataset_pointer_oid,
            "source_dataset_lfs_pointer": source_dataset_pointer_ref,
            "source_dataset_artifact_lfs_sha256": source_dataset_lfs_sha256,
            "source_dataset_artifact_lfs_bytes": len(source_dataset_bytes),
            "source_dataset_artifact_xet_sha256": "5" * 64,
            "source_dataset_artifact": source_dataset_ref,
            "source_dataset_row_ordinal": 8,
            "instance_id": "owner__repo-9",
            "upstream_record": upstream_ref,
            "fixing_pr_evidence": fixing_evidence_ref,
            "mapping_method": (
                "pinned_tdd_filter_plus_upstream_row_plus_pr_capture_plus_independent_review"
            ),
        },
        "fixing_pull_request": {
            "number": 9,
            "url": "https://github.com/owner/repo/pull/9",
            "created_at": PR_CREATED_AT,
            "published_at": CUTOFF_AT,
            "target_sha256": _target_sha256(),
            "fixed_commit_sha": "d" * 40,
            "base_root_tree_oid": BASE_TREE_OID,
            "head_root_tree_oid": HEAD_TREE_OID,
            "production_patch_sha256": hashlib.sha256(PRODUCTION_PATCH.encode()).hexdigest(),
            "developer_tests_sha256": hashlib.sha256(DEVELOPER_TESTS.encode()).hexdigest(),
        },
        "evaluator_artifacts": hidden,
        "review": {
            "status": "approved",
            "reviewed_at": "2026-07-10T14:00:00Z",
            "reviewer_ids": ["mapping-reviewer-1", "mapping-reviewer-2"],
            "checklist": mapping_checklist,
            "mapping_correct": True,
            "upstream_license_reviewed": True,
            "generator_access": "forbidden",
        },
        "tool": {"name": "fixture-builder", "version": "1.0.0", "git_sha": "e" * 40},
    }
    mapping_ref = _write(root, "evaluator/benchmark-v02-fix-mapping.json", _canonical(fix_mapping))
    supporting = {
        "source_receipt": _write(root, "support/source-receipt.json", b'{"source":true}\n'),
        "dependency_receipt": _write(
            root, "support/dependency-receipt.json", b'{"dependencies":true}\n'
        ),
        "isolation_canary_receipt": _write(
            root, "support/isolation-canary.json", b'{"accepted":true}\n'
        ),
        "reviewer_role_seal": _write(root, "support/reviewer-role-seal.json", b'{"sealed":true}\n'),
    }
    mapping_verified = load_fix_mapping_receipt(
        root / "evaluator/benchmark-v02-fix-mapping.json",
        package_root=root,
        expected_case=CASE,
    )
    semantic = _fixture_semantic_verification(
        V02SemanticVerificationContext(
            case=CASE,
            package_root=root,
            mapping=mapping_verified,
            supporting_inputs={
                name: ArtifactReference(**cast(dict[str, Any], reference))
                for name, reference in supporting.items()
            },
            generator_projection=ArtifactReference(**cast(dict[str, Any], projection_ref)),
            isolation_policy_sha256="f" * 64,
        )
    )
    supporting["semantic_verification_receipt"] = _write(
        root, "support/semantic-verification.json", _canonical(asdict(semantic))
    )
    snapshot_refs = {
        "receipt": snapshot_ref,
        "raw_history": raw_ref,
        "cutoff_basis": cutoff_ref,
        "privacy_review": privacy_ref,
        "generator_projection": projection_ref,
    }
    mapping_artifacts = [
        tdd_id_list_ref,
        source_dataset_pointer_ref,
        source_dataset_ref,
        upstream_ref,
        fixing_evidence_ref,
        hidden["causal_controls"],
        hidden["developer_tests"],
        hidden["oracle_rubric"],
        hidden["production_patch"],
        hidden["reviewer_packet"],
        mapping_checklist,
    ]
    tool = {"name": "fixture-builder", "version": "1.0.0", "git_sha": "e" * 40}
    identity = {
        "algorithm": EVALUATOR_PACKAGE_ALGORITHM,
        "case": asdict(CASE),
        "snapshot": snapshot_refs,
        "fix_mapping": mapping_ref,
        "fix_artifacts": mapping_artifacts,
        "supporting_inputs": supporting,
        "isolation_policy_sha256": "f" * 64,
        "semantic_verification": asdict(semantic),
        "tool": tool,
    }
    identity_sha256 = hashlib.sha256(_canonical(identity)[:-1]).hexdigest()
    nonce = new_evaluator_commitment_nonce()
    public_commitment = hashlib.sha256(
        EVALUATOR_COMMITMENT_ALGORITHM.encode()
        + b"\0"
        + bytes.fromhex(nonce)
        + b"\0"
        + bytes.fromhex(identity_sha256)
    ).hexdigest()
    package = {
        "schema_version": "1.0.0",
        "benchmark_version": BENCHMARK_VERSION,
        "case": asdict(CASE),
        "snapshot": snapshot_refs,
        "fix_mapping": {"receipt": mapping_ref},
        "supporting_inputs": supporting,
        "isolation": {
            "policy_sha256": "f" * 64,
            "generator_visible_artifacts": ["generator_projection"],
            "evaluator_artifacts_mounted_in_generator": False,
            "network_after_dependency_prep": "disabled",
        },
        "evaluator_package": {
            "algorithm": EVALUATOR_PACKAGE_ALGORITHM,
            "commitment_algorithm": EVALUATOR_COMMITMENT_ALGORITHM,
            "commitment_nonce": nonce,
            "nonce_generation": "controller_secrets_token_bytes_32",
            "identity_sha256": identity_sha256,
            "public_commitment_sha256": public_commitment,
        },
        "tool": tool,
    }
    package_path = root / CASE_PACKAGE_FILENAME
    package_path.write_bytes(_canonical(package))
    return package_path, package, fix_mapping


def _preregistered_cases() -> list[PreregisteredV02Case]:
    return [
        PreregisteredV02Case(
            id=f"rk-v0.2-{index:03d}",
            repo=f"owner/repo{(index + 1) // 2}",
            issue_url=f"https://github.com/owner/repo{(index + 1) // 2}/issues/{index}",
            base_sha=f"{index:040x}",
            difficulty="lt_15m" if index <= 14 else "15m_to_1h",
            smoke=index in {4, 6, 10, 11, 18},
            generator_projection_sha256=f"{index + 100:064x}",
            evaluator_commitment_sha256=f"{index + 200:064x}",
            source_context_sha256=f"{index + 300:064x}",
        )
        for index in range(1, 21)
    ]


def test_root_and_bundled_v02_schemas_are_identical_and_valid() -> None:
    for filename in (
        "benchmark-v02-fix-mapping.schema.json",
        "benchmark-v02-case-package.schema.json",
        "benchmark-v02-preregistration.schema.json",
        "benchmark-v02-semantic-verification.schema.json",
    ):
        root = ROOT / "schemas" / filename
        bundled = ROOT / "src" / "reproassert" / "schemas" / filename
        assert root.read_bytes() == bundled.read_bytes()
        Draft202012Validator.check_schema(json.loads(root.read_text()))


def test_complete_private_case_package_rederives_safe_projection_and_hidden_identity(
    tmp_path: Path,
) -> None:
    package_path, package, fix_mapping = _build_case_package(tmp_path)

    verified = verify_v02_case_package(package_path, trusted_semantic_verifier=SEMANTIC_VERIFIER)

    assert verified.case == CASE
    assert (
        verified.generator_projection_sha256
        == package["snapshot"]["generator_projection"]["sha256"]
    )
    assert verified.evaluator_package_sha256 == package["evaluator_package"]["identity_sha256"]
    assert (
        verified.evaluator_commitment_sha256
        == package["evaluator_package"]["public_commitment_sha256"]
    )
    assert verified.difficulty == "lt_15m"
    assert verified.evaluator_capability is None
    projection = (package_path.parent / "generator/generator-case.json").read_text()
    assert set(json.loads(projection)) == {
        "schema_version",
        "benchmark_version",
        "case_id",
        "repo",
        "issue_url",
        "base_sha",
        "issue_snapshot",
    }
    for evaluator_only in (
        fix_mapping["fixing_pull_request"]["url"],
        fix_mapping["fixing_pull_request"]["fixed_commit_sha"],
        "production fix",
        "mapping-reviewer-1",
    ):
        assert evaluator_only not in projection

    for filename, instance in (
        ("benchmark-v02-fix-mapping.schema.json", fix_mapping),
        ("benchmark-v02-case-package.schema.json", package),
        (
            "benchmark-v02-semantic-verification.schema.json",
            json.loads((package_path.parent / "support/semantic-verification.json").read_text()),
        ),
    ):
        schema = json.loads((ROOT / "schemas" / filename).read_text())
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(instance)


def test_case_package_defaults_to_not_ready_without_application_trusted_verifier(
    tmp_path: Path,
) -> None:
    package_path, _, _ = _build_case_package(tmp_path)
    with pytest.raises(PolicyRejection, match="trusted external semantic verifier"):
        verify_v02_case_package(package_path)


def test_plugin_semantic_verifier_cannot_mint_l1_evaluator_capability(tmp_path: Path) -> None:
    package_path, _, _ = _build_case_package(tmp_path)
    verified = verify_v02_case_package(package_path, trusted_semantic_verifier=SEMANTIC_VERIFIER)
    assert verified.evaluator_capability is None


def test_nominal_evaluator_capability_rejects_corrupted_issuer() -> None:
    capability = package_module.VerifiedV02EvaluatorCapability(
        package_module._CAPABILITY_ISSUER,
        case=CASE,
        preregistration_sha256="1" * 64,
        cohort_sha256="2" * 64,
        preregistered_case_sha256="3" * 64,
        package_identity_sha256="5" * 64,
        public_commitment_sha256="6" * 64,
        generator_projection_sha256="4" * 64,
        dataset_evidence_sha256="a" * 64,
        base_commit_sha=CASE.base_sha,
        base_root_tree_oid=BASE_TREE_OID,
        source_receipt_sha256="b" * 64,
        source_tree_sha256=SOURCE_TREE_SHA256,
        source_context_algorithm="reproassert-v02-source-context-v1",
        source_context_policy_sha256="c" * 64,
        source_context_sha256="d" * 64,
        hidden_fixed_root_tree_oid=HIDDEN_FIXED_TREE_OID,
        fixing_head_commit_sha="7" * 40,
        fixing_head_root_tree_oid=HEAD_TREE_OID,
        production_patch_sha256="8" * 64,
        developer_tests_sha256="9" * 64,
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
    object.__setattr__(capability, "_issuer", object())

    with pytest.raises(PolicyRejection, match="issuer"):
        package_module.require_v02_evaluator_capability(capability)


@pytest.mark.parametrize(
    "mutation",
    [
        "raw_changed",
        "projection_changed",
        "privacy_changed",
        "mapping_missing",
        "source_symlink",
        "path_traversal",
        "path_double_slash",
        "path_dot_segment",
        "support_hardlink",
        "isolation_mount",
        "identity_hash",
        "public_commitment",
    ],
)
def test_case_package_fails_closed_on_missing_changed_or_exposed_artifacts(
    tmp_path: Path, mutation: str
) -> None:
    package_path, package, _ = _build_case_package(tmp_path)
    root = package_path.parent
    if mutation == "raw_changed":
        (root / "snapshot/issue-history.json").write_text("changed")
    elif mutation == "projection_changed":
        (root / "generator/generator-case.json").write_text('{"fix":"leaked"}\n')
    elif mutation == "privacy_changed":
        (root / "reviews/privacy-review.txt").write_text("changed review\n")
    elif mutation == "mapping_missing":
        (root / "evaluator/benchmark-v02-fix-mapping.json").unlink()
    elif mutation == "source_symlink":
        source = root / "support/source-receipt.json"
        content = source.read_bytes()
        source.unlink()
        replacement = root / "outside-source.json"
        replacement.write_bytes(content)
        source.symlink_to(replacement)
    elif mutation == "path_traversal":
        package["snapshot"]["raw_history"]["path"] = "../issue-history.json"
        package_path.write_bytes(_canonical(package))
    elif mutation == "path_double_slash":
        package["snapshot"]["raw_history"]["path"] = "snapshot//issue-history.json"
        package_path.write_bytes(_canonical(package))
    elif mutation == "path_dot_segment":
        package["snapshot"]["raw_history"]["path"] = "snapshot/./issue-history.json"
        package_path.write_bytes(_canonical(package))
    elif mutation == "support_hardlink":
        source = root / "support/source-receipt.json"
        dependency = root / "support/dependency-receipt.json"
        dependency.unlink()
        dependency.hardlink_to(source)
        package["supporting_inputs"]["dependency_receipt"] = {
            "path": "support/dependency-receipt.json",
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "bytes": len(source.read_bytes()),
        }
        package_path.write_bytes(_canonical(package))
    elif mutation == "isolation_mount":
        package["isolation"]["evaluator_artifacts_mounted_in_generator"] = True
        package_path.write_bytes(_canonical(package))
    elif mutation == "identity_hash":
        package["evaluator_package"]["identity_sha256"] = "0" * 64
        package_path.write_bytes(_canonical(package))
    else:
        package["evaluator_package"]["public_commitment_sha256"] = "0" * 64
        package_path.write_bytes(_canonical(package))

    with pytest.raises((PolicyRejection, OSError)):
        verify_v02_case_package(package_path, trusted_semantic_verifier=SEMANTIC_VERIFIER)


@pytest.mark.parametrize(
    "mutation",
    [
        "one_reviewer",
        "duplicate_reviewers",
        "wrong_target",
        "wrong_repo",
        "mapping_unapproved",
        "license_unreviewed",
        "generator_access",
        "reused_path",
        "upstream_base",
        "production_patch_drift",
        "upstream_difficulty",
        "fix_capture_head",
        "source_revision",
    ],
)
def test_fix_mapping_requires_independent_review_and_exact_target(
    tmp_path: Path, mutation: str
) -> None:
    package_path, _, fix_mapping = _build_case_package(tmp_path)
    root = package_path.parent
    if mutation == "one_reviewer":
        fix_mapping["review"]["reviewer_ids"] = ["mapping-reviewer-1"]
    elif mutation == "duplicate_reviewers":
        fix_mapping["review"]["reviewer_ids"] = ["mapping-reviewer-1", "mapping-reviewer-1"]
    elif mutation == "wrong_target":
        fix_mapping["fixing_pull_request"]["target_sha256"] = "0" * 64
    elif mutation == "wrong_repo":
        fix_mapping["fixing_pull_request"]["url"] = "https://github.com/other/repo/pull/9"
    elif mutation == "mapping_unapproved":
        fix_mapping["review"]["status"] = "pending"
    elif mutation == "license_unreviewed":
        fix_mapping["review"]["upstream_license_reviewed"] = False
    elif mutation == "generator_access":
        fix_mapping["review"]["generator_access"] = "allowed"
    elif mutation == "reused_path":
        fix_mapping["evaluator_artifacts"]["developer_tests"] = fix_mapping["evaluator_artifacts"][
            "production_patch"
        ]
    elif mutation == "upstream_base":
        upstream_path = root / "evaluator/upstream-record.json"
        upstream = json.loads(upstream_path.read_text())
        upstream["base_commit"] = "0" * 40
        fix_mapping["provenance"]["upstream_record"] = _write(
            root, "evaluator/upstream-record.json", _canonical(upstream)
        )
    elif mutation == "production_patch_drift":
        fix_mapping["evaluator_artifacts"]["production_patch"] = _write(
            root, "evaluator/production.patch", b"different production fix\n"
        )
    elif mutation == "upstream_difficulty":
        upstream_path = root / "evaluator/upstream-record.json"
        upstream = json.loads(upstream_path.read_text())
        upstream["difficulty"] = "<15 min"
        fix_mapping["provenance"]["upstream_record"] = _write(
            root, "evaluator/upstream-record.json", _canonical(upstream)
        )
    elif mutation == "fix_capture_head":
        evidence_path = root / "evaluator/fixing-pr-evidence.json"
        evidence = json.loads(evidence_path.read_text())
        evidence["response"]["data"]["repository"]["pullRequest"]["headRefOid"] = "0" * 40
        fix_mapping["provenance"]["fixing_pr_evidence"] = _write(
            root, "evaluator/fixing-pr-evidence.json", _canonical(evidence)
        )
    else:
        fix_mapping["provenance"]["source_dataset_git_sha"] = "not-pinned"
    mapping_path = root / "evaluator/benchmark-v02-fix-mapping.json"
    mapping_path.write_bytes(_canonical(fix_mapping))

    with pytest.raises(PolicyRejection):
        load_fix_mapping_receipt(mapping_path, package_root=root, expected_case=CASE)


def test_preregistration_freezes_exactly_20_safe_commitments_and_round_trips(
    tmp_path: Path,
) -> None:
    cases = _preregistered_cases()
    preregistration = build_v02_preregistration(
        cases,
        frozen_at="2026-07-10T15:00:00Z",
        tool_name="preregistration-builder",
        tool_version="1.0.0",
        tool_git_sha="f" * 40,
    )
    path = tmp_path / "preregistration.json"
    path.write_bytes(canonical_preregistration_bytes(preregistration))

    loaded = load_v02_preregistration(path)

    assert loaded.cases == tuple(cases)
    assert loaded.raw_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    serialized = path.read_text()
    for forbidden in (
        "https://github.com/owner/repo/pull/9",
        "d" * 40,
        "production fix",
        "mapping-reviewer-1",
    ):
        assert forbidden not in serialized
    schema = json.loads((ROOT / "schemas/benchmark-v02-preregistration.schema.json").read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(preregistration)


@pytest.mark.parametrize(
    "mutation",
    ["nineteen", "wrong_order", "six_smoke", "duplicate_url", "difficulty_skew", "repo_skew"],
)
def test_preregistration_rejects_post_hoc_or_malformed_cohorts(mutation: str) -> None:
    cases = _preregistered_cases()
    if mutation == "nineteen":
        cases.pop()
    elif mutation == "wrong_order":
        cases[0], cases[1] = cases[1], cases[0]
    elif mutation == "six_smoke":
        cases[0] = PreregisteredV02Case(**{**asdict(cases[0]), "smoke": True})
    elif mutation == "duplicate_url":
        cases[1] = PreregisteredV02Case(**{**asdict(cases[1]), "issue_url": cases[0].issue_url})
    elif mutation == "difficulty_skew":
        cases[14] = PreregisteredV02Case(**{**asdict(cases[14]), "difficulty": "lt_15m"})
    else:
        cases[18] = PreregisteredV02Case(
            **{
                **asdict(cases[18]),
                "repo": cases[0].repo,
                "issue_url": f"https://github.com/{cases[0].repo}/issues/19",
            }
        )
        cases[19] = PreregisteredV02Case(
            **{
                **asdict(cases[19]),
                "repo": cases[0].repo,
                "issue_url": f"https://github.com/{cases[0].repo}/issues/20",
            }
        )

    with pytest.raises(PolicyRejection):
        build_v02_preregistration(
            cases,
            frozen_at="2026-07-10T15:00:00Z",
            tool_name="preregistration-builder",
            tool_version="1.0.0",
            tool_git_sha="f" * 40,
        )


def test_cohort_audit_stays_false_when_private_packages_are_absent(tmp_path: Path) -> None:
    preregistration = build_v02_preregistration(
        _preregistered_cases(),
        frozen_at="2026-07-10T15:00:00Z",
        tool_name="preregistration-builder",
        tool_version="1.0.0",
        tool_git_sha="f" * 40,
    )
    prereg_path = tmp_path / "preregistration.json"
    prereg_path.write_bytes(canonical_preregistration_bytes(preregistration))
    packages = tmp_path / "private-packages"
    packages.mkdir(mode=0o700)

    audit = audit_v02_cohort_packages(prereg_path, packages_root=packages)

    assert audit.ready is False
    assert audit.verified_case_count == 0
    assert len(audit.blockers) == 20
    assert all(blocker.startswith("rk-v0.2-") for blocker in audit.blockers)


def test_cohort_audit_requires_every_commitment_to_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cases = _preregistered_cases()
    preregistration = build_v02_preregistration(
        cases,
        frozen_at="2026-07-10T15:00:00Z",
        tool_name="preregistration-builder",
        tool_version="1.0.0",
        tool_git_sha="f" * 40,
    )
    prereg_path = tmp_path / "preregistration.json"
    prereg_path.write_bytes(canonical_preregistration_bytes(preregistration))
    packages = tmp_path / "private-packages"
    packages.mkdir(mode=0o700)
    by_id = {case.id: case for case in cases}
    private_overrides: dict[str, dict[str, object]] = {}

    def fake_verify(
        path: Path, *, trusted_semantic_verifier: object = None
    ) -> VerifiedV02CasePackage:
        frozen = by_id[path.parent.name]
        ordinal = int(frozen.id.rsplit("-", 1)[1])
        capability = package_module.VerifiedV02EvaluatorCapability(
            package_module._CAPABILITY_ISSUER,
            case=V02CaseIdentity(frozen.id, frozen.repo, frozen.issue_url, frozen.base_sha),
            preregistration_sha256=hashlib.sha256(prereg_path.read_bytes()).hexdigest(),
            cohort_sha256=cast(str, preregistration["cohort_sha256"]),
            preregistered_case_sha256=hashlib.sha256(_canonical(asdict(frozen))[:-1]).hexdigest(),
            package_identity_sha256="9" * 64,
            public_commitment_sha256=frozen.evaluator_commitment_sha256,
            generator_projection_sha256=frozen.generator_projection_sha256,
            dataset_evidence_sha256="a" * 64,
            base_commit_sha=frozen.base_sha,
            base_root_tree_oid=f"{ordinal + 900:040x}",
            source_receipt_sha256="b" * 64,
            source_tree_sha256="8" * 64,
            source_context_algorithm="reproassert-v02-source-context-v1",
            source_context_policy_sha256="c" * 64,
            source_context_sha256=frozen.source_context_sha256,
            hidden_fixed_root_tree_oid=f"{ordinal + 1000:040x}",
            fixing_head_commit_sha=f"{ordinal + 500:040x}",
            fixing_head_root_tree_oid=f"{ordinal + 1100:040x}",
            production_patch_sha256="7" * 64,
            developer_tests_sha256="6" * 64,
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
        values: dict[str, object] = {
            "case": V02CaseIdentity(frozen.id, frozen.repo, frozen.issue_url, frozen.base_sha),
            "generator_projection_sha256": frozen.generator_projection_sha256,
            "evaluator_package_sha256": "9" * 64,
            "evaluator_commitment_sha256": frozen.evaluator_commitment_sha256,
            "snapshot_sha256": "8" * 64,
            "difficulty": frozen.difficulty,
            "upstream_instance_id": f"owner__repo{(ordinal + 1) // 2}-{ordinal}",
            "fixing_pr_number": ordinal,
            "fixed_commit_sha": f"{ordinal + 500:040x}",
            "hidden_fixed_root_tree_oid": f"{ordinal + 1000:040x}",
            "evaluator_commitment_nonce": f"{ordinal + 2000:064x}",
            "verification_completed_at": "2026-07-10T14:00:00Z",
            "evaluator_capability": capability,
        }
        values.update(private_overrides.get(frozen.id, {}))
        return VerifiedV02CasePackage(**values)  # type: ignore[arg-type]

    monkeypatch.setattr(package_module, "verify_v02_case_package", fake_verify)
    complete = audit_v02_cohort_packages(prereg_path, packages_root=packages)
    assert complete.ready is True
    assert complete.verified_case_count == 20

    private_overrides[cases[1].id] = {
        "upstream_instance_id": "owner__repo1-1",
        "evaluator_commitment_nonce": f"{1 + 2000:064x}",
    }
    duplicate = audit_v02_cohort_packages(prereg_path, packages_root=packages)
    assert duplicate.ready is False
    assert duplicate.verified_case_count == 20
    assert any("upstream_instance_duplicate" in blocker for blocker in duplicate.blockers)
    assert any("commitment_nonce_reused" in blocker for blocker in duplicate.blockers)
    private_overrides.clear()

    first = cases[0]
    by_id[first.id] = PreregisteredV02Case(
        **{**asdict(first), "evaluator_commitment_sha256": "0" * 64}
    )
    mismatched = audit_v02_cohort_packages(prereg_path, packages_root=packages)
    assert mismatched.ready is False
    assert mismatched.verified_case_count == 19


def test_preregistration_hash_and_canonical_encoding_are_independently_checked(
    tmp_path: Path,
) -> None:
    preregistration = build_v02_preregistration(
        _preregistered_cases(),
        frozen_at="2026-07-10T15:00:00Z",
        tool_name="preregistration-builder",
        tool_version="1.0.0",
        tool_git_sha="f" * 40,
    )
    preregistration["cohort_sha256"] = "0" * 64
    path = tmp_path / "preregistration.json"
    path.write_bytes(canonical_preregistration_bytes(preregistration))
    with pytest.raises(PolicyRejection):
        load_v02_preregistration(path)

    preregistration = build_v02_preregistration(
        _preregistered_cases(),
        frozen_at="2026-07-10T15:00:00Z",
        tool_name="preregistration-builder",
        tool_version="1.0.0",
        tool_git_sha="f" * 40,
    )
    preregistration["frozen_at"] = "2026-07-10T16:00:00Z"
    path.write_bytes(canonical_preregistration_bytes(preregistration))
    with pytest.raises(PolicyRejection):
        load_v02_preregistration(path)

    preregistration = build_v02_preregistration(
        _preregistered_cases(),
        frozen_at="2026-07-10T15:00:00Z",
        tool_name="preregistration-builder",
        tool_version="1.0.0",
        tool_git_sha="f" * 40,
    )
    cast(dict[str, Any], preregistration["tool"])["git_sha"] = "e" * 40
    path.write_bytes(canonical_preregistration_bytes(preregistration))
    with pytest.raises(PolicyRejection):
        load_v02_preregistration(path)

    path.write_text(json.dumps(preregistration, indent=2))
    with pytest.raises(PolicyRejection):
        load_v02_preregistration(path)


def test_private_package_root_must_be_mode_0700(tmp_path: Path) -> None:
    package_path, _, _ = _build_case_package(tmp_path)
    package_path.parent.chmod(0o755)
    with pytest.raises(PolicyRejection):
        verify_v02_case_package(package_path, trusted_semantic_verifier=SEMANTIC_VERIFIER)
    assert stat.S_IMODE(package_path.parent.stat().st_mode) == 0o755


def test_private_package_must_be_outside_any_git_checkout(tmp_path: Path) -> None:
    package_path, _, _ = _build_case_package(tmp_path)
    (tmp_path / ".git").mkdir()

    with pytest.raises(PolicyRejection, match="outside every Git checkout"):
        verify_v02_case_package(package_path, trusted_semantic_verifier=SEMANTIC_VERIFIER)


def test_git_checkout_rejection_does_not_depend_on_editable_import_location(
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "synthetic-checkout"
    package_root = checkout / "private-package"
    package_root.mkdir(parents=True, mode=0o700)
    (checkout / ".git").write_text("gitdir: /outside/worktree\n", encoding="utf-8")
    fake_installed_module = (
        tmp_path / "venv/lib/python3.14/site-packages/reproassert/benchmark_v02_package.py"
    )
    script = """
import sys
from pathlib import Path

import reproassert.benchmark_v02_package as package
from reproassert.errors import PolicyRejection

package.__file__ = sys.argv[2]
try:
    package._require_outside_source_checkout(Path(sys.argv[1]))
except PolicyRejection:
    raise SystemExit(0)
raise SystemExit(42)
"""

    completed = subprocess.run(
        [sys.executable, "-I", "-c", script, str(package_root), str(fake_installed_module)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_publication_scan_rejects_private_nonce_identity_and_patch_bytes(tmp_path: Path) -> None:
    package_path, package, _ = _build_case_package(tmp_path)
    public = tmp_path / "public"
    public.mkdir()
    (public / "README.md").write_text("safe public content\n")

    clean = scan_v02_publication_tree(public, private_package_paths=[package_path])
    assert clean.safe is True

    nonce = package["evaluator_package"]["commitment_nonce"]
    identity_sha256 = package["evaluator_package"]["identity_sha256"]
    (public / "leak.txt").write_text(
        f"owner__repo-9\n{nonce}\n{identity_sha256}\n{PRODUCTION_PATCH}", encoding="utf-8"
    )
    leaked = scan_v02_publication_tree(public, private_package_paths=[package_path])
    assert leaked.safe is False
    assert any("upstream_instance" in blocker for blocker in leaked.blockers)
    assert any("commitment_nonce" in blocker for blocker in leaked.blockers)
    assert any("package_identity_sha256" in blocker for blocker in leaked.blockers)
    assert any("production_patch" in blocker for blocker in leaked.blockers)


def test_publication_scan_rejects_exact_evaluator_only_artifact_copy(tmp_path: Path) -> None:
    package_path, _, fix_mapping = _build_case_package(tmp_path)
    public = tmp_path / "public"
    public.mkdir()
    oracle_reference = cast(dict[str, Any], fix_mapping["evaluator_artifacts"])["oracle_rubric"]
    oracle_path = package_path.parent / oracle_reference["path"]
    (public / "rubric.json").write_bytes(oracle_path.read_bytes())

    scan = scan_v02_publication_tree(public, private_package_paths=[package_path])

    assert scan.safe is False
    assert any("exact-private-artifact" in blocker for blocker in scan.blockers)
    assert any("oracle-rubric" in blocker for blocker in scan.blockers)


@pytest.mark.parametrize("directory_name", [".venv", "__pycache__", ".pytest_cache", ".mypy_cache"])
def test_publication_scan_fails_closed_on_excluded_directory(
    tmp_path: Path, directory_name: str
) -> None:
    package_path, _, fix_mapping = _build_case_package(tmp_path)
    public = tmp_path / "public"
    hidden = public / directory_name
    hidden.mkdir(parents=True)
    oracle_reference = cast(dict[str, Any], fix_mapping["evaluator_artifacts"])["oracle_rubric"]
    oracle_path = package_path.parent / oracle_reference["path"]
    (hidden / "oracle.json").write_bytes(oracle_path.read_bytes())

    scan = scan_v02_publication_tree(public, private_package_paths=[package_path])

    assert scan.safe is False
    assert f"excluded-directory:{directory_name}" in scan.blockers


def test_publication_scan_rejects_secret_paths_and_symlinks(tmp_path: Path) -> None:
    package_path, package, _ = _build_case_package(tmp_path)
    public = tmp_path / "public"
    public.mkdir()

    identity = "owner__repo-9"
    (public / f"{identity}.txt").write_text("safe body\n", encoding="utf-8")
    identity_leak = scan_v02_publication_tree(public, private_package_paths=[package_path])
    assert identity_leak.safe is False
    assert any(
        ":path:" in blocker and "upstream_instance" in blocker for blocker in identity_leak.blockers
    )

    (public / f"{identity}.txt").unlink()
    nonce = package["evaluator_package"]["commitment_nonce"]
    secret_directory = public / nonce
    secret_directory.mkdir()
    directory_leak = scan_v02_publication_tree(public, private_package_paths=[package_path])
    assert directory_leak.safe is False
    assert any(
        ":path:" in blocker and "commitment_nonce" in blocker for blocker in directory_leak.blockers
    )

    secret_directory.rmdir()
    (public / "private-package").symlink_to(package_path.parent, target_is_directory=True)
    symlink_leak = scan_v02_publication_tree(public, private_package_paths=[package_path])
    assert symlink_leak.safe is False
    assert "symlink:private-package" in symlink_leak.blockers


def test_publication_scan_rejects_file_symlink_even_when_target_is_safe(tmp_path: Path) -> None:
    package_path, _, _ = _build_case_package(tmp_path)
    public = tmp_path / "public"
    public.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("safe body\n", encoding="utf-8")
    (public / "outside.txt").symlink_to(target)

    scan = scan_v02_publication_tree(public, private_package_paths=[package_path])

    assert scan.safe is False
    assert "symlink:outside.txt" in scan.blockers
