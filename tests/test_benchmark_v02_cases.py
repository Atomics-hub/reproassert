from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from reproassert import benchmark_v02_cases as cases
from reproassert.benchmark_v02_runner import V02PricingSnapshot
from reproassert.errors import PolicyRejection
from reproassert.git_objects import VerifiedGitObjectPlan


def _write_json(path: Path, value: object) -> dict[str, object]:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    raw = cases._canonical(value) + b"\n"
    path.write_bytes(raw)
    os.chmod(path, 0o600)
    return {
        "bytes": len(raw),
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _relative_ref(root: Path, relative: str, value: object) -> dict[str, object]:
    result = _write_json(root / relative, value)
    result["path"] = relative
    return result


@pytest.fixture
def prepared_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    root = tmp_path / "private" / cases.CASES_PREPARATION_DIRECTORY
    root.mkdir(mode=0o700, parents=True)
    os.chmod(root.parent, 0o700)
    os.chmod(root, 0o700)
    (root / "cases").mkdir(mode=0o700)
    (root / "inputs").mkdir(mode=0o700)
    cohort_cases: list[dict[str, object]] = [
        {
            "base_sha": f"{position:040x}",
            "case_id": f"rk-v0.2-{position:03d}",
            "issue_url": f"https://github.com/acme/project/issues/{position}",
            "repo": "acme/project",
        }
        for position in range(1, 21)
    ]
    cohort: dict[str, object] = {"cases": cohort_cases}
    cohort_ref = _relative_ref(root, "inputs/cohort-plan.json", cohort)
    pricing = V02PricingSnapshot(
        provider="openai",
        requested_model="gpt-5.4-mini-2026-03-17",
        effective_at="2026-07-10T00:00:00Z",
        source="official pricing snapshot fixture",
        input_microusd_per_million_tokens=750_000,
        cached_input_microusd_per_million_tokens=75_000,
        output_microusd_per_million_tokens=4_500_000,
        sandbox_microusd_per_second=0,
        artifact_microusd_per_million_bytes=0,
        paid_storage_microusd=0,
        dependency_prep_microusd=0,
    )
    pricing_ref = _relative_ref(root, "inputs/pricing-snapshot.json", pricing.record())

    dataset_root = tmp_path / "dataset"
    dataset_root.mkdir(mode=0o700)
    projections: list[dict[str, object]] = []
    projection_values: dict[str, dict[str, object]] = {}
    for item in cohort_cases:
        case_id = cast(str, item["case_id"])
        projection: dict[str, object] = {
            "base_sha": item["base_sha"],
            "case_id": case_id,
            "issue_text": f"public issue report {case_id}",
            "issue_text_chronology": "chronology_unproven",
            "issue_url": item["issue_url"],
            "repo": item["repo"],
        }
        projection_values[case_id] = projection
        ref = _relative_ref(dataset_root, f"projections/{case_id}.json", projection)
        projections.append({"case_id": case_id, **ref})
    dataset_record = {
        "inputs": {"cohort_plan": {"sha256": cohort_ref["sha256"]}},
        "outputs": {"projections": projections},
    }
    dataset_receipt = dataset_root / "dataset.json"
    _write_json(dataset_receipt, dataset_record)

    hidden_root = tmp_path / "hidden"
    hidden_root.mkdir(mode=0o700)
    hidden_receipt = hidden_root / "hidden.json"
    _write_json(hidden_receipt, {"fixture": True})
    gold: dict[str, dict[str, dict[str, object]]] = {}
    for item in cohort_cases:
        case_id = cast(str, item["case_id"])
        refs: dict[str, dict[str, object]] = {}
        for name in ("developer_tests", "metadata", "production_patch"):
            path = hidden_root / case_id / f"{name}.bin"
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            raw = (f"secret-{case_id}-{name}-" * 3).encode()
            path.write_bytes(raw)
            os.chmod(path, 0o600)
            refs[name] = {
                "bytes": len(raw),
                "path": path,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        gold[case_id] = refs

    source_root = tmp_path / "sources"
    source_root.mkdir(mode=0o700)
    sources: dict[str, dict[str, object]] = {
        cast(str, item["case_id"]): {
            "archive_bytes": 123,
            "archive_path": str(source_root / f"{item['case_id']}.tar.gz"),
            "archive_sha256": hashlib.sha256(f"archive-{item['case_id']}".encode()).hexdigest(),
            "git_root_tree_oid": "1" * 40,
            "receipt_path": str(source_root / f"{item['case_id']}.json"),
            "receipt_sha256": "2" * 64,
            "tree_sha256": hashlib.sha256(f"tree-{item['case_id']}".encode()).hexdigest(),
            "verification_state": "fresh_git_object_rederivation_passed",
        }
        for item in cohort_cases
    }
    hidden_verified = SimpleNamespace(
        prepared=SimpleNamespace(
            receipt_path=hidden_receipt,
            artifacts_sha256="3" * 64,
        )
    )
    dataset_verified = SimpleNamespace(root=dataset_root, receipt_path=dataset_receipt)

    monkeypatch.setattr(cases, "load_v02_object_source_plan", lambda _: None)
    monkeypatch.setattr(cases, "load_v02_leak_audited_cohort_plan", lambda _: cohort)
    monkeypatch.setattr(cases, "_load_pricing", lambda _: pricing)
    monkeypatch.setattr(cases, "verify_v02_dataset_preparation", lambda _: dataset_verified)
    monkeypatch.setattr(cases, "verify_v02_hidden_gold", lambda _: hidden_verified)
    monkeypatch.setattr(cases, "hidden_case_artifacts", lambda _, case_id: gold[case_id])
    monkeypatch.setattr(
        cases,
        "_source_package",
        lambda _root, case, cohort_plan_path: (dict(sources[case["case_id"]]), object()),
    )
    monkeypatch.setattr(
        cases,
        "_render_provider_request",
        lambda projection, source, pricing: (
            {"input": projection["case_id"], "model": pricing.requested_model},
            hashlib.sha256(str(projection["case_id"]).encode()).hexdigest(),
        ),
    )

    package_rows: list[dict[str, object]] = []
    request_digests: list[str] = []
    for item in cohort_cases:
        case_id = cast(str, item["case_id"])
        projection_ref = _relative_ref(
            root, f"cases/{case_id}/generator-projection.json", projection_values[case_id]
        )
        source = sources[case_id]
        inventory_ref = _relative_ref(
            root, f"cases/{case_id}/dependency-inventory.json", cases._dependency_inventory(source)
        )
        provider_request, rendered_sha = cases._render_provider_request(
            projection_values[case_id], cast(VerifiedGitObjectPlan, object()), pricing
        )
        request_ref = _relative_ref(
            root,
            f"cases/{case_id}/request-envelope.json",
            cases._request_envelope(
                case_id=case_id,
                projection=projection_ref,
                source=source,
                pricing=pricing,
                tool_git_sha="4" * 40,
                provider_request=provider_request,
                rendered_input_sha256=rendered_sha,
            ),
        )
        overlap_audit = cases._gold_overlap_audit(
            cases._canonical(json.loads((root / cast(str, request_ref["path"])).read_text())),
            gold[case_id],
        )
        request_digests.append(cast(str, request_ref["sha256"]))
        review_ref = _relative_ref(
            root,
            f"cases/{case_id}/review-workflow.json",
            cases._review_workflow(case_id, gold[case_id]),
        )
        dependency, dependency_blockers = cases._dependency_state(
            None, item, cast(str, source["tree_sha256"])
        )
        package = {
            "base_sha": item["base_sha"],
            "blockers": sorted(
                [
                    "chronology_unproven",
                    "mapping_review_requires_two_genuine_reviewers",
                    "semantic_review_requires_candidate_and_two_genuine_reviewers",
                    "preregistration_not_bound",
                    "spend_not_authorized",
                    *dependency_blockers,
                ]
            ),
            "case_id": case_id,
            "dependency": dependency,
            "dependency_inventory": inventory_ref,
            "generator_projection": projection_ref,
            "hidden_artifacts_sha256": "3" * 64,
            "issue_url": item["issue_url"],
            "preexisting_gold_overlap": overlap_audit,
            "repo": item["repo"],
            "request_envelope": request_ref,
            "review_workflow": review_ref,
            "source": {key: value for key, value in source.items() if key != "archive_path"},
            "status": "pre_review_preparation_blocked",
        }
        package_ref = _relative_ref(root, f"cases/{case_id}/package.json", package)
        package_rows.append(
            {"case_id": case_id, **package_ref, "status": "pre_review_preparation_blocked"}
        )

    request_set = cases._set_hash(
        request_digests, "reproassert-v02-provider-request-envelope-set-v1"
    )
    spend_ref = _relative_ref(root, "spend-gate.json", cases._spend_gate(pricing, request_set))
    dataset_external = _write_json(dataset_receipt, dataset_record)
    dataset_external["storage"] = "evaluator_private_external"
    hidden_external = _write_json(hidden_receipt, {"fixture": True})
    hidden_external["storage"] = "evaluator_private_external"
    record: dict[str, object] = {
        "algorithm": cases.CASES_PREPARATION_ALGORITHM,
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
            "cohort_plan": cohort_ref,
            "dataset_preparation": dataset_external,
            "dependency_plans_root": None,
            "hidden_extraction": hidden_external,
            "object_sources_root": {
                "path": str(source_root),
                "storage": "evaluator_private_external_directory",
            },
            "pricing_snapshot": pricing_ref,
        },
        "packages": package_rows,
        "prepared_at": "2026-07-10T12:00:00Z",
        "preparation_set_sha256": cases._set_hash(
            [str(row["sha256"]) for row in package_rows],
            "reproassert-v02-preparation-package-set-v1",
        ),
        "provider_execution_enabled": False,
        "request_set_sha256": request_set,
        "schema_version": cases.CASES_PREPARATION_SCHEMA_VERSION,
        "spend_gate": spend_ref,
        "status": "prepared_review_required_provider_disabled",
        "tool": {"git_sha": "4" * 40, "provenance": "publisher_declared_revision"},
    }
    record["receipt_sha256"] = cases._self_hash(record)
    receipt = root / cases.CASES_PREPARATION_FILENAME
    receipt.write_bytes(cases._canonical(record) + b"\n")
    os.chmod(receipt, 0o600)
    prepared = cases.V02CasesPreparation(root, receipt, "5" * 64, 20, 0, 0)
    monkeypatch.setattr(cases, "load_v02_cases_preparation", lambda _: prepared)
    return {"prepared": prepared, "record": record, "sources": sources}


def test_verifier_accepts_exact_provider_disabled_tree(prepared_tree: dict[str, Any]) -> None:
    prepared = cases.verify_v02_cases(prepared_tree["prepared"].receipt_path)
    assert prepared.case_count == 20
    assert prepared.provider_calls == 0


def test_verifier_rejects_ready_package_index(prepared_tree: dict[str, Any]) -> None:
    prepared_tree["record"]["packages"][0]["status"] = "ready"
    prepared_tree["record"]["receipt_sha256"] = cases._self_hash(prepared_tree["record"])
    receipt = prepared_tree["prepared"].receipt_path
    receipt.write_bytes(cases._canonical(prepared_tree["record"]) + b"\n")
    with pytest.raises(PolicyRejection, match="unsupported readiness claim"):
        cases.verify_v02_cases(receipt)


@pytest.mark.parametrize(
    ("filename", "mutate", "message"),
    [
        (
            "request-envelope.json",
            lambda value: value.update({"hidden_patch": "leak"}),
            "Request envelope differs",
        ),
        (
            "review-workflow.json",
            lambda value: value["mapping_review"]["reviewers"].__setitem__(0, "fake-reviewer"),
            "Reviewer workflow differs",
        ),
    ],
)
def test_verifier_rejects_recommitted_security_mutation(
    prepared_tree: dict[str, Any], filename: str, mutate: Any, message: str
) -> None:
    root = prepared_tree["prepared"].root
    case_id = "rk-v0.2-001"
    package_path = root / "cases" / case_id / "package.json"
    package = json.loads(package_path.read_text())
    artifact_path = root / "cases" / case_id / filename
    artifact = json.loads(artifact_path.read_text())
    mutate(artifact)
    package["request_envelope" if filename.startswith("request") else "review_workflow"] = (
        _relative_ref(root, f"cases/{case_id}/{filename}", artifact)
    )
    package_ref = _relative_ref(root, f"cases/{case_id}/package.json", package)
    row = prepared_tree["record"]["packages"][0]
    row.update(package_ref)
    prepared_tree["record"]["preparation_set_sha256"] = cases._set_hash(
        [str(item["sha256"]) for item in prepared_tree["record"]["packages"]],
        "reproassert-v02-preparation-package-set-v1",
    )
    prepared_tree["record"]["receipt_sha256"] = cases._self_hash(prepared_tree["record"])
    prepared_tree["prepared"].receipt_path.write_bytes(
        cases._canonical(prepared_tree["record"]) + b"\n"
    )
    with pytest.raises(PolicyRejection, match=message):
        cases.verify_v02_cases(prepared_tree["prepared"].receipt_path)


def test_verifier_rejects_world_visible_preparation_directory(
    prepared_tree: dict[str, Any],
) -> None:
    os.chmod(prepared_tree["prepared"].root / "cases", 0o755)  # noqa: S103
    with pytest.raises(PolicyRejection, match="owner-only 0700"):
        cases.verify_v02_cases(prepared_tree["prepared"].receipt_path)


def test_verifier_rejects_alternate_fresh_source(
    prepared_tree: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    original = dict(prepared_tree["sources"]["rk-v0.2-001"])
    original["tree_sha256"] = "f" * 64
    monkeypatch.setattr(cases, "_source_package", lambda *_args, **_kwargs: (original, object()))
    with pytest.raises(PolicyRejection):
        cases.verify_v02_cases(prepared_tree["prepared"].receipt_path)
