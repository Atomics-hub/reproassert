"""Trusted, provider-disabled preparation controller for the frozen v0.2 cases."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from reproassert.benchmark_v02_cohort import load_v02_leak_audited_cohort_plan
from reproassert.benchmark_v02_hidden import (
    hidden_case_artifacts,
    verify_v02_hidden_gold,
)
from reproassert.benchmark_v02_object_source import (
    _rederive_v02_object_source_receipt,
    load_v02_object_source_plan,
)
from reproassert.benchmark_v02_package import _require_outside_source_checkout
from reproassert.benchmark_v02_preparation import verify_v02_dataset_preparation
from reproassert.benchmark_v02_runner import (
    V02PricingSnapshot,
    _openai_request_payload,
    _pricing_from_record,
    _rendered_input_sha256,
)
from reproassert.context import build_source_context
from reproassert.dependency_prep import load_dependency_plan
from reproassert.errors import PolicyRejection
from reproassert.generator import GenerationRequest
from reproassert.git_objects import VerifiedGitObjectPlan, materialize_git_workspace
from reproassert.github_blobs import fetch_raw_git_blob
from reproassert.intake import parse_issue_url
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

CASES_PREPARATION_ALGORITHM = "reproassert-v02-cases-preparation-v1"
CASES_PREPARATION_SCHEMA_VERSION = "1.0.0"
CASES_PREPARATION_DIRECTORY = "v02-case-preparation"
CASES_PREPARATION_FILENAME = "benchmark-v02-cases-preparation.json"
MAX_RECEIPT_BYTES = 512 * 1024
MAX_SOURCE_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_PROJECTION_BYTES = 128 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
_CASE_ID = re.compile(r"rk-v0\.2-(?:00[1-9]|01[0-9]|020)\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_TIMESTAMP = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


@dataclass(frozen=True)
class V02CasesPreparation:
    root: Path
    receipt_path: Path
    receipt_sha256: str
    case_count: int
    dependency_ready_count: int
    campaign_ready_count: int
    provider_calls: int = 0


def prepare_v02_cases(
    *,
    cohort_plan_path: Path,
    dataset_preparation_receipt: Path,
    hidden_extraction_receipt: Path,
    object_sources_root: Path,
    output_root: Path,
    pricing_snapshot_path: Path,
    tool_git_sha: str,
    prepared_at: str,
    dependency_plans_root: Path | None = None,
) -> V02CasesPreparation:
    """Create 20 review-ready preparation packages without provider-capable behavior."""

    parent = Path(output_root)
    require_private_directory(parent)
    _require_outside_source_checkout(parent)
    timestamp = _timestamp(prepared_at)
    producer_sha = _git_sha(tool_git_sha)
    destination = parent / CASES_PREPARATION_DIRECTORY
    if destination.exists() or destination.is_symlink():
        raise _reject("Refusing to overwrite an existing v0.2 case preparation.")

    # These verifiers rerun the no-network Docker boundaries before any package is written.
    dataset = verify_v02_dataset_preparation(Path(dataset_preparation_receipt))
    hidden = verify_v02_hidden_gold(Path(hidden_extraction_receipt))
    load_v02_object_source_plan(Path(cohort_plan_path))
    plan = load_v02_leak_audited_cohort_plan(Path(cohort_plan_path))
    cases = _ordered_cases(plan)
    pricing = _load_pricing(Path(pricing_snapshot_path))
    if pricing.requested_model != "gpt-5.4-mini-2026-03-17":
        raise _reject("Pricing must use the frozen GPT-5.4 mini model snapshot.")

    created = False
    try:
        destination.mkdir(mode=0o700)
        created = True
        os.chmod(destination, 0o700, follow_symlinks=False)
        require_private_directory(destination)
        for relative in ("cases", "inputs"):
            path = destination / relative
            path.mkdir(mode=0o700)
            os.chmod(path, 0o700, follow_symlinks=False)

        input_refs = {
            "cohort_plan": _copy_ref(
                Path(cohort_plan_path), destination, "inputs/cohort-plan.json", 512 * 1024
            ),
            "dataset_preparation": _external_ref(dataset.receipt_path, MAX_RECEIPT_BYTES),
            "hidden_extraction": _external_ref(hidden.prepared.receipt_path, MAX_RECEIPT_BYTES),
            "pricing_snapshot": _copy_ref(
                Path(pricing_snapshot_path), destination, "inputs/pricing-snapshot.json", 64 * 1024
            ),
            "object_sources_root": {
                "path": str(Path(object_sources_root).resolve(strict=True)),
                "storage": "evaluator_private_external_directory",
            },
            "dependency_plans_root": (
                None
                if dependency_plans_root is None
                else {
                    "path": str(Path(dependency_plans_root).resolve(strict=True)),
                    "storage": "evaluator_private_external_directory",
                }
            ),
        }

        dataset_record = _json_object(
            dataset.receipt_path, MAX_RECEIPT_BYTES, "dataset preparation"
        )
        projection_rows = cast(
            dict[str, dict[str, object]],
            {
                cast(str, row["case_id"]): cast(dict[str, object], row)
                for row in cast(dict[str, Any], dataset_record["outputs"])["projections"]
            },
        )
        package_rows: list[dict[str, object]] = []
        request_envelope_digests: list[str] = []
        dependency_ready_count = 0
        for case in cases:
            case_id = cast(str, case["case_id"])
            case_dir = destination / "cases" / case_id
            case_dir.mkdir(mode=0o700)
            os.chmod(case_dir, 0o700, follow_symlinks=False)
            projection_ref = projection_rows[case_id]
            projection_source = dataset.root / cast(str, projection_ref["path"])
            projection = _copy_ref(
                projection_source,
                destination,
                f"cases/{case_id}/generator-projection.json",
                MAX_PROJECTION_BYTES,
            )
            projection_value = _json_object(
                destination / cast(str, projection["path"]),
                MAX_PROJECTION_BYTES,
                "generator projection",
                allow_utf8_canonical=True,
            )
            _require_projection_binding(case, projection_value)

            source, exact_source_plan = _source_package(
                Path(object_sources_root), case, cohort_plan_path=Path(cohort_plan_path)
            )
            inventory = _dependency_inventory(source)
            inventory_ref = _write_json_ref(
                destination,
                f"cases/{case_id}/dependency-inventory.json",
                inventory,
            )
            dependency, dependency_blockers = _dependency_state(
                dependency_plans_root,
                case,
                cast(str, source["tree_sha256"]),
            )
            if not dependency_blockers:
                dependency_ready_count += 1

            gold = hidden_case_artifacts(hidden, case_id)
            _reject_gold_leak(projection_source, gold)
            provider_request, rendered_input_sha256 = _render_provider_request(
                projection_value, exact_source_plan, pricing
            )
            request = _request_envelope(
                case_id=case_id,
                projection=projection,
                source=source,
                pricing=pricing,
                tool_git_sha=producer_sha,
                provider_request=provider_request,
                rendered_input_sha256=rendered_input_sha256,
            )
            _reject_gold_content(
                _canonical(request), gold, f"provider request envelope for {case_id}"
            )
            overlap_audit = _gold_overlap_audit(_canonical(request), gold)
            request_ref = _write_json_ref(
                destination, f"cases/{case_id}/request-envelope.json", request
            )
            request_envelope_digests.append(cast(str, request_ref["sha256"]))
            reviews = _review_workflow(case_id, gold)
            review_ref = _write_json_ref(
                destination, f"cases/{case_id}/review-workflow.json", reviews
            )
            blockers = [
                "chronology_unproven",
                "mapping_review_requires_two_genuine_reviewers",
                "semantic_review_requires_candidate_and_two_genuine_reviewers",
                "preregistration_not_bound",
                "spend_not_authorized",
                *dependency_blockers,
            ]
            if cast(int, overlap_audit["added_line_overlap_count"]) > 0:
                blockers.append("preexisting_hidden_added_line_overlap_detected")
            package = {
                "base_sha": case["base_sha"],
                "blockers": sorted(blockers),
                "case_id": case_id,
                "dependency": dependency,
                "dependency_inventory": inventory_ref,
                "generator_projection": projection,
                "hidden_artifacts_sha256": hidden.prepared.artifacts_sha256,
                "issue_url": case["issue_url"],
                "preexisting_gold_overlap": overlap_audit,
                "repo": case["repo"],
                "request_envelope": request_ref,
                "review_workflow": review_ref,
                "source": {key: value for key, value in source.items() if key != "archive_path"},
                "status": "pre_review_preparation_blocked",
            }
            package_ref = _write_json_ref(destination, f"cases/{case_id}/package.json", package)
            package_rows.append({"case_id": case_id, **package_ref, "status": package["status"]})

        request_set_sha256 = _set_hash(
            request_envelope_digests, "reproassert-v02-provider-request-envelope-set-v1"
        )
        spend_gate = _spend_gate(pricing, request_set_sha256)
        spend_ref = _write_json_ref(destination, "spend-gate.json", spend_gate)
        preparation_set_sha256 = _set_hash(
            [cast(str, row["sha256"]) for row in package_rows],
            "reproassert-v02-preparation-package-set-v1",
        )
        record: dict[str, object] = {
            "algorithm": CASES_PREPARATION_ALGORITHM,
            "benchmark_version": "0.2",
            "case_count": 20,
            "claims": {
                "campaign_ready_count": 0,
                "chronology": "unproven",
                "model_or_provider_invoked": False,
                "provider_calls": 0,
                "reviewer_approvals_fabricated": False,
            },
            "dependency_ready_count": dependency_ready_count,
            "inputs": input_refs,
            "packages": package_rows,
            "prepared_at": timestamp,
            "preparation_set_sha256": preparation_set_sha256,
            "provider_execution_enabled": False,
            "request_set_sha256": request_set_sha256,
            "schema_version": CASES_PREPARATION_SCHEMA_VERSION,
            "spend_gate": spend_ref,
            "status": "prepared_review_required_provider_disabled",
            "tool": {"git_sha": producer_sha, "provenance": "publisher_declared_revision"},
        }
        record["receipt_sha256"] = _self_hash(record)
        encoded = _canonical(record) + b"\n"
        if len(encoded) > MAX_RECEIPT_BYTES:
            raise _reject("Case preparation receipt exceeds its byte limit.")
        write_bytes_exclusive(destination / CASES_PREPARATION_FILENAME, encoded)
        return load_v02_cases_preparation(destination / CASES_PREPARATION_FILENAME)
    except BaseException:
        if created:
            shutil.rmtree(destination, ignore_errors=True)
        raise


def verify_v02_cases(receipt_path: Path) -> V02CasesPreparation:
    """Verify canonical packages, permissions, hashes, frozen pricing, and zero-spend state."""

    prepared = load_v02_cases_preparation(receipt_path)
    record = _load_receipt(prepared.receipt_path)
    _verify_private_tree(prepared.root)
    inputs = cast(dict[str, object], record["inputs"])
    if set(inputs) != {
        "cohort_plan",
        "dataset_preparation",
        "dependency_plans_root",
        "hidden_extraction",
        "object_sources_root",
        "pricing_snapshot",
    }:
        raise _reject("Case preparation input fields are invalid.")
    cohort_ref = cast(dict[str, object], inputs["cohort_plan"])
    pricing_ref = cast(dict[str, object], inputs["pricing_snapshot"])
    _verify_ref(prepared.root, cohort_ref, "cohort plan")
    _verify_ref(prepared.root, pricing_ref, "pricing snapshot")
    cohort_path = prepared.root / cast(str, cohort_ref["path"])
    load_v02_object_source_plan(cohort_path)
    plan = load_v02_leak_audited_cohort_plan(cohort_path)
    cases = _ordered_cases(plan)
    pricing = _load_pricing(prepared.root / cast(str, pricing_ref["path"]))
    if pricing.requested_model != "gpt-5.4-mini-2026-03-17":
        raise _reject("Pricing must use the frozen GPT-5.4 mini model snapshot.")

    dataset_ref = cast(dict[str, object], inputs["dataset_preparation"])
    hidden_ref = cast(dict[str, object], inputs["hidden_extraction"])
    _verify_external_ref(dataset_ref, "dataset preparation")
    _verify_external_ref(hidden_ref, "hidden extraction")
    dataset = verify_v02_dataset_preparation(Path(cast(str, dataset_ref["path"])))
    hidden = verify_v02_hidden_gold(Path(cast(str, hidden_ref["path"])))
    dataset_record = _json_object(dataset.receipt_path, MAX_RECEIPT_BYTES, "dataset preparation")
    dataset_cohort_ref = cast(
        dict[str, object], cast(dict[str, object], dataset_record["inputs"])["cohort_plan"]
    )
    if dataset_cohort_ref.get("sha256") != cohort_ref.get("sha256"):
        raise _reject("Dataset preparation is not bound to the frozen controller cohort.")
    projection_rows = {
        cast(str, item["case_id"]): cast(dict[str, object], item)
        for item in cast(dict[str, Any], dataset_record["outputs"])["projections"]
    }
    source_root = _external_directory(inputs["object_sources_root"], "object sources root")
    dependency_root = (
        None
        if inputs["dependency_plans_root"] is None
        else _external_directory(inputs["dependency_plans_root"], "dependency plans root")
    )
    packages = cast(list[dict[str, object]], record["packages"])
    expected = [f"rk-v0.2-{position:03d}" for position in range(1, 21)]
    if [row.get("case_id") for row in packages] != expected:
        raise _reject("Prepared package ordering differs from the frozen cohort.")
    dependency_ready_count = 0
    request_envelope_digests: list[str] = []
    for row, case in zip(packages, cases, strict=True):
        case_id = cast(str, case["case_id"])
        if row.get("status") != "pre_review_preparation_blocked":
            raise _reject("Package index contains an unsupported readiness claim.")
        _verify_ref(prepared.root, row, f"package {row['case_id']}", extras={"case_id", "status"})
        package = _json_object(prepared.root / cast(str, row["path"]), MAX_RECEIPT_BYTES, "package")
        for name in (
            "dependency_inventory",
            "generator_projection",
            "request_envelope",
            "review_workflow",
        ):
            _verify_ref(prepared.root, cast(dict[str, object], package[name]), name)
        source, exact_source_plan = _source_package(source_root, case, cohort_plan_path=cohort_path)
        dependency, dependency_blockers = _dependency_state(
            dependency_root, case, cast(str, source["tree_sha256"])
        )
        if not dependency_blockers:
            dependency_ready_count += 1
        projection_ref = cast(dict[str, object], package["generator_projection"])
        projection_path = prepared.root / cast(str, projection_ref["path"])
        expected_projection_path = dataset.root / cast(str, projection_rows[case_id]["path"])
        if _read_regular(projection_path, MAX_PROJECTION_BYTES) != _read_regular(
            expected_projection_path, MAX_PROJECTION_BYTES
        ):
            raise _reject(
                f"Generator projection differs from fresh dataset evidence for {case_id}."
            )
        projection_value = _json_object(
            projection_path,
            MAX_PROJECTION_BYTES,
            "projection",
            allow_utf8_canonical=True,
        )
        _require_projection_binding(case, projection_value)
        gold = hidden_case_artifacts(hidden, case_id)
        _reject_gold_leak(projection_path, gold)
        review = _json_object(
            prepared.root / cast(str, cast(dict[str, object], package["review_workflow"])["path"]),
            MAX_RECEIPT_BYTES,
            "review workflow",
        )
        if review != _review_workflow(case_id, gold):
            raise _reject(f"Reviewer workflow differs from the trusted template for {case_id}.")
        request = _json_object(
            prepared.root / cast(str, cast(dict[str, object], package["request_envelope"])["path"]),
            MAX_RECEIPT_BYTES,
            "request",
        )
        provider_request, rendered_input_sha256 = _render_provider_request(
            projection_value, exact_source_plan, pricing
        )
        expected_request = _request_envelope(
            case_id=case_id,
            projection=projection_ref,
            source=source,
            pricing=pricing,
            tool_git_sha=cast(str, cast(dict[str, object], record["tool"])["git_sha"]),
            provider_request=provider_request,
            rendered_input_sha256=rendered_input_sha256,
        )
        if request != expected_request:
            raise _reject(f"Request envelope differs from trusted inputs for {case_id}.")
        _reject_gold_content(_canonical(request), gold, f"provider request envelope for {case_id}")
        overlap_audit = _gold_overlap_audit(_canonical(request), gold)
        request_envelope_digests.append(
            cast(str, cast(dict[str, object], package["request_envelope"])["sha256"])
        )
        inventory_ref = cast(dict[str, object], package["dependency_inventory"])
        inventory = _json_object(
            prepared.root / cast(str, inventory_ref["path"]),
            MAX_RECEIPT_BYTES,
            "dependency inventory",
        )
        if inventory != _dependency_inventory(source):
            raise _reject(f"Dependency source binding differs for {case_id}.")
        blockers = sorted(
            [
                "chronology_unproven",
                "mapping_review_requires_two_genuine_reviewers",
                "semantic_review_requires_candidate_and_two_genuine_reviewers",
                "preregistration_not_bound",
                "spend_not_authorized",
                *dependency_blockers,
            ]
        )
        if cast(int, overlap_audit["added_line_overlap_count"]) > 0:
            blockers.append("preexisting_hidden_added_line_overlap_detected")
            blockers.sort()
        expected_package = {
            "base_sha": case["base_sha"],
            "blockers": blockers,
            "case_id": case_id,
            "dependency": dependency,
            "dependency_inventory": inventory_ref,
            "generator_projection": projection_ref,
            "hidden_artifacts_sha256": hidden.prepared.artifacts_sha256,
            "issue_url": case["issue_url"],
            "preexisting_gold_overlap": overlap_audit,
            "repo": case["repo"],
            "request_envelope": package["request_envelope"],
            "review_workflow": package["review_workflow"],
            "source": {key: value for key, value in source.items() if key != "archive_path"},
            "status": "pre_review_preparation_blocked",
        }
        if package != expected_package:
            raise _reject(f"Preparation package differs from freshly derived inputs for {case_id}.")
    if record.get("dependency_ready_count") != dependency_ready_count:
        raise _reject("Dependency-ready count differs from fresh plan validation.")
    expected_set = _set_hash(
        [cast(str, row["sha256"]) for row in packages],
        "reproassert-v02-preparation-package-set-v1",
    )
    if record.get("preparation_set_sha256") != expected_set:
        raise _reject("Preparation package set commitment is invalid.")
    expected_request_set = _set_hash(
        request_envelope_digests, "reproassert-v02-provider-request-envelope-set-v1"
    )
    if record.get("request_set_sha256") != expected_request_set:
        raise _reject("Rendered request set commitment is invalid.")
    spend_ref = cast(dict[str, object], record["spend_gate"])
    _verify_ref(prepared.root, spend_ref, "spend gate")
    spend = _json_object(prepared.root / cast(str, spend_ref["path"]), 64 * 1024, "spend gate")
    expected_spend = _spend_gate(pricing, expected_request_set)
    if spend != expected_spend:
        raise _reject("Spend gate is not deny-by-default.")
    return prepared


def load_v02_cases_preparation(receipt_path: Path) -> V02CasesPreparation:
    path = Path(receipt_path)
    require_private_directory(path.parent)
    _require_outside_source_checkout(path.parent)
    record = _load_receipt(path)
    raw = _read_regular(path, MAX_RECEIPT_BYTES)
    return V02CasesPreparation(
        root=path.parent,
        receipt_path=path,
        receipt_sha256=hashlib.sha256(raw).hexdigest(),
        case_count=20,
        dependency_ready_count=cast(int, record["dependency_ready_count"]),
        campaign_ready_count=0,
    )


def _source_package(
    root: Path, case: dict[str, object], *, cohort_plan_path: Path
) -> tuple[dict[str, object], VerifiedGitObjectPlan]:
    case_id = cast(str, case["case_id"])
    case_root = root / f"{case_id}-object-v2"
    receipt_path = case_root / "benchmark-object-source-receipt.json"
    receipt_raw = _read_regular(receipt_path, MAX_SOURCE_RECEIPT_BYTES)
    receipt, _, exact_plan = _rederive_v02_object_source_receipt(
        receipt_path,
        plan_path=cohort_plan_path,
        expected_case_id=case_id,
        expected_receipt_sha256=hashlib.sha256(receipt_raw).hexdigest(),
        scratch_root=None,
        timeout_seconds=15.0,
        blob_fetcher=fetch_raw_git_blob,
    )
    identity = cast(dict[str, object], receipt.get("case"))
    if (
        identity.get("id") != case_id
        or identity.get("base_sha") != case["base_sha"]
        or identity.get("repository") != case["repo"]
    ):
        raise _reject(f"Object source identity differs for {case_id}.")
    source = cast(dict[str, object], receipt.get("source"))
    transport = cast(dict[str, object], source.get("transport"))
    workspace = cast(dict[str, object], source.get("verified_workspace"))
    if transport.get("path") != "source.tar.gz":
        raise _reject(f"Object source archive path is invalid for {case_id}.")
    archive = case_root / "source.tar.gz"
    archive_sha, archive_bytes = _hash_regular(archive, 256 * 1024 * 1024)
    if archive_sha != transport.get("sha256") or archive_bytes != transport.get("bytes"):
        raise _reject(f"Object source archive differs from its receipt for {case_id}.")
    return {
        "archive_bytes": archive_bytes,
        "archive_path": str(archive),
        "archive_sha256": archive_sha,
        "git_root_tree_oid": source.get("github_root_tree_oid"),
        "receipt_path": str(receipt_path.resolve(strict=True)),
        "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
        "tree_sha256": workspace.get("tree_sha256"),
        "verification_state": "fresh_git_object_rederivation_passed",
    }, exact_plan


def _dependency_inventory(source: dict[str, object]) -> dict[str, object]:
    """Bind dependency preparation to fresh source without host-parsing repository archives."""

    return {
        "algorithm": "reproassert-dependency-source-binding-v1",
        "archive_sha256": source["archive_sha256"],
        "execution_performed": False,
        "manifest_parsing": "deferred_to_resource_limited_dependency_preparation",
        "source_tree_sha256": source["tree_sha256"],
        "status": "source_bound_dependency_plan_required",
    }


def _dependency_state(
    root: Path | None, case: dict[str, object], tree_sha256: str
) -> tuple[dict[str, object], list[str]]:
    if root is None:
        return {"plan": None, "status": "hash_locked_dependency_plan_missing"}, [
            "hash_locked_dependency_plan_missing",
            "dependency_execution_receipt_missing",
        ]
    path = Path(root) / f"{case['case_id']}.json"
    if not path.is_file():
        return {"plan": None, "status": "hash_locked_dependency_plan_missing"}, [
            "hash_locked_dependency_plan_missing",
            "dependency_execution_receipt_missing",
        ]
    plan = load_dependency_plan(path)
    if (
        plan.case_id != case["case_id"]
        or plan.base_sha != case["base_sha"]
        or plan.source_tree_sha256 != tree_sha256
    ):
        raise _reject(f"Dependency plan binding differs for {case['case_id']}.")
    return {
        "canonical_sha256": plan.canonical_sha256,
        "package_count": len(plan.packages),
        "plan_sha256": plan.raw_sha256,
        "python_version": plan.python_version,
        "runner_image": plan.runner_image,
        "status": "hash_locked_plan_valid_execution_receipt_missing",
    }, ["dependency_execution_receipt_missing"]


def _reject_gold_leak(projection: Path, gold: dict[str, dict[str, object]]) -> None:
    safe = _read_regular(projection, MAX_PROJECTION_BYTES)
    _reject_gold_content(safe, gold, "generator projection")


def _reject_gold_content(safe: bytes, gold: dict[str, dict[str, object]], label: str) -> None:
    for artifact_name, reference in gold.items():
        hidden = _read_regular(cast(Path, reference["path"]), MAX_MANIFEST_BYTES)
        direct = {
            "artifact_bytes": hidden,
            "artifact_sha256": cast(str, reference["sha256"]).encode("ascii"),
            "artifact_path": str(reference["path"]).encode("utf-8"),
        }
        for match_type, value in direct.items():
            if value and value in safe:
                raise _reject(f"Hidden gold {artifact_name} {match_type} crossed into the {label}.")
        # Do not reject individual added lines: the exact request is independently rederived only
        # from the buggy base plus the leak-audited issue projection, so a matching line can be
        # legitimate pre-existing source (as in rk-v0.2-007). Full gold bytes, hashes, and private
        # paths above remain forbidden and catch actual evaluator-to-generator boundary crossings.


def _gold_overlap_audit(safe: bytes, gold: dict[str, dict[str, object]]) -> dict[str, object]:
    counts: dict[str, int] = {}
    for artifact_name in ("developer_tests", "production_patch"):
        reference = gold[artifact_name]
        hidden = _read_regular(cast(Path, reference["path"]), MAX_MANIFEST_BYTES)
        fragments = {
            line[1:]
            for line in hidden.splitlines()
            if line.startswith(b"+") and not line.startswith(b"+++") and len(line[1:]) >= 40
        }
        counts[artifact_name] = sum(fragment in safe for fragment in fragments)
    return {
        "added_line_overlap_count": sum(counts.values()),
        "artifact_counts": counts,
        "interpretation": (
            "overlap_independently_present_in_exact_buggy_base_or_leak_audited_issue_projection"
        ),
        "status": "bounded_nonsecret_contamination_signal",
    }


def _require_projection_binding(case: dict[str, object], projection: dict[str, object]) -> None:
    if (
        projection.get("case_id") != case["case_id"]
        or projection.get("base_sha") != case["base_sha"]
        or projection.get("repo") != case["repo"]
        or projection.get("issue_text_chronology") != "chronology_unproven"
    ):
        raise _reject(f"Generator projection differs from frozen case {case['case_id']}.")


def _request_envelope(
    *,
    case_id: str,
    projection: dict[str, object],
    source: dict[str, object],
    pricing: V02PricingSnapshot,
    tool_git_sha: str,
    provider_request: dict[str, object],
    rendered_input_sha256: str,
) -> dict[str, object]:
    return {
        "algorithm": "reproassert-v02-provider-disabled-request-envelope-v1",
        "case_id": case_id,
        "execution": {
            "authorization_status": "not_authorized",
            "provider_calls": 0,
            "provider_execution_enabled": False,
        },
        "generator_input": {
            "issue_projection_sha256": projection["sha256"],
            "source_archive_sha256": source["archive_sha256"],
            "source_tree_sha256": source["tree_sha256"],
        },
        "model": {
            "provider": pricing.provider,
            "requested_model": pricing.requested_model,
            "pricing_snapshot_sha256": pricing.sha256,
        },
        "provider_request": provider_request,
        "rendered_input_sha256": rendered_input_sha256,
        "status": "frozen_not_executable_pending_preregistration_and_authorization",
        "tool_git_sha": tool_git_sha,
    }


def _render_provider_request(
    projection: dict[str, object],
    exact_source_plan: VerifiedGitObjectPlan,
    pricing: V02PricingSnapshot,
) -> tuple[dict[str, object], str]:
    issue_url = cast(str, projection["issue_url"])
    issue_text = cast(str, projection["issue_text"])
    issue_number = parse_issue_url(issue_url).number
    with tempfile.TemporaryDirectory(prefix="reproassert-v02-request-") as temporary:
        root = Path(temporary).resolve(strict=True)
        os.chmod(root, 0o700)
        workspace = materialize_git_workspace(exact_source_plan, root / "base")
        context = build_source_context(
            workspace.path,
            issue_title="",
            issue_body=issue_text,
        )
        request = GenerationRequest(
            issue_url=issue_url,
            issue_number=issue_number,
            issue_title="",
            issue_body=issue_text,
            source_sha=cast(str, projection["base_sha"]),
            source_context=context,
        )
        payload = _openai_request_payload(request, pricing.requested_model)
        rendered_sha256 = _rendered_input_sha256(request)
    return payload, rendered_sha256


def _review_workflow(case_id: str, gold: dict[str, dict[str, object]]) -> dict[str, object]:
    return {
        "algorithm": "reproassert-v02-two-reviewer-workflow-v1",
        "artifact_access": (
            "evaluator_private_verified_hidden_capability_only_never_generator_visible"
        ),
        "case_id": case_id,
        "consensus": {
            "acceptance": "two_matching_accept_verdicts",
            "rejection": "two_matching_reject_verdicts",
            "tie_break_trigger": "first_two_verdicts_disagree",
            "tie_break_result": "third_independent_verdict_is_decisive",
        },
        "mapping_review": {
            "blind_artifact_commitments": {
                name: {"bytes": ref["bytes"], "sha256": ref["sha256"]} for name, ref in gold.items()
            },
            "rubric": [
                "production_patch_targets_the_reported_symptom",
                "developer_tests_exercise_the_same_symptom",
                "patch_pair_maps_to_the_exact_base_commit",
                "license_and_redistribution_are_acceptable",
                "no_unrelated_or_oracle_only_change_is_relied_upon",
            ],
            "reviewers": [None, None],
            "status": "blocked_genuine_reviewers",
            "tie_break": {"reviewer": None, "required_only_on_disagreement": True},
        },
        "semantic_review": {
            "candidate_sha256": None,
            "evidence_contract": [
                "base_failure_classification",
                "patched_base_pass_result",
                "perturbed_candidate_control_result",
                "repeated_run_consistency",
                "bounded_logs",
            ],
            "rubric": [
                "candidate_fails_on_buggy_base_for_intended_symptom",
                "candidate_passes_after_hidden_human_fix",
                "candidate_does_not_pass_only_by_generic_failure",
                "causal_control_supports_fix_specificity",
                "result_is_consistent_and_nonflaky",
            ],
            "reviewers": [None, None],
            "status": "blocked_candidate_and_genuine_reviewers",
            "tie_break": {"reviewer": None, "required_only_on_disagreement": True},
        },
        "separation_policy": "mapping_and_semantic_reviewers_must_be_disjoint",
        "submission_schema": {
            "additional_fields": False,
            "required": [
                "reviewer_id",
                "role",
                "verdict",
                "rationale",
                "evidence_sha256",
                "reviewed_at",
                "conflict_of_interest",
            ],
            "verdicts": ["accept", "reject"],
        },
    }


def _spend_gate(pricing: V02PricingSnapshot, request_set_sha256: str) -> dict[str, object]:
    authorization_text = (
        "NOT AUTHORIZED. Proposed maximum: USD 0.25 per case and USD 5.00 total for "
        "20 frozen v0.2 cases using gpt-5.4-mini-2026-03-17. Provider execution remains "
        "disabled until Tom separately approves these exact caps and the bound request set."
    )
    return {
        "algorithm": "reproassert-v02-zero-spend-gate-v1",
        "authorization_proposal": {
            "approved": False,
            "authorization_text": authorization_text,
            "authorization_text_sha256": hashlib.sha256(
                authorization_text.encode("utf-8")
            ).hexdigest(),
            "limits": {
                "max_campaign_attributable_microusd": 5_000_000,
                "max_case_attributable_microusd": 250_000,
                "max_case_wall_ms": 600_000,
                "max_input_tokens": 128_000,
                "max_output_tokens": 4_096,
                "provider_timeout_ms": 120_000,
            },
            "request_set_sha256": request_set_sha256,
            "signed_at": None,
        },
        "authorization_status": "not_authorized",
        "environment_credentials_read": False,
        "pricing_snapshot_sha256": pricing.sha256,
        "provider_calls": 0,
        "provider_execution_enabled": False,
        "requested_model": pricing.requested_model,
        "status": "blocked_until_exact_capped_user_authorization",
    }


def _ordered_cases(plan: dict[str, object]) -> list[dict[str, object]]:
    raw = plan.get("cases")
    if not isinstance(raw, list) or len(raw) != 20:
        raise _reject("Frozen cohort must contain exactly 20 cases.")
    cases = [cast(dict[str, object], item) for item in raw if isinstance(item, dict)]
    expected = [f"rk-v0.2-{position:03d}" for position in range(1, 21)]
    if [case.get("case_id") for case in cases] != expected:
        raise _reject("Frozen cohort case ordering is invalid.")
    return cases


def _load_receipt(path: Path) -> dict[str, object]:
    value = _json_object(path, MAX_RECEIPT_BYTES, "case preparation receipt")
    required = {
        "algorithm",
        "benchmark_version",
        "case_count",
        "claims",
        "dependency_ready_count",
        "inputs",
        "packages",
        "prepared_at",
        "preparation_set_sha256",
        "provider_execution_enabled",
        "request_set_sha256",
        "receipt_sha256",
        "schema_version",
        "spend_gate",
        "status",
        "tool",
    }
    if (
        set(value) != required
        or value.get("algorithm") != CASES_PREPARATION_ALGORITHM
        or value.get("benchmark_version") != "0.2"
        or value.get("schema_version") != CASES_PREPARATION_SCHEMA_VERSION
        or value.get("case_count") != 20
        or value.get("status") != "prepared_review_required_provider_disabled"
        or value.get("provider_execution_enabled") is not False
        or value.get("receipt_sha256") != _self_hash(value)
    ):
        raise _reject("Case preparation receipt identity is invalid.")
    claims = value.get("claims")
    if claims != {
        "campaign_ready_count": 0,
        "chronology": "unproven",
        "model_or_provider_invoked": False,
        "provider_calls": 0,
        "reviewer_approvals_fabricated": False,
    }:
        raise _reject("Case preparation claims are invalid.")
    dependency_count = value.get("dependency_ready_count")
    if type(dependency_count) is not int or not 0 <= dependency_count <= 20:
        raise _reject("Dependency-ready count is invalid.")
    packages = value.get("packages")
    if not isinstance(packages, list) or len(packages) != 20:
        raise _reject("Case preparation must index exactly 20 packages.")
    tool = value.get("tool")
    if (
        not isinstance(tool, dict)
        or set(tool) != {"git_sha", "provenance"}
        or tool.get("provenance") != "publisher_declared_revision"
    ):
        raise _reject("Case preparation tool provenance is invalid.")
    _git_sha(tool.get("git_sha"))
    for name in ("preparation_set_sha256", "request_set_sha256"):
        value_digest = value.get(name)
        if not isinstance(value_digest, str) or _SHA256.fullmatch(value_digest) is None:
            raise _reject(f"Case preparation {name} is invalid.")
    _timestamp(value.get("prepared_at"))
    return value


def _copy_ref(source: Path, root: Path, relative: str, limit: int) -> dict[str, object]:
    return _write_ref(root, relative, _read_regular(source, limit))


def _external_ref(path: Path, limit: int) -> dict[str, object]:
    raw = _read_regular(path, limit)
    return {
        "bytes": len(raw),
        "path": str(path.resolve(strict=True)),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "storage": "evaluator_private_external",
    }


def _verify_external_ref(reference: dict[str, object], label: str) -> None:
    if (
        set(reference) != {"bytes", "path", "sha256", "storage"}
        or reference.get("storage") != "evaluator_private_external"
    ):
        raise _reject(f"{label} external reference is invalid.")
    path = Path(cast(str, reference["path"]))
    raw = _read_regular(path, MAX_RECEIPT_BYTES)
    if len(raw) != reference["bytes"] or hashlib.sha256(raw).hexdigest() != reference["sha256"]:
        raise _reject(f"{label} differs from its external commitment.")


def _external_directory(value: object, label: str) -> Path:
    if (
        not isinstance(value, dict)
        or value.get("storage") != "evaluator_private_external_directory"
        or set(value) != {"path", "storage"}
    ):
        raise _reject(f"{label} reference is invalid.")
    raw_path = value.get("path")
    if not isinstance(raw_path, str) or not Path(raw_path).is_absolute():
        raise _reject(f"{label} must be an absolute private path.")
    path = Path(raw_path)
    require_private_directory(path)
    _require_outside_source_checkout(path)
    return path


def _verify_private_tree(root: Path) -> None:
    expected_files = {
        Path(CASES_PREPARATION_FILENAME),
        Path("inputs/cohort-plan.json"),
        Path("inputs/pricing-snapshot.json"),
        Path("spend-gate.json"),
    }
    expected_dirs = {Path("."), Path("inputs"), Path("cases")}
    for position in range(1, 21):
        case_id = f"rk-v0.2-{position:03d}"
        case_dir = Path("cases") / case_id
        expected_dirs.add(case_dir)
        expected_files.update(
            case_dir / name
            for name in (
                "dependency-inventory.json",
                "generator-projection.json",
                "package.json",
                "request-envelope.json",
                "review-workflow.json",
            )
        )
    seen_files: set[Path] = set()
    seen_dirs: set[Path] = {Path(".")}
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        metadata = path.lstat()
        if metadata.st_uid != os.getuid():
            raise _reject("Preparation tree contains an artifact owned by another user.")
        mode = metadata.st_mode & 0o777
        if path.is_symlink():
            raise _reject("Preparation tree contains a symbolic link.")
        if path.is_dir():
            if mode != 0o700:
                raise _reject("Preparation directories must remain owner-only 0700.")
            seen_dirs.add(relative)
        elif path.is_file():
            if mode != 0o600 or metadata.st_nlink != 1:
                raise _reject("Preparation files must remain private regular single-link files.")
            seen_files.add(relative)
        else:
            raise _reject("Preparation tree contains a special filesystem entry.")
    if seen_dirs != expected_dirs or seen_files != expected_files:
        raise _reject("Preparation tree entries differ from the exact private layout.")


def _write_json_ref(root: Path, relative: str, value: object) -> dict[str, object]:
    return _write_ref(root, relative, _canonical(value) + b"\n")


def _write_ref(root: Path, relative: str, content: bytes) -> dict[str, object]:
    path = root / relative
    write_bytes_exclusive(path, content)
    return {"bytes": len(content), "path": relative, "sha256": hashlib.sha256(content).hexdigest()}


def _verify_ref(
    root: Path, reference: dict[str, object], label: str, *, extras: set[str] | None = None
) -> None:
    if set(reference) != {"bytes", "path", "sha256"} | (extras or set()):
        raise _reject(f"{label} reference fields are invalid.")
    relative = reference.get("path")
    if (
        not isinstance(relative, str)
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
    ):
        raise _reject(f"{label} path is unsafe.")
    raw = _read_regular(root / relative, MAX_RECEIPT_BYTES)
    if len(raw) != reference.get("bytes") or hashlib.sha256(raw).hexdigest() != reference.get(
        "sha256"
    ):
        raise _reject(f"{label} differs from its commitment.")


def _json_object(
    path: Path, limit: int, label: str, *, allow_utf8_canonical: bool = False
) -> dict[str, object]:
    raw = _read_regular(path, limit)
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _reject(f"{label} is invalid JSON.") from exc
    canonical_forms = {_canonical(value)}
    if allow_utf8_canonical:
        canonical_forms.add(_canonical_utf8(value))
    if not isinstance(value, dict) or raw.rstrip(b"\n") not in canonical_forms:
        raise _reject(f"{label} is not canonical JSON.")
    return cast(dict[str, object], value)


def _load_pricing(path: Path) -> V02PricingSnapshot:
    value = _json_object(path, 64 * 1024, "pricing snapshot")
    pricing = _pricing_from_record(value)
    if pricing.record() != value:
        raise _reject("Pricing snapshot is not canonical.")
    return pricing


def _read_regular(path: Path, limit: int) -> bytes:
    try:
        with open_regular_file(path) as stream:
            content = stream.read(limit + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject("A case preparation artifact could not be read safely.") from exc
    if len(content) > limit:
        raise _reject("A case preparation artifact exceeds its byte limit.")
    return content


def _hash_regular(path: Path, limit: int) -> tuple[str, int]:
    raw = _read_regular(path, limit)
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _set_hash(values: list[str], algorithm: str) -> str:
    return hashlib.sha256(_canonical({"algorithm": algorithm, "sha256": values})).hexdigest()


def _self_hash(record: dict[str, object]) -> str:
    unsigned = dict(record)
    unsigned.pop("receipt_sha256", None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _canonical_utf8(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject("Preparation timestamp is invalid.")
    return value


def _git_sha(value: object) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject("Tool Git SHA is invalid.")
    return value


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_cases", message)
