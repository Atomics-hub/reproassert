"""Exact-image successor preregistration assembled from verified provider-free evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from reproassert.benchmark_v02_cases import verify_v02_cases
from reproassert.benchmark_v02_chronology import verify_v02_chronology_evidence
from reproassert.benchmark_v02_cohort import load_v02_leak_audited_cohort_plan
from reproassert.benchmark_v02_exact_capability import (
    verify_v02_exact_image_capability_index,
)
from reproassert.benchmark_v02_mapping_packets import verify_v02_mapping_consensus
from reproassert.benchmark_v02_package import EXPECTED_SMOKE_CASE_IDS
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

ALGORITHM = "reproassert-v02-exact-image-preregistration-v1"
SCHEMA_VERSION = "1.0.0"
BENCHMARK_VERSION = "0.2"
MAX_BYTES = 2 * 1024 * 1024
_CASE_ID = re.compile(r"rk-v0\.2-(?:00[1-9]|01[0-9]|020)\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
_SMOKE_IDS = frozenset(EXPECTED_SMOKE_CASE_IDS)


@dataclass(frozen=True)
class VerifiedV02ExactPreregistration:
    path: Path
    sha256: str
    cohort_sha256: str
    request_set_sha256: str
    case_count: int
    evaluator_preflight_ready_count: int
    infrastructure_failure_count: int
    provider_calls: int = 0


def prepare_v02_exact_preregistration(
    *,
    cases_preparation_path: Path,
    cohort_plan_path: Path,
    chronology_path: Path,
    hidden_extraction_receipt: Path,
    issue_responses_root: Path,
    mapping_preparation_path: Path,
    mapping_consensus_path: Path,
    capability_index_path: Path,
    runtime_manifest_path: Path,
    expected_runtime_manifest_sha256: str,
    gold_smoke_receipt_path: Path,
    frozen_at: str,
    tool_git_sha: str,
    output_path: Path,
) -> VerifiedV02ExactPreregistration:
    """Freeze the exact 20-case request/evaluator bridge without invoking a provider."""

    destination = Path(output_path)
    require_private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise _reject("Refusing to overwrite an exact-image preregistration.")
    record = _derive_record(
        cases_preparation_path=Path(cases_preparation_path),
        cohort_plan_path=Path(cohort_plan_path),
        chronology_path=Path(chronology_path),
        hidden_extraction_receipt=Path(hidden_extraction_receipt),
        issue_responses_root=Path(issue_responses_root),
        mapping_preparation_path=Path(mapping_preparation_path),
        mapping_consensus_path=Path(mapping_consensus_path),
        capability_index_path=Path(capability_index_path),
        runtime_manifest_path=Path(runtime_manifest_path),
        expected_runtime_manifest_sha256=expected_runtime_manifest_sha256,
        gold_smoke_receipt_path=Path(gold_smoke_receipt_path),
        frozen_at=frozen_at,
        tool_git_sha=tool_git_sha,
    )
    record["preregistration_sha256"] = _self_hash(record)
    write_bytes_exclusive(destination, _canonical(record) + b"\n")
    return verify_v02_exact_preregistration(
        destination,
        cases_preparation_path=cases_preparation_path,
        cohort_plan_path=cohort_plan_path,
        chronology_path=chronology_path,
        hidden_extraction_receipt=hidden_extraction_receipt,
        issue_responses_root=issue_responses_root,
        mapping_preparation_path=mapping_preparation_path,
        mapping_consensus_path=mapping_consensus_path,
        capability_index_path=capability_index_path,
        runtime_manifest_path=runtime_manifest_path,
        expected_runtime_manifest_sha256=expected_runtime_manifest_sha256,
        gold_smoke_receipt_path=gold_smoke_receipt_path,
    )


def verify_v02_exact_preregistration(
    path: Path,
    *,
    cases_preparation_path: Path,
    cohort_plan_path: Path,
    chronology_path: Path,
    hidden_extraction_receipt: Path,
    issue_responses_root: Path,
    mapping_preparation_path: Path,
    mapping_consensus_path: Path,
    capability_index_path: Path,
    runtime_manifest_path: Path,
    expected_runtime_manifest_sha256: str,
    gold_smoke_receipt_path: Path,
) -> VerifiedV02ExactPreregistration:
    """Freshly rederive every preregistration row and exact evidence commitment."""

    output = Path(path)
    raw = _read_regular(output, MAX_BYTES, "exact-image preregistration")
    record = _decode_canonical(raw, "exact-image preregistration")
    _exact_keys(
        record,
        {
            "algorithm",
            "benchmark_version",
            "case_count",
            "case_set_sha256",
            "cases",
            "claims",
            "cohort_sha256",
            "evidence",
            "frozen_at",
            "policy",
            "preregistration_sha256",
            "request_set_sha256",
            "schema_version",
            "status",
            "tool_git_sha",
        },
        "exact-image preregistration",
    )
    if (
        record.get("algorithm") != ALGORITHM
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("benchmark_version") != BENCHMARK_VERSION
        or record.get("case_count") != 20
        or record.get("status") != "frozen_preinference_exact_image"
        or record.get("preregistration_sha256") != _self_hash(record)
    ):
        raise _reject("Exact-image preregistration identity is invalid.")
    expected = _derive_record(
        cases_preparation_path=Path(cases_preparation_path),
        cohort_plan_path=Path(cohort_plan_path),
        chronology_path=Path(chronology_path),
        hidden_extraction_receipt=Path(hidden_extraction_receipt),
        issue_responses_root=Path(issue_responses_root),
        mapping_preparation_path=Path(mapping_preparation_path),
        mapping_consensus_path=Path(mapping_consensus_path),
        capability_index_path=Path(capability_index_path),
        runtime_manifest_path=Path(runtime_manifest_path),
        expected_runtime_manifest_sha256=expected_runtime_manifest_sha256,
        gold_smoke_receipt_path=Path(gold_smoke_receipt_path),
        frozen_at=_timestamp(record.get("frozen_at"), "preregistration freeze"),
        tool_git_sha=_git_sha(record.get("tool_git_sha"), "preregistration tool Git SHA"),
    )
    unsigned = dict(record)
    unsigned.pop("preregistration_sha256")
    if unsigned != expected:
        raise _reject("Exact-image preregistration differs from freshly verified evidence.")
    return VerifiedV02ExactPreregistration(
        path=output,
        sha256=hashlib.sha256(raw).hexdigest(),
        cohort_sha256=cast(str, record["cohort_sha256"]),
        request_set_sha256=cast(str, record["request_set_sha256"]),
        case_count=20,
        evaluator_preflight_ready_count=19,
        infrastructure_failure_count=1,
    )


def _derive_record(
    *,
    cases_preparation_path: Path,
    cohort_plan_path: Path,
    chronology_path: Path,
    hidden_extraction_receipt: Path,
    issue_responses_root: Path,
    mapping_preparation_path: Path,
    mapping_consensus_path: Path,
    capability_index_path: Path,
    runtime_manifest_path: Path,
    expected_runtime_manifest_sha256: str,
    gold_smoke_receipt_path: Path,
    frozen_at: str,
    tool_git_sha: str,
) -> dict[str, object]:
    frozen = _timestamp(frozen_at, "preregistration freeze")
    frozen_value = _timestamp_value(frozen)
    if frozen_value > datetime.now(timezone.utc):
        raise _reject("Exact-image preregistration cannot be future-dated.")
    producer_sha = _git_sha(tool_git_sha, "preregistration tool Git SHA")
    manifest_sha = _digest(expected_runtime_manifest_sha256, "runtime manifest")

    prepared = verify_v02_cases(cases_preparation_path)
    chronology = verify_v02_chronology_evidence(
        chronology_path,
        cohort_plan_path=cohort_plan_path,
        hidden_extraction_receipt=hidden_extraction_receipt,
        issue_responses_root=issue_responses_root,
    )
    mapping = verify_v02_mapping_consensus(
        mapping_consensus_path, preparation_path=mapping_preparation_path
    )
    capability = verify_v02_exact_image_capability_index(
        capability_index_path,
        manifest_path=runtime_manifest_path,
        expected_manifest_sha256=manifest_sha,
        gold_smoke_receipt_path=gold_smoke_receipt_path,
        hidden_extraction_receipt=hidden_extraction_receipt,
    )
    if (
        prepared.case_count != 20
        or chronology.case_count != 20
        or chronology.issue_precedes_fix_count != 20
        or mapping.case_count != 20
        or capability.case_count != 20
        or capability.runtime_attested_count != 20
        or capability.evaluator_preflight_ready_count != 19
        or capability.infrastructure_failure_count != 1
        or any(item.provider_calls != 0 for item in (prepared, chronology, capability))
    ):
        raise _reject("Successor evidence does not preserve the exact 20-case denominator.")

    plan = load_v02_leak_audited_cohort_plan(cohort_plan_path)
    prep_record = _decode_canonical(
        _read_regular(prepared.receipt_path, MAX_BYTES, "case preparation"),
        "case preparation",
    )
    mapping_prep = _decode_canonical(
        _read_regular(mapping_preparation_path, MAX_BYTES, "mapping packet set"),
        "mapping packet set",
    )
    consensus = _decode_canonical(
        _read_regular(mapping.path, MAX_BYTES, "mapping consensus"), "mapping consensus"
    )
    capability_record = _decode_canonical(
        _read_regular(capability.path, MAX_BYTES, "capability index"), "capability index"
    )
    chronology_record = _decode_canonical(
        _read_regular(chronology.path, MAX_BYTES, "chronology evidence"),
        "chronology evidence",
    )
    _require_before_freeze(prep_record.get("prepared_at"), frozen_value, "case preparation")
    _require_before_freeze(mapping_prep.get("prepared_at"), frozen_value, "mapping packets")
    _require_before_freeze(consensus.get("sealed_at"), frozen_value, "mapping consensus")
    _require_before_freeze(capability_record.get("prepared_at"), frozen_value, "capability index")
    _require_before_freeze(chronology_record.get("captured_at"), frozen_value, "chronology")
    prep_tool = _dict(prep_record.get("tool"), "case preparation tool")
    if (
        prep_tool.get("git_sha") != producer_sha
        or capability_record.get("tool_git_sha") != producer_sha
    ):
        raise _reject(
            "Case preparation, capability index, and preregistration must share the final tool SHA."
        )

    plan_cases = _ordered_rows(plan.get("cases"), "cohort plan")
    prep_packages = _ordered_rows(prep_record.get("packages"), "case preparation")
    mapping_cases = _ordered_rows(mapping_prep.get("cases"), "mapping packet set")
    consensus_cases = _ordered_rows(consensus.get("cases"), "mapping consensus")
    capability_cases = _ordered_rows(capability_record.get("cases"), "capability index")
    rows: list[dict[str, object]] = []
    for position, values in enumerate(
        zip(
            plan_cases,
            prep_packages,
            mapping_cases,
            consensus_cases,
            capability_cases,
            strict=True,
        ),
        start=1,
    ):
        plan_case, package_ref, mapping_case, consensus_case, capability_case = values
        case_id = f"rk-v0.2-{position:03d}"
        if any(row.get("case_id") != case_id for row in values):
            raise _reject("Successor case evidence is incomplete or cross-case swapped.")
        decision = _dict(consensus_case.get("consensus"), "mapping consensus decision")
        selected = decision.get("selected_hunk_ids")
        if decision.get("verdict") != "approved" or not isinstance(selected, list) or not selected:
            raise _reject(f"{case_id} lacks an approved non-empty mapping consensus.")
        packet_path = _resolve_relative(
            Path(mapping_preparation_path).parent,
            cast(str, _dict(mapping_case.get("packet"), "mapping packet reference")["path"]),
        )
        packet = _decode_canonical(
            _read_regular(packet_path, MAX_BYTES, "mapping packet"), "mapping packet"
        )
        if packet.get("packet_sha256") != consensus_case.get("packet_sha256"):
            raise _reject(f"{case_id} consensus changed after packet verification.")

        package_path = _resolve_relative(
            prepared.root,
            cast(str, _dict(package_ref, "case package reference")["path"]),
        )
        package = _decode_canonical(
            _read_regular(package_path, MAX_BYTES, "case package"), "case package"
        )
        projection = _dict(package.get("generator_projection"), "generator projection reference")
        request_ref = _dict(package.get("request_envelope"), "request envelope reference")
        request_path = _resolve_relative(prepared.root, cast(str, request_ref["path"]))
        request = _decode_canonical(
            _read_regular(request_path, MAX_BYTES, "request envelope"), "request envelope"
        )
        generator_input = _dict(request.get("generator_input"), "request generator input")
        provider_request = _dict(request.get("provider_request"), "provider request")
        evidence = _dict(capability_case.get("evidence"), "exact evaluator evidence")
        runtime = _dict(evidence.get("runtime"), "exact runtime")
        hidden = _dict(evidence.get("hidden_inputs"), "exact hidden commitments")
        gold = _dict(evidence.get("gold_smoke"), "exact gold smoke")
        if (
            package.get("repo") != plan_case.get("repo")
            or package.get("issue_url") != plan_case.get("issue_url")
            or package.get("base_sha") != plan_case.get("base_sha")
            or runtime.get("base_sha") != plan_case.get("base_sha")
            or runtime.get("instance_id") != plan_case.get("instance_id")
            or runtime.get("case_id") != case_id
            or evidence.get("runtime_manifest_sha256") != manifest_sha
            or generator_input.get("issue_projection_sha256") != projection.get("sha256")
            or hidden.get("production_patch_sha256") != mapping_case.get("production_patch_sha256")
        ):
            raise _reject(f"{case_id} successor source/evaluator identity is inconsistent.")
        expected_status = (
            "runtime_attested_gold_smoke_infrastructure_failure"
            if case_id == "rk-v0.2-014"
            else "runtime_attested_evaluator_preflight_ready"
        )
        expected_gold = (
            ("infrastructure_failure", "network_dependency")
            if case_id == "rk-v0.2-014"
            else ("semantic_valid", "fails_on_base_passes_on_fixed")
        )
        if (
            capability_case.get("status") != expected_status
            or (gold.get("case_classification"), gold.get("case_reason")) != expected_gold
        ):
            raise _reject(f"{case_id} exact evaluator preflight status is invalid.")
        candidate_profile = (
            "sympy-native-v1"
            if runtime.get("test_command_profile") == "sympy-bin-test-v1"
            else "pytest-v1"
        )
        rendered_input = provider_request.get("input")
        if not isinstance(rendered_input, str):
            raise _reject(f"{case_id} provider request lacks exact rendered input.")
        try:
            rendered_record = json.loads(rendered_input)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise _reject(f"{case_id} rendered provider input is invalid JSON.") from exc
        if not isinstance(rendered_record, dict):
            raise _reject(f"{case_id} rendered provider input is not an object.")
        candidate_contract = _dict(
            rendered_record.get("candidate_contract"), "rendered candidate contract"
        )
        if candidate_contract.get("profile") != candidate_profile:
            raise _reject(f"{case_id} request and runtime candidate profiles differ.")
        rendered_sha = hashlib.sha256(rendered_input.encode()).hexdigest()
        if rendered_sha != request.get("rendered_input_sha256"):
            raise _reject(f"{case_id} rendered provider input commitment is invalid.")
        source_projection = {
            "generator_projection_sha256": _digest(
                projection.get("sha256"), "generator projection"
            ),
            "source_archive_sha256": _digest(
                generator_input.get("source_archive_sha256"), "source archive"
            ),
            "source_tree_sha256": _digest(generator_input.get("source_tree_sha256"), "source tree"),
        }
        source_projection_sha = _json_sha256(source_projection)
        selected_hunks_sha = _json_sha256(
            {"algorithm": "reproassert-v02-selected-hunk-set-v1", "atomic_ids": selected}
        )
        case_record: dict[str, object] = {
            "base_sha": plan_case["base_sha"],
            "candidate_profile": candidate_profile,
            "case_id": case_id,
            "difficulty": plan_case["difficulty"],
            "evaluator_commitment_sha256": capability_case["evaluator_public_commitment_sha256"],
            "evaluator_status": expected_status,
            "generator_projection_sha256": projection["sha256"],
            "instance_id": plan_case["instance_id"],
            "issue_url": plan_case["issue_url"],
            "mapping_selected_hunks_sha256": selected_hunks_sha,
            "outbound_request_sha256": request["outbound_request_sha256"],
            "rendered_input_sha256": rendered_sha,
            "repo": plan_case["repo"],
            "request_envelope_sha256": request_ref["sha256"],
            "smoke": case_id in _SMOKE_IDS,
            "source_projection_commitment_sha256": source_projection_sha,
            "test_command_profile": runtime["test_command_profile"],
        }
        case_record["case_commitment_sha256"] = _json_sha256(case_record)
        rows.append(case_record)

    request_set_sha = _digest(prep_record.get("request_set_sha256"), "request set")
    cohort_sha = _digest(plan.get("cohort_plan_sha256"), "cohort plan")
    case_set_sha = _json_sha256(
        {
            "algorithm": "reproassert-v02-exact-preregistered-case-set-v1",
            "case_commitments": [row["case_commitment_sha256"] for row in rows],
        }
    )
    return {
        "algorithm": ALGORITHM,
        "benchmark_version": BENCHMARK_VERSION,
        "case_count": 20,
        "case_set_sha256": case_set_sha,
        "cases": rows,
        "claims": {
            "evaluator_preflight_ready_count": 19,
            "infrastructure_failure_count": 1,
            "mapping_approved_count": 20,
            "model_or_provider_invoked": False,
            "provider_calls": 0,
        },
        "cohort_sha256": cohort_sha,
        "evidence": {
            "capability_index_sha256": capability.sha256,
            "cases_preparation_sha256": prepared.receipt_sha256,
            "chronology_sha256": chronology.sha256,
            "mapping_consensus_sha256": mapping.sha256,
            "mapping_packet_set_sha256": hashlib.sha256(
                _read_regular(mapping_preparation_path, MAX_BYTES, "mapping packet set")
            ).hexdigest(),
            "runtime_manifest_sha256": manifest_sha,
        },
        "frozen_at": frozen,
        "policy": {
            "candidate_budget_per_case": 1,
            "case_014_disposition": "retained_infrastructure_failure_network_disabled",
            "evaluator": "exact_swebench_instance_image_v1",
            "hidden_fix_generator_visible": False,
            "mapping_consensus_required": True,
            "preinference_freeze": True,
        },
        "request_set_sha256": request_set_sha,
        "schema_version": SCHEMA_VERSION,
        "status": "frozen_preinference_exact_image",
        "tool_git_sha": producer_sha,
    }


def _ordered_rows(value: object, label: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) != 20:
        raise _reject(f"{label.capitalize()} must preserve exactly 20 cases.")
    rows = [_dict(row, f"{label} case") for row in value]
    expected = [f"rk-v0.2-{number:03d}" for number in range(1, 21)]
    actual = [row.get("case_id") for row in rows]
    if any(not isinstance(item, str) or _CASE_ID.fullmatch(item) is None for item in actual):
        raise _reject(f"{label.capitalize()} contains an invalid case ID.")
    if actual != expected:
        raise _reject(f"{label.capitalize()} cases are incomplete or out of order.")
    return rows


def _require_before_freeze(value: object, frozen: datetime, label: str) -> None:
    if _timestamp_value(_timestamp(value, label)) > frozen:
        raise _reject(f"{label.capitalize()} occurs after preregistration freeze.")


def _resolve_relative(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or relative.startswith("/"):
        raise _reject("Evidence reference path is invalid.")
    parts = relative.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise _reject("Evidence reference path traversal is forbidden.")
    resolved_root = root.resolve(strict=True)
    resolved = root.joinpath(*parts).resolve(strict=True)
    if resolved_root not in resolved.parents:
        raise _reject("Evidence reference escapes its verified root.")
    return resolved


def _read_regular(path: Path, limit: int, label: str) -> bytes:
    try:
        with open_regular_file(Path(path)) as stream:
            raw = stream.read(limit + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"{label.capitalize()} could not be read safely.") from exc
    if not raw or len(raw) > limit:
        raise _reject(f"{label.capitalize()} exceeds its byte bound.")
    return raw


def _decode_canonical(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject(f"{label.capitalize()} is invalid JSON.") from exc
    if not isinstance(value, dict) or raw != _canonical(value) + b"\n":
        raise _reject(f"{label.capitalize()} is not canonical JSON.")
    return cast(dict[str, object], value)


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _dict(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise _reject(f"{label.capitalize()} must be an object.")
    return cast(dict[str, object], value)


def _exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise _reject(f"{label.capitalize()} fields are invalid.")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _json_sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _self_hash(value: dict[str, object]) -> str:
    return _json_sha256(
        {key: item for key, item in value.items() if key != "preregistration_sha256"}
    )


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject(f"{label.capitalize()} timestamp is invalid.")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _reject(f"{label.capitalize()} timestamp is invalid.") from exc
    return value


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _reject(f"{label.capitalize()} SHA-256 is invalid.")
    return value


def _git_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject(f"{label.capitalize()} is invalid.")
    return value


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_exact_preregistration", message)
