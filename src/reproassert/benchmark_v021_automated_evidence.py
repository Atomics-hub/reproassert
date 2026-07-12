"""Automated, provider-free oracle evidence for the v0.2.1 benchmark."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from reproassert.benchmark_v02_amendment import (
    VerifiedV02BenchmarkAmendment,
    require_v02_benchmark_amendment,
)
from reproassert.benchmark_v02_cases import verify_v02_cases
from reproassert.benchmark_v02_chronology import verify_v02_chronology_evidence
from reproassert.benchmark_v02_cohort import load_v02_leak_audited_cohort_plan
from reproassert.benchmark_v02_exact_capability import verify_v02_exact_image_capability_index
from reproassert.benchmark_v02_mapping_packets import verify_v02_mapping_packets
from reproassert.benchmark_v02_runner import _pricing_from_record
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

ALGORITHM = "reproassert-v021-automated-oracle-evidence-v1"
SCHEMA_VERSION = "1.0.0"
STATUS = "automated_oracle_validated_provider_disabled"
CASE_COUNT = 20
MAX_BYTES = 2 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TIMESTAMP = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
_ISSUER = object()


@dataclass(frozen=True, init=False)
class VerifiedV021AutomatedEvidence:
    """Process-local authority; the serialized receipt is evidence, not authority."""

    path: Path
    sha256: str
    lineage_commitment_sha256: str
    amendment_receipt_sha256: str
    request_set_sha256: str
    tool_git_sha: str
    case_count: int
    provider_calls: int
    human_reviewed: bool
    maintainer_validated: bool
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV021AutomatedEvidence is verifier-issued only")


def prepare_v021_automated_evidence(
    *,
    amendment_authority: VerifiedV02BenchmarkAmendment,
    cases_preparation_path: Path,
    cohort_plan_path: Path,
    chronology_path: Path,
    hidden_extraction_receipt: Path,
    issue_responses_root: Path,
    mapping_preparation_path: Path,
    capability_index_path: Path,
    runtime_manifest_path: Path,
    expected_runtime_manifest_sha256: str,
    gold_smoke_receipt_path: Path,
    pricing_snapshot_path: Path,
    verified_at: str,
    tool_git_sha: str,
    output_path: Path,
) -> VerifiedV021AutomatedEvidence:
    """Rederive the deterministic oracle chain and seal a non-human receipt."""

    destination = Path(output_path)
    require_private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise _reject("Refusing to overwrite automated evidence.")
    record = _derive(
        amendment_authority=amendment_authority,
        cases_preparation_path=Path(cases_preparation_path),
        cohort_plan_path=Path(cohort_plan_path),
        chronology_path=Path(chronology_path),
        hidden_extraction_receipt=Path(hidden_extraction_receipt),
        issue_responses_root=Path(issue_responses_root),
        mapping_preparation_path=Path(mapping_preparation_path),
        capability_index_path=Path(capability_index_path),
        runtime_manifest_path=Path(runtime_manifest_path),
        expected_runtime_manifest_sha256=expected_runtime_manifest_sha256,
        gold_smoke_receipt_path=Path(gold_smoke_receipt_path),
        pricing_snapshot_path=Path(pricing_snapshot_path),
        verified_at=verified_at,
        tool_git_sha=tool_git_sha,
    )
    record["receipt_sha256"] = _self_hash(record)
    write_bytes_exclusive(destination, _canonical(record) + b"\n")
    return verify_v021_automated_evidence(
        destination,
        amendment_authority=amendment_authority,
        cases_preparation_path=cases_preparation_path,
        cohort_plan_path=cohort_plan_path,
        chronology_path=chronology_path,
        hidden_extraction_receipt=hidden_extraction_receipt,
        issue_responses_root=issue_responses_root,
        mapping_preparation_path=mapping_preparation_path,
        capability_index_path=capability_index_path,
        runtime_manifest_path=runtime_manifest_path,
        expected_runtime_manifest_sha256=expected_runtime_manifest_sha256,
        gold_smoke_receipt_path=gold_smoke_receipt_path,
        pricing_snapshot_path=pricing_snapshot_path,
    )


def verify_v021_automated_evidence(
    path: Path,
    *,
    amendment_authority: VerifiedV02BenchmarkAmendment,
    cases_preparation_path: Path,
    cohort_plan_path: Path,
    chronology_path: Path,
    hidden_extraction_receipt: Path,
    issue_responses_root: Path,
    mapping_preparation_path: Path,
    capability_index_path: Path,
    runtime_manifest_path: Path,
    expected_runtime_manifest_sha256: str,
    gold_smoke_receipt_path: Path,
    pricing_snapshot_path: Path,
) -> VerifiedV021AutomatedEvidence:
    """Freshly rederive every input before issuing automated evidence authority."""

    output = Path(path)
    raw = _read(output, MAX_BYTES, "automated evidence")
    record = _decode(raw, "automated evidence")
    if set(record) != {
        "algorithm",
        "benchmark_version",
        "case_count",
        "claims",
        "evidence",
        "lineage_commitment_sha256",
        "policy",
        "receipt_sha256",
        "schema_version",
        "status",
        "tool_git_sha",
        "verified_at",
    }:
        raise _reject("Automated evidence fields are invalid.")
    if (
        record.get("algorithm") != ALGORITHM
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("benchmark_version") != "0.2.1"
        or record.get("case_count") != CASE_COUNT
        or record.get("status") != STATUS
        or record.get("receipt_sha256") != _self_hash(record)
    ):
        raise _reject("Automated evidence identity is invalid.")
    expected = _derive(
        amendment_authority=amendment_authority,
        cases_preparation_path=Path(cases_preparation_path),
        cohort_plan_path=Path(cohort_plan_path),
        chronology_path=Path(chronology_path),
        hidden_extraction_receipt=Path(hidden_extraction_receipt),
        issue_responses_root=Path(issue_responses_root),
        mapping_preparation_path=Path(mapping_preparation_path),
        capability_index_path=Path(capability_index_path),
        runtime_manifest_path=Path(runtime_manifest_path),
        expected_runtime_manifest_sha256=expected_runtime_manifest_sha256,
        gold_smoke_receipt_path=Path(gold_smoke_receipt_path),
        pricing_snapshot_path=Path(pricing_snapshot_path),
        verified_at=_timestamp(record.get("verified_at")),
        tool_git_sha=_git_sha(record.get("tool_git_sha")),
    )
    unsigned = dict(record)
    unsigned.pop("receipt_sha256")
    if unsigned != expected:
        raise _reject("Automated evidence differs from freshly verified inputs.")
    evidence = _dict(record["evidence"], "evidence")
    commitments = _dict(evidence["internal_commitments"], "internal commitments")
    authority = object.__new__(VerifiedV021AutomatedEvidence)
    values: dict[str, object] = {
        "path": output,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "lineage_commitment_sha256": record["lineage_commitment_sha256"],
        "amendment_receipt_sha256": commitments["amendment_receipt_sha256"],
        "request_set_sha256": commitments["case_request_set_sha256"],
        "tool_git_sha": record["tool_git_sha"],
        "case_count": CASE_COUNT,
        "provider_calls": 0,
        "human_reviewed": False,
        "maintainer_validated": False,
        "_issuer": _ISSUER,
    }
    for name, value in values.items():
        object.__setattr__(authority, name, value)
    return authority


def require_v021_automated_evidence(value: object) -> VerifiedV021AutomatedEvidence:
    if type(value) is not VerifiedV021AutomatedEvidence or value._issuer is not _ISSUER:
        raise _reject("Fresh verifier-issued automated evidence is required.")
    if value.provider_calls != 0 or value.human_reviewed or value.maintainer_validated:
        raise _reject("Automated evidence claim ceiling is invalid.")
    return value


def _derive(
    *,
    amendment_authority: VerifiedV02BenchmarkAmendment,
    cases_preparation_path: Path,
    cohort_plan_path: Path,
    chronology_path: Path,
    hidden_extraction_receipt: Path,
    issue_responses_root: Path,
    mapping_preparation_path: Path,
    capability_index_path: Path,
    runtime_manifest_path: Path,
    expected_runtime_manifest_sha256: str,
    gold_smoke_receipt_path: Path,
    pricing_snapshot_path: Path,
    verified_at: str,
    tool_git_sha: str,
) -> dict[str, object]:
    amendment = require_v02_benchmark_amendment(amendment_authority)
    producer = _git_sha(tool_git_sha)
    timestamp = _timestamp(verified_at)
    if _time(timestamp) > datetime.now(timezone.utc):
        raise _reject("Automated evidence cannot be future-dated.")
    if (
        amendment.review_status != "pending"
        or amendment.reviewer_ids
        or amendment.provider_calls != 0
        or amendment.tool_git_sha != producer
    ):
        raise _reject("Automated evidence requires the exact pending amendment with no reviewers.")

    cases = verify_v02_cases(cases_preparation_path)
    chronology = verify_v02_chronology_evidence(
        chronology_path,
        cohort_plan_path=cohort_plan_path,
        hidden_extraction_receipt=hidden_extraction_receipt,
        issue_responses_root=issue_responses_root,
    )
    mapping = verify_v02_mapping_packets(mapping_preparation_path)
    capability = verify_v02_exact_image_capability_index(
        capability_index_path,
        manifest_path=runtime_manifest_path,
        expected_manifest_sha256=_sha(expected_runtime_manifest_sha256),
        gold_smoke_receipt_path=gold_smoke_receipt_path,
        hidden_extraction_receipt=hidden_extraction_receipt,
        amendment_authority=amendment,
    )
    plan = load_v02_leak_audited_cohort_plan(cohort_plan_path)
    if (
        cases.case_count != CASE_COUNT
        or cases.dependency_ready_count != 0
        or chronology.case_count != CASE_COUNT
        or chronology.issue_precedes_fix_count != CASE_COUNT
        or mapping.case_count != CASE_COUNT
        or capability.case_count != CASE_COUNT
        or capability.runtime_attested_count != CASE_COUNT
        or capability.evaluator_preflight_ready_count != CASE_COUNT
        or capability.infrastructure_failure_count != 0
        or any(value.provider_calls != 0 for value in (cases, chronology, capability))
    ):
        raise _reject(
            "Automated evidence requires uniform all-20 evidence with zero infrastructure failures."
        )

    paths = {
        "amendment": amendment.receipt_path,
        "capability_index": capability.path,
        "case_preparation": cases.receipt_path,
        "chronology": chronology.path,
        "cohort_plan": cohort_plan_path,
        "gold_smoke": gold_smoke_receipt_path,
        "hidden_extraction": hidden_extraction_receipt,
        "mapping_preparation": mapping.receipt_path,
        "pricing_snapshot": pricing_snapshot_path,
        "runtime_manifest": runtime_manifest_path,
    }
    loaded = {name: _load(path, name) for name, path in paths.items()}
    records = {name: pair[0] for name, pair in loaded.items()}
    raws = {name: pair[1] for name, pair in loaded.items()}
    for reread, digest, label in (
        (raws["amendment"], amendment.receipt_sha256, "amendment"),
        (raws["capability_index"], capability.sha256, "capability index"),
        (raws["case_preparation"], cases.receipt_sha256, "case preparation"),
        (raws["chronology"], chronology.sha256, "chronology"),
        (raws["mapping_preparation"], mapping.receipt_sha256, "mapping preparation"),
    ):
        if hashlib.sha256(reread).hexdigest() != digest:
            raise _reject(f"{label.capitalize()} changed after verification.")

    case_record = records["case_preparation"]
    capability_record = records["capability_index"]
    mapping_record = records["mapping_preparation"]
    gold_record = records["gold_smoke"]
    amendment_record = records["amendment"]
    chronology_record = records["chronology"]
    inputs = _dict(case_record.get("inputs"), "case preparation inputs")
    if (
        _dict(inputs.get("cohort_plan"), "cohort input").get("sha256")
        != hashlib.sha256(raws["cohort_plan"]).hexdigest()
        or _dict(inputs.get("hidden_extraction"), "hidden input").get("sha256")
        != hashlib.sha256(raws["hidden_extraction"]).hexdigest()
        or _dict(inputs.get("pricing_snapshot"), "pricing input").get("sha256")
        != hashlib.sha256(raws["pricing_snapshot"]).hexdigest()
        or mapping_record.get("hidden_extraction_receipt_sha256")
        != hashlib.sha256(raws["hidden_extraction"]).hexdigest()
    ):
        raise _reject("Automated evidence mixes artifacts from different lineages.")

    if (
        case_record.get("benchmark_version") != "0.2.1"
        or case_record.get("dependency_ready_count") != 0
        or capability_record.get("algorithm") != "reproassert-v02-exact-image-capability-index-v2"
        or capability_record.get("benchmark_version") != "0.2.1"
        or capability_record.get("tool_git_sha") != producer
        or _dict(case_record.get("tool"), "case tool").get("git_sha") != producer
        or amendment_record.get("tool_git_sha") != producer
        or chronology_record.get("tool_git_sha") != producer
        or _dict(mapping_record.get("tool"), "mapping tool").get("git_sha") != producer
    ):
        raise _reject("Automated evidence tool, version, or capability lineage is invalid.")

    _verify_uniform_pending_packages(cases.root, case_record)
    mapping_patches = _verify_mapping_packets(mapping.root, mapping_record)
    _verify_capability_rows(
        capability_record,
        mapping_patches=mapping_patches,
        gold_raw_sha256=hashlib.sha256(raws["gold_smoke"]).hexdigest(),
        amendment=amendment,
    )
    _verify_leak_audit(plan)
    for label, value in (
        ("amendment", amendment_record.get("prepared_at")),
        ("capability", capability_record.get("prepared_at")),
        ("case preparation", case_record.get("prepared_at")),
        ("chronology", chronology_record.get("captured_at")),
        ("mapping preparation", mapping_record.get("prepared_at")),
    ):
        _require_before(timestamp, value, label)

    pricing = _pricing_from_record(records["pricing_snapshot"])
    if pricing.requested_model != "gpt-5.4-mini-2026-03-17":
        raise _reject("Pricing snapshot is not the exact frozen model snapshot.")
    evidence: dict[str, object] = {
        f"{name}_raw_sha256": hashlib.sha256(raw).hexdigest() for name, raw in sorted(raws.items())
    }
    evidence["pricing_snapshot_commitment_sha256"] = pricing.sha256
    evidence["runtime_manifest_sha256"] = _sha(expected_runtime_manifest_sha256)
    evidence["internal_commitments"] = {
        "amendment_receipt_sha256": _sha(amendment_record.get("receipt_sha256")),
        "capability_index_sha256": _sha(capability_record.get("index_sha256")),
        "case_preparation_set_sha256": _sha(case_record.get("preparation_set_sha256")),
        "case_request_set_sha256": _sha(case_record.get("request_set_sha256")),
        "chronology_receipt_sha256": _sha(chronology_record.get("receipt_sha256")),
        "gold_smoke_receipt_sha256": _sha(gold_record.get("receipt_sha256")),
        "hidden_extraction_receipt_sha256": hashlib.sha256(raws["hidden_extraction"]).hexdigest(),
        "mapping_preparation_receipt_sha256": _sha(mapping_record.get("receipt_sha256")),
    }
    lineage = hashlib.sha256(
        _canonical({"evidence": evidence, "tool_git_sha": producer})
    ).hexdigest()
    return {
        "algorithm": ALGORITHM,
        "benchmark_version": "0.2.1",
        "case_count": CASE_COUNT,
        "claims": {
            "automated_oracle_validated": True,
            "evaluator_preflight_ready_count": CASE_COUNT,
            "human_reviewed": False,
            "infrastructure_failure_count": 0,
            "maintainer_validated": False,
            "mapping_packet_count": CASE_COUNT,
            "model_or_provider_invoked": False,
            "provider_calls": 0,
        },
        "evidence": evidence,
        "lineage_commitment_sha256": lineage,
        "policy": {
            "human_consensus_used": False,
            "mapping_decisions_generated": False,
            "oracle_bytes_public": False,
            "pricing_effective_at": pricing.effective_at,
            "pricing_model": pricing.requested_model,
            "human_identity_fields_allowed": False,
        },
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "tool_git_sha": producer,
        "verified_at": timestamp,
    }


def _verify_uniform_pending_packages(root: Path, record: dict[str, object]) -> None:
    packages = record.get("packages")
    if not isinstance(packages, list) or len(packages) != CASE_COUNT:
        raise _reject("Case preparation must preserve exactly 20 packages.")
    for position, value in enumerate(packages, start=1):
        ref = _dict(value, "package reference")
        package_path = _resolve(root, ref.get("path"), "case package")
        package, raw = _load(package_path, "case package")
        if hashlib.sha256(raw).hexdigest() != ref.get("sha256"):
            raise _reject("A case package changed after verification.")
        expected_id = f"rk-v0.2-{position:03d}"
        blockers = package.get("blockers")
        if (
            package.get("case_id") != expected_id
            or not isinstance(blockers, list)
            or "exact_image_amendment_review_pending" not in blockers
            or _dict(package.get("dependency"), "dependency").get("status")
            != "amendment_review_pending"
        ):
            raise _reject("All 20 case packages must use the uniform pending amendment gate.")


def _verify_mapping_packets(root: Path, record: dict[str, object]) -> dict[str, str]:
    rows = record.get("cases")
    if not isinstance(rows, list) or len(rows) != CASE_COUNT:
        raise _reject("Mapping preparation must preserve all 20 cases.")
    result: dict[str, str] = {}
    for position, value in enumerate(rows, start=1):
        row = _dict(value, "mapping row")
        case_id = f"rk-v0.2-{position:03d}"
        if row.get("case_id") != case_id or row.get("status") != "review_required":
            raise _reject("Mapping packets are incomplete, reordered, or consensus-shaped.")
        packet_ref = _dict(row.get("packet"), "mapping packet reference")
        packet_path = _resolve(root, packet_ref.get("path"), "mapping packet")
        packet, packet_raw = _load(packet_path, "mapping packet")
        if hashlib.sha256(packet_raw).hexdigest() != packet_ref.get("sha256"):
            raise _reject("A mapping packet changed after verification.")
        inventory = packet.get("hunk_inventory")
        algebra = _dict(packet.get("patch_algebra"), "patch algebra")
        patch = _dict(packet.get("production_patch"), "production patch")
        if (
            packet.get("case_id") != case_id
            or packet.get("reviews") != []
            or packet.get("status") != "awaiting_two_independent_mapping_reviews"
            or not isinstance(inventory, list)
            or not inventory
            or not algebra.get("ordered_atomic_ids")
            or not algebra.get("ordered_hunk_sha256")
            or type(patch.get("bytes")) is not int
            or cast(int, patch["bytes"]) <= 0
            or row.get("hunk_count") != len(inventory)
            or row.get("production_patch_sha256") != patch.get("sha256")
        ):
            raise _reject(
                "Mapping packet must contain exact non-empty human-fix hunks and no reviews."
            )
        if "reviewer" in json.dumps(packet, sort_keys=True).lower().replace(
            "awaiting_two_independent_mapping_reviews", ""
        ):
            raise _reject("Mapping packets must not contain reviewer identities or consensus.")
        result[case_id] = _sha(patch.get("sha256"))
    return result


def _verify_capability_rows(
    record: dict[str, object],
    *,
    mapping_patches: dict[str, str],
    gold_raw_sha256: str,
    amendment: VerifiedV02BenchmarkAmendment,
) -> None:
    if gold_raw_sha256 != amendment.amended_gold_smoke_receipt_sha256:
        raise _reject("Gold smoke changed after amendment verification.")
    rows = record.get("cases")
    if not isinstance(rows, list) or len(rows) != CASE_COUNT:
        raise _reject("Capability index must preserve all 20 cases.")
    for position, value in enumerate(rows, start=1):
        row = _dict(value, "capability row")
        case_id = f"rk-v0.2-{position:03d}"
        evidence = _dict(row.get("evidence"), "capability evidence")
        hidden = _dict(evidence.get("hidden_inputs"), "capability hidden inputs")
        gold = _dict(evidence.get("gold_smoke"), "capability gold smoke")
        if (
            row.get("case_id") != case_id
            or row.get("status") != "runtime_attested_evaluator_preflight_ready"
            or evidence.get("case_id") != case_id
            or evidence.get("benchmark_amendment_receipt_sha256") != amendment.receipt_sha256
            or hidden.get("production_patch_sha256") != mapping_patches[case_id]
            or type(hidden.get("production_patch_bytes")) is not int
            or cast(int, hidden["production_patch_bytes"]) <= 0
            or gold.get("receipt_sha256") != gold_raw_sha256
            or gold.get("case_classification") != "semantic_valid"
            or gold.get("case_reason") != "fails_on_base_passes_on_fixed"
        ):
            raise _reject(
                "Capability, gold, hidden-fix, and mapping evidence are mixed or invalid."
            )


def _verify_leak_audit(plan: dict[str, object]) -> None:
    cases = plan.get("cases")
    if not isinstance(cases, list) or len(cases) != CASE_COUNT:
        raise _reject("Leak-audited cohort must preserve all 20 cases.")
    for value in cases:
        audit = _dict(_dict(value, "cohort case").get("oracle_leak_audit"), "leak audit")
        if (
            audit.get("oracle_leak_free") is not True
            or audit.get("direct_own_fixing_pr_reference") is not False
            or audit.get("production_added_line_overlap") is not False
            or audit.get("test_added_line_overlap") is not False
        ):
            raise _reject("Cohort contains a gold-oracle leak.")


def _resolve(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or value.startswith("/"):
        raise _reject(f"{label.capitalize()} path is invalid.")
    parts = value.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise _reject(f"{label.capitalize()} path traversal is forbidden.")
    base = root.resolve(strict=True)
    path = root.joinpath(*parts).resolve(strict=True)
    if base != path and base not in path.parents:
        raise _reject(f"{label.capitalize()} escapes its verified root.")
    return path


def _require_before(verified_at: str, value: object, label: str) -> None:
    if _time(_timestamp(value)) > _time(verified_at):
        raise _reject(f"{label.capitalize()} occurs after automated verification.")


def _load(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    raw = _read(path, MAX_BYTES, label)
    return _decode(raw, label), raw


def _read(path: Path, maximum: int, label: str) -> bytes:
    try:
        with open_regular_file(Path(path)) as stream:
            raw = stream.read(maximum + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"{label.capitalize()} could not be read safely.") from exc
    if not raw or len(raw) > maximum:
        raise _reject(f"{label.capitalize()} exceeds its byte bound.")
    return raw


def _decode(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject(f"{label.capitalize()} is invalid JSON.") from exc
    if not isinstance(value, dict) or raw != _canonical(value) + b"\n":
        raise _reject(f"{label.capitalize()} is not canonical JSON.")
    return cast(dict[str, object], value)


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _dict(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _reject(f"{label.capitalize()} must be an object.")
    return cast(dict[str, object], value)


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject("Timestamp is invalid.")
    try:
        _time(value)
    except ValueError as exc:
        raise _reject("Timestamp is invalid.") from exc
    return value


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _sha(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _reject("SHA-256 commitment is invalid.")
    return value


def _git_sha(value: object) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject("Tool Git SHA is invalid.")
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _self_hash(record: dict[str, object]) -> str:
    unsigned = dict(record)
    unsigned.pop("receipt_sha256", None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v021_automated_evidence", message)
