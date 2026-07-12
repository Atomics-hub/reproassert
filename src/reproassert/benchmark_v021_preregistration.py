"""Provider-disabled v0.2.1 preregistration after genuine amendment consensus."""

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
from reproassert.benchmark_v02_mapping_packets import (
    verify_v02_mapping_consensus,
    verify_v02_mapping_packets,
)
from reproassert.benchmark_v02_runner import _pricing_from_record
from reproassert.benchmark_v021_amendment_review import (
    VerifiedV021AmendmentConsensus,
    require_approved_v021_amendment_consensus,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

ALGORITHM = "reproassert-v021-provider-disabled-preregistration-v1"
SCHEMA_VERSION = "1.0.0"
BENCHMARK_VERSION = "0.2.1"
STATUS = "execution_disabled_until_v021_runtime_migration"
MAX_BYTES = 2 * 1024 * 1024
TOTAL_CAP_USD = "5.00"
PER_CASE_CAP_USD = "0.25"
CASE_COUNT = 20
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_TIMESTAMP = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
_ISSUER = object()


@dataclass(frozen=True, init=False)
class VerifiedV021Preregistration:
    """Process-local authority for a frozen but deliberately unexecutable campaign."""

    path: Path
    sha256: str
    lineage_commitment_sha256: str
    approval_statement: str
    approval_statement_sha256: str
    case_count: int
    dependency_ready_count: int
    provider_calls: int
    execution_enabled: bool
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV021Preregistration is verifier-issued only")


def prepare_v021_preregistration(
    *,
    amendment_authority: VerifiedV02BenchmarkAmendment,
    amendment_consensus_authority: VerifiedV021AmendmentConsensus,
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
    pricing_snapshot_path: Path,
    frozen_at: str,
    tool_git_sha: str,
    output_path: Path,
) -> VerifiedV021Preregistration:
    """Freeze the reviewed 20/20 lineage without exposing an execution path."""

    destination = Path(output_path)
    require_private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise _reject("Refusing to overwrite a v0.2.1 preregistration.")
    record = _derive(
        amendment_authority=amendment_authority,
        amendment_consensus_authority=amendment_consensus_authority,
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
        pricing_snapshot_path=Path(pricing_snapshot_path),
        frozen_at=frozen_at,
        tool_git_sha=tool_git_sha,
    )
    record["preregistration_sha256"] = _self_hash(record)
    write_bytes_exclusive(destination, _canonical(record) + b"\n")
    return verify_v021_preregistration(
        destination,
        amendment_authority=amendment_authority,
        amendment_consensus_authority=amendment_consensus_authority,
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
        pricing_snapshot_path=pricing_snapshot_path,
    )


def verify_v021_preregistration(
    path: Path,
    *,
    amendment_authority: VerifiedV02BenchmarkAmendment,
    amendment_consensus_authority: VerifiedV021AmendmentConsensus,
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
    pricing_snapshot_path: Path,
) -> VerifiedV021Preregistration:
    """Freshly rederive all evidence and issue only disabled preregistration authority."""

    output = Path(path)
    raw = _read(output, MAX_BYTES, "v0.2.1 preregistration")
    record = _decode(raw, "v0.2.1 preregistration")
    if set(record) != {
        "algorithm",
        "approval",
        "benchmark_version",
        "case_count",
        "claims",
        "evidence",
        "frozen_at",
        "lineage_commitment_sha256",
        "policy",
        "preregistration_sha256",
        "schema_version",
        "status",
        "tool_git_sha",
    }:
        raise _reject("v0.2.1 preregistration fields are invalid.")
    if (
        record.get("algorithm") != ALGORITHM
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("benchmark_version") != BENCHMARK_VERSION
        or record.get("case_count") != CASE_COUNT
        or record.get("status") != STATUS
        or record.get("preregistration_sha256") != _self_hash(record)
    ):
        raise _reject("v0.2.1 preregistration identity is invalid.")
    expected = _derive(
        amendment_authority=amendment_authority,
        amendment_consensus_authority=amendment_consensus_authority,
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
        pricing_snapshot_path=Path(pricing_snapshot_path),
        frozen_at=_timestamp(record.get("frozen_at")),
        tool_git_sha=_git_sha(record.get("tool_git_sha")),
    )
    unsigned = dict(record)
    unsigned.pop("preregistration_sha256")
    if unsigned != expected:
        raise _reject("v0.2.1 preregistration differs from freshly verified evidence.")
    approval = _dict(record["approval"], "approval")
    authority = object.__new__(VerifiedV021Preregistration)
    for name, value in {
        "path": output,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "lineage_commitment_sha256": record["lineage_commitment_sha256"],
        "approval_statement": approval["required_exact_statement"],
        "approval_statement_sha256": approval["required_exact_statement_sha256"],
        "case_count": CASE_COUNT,
        "dependency_ready_count": CASE_COUNT,
        "provider_calls": 0,
        "execution_enabled": False,
        "_issuer": _ISSUER,
    }.items():
        object.__setattr__(authority, name, value)
    return authority


def require_v021_preregistration(value: object) -> VerifiedV021Preregistration:
    if type(value) is not VerifiedV021Preregistration or value._issuer is not _ISSUER:
        raise _reject("Fresh verifier-issued v0.2.1 preregistration is required.")
    if value.execution_enabled or value.provider_calls != 0:
        raise _reject("v0.2.1 preregistration must remain provider-disabled.")
    return value


def _derive(
    *,
    amendment_authority: VerifiedV02BenchmarkAmendment,
    amendment_consensus_authority: VerifiedV021AmendmentConsensus,
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
    pricing_snapshot_path: Path,
    frozen_at: str,
    tool_git_sha: str,
) -> dict[str, object]:
    amendment = require_v02_benchmark_amendment(amendment_authority)
    consensus = require_approved_v021_amendment_consensus(amendment_consensus_authority)
    producer = _git_sha(tool_git_sha)
    timestamp = _timestamp(frozen_at)
    if _timestamp_value(timestamp) > datetime.now(timezone.utc):
        raise _reject("v0.2.1 preregistration cannot be future-dated.")
    if (
        consensus.amendment_receipt_sha256 != amendment.receipt_sha256
        or consensus.tool_git_sha != producer
        or amendment.tool_git_sha != producer
        or consensus.provider_calls != 0
        or amendment.provider_calls != 0
    ):
        raise _reject("Approved consensus does not bind the exact amendment and final tool SHA.")

    cases = verify_v02_cases(cases_preparation_path)
    chronology = verify_v02_chronology_evidence(
        chronology_path,
        cohort_plan_path=cohort_plan_path,
        hidden_extraction_receipt=hidden_extraction_receipt,
        issue_responses_root=issue_responses_root,
    )
    mapping_preparation = verify_v02_mapping_packets(mapping_preparation_path)
    mapping = verify_v02_mapping_consensus(
        mapping_consensus_path, preparation_path=mapping_preparation_path
    )
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
            "v0.2.1 requires pending-consensus cases plus amended 20/0 evaluator evidence; "
            "legacy 19/1 and pre-approved case packages are forbidden."
        )

    cases_record, cases_raw = _load(cases.receipt_path, "case preparation")
    capability_record, capability_raw = _load(capability.path, "capability index")
    mapping_record, mapping_raw = _load(mapping.path, "mapping consensus")
    mapping_preparation_record, mapping_preparation_raw = _load(
        mapping_preparation_path, "mapping preparation"
    )
    chronology_record, chronology_raw = _load(chronology.path, "chronology evidence")
    amendment_record, amendment_raw = _load(amendment.receipt_path, "amendment")
    consensus_record, consensus_raw = _load(consensus.path, "amendment consensus")
    pricing_record, pricing_raw = _load(pricing_snapshot_path, "pricing snapshot", 64 * 1024)
    hidden_record, hidden_raw = _load(hidden_extraction_receipt, "hidden extraction receipt")
    gold_record, gold_raw = _load(gold_smoke_receipt_path, "gold smoke receipt")
    plan_raw = _read(cohort_plan_path, MAX_BYTES, "cohort plan")

    authority_digests = (
        (cases_raw, cases.receipt_sha256, "case preparation"),
        (capability_raw, capability.sha256, "capability index"),
        (mapping_raw, mapping.sha256, "mapping consensus"),
        (
            mapping_preparation_raw,
            mapping_preparation.receipt_sha256,
            "mapping preparation",
        ),
        (chronology_raw, chronology.sha256, "chronology evidence"),
        (amendment_raw, amendment.receipt_sha256, "amendment"),
        (consensus_raw, consensus.sha256, "amendment consensus"),
    )
    for reread, verified_sha256, label in authority_digests:
        if hashlib.sha256(reread).hexdigest() != verified_sha256:
            raise _reject(f"{label.capitalize()} changed after verification.")

    inputs = _dict(cases_record.get("inputs"), "case preparation inputs")
    cohort_ref = _dict(inputs.get("cohort_plan"), "case preparation cohort plan")
    hidden_ref = _dict(inputs.get("hidden_extraction"), "case preparation hidden extraction")
    pricing_ref = _dict(inputs.get("pricing_snapshot"), "case preparation pricing snapshot")
    if (
        cohort_ref.get("sha256") != hashlib.sha256(plan_raw).hexdigest()
        or hidden_ref.get("sha256") != hashlib.sha256(hidden_raw).hexdigest()
        or pricing_ref.get("sha256") != hashlib.sha256(pricing_raw).hexdigest()
        or mapping_record.get("mapping_preparation_receipt_sha256")
        != mapping_preparation_record.get("receipt_sha256")
        or mapping_preparation_record.get("hidden_extraction_receipt_sha256")
        != hidden_record.get("receipt_sha256")
    ):
        raise _reject("v0.2.1 inputs mix evidence from different campaign lineages.")

    capability_rows = capability_record.get("cases")
    gold_raw_sha256 = hashlib.sha256(gold_raw).hexdigest()
    if gold_raw_sha256 != amendment.amended_gold_smoke_receipt_sha256:
        raise _reject("Gold smoke receipt changed after amendment verification.")
    if not isinstance(capability_rows, list) or len(capability_rows) != CASE_COUNT:
        raise _reject("v0.2.1 capability index does not preserve all 20 cases.")
    for raw_row in capability_rows:
        evidence_row = _dict(
            _dict(raw_row, "capability row").get("evidence"), "capability evidence"
        )
        gold_ref = _dict(evidence_row.get("gold_smoke"), "capability gold smoke")
        if gold_ref.get("receipt_sha256") != gold_raw_sha256:
            raise _reject("Gold smoke receipt changed after capability verification.")

    if (
        cases_record.get("benchmark_version") != BENCHMARK_VERSION
        or cases_record.get("dependency_ready_count") != 0
        or capability_record.get("algorithm") != "reproassert-v02-exact-image-capability-index-v2"
        or capability_record.get("benchmark_version") != BENCHMARK_VERSION
        or capability_record.get("tool_git_sha") != producer
        or _dict(cases_record.get("tool"), "case preparation tool").get("git_sha") != producer
    ):
        raise _reject("v0.2.1 case/capability lineage is not exact or final-SHA bound.")
    packages = cases_record.get("packages")
    if not isinstance(packages, list) or len(packages) != CASE_COUNT:
        raise _reject("v0.2.1 case preparation does not preserve 20 packages.")
    for package_ref in packages:
        ref = _dict(package_ref, "package reference")
        package_path = _resolve(cases.root, cast(str, ref.get("path")))
        package, package_raw = _load(package_path, "case package")
        if hashlib.sha256(package_raw).hexdigest() != ref.get("sha256"):
            raise _reject("A v0.2.1 case package changed after verification.")
        blockers = package.get("blockers")
        if (
            not isinstance(blockers, list)
            or "exact_image_amendment_review_pending" not in blockers
            or _dict(package.get("dependency"), "dependency").get("status")
            != "amendment_review_pending"
        ):
            raise _reject("Case readiness was not held exclusively behind amendment review.")

    consensus_rows = mapping_record.get("cases")
    if not isinstance(consensus_rows, list) or len(consensus_rows) != CASE_COUNT:
        raise _reject("Mapping consensus does not contain all 20 cases.")
    for row in consensus_rows:
        decision = _dict(_dict(row, "mapping row").get("consensus"), "mapping decision")
        if decision.get("verdict") != "approved" or not decision.get("selected_hunk_ids"):
            raise _reject("All 20 mappings must be approved and non-empty.")
    _require_before(timestamp, cases_record.get("prepared_at"), "case preparation")
    _require_before(timestamp, capability_record.get("prepared_at"), "capability index")
    _require_before(timestamp, mapping_record.get("sealed_at"), "mapping consensus")
    _require_before(timestamp, chronology_record.get("captured_at"), "chronology")
    _require_before(timestamp, amendment_record.get("prepared_at"), "amendment")
    _require_before(timestamp, consensus_record.get("sealed_at"), "amendment consensus")

    pricing = _pricing(pricing_record)
    evidence = {
        "amendment_consensus_raw_sha256": hashlib.sha256(consensus_raw).hexdigest(),
        "amendment_raw_sha256": hashlib.sha256(amendment_raw).hexdigest(),
        "capability_index_raw_sha256": hashlib.sha256(capability_raw).hexdigest(),
        "cases_preparation_raw_sha256": hashlib.sha256(cases_raw).hexdigest(),
        "chronology_raw_sha256": hashlib.sha256(chronology_raw).hexdigest(),
        "cohort_plan_raw_sha256": hashlib.sha256(plan_raw).hexdigest(),
        "cohort_plan_sha256": _sha(plan.get("cohort_plan_sha256")),
        "gold_smoke_receipt_raw_sha256": hashlib.sha256(gold_raw).hexdigest(),
        "hidden_extraction_receipt_raw_sha256": hashlib.sha256(hidden_raw).hexdigest(),
        "internal_commitments": {
            "amendment_receipt_sha256": _sha(amendment_record.get("receipt_sha256")),
            "amendment_consensus_seal_sha256": _sha(consensus_record.get("seal_sha256")),
            "capability_index_sha256": _sha(capability_record.get("index_sha256")),
            "case_preparation_set_sha256": _sha(cases_record.get("preparation_set_sha256")),
            "case_request_set_sha256": _sha(cases_record.get("request_set_sha256")),
            "chronology_receipt_sha256": _sha(chronology_record.get("receipt_sha256")),
            "gold_smoke_receipt_sha256": _sha(gold_record.get("receipt_sha256")),
            "hidden_extraction_receipt_sha256": _sha(hidden_record.get("receipt_sha256")),
            "mapping_consensus_seal_sha256": _sha(mapping_record.get("seal_sha256")),
        },
        "mapping_consensus_raw_sha256": hashlib.sha256(mapping_raw).hexdigest(),
        "mapping_preparation_raw_sha256": hashlib.sha256(mapping_preparation_raw).hexdigest(),
        "pricing_snapshot_raw_sha256": hashlib.sha256(pricing_raw).hexdigest(),
        "runtime_manifest_sha256": _sha(expected_runtime_manifest_sha256),
    }
    lineage = hashlib.sha256(
        _canonical({"evidence": evidence, "tool_git_sha": producer})
    ).hexdigest()
    statement = (
        "Authorize ReproAssert v0.2.1 benchmark lineage "
        f"{lineage} for exactly 20 cases with a USD 5.00 total cap, "
        "USD 0.25 per-case cap, and zero overage."
    )
    return {
        "algorithm": ALGORITHM,
        "approval": {
            "authorized": False,
            "required_exact_statement": statement,
            "required_exact_statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        },
        "benchmark_version": BENCHMARK_VERSION,
        "case_count": CASE_COUNT,
        "claims": {
            "amendment_review_approved": True,
            "dependency_ready_count_after_consensus": CASE_COUNT,
            "dependency_ready_count_before_consensus": 0,
            "evaluator_preflight_ready_count": CASE_COUNT,
            "infrastructure_failure_count": 0,
            "mapping_approved_count": CASE_COUNT,
            "model_or_provider_invoked": False,
            "provider_calls": 0,
        },
        "evidence": evidence,
        "frozen_at": timestamp,
        "lineage_commitment_sha256": lineage,
        "policy": {
            "case_cap_usd": PER_CASE_CAP_USD,
            "case_count": CASE_COUNT,
            "credential_fields_allowed": False,
            "execution_enabled": False,
            "model": pricing["model"],
            "overage_allowed": False,
            "pricing_effective_at": pricing["effective_at"],
            "pricing_snapshot_status": pricing["status"],
            "total_cap_usd": TOTAL_CAP_USD,
        },
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "tool_git_sha": producer,
    }


def _pricing(record: dict[str, object]) -> dict[str, str]:
    pricing = _pricing_from_record(record)
    if pricing.requested_model != "gpt-5.4-mini-2026-03-17":
        raise _reject("Pricing snapshot is not the frozen GPT-5.4 mini snapshot.")
    return {
        "model": pricing.requested_model,
        "effective_at": pricing.effective_at,
        "status": "exact_public_snapshot_hash_bound",
    }


def _require_before(frozen: str, value: object, label: str) -> None:
    if _timestamp_value(_timestamp(value)) > _timestamp_value(frozen):
        raise _reject(f"{label.capitalize()} occurs after the preregistration freeze.")


def _resolve(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or relative.startswith("/"):
        raise _reject("Case package path is invalid.")
    parts = relative.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise _reject("Case package path traversal is forbidden.")
    base = root.resolve(strict=True)
    resolved = root.joinpath(*parts).resolve(strict=True)
    if base not in resolved.parents:
        raise _reject("Case package path escapes its verified root.")
    return resolved


def _load(path: Path, label: str, maximum: int = MAX_BYTES) -> tuple[dict[str, object], bytes]:
    raw = _read(path, maximum, label)
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
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _dict(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _reject(f"{label.capitalize()} must be an object.")
    return cast(dict[str, object], value)


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject("Timestamp is invalid.")
    try:
        _timestamp_value(value)
    except ValueError as exc:
        raise _reject("Timestamp is invalid.") from exc
    return value


def _timestamp_value(value: str) -> datetime:
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
    unsigned.pop("preregistration_sha256", None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v021_preregistration", message)
