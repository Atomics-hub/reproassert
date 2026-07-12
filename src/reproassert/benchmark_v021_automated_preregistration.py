"""Automated-oracle v0.2.1 preregistration without human-review claims."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from reproassert.benchmark_v021_automated_evidence import (
    ALGORITHM as EVIDENCE_ALGORITHM,
)
from reproassert.benchmark_v021_automated_evidence import (
    STATUS as EVIDENCE_STATUS,
)
from reproassert.benchmark_v021_automated_evidence import (
    VerifiedV021AutomatedEvidence,
    require_v021_automated_evidence,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import (
    open_regular_file,
    require_private_directory,
    write_bytes_exclusive,
)

ALGORITHM = "reproassert-v021-automated-oracle-preregistration-v1"
SCHEMA_VERSION = "1.0.0"
STATUS = "automated_oracle_preregistered_execution_requires_explicit_authorization"
CASE_COUNT = 20
TOTAL_CAP_USD = "5.00"
PER_CASE_CAP_USD = "0.25"
MAX_BYTES = 2 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TIMESTAMP = re.compile(
    r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z"
)
_ISSUER = object()


@dataclass(frozen=True, init=False)
class VerifiedV021AutomatedPreregistration:
    """Verifier-issued authority implementing the v0.2.1 preregistration interface."""

    path: Path
    sha256: str
    lineage_commitment_sha256: str
    approval_statement: str
    approval_statement_sha256: str
    case_count: int
    dependency_ready_count: int
    provider_calls: int
    execution_enabled: bool
    human_reviewed: bool
    maintainer_validated: bool
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV021AutomatedPreregistration is verifier-issued only")


def prepare_v021_automated_preregistration(
    *,
    automated_evidence_authority: VerifiedV021AutomatedEvidence,
    frozen_at: str,
    output_path: Path,
) -> VerifiedV021AutomatedPreregistration:
    """Freeze the exact automated evidence while keeping provider execution disabled."""

    evidence = require_v021_automated_evidence(automated_evidence_authority)
    destination = Path(output_path)
    require_private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise _reject("Refusing to overwrite automated preregistration.")
    record = _derive(evidence=evidence, frozen_at=frozen_at)
    record["preregistration_sha256"] = _self_hash(record)
    write_bytes_exclusive(destination, _canonical(record) + b"\n")
    return verify_v021_automated_preregistration(
        destination, automated_evidence_authority=evidence
    )


def verify_v021_automated_preregistration(
    path: Path,
    *,
    automated_evidence_authority: VerifiedV021AutomatedEvidence,
) -> VerifiedV021AutomatedPreregistration:
    """Reread the exact evidence authority and rederive the preregistration."""

    evidence = require_v021_automated_evidence(automated_evidence_authority)
    output = Path(path)
    raw = _read(output, "automated preregistration")
    record = _decode(raw, "automated preregistration")
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
        raise _reject("Automated preregistration fields are invalid.")
    if (
        record.get("algorithm") != ALGORITHM
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("benchmark_version") != "0.2.1"
        or record.get("case_count") != CASE_COUNT
        or record.get("status") != STATUS
        or record.get("preregistration_sha256") != _self_hash(record)
    ):
        raise _reject("Automated preregistration identity is invalid.")
    expected = _derive(evidence=evidence, frozen_at=_timestamp(record.get("frozen_at")))
    unsigned = dict(record)
    unsigned.pop("preregistration_sha256")
    if unsigned != expected:
        raise _reject("Automated preregistration differs from freshly verified evidence.")
    approval = _dict(record["approval"], "approval")
    authority = object.__new__(VerifiedV021AutomatedPreregistration)
    values: dict[str, object] = {
        "path": output,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "lineage_commitment_sha256": record["lineage_commitment_sha256"],
        "approval_statement": approval["required_exact_statement"],
        "approval_statement_sha256": approval["required_exact_statement_sha256"],
        "case_count": CASE_COUNT,
        "dependency_ready_count": CASE_COUNT,
        "provider_calls": 0,
        "execution_enabled": False,
        "human_reviewed": False,
        "maintainer_validated": False,
        "_issuer": _ISSUER,
    }
    for name, value in values.items():
        object.__setattr__(authority, name, value)
    return authority


def require_v021_automated_preregistration(
    value: object,
) -> VerifiedV021AutomatedPreregistration:
    if type(value) is not VerifiedV021AutomatedPreregistration or value._issuer is not _ISSUER:
        raise _reject("Fresh verifier-issued automated preregistration is required.")
    if (
        value.case_count != CASE_COUNT
        or value.dependency_ready_count != CASE_COUNT
        or value.provider_calls != 0
        or value.execution_enabled
        or value.human_reviewed
        or value.maintainer_validated
    ):
        raise _reject("Automated preregistration claim ceiling is invalid.")
    return value


def _derive(
    *, evidence: VerifiedV021AutomatedEvidence, frozen_at: str
) -> dict[str, object]:
    frozen = _timestamp(frozen_at)
    if _time(frozen) > datetime.now(timezone.utc):
        raise _reject("Automated preregistration cannot be future-dated.")
    evidence_raw = _read(evidence.path, "automated evidence")
    if hashlib.sha256(evidence_raw).hexdigest() != evidence.sha256:
        raise _reject("Automated evidence changed after verification.")
    evidence_record = _decode(evidence_raw, "automated evidence")
    if (
        evidence_record.get("algorithm") != EVIDENCE_ALGORITHM
        or evidence_record.get("status") != EVIDENCE_STATUS
        or evidence_record.get("lineage_commitment_sha256")
        != evidence.lineage_commitment_sha256
        or evidence_record.get("tool_git_sha") != evidence.tool_git_sha
        or _time(_timestamp(evidence_record.get("verified_at"))) > _time(frozen)
    ):
        raise _reject("Automated evidence identity or chronology is invalid.")
    evidence_claims = _dict(evidence_record.get("claims"), "automated evidence claims")
    if evidence_claims != {
        "automated_oracle_validated": True,
        "evaluator_preflight_ready_count": CASE_COUNT,
        "human_reviewed": False,
        "infrastructure_failure_count": 0,
        "maintainer_validated": False,
        "mapping_packet_count": CASE_COUNT,
        "model_or_provider_invoked": False,
        "provider_calls": 0,
    }:
        raise _reject("Automated evidence claim ceiling is invalid.")
    source_evidence = _dict(evidence_record.get("evidence"), "automated evidence")
    commitments = _dict(source_evidence.get("internal_commitments"), "internal commitments")
    policy = _dict(evidence_record.get("policy"), "automated evidence policy")
    pricing_sha = _sha(source_evidence.get("pricing_snapshot_raw_sha256"))
    runtime_sha = _sha(source_evidence.get("runtime_manifest_sha256"))
    capability_sha = _sha(source_evidence.get("capability_index_raw_sha256"))
    statement = (
        "Authorize ReproAssert v0.2.1 automated-oracle benchmark lineage "
        f"{evidence.lineage_commitment_sha256} for exactly 20 cases with a USD 5.00 "
        "total cap, USD 0.25 per-case cap, and zero overage."
    )
    prereg_evidence = {
        "automated_evidence_raw_sha256": evidence.sha256,
        "capability_index_raw_sha256": capability_sha,
        "internal_commitments": commitments,
        "pricing_snapshot_raw_sha256": pricing_sha,
        "runtime_manifest_sha256": runtime_sha,
    }
    return {
        "algorithm": ALGORITHM,
        "approval": {
            "authorized": False,
            "required_exact_statement": statement,
            "required_exact_statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        },
        "benchmark_version": "0.2.1",
        "case_count": CASE_COUNT,
        "claims": {
            "automated_oracle_validated": True,
            "dependency_ready_count": CASE_COUNT,
            "evaluator_preflight_ready_count": CASE_COUNT,
            "human_reviewed": False,
            "infrastructure_failure_count": 0,
            "maintainer_validated": False,
            "model_or_provider_invoked": False,
            "provider_calls": 0,
        },
        "evidence": prereg_evidence,
        "frozen_at": frozen,
        "lineage_commitment_sha256": evidence.lineage_commitment_sha256,
        "policy": {
            "case_cap_usd": PER_CASE_CAP_USD,
            "case_count": CASE_COUNT,
            "credential_fields_allowed": False,
            "execution_enabled": False,
            "model": policy.get("pricing_model"),
            "overage_allowed": False,
            "pricing_effective_at": policy.get("pricing_effective_at"),
            "pricing_snapshot_status": "exact_public_snapshot_hash_bound",
            "total_cap_usd": TOTAL_CAP_USD,
        },
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "tool_git_sha": _git_sha(evidence.tool_git_sha),
    }


def _read(path: Path, label: str) -> bytes:
    try:
        with open_regular_file(Path(path)) as stream:
            raw = stream.read(MAX_BYTES + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"{label.capitalize()} could not be read safely.") from exc
    if not raw or len(raw) > MAX_BYTES:
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
    unsigned.pop("preregistration_sha256", None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v021_automated_preregistration", message)
