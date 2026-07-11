"""Provider-free, operator-attested human consensus for the v0.2.1 amendment."""

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
from reproassert.benchmark_v02_mapping_handoff import (
    verify_v02_mapping_review_handoff,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

HANDOFF_ALGORITHM = "reproassert-v021-amendment-review-handoff-v1"
CONSENSUS_ALGORITHM = "reproassert-v021-amendment-review-consensus-v1"
SCHEMA_VERSION = "1.0.0"
MAX_BYTES = 256 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TIMESTAMP = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
_PLACEHOLDER = re.compile(
    r"(?:placeholder|example|tbd|todo|fake|dummy|test[-_.]?reviewer|reviewer[-_.]?(?:[0-9]+|[abcxyz]))",
    re.IGNORECASE,
)
_ISSUER = object()


@dataclass(frozen=True, init=False)
class VerifiedV021AmendmentReviewHandoff:
    path: Path
    sha256: str
    amendment_receipt_sha256: str
    primary_reviewer_ids: tuple[str, str]
    semantic_reviewer_ids: tuple[str, ...]
    tiebreak_reviewer_id: str | None
    prepared_at: str
    tool_git_sha: str
    _issuer: object = field(repr=False, compare=False)
    provider_calls: int = 0

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV021AmendmentReviewHandoff is verifier-issued only")


@dataclass(frozen=True, init=False)
class VerifiedV021AmendmentConsensus:
    path: Path
    sha256: str
    amendment_receipt_sha256: str
    reviewer_ids: tuple[str, ...]
    verdict: str
    tool_git_sha: str
    _issuer: object = field(repr=False, compare=False)
    provider_calls: int = 0

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV021AmendmentConsensus is verifier-issued only")


def prepare_v021_amendment_review_handoff(
    *,
    amendment_authority: VerifiedV02BenchmarkAmendment,
    mapping_handoff_path: Path,
    mapping_preparation_path: Path,
    prepared_at: str,
    tool_git_sha: str,
    output_path: Path,
) -> VerifiedV021AmendmentReviewHandoff:
    """Bind a pending amendment to the already declared mapping-review roster."""

    amendment = require_v02_benchmark_amendment(amendment_authority)
    if amendment.review_status != "pending" or amendment.reviewer_ids:
        raise _reject("Amendment review handoff requires a pending amendment with no reviewer IDs.")
    mapping = verify_v02_mapping_review_handoff(
        mapping_handoff_path, mapping_preparation_path=mapping_preparation_path
    )
    mapping_record, mapping_raw = _load(mapping.receipt_path, "mapping review handoff")
    if hashlib.sha256(mapping_raw).hexdigest() != mapping.sha256:
        raise _reject("Mapping handoff changed after verification.")
    role_plan = _object(mapping_record.get("role_plan"), "mapping reviewer role plan")
    primary, semantic, tiebreak = _roster(role_plan)
    timestamp = _timestamp(prepared_at, "amendment review handoff")
    if _timestamp_value(timestamp) <= _timestamp_value(
        _timestamp(cast(str, mapping_record.get("prepared_at")), "mapping handoff")
    ):
        raise _reject("Amendment review handoff must follow the mapping-review handoff.")
    amendment_record, amendment_raw = _load(amendment.receipt_path, "pending amendment")
    if hashlib.sha256(amendment_raw).hexdigest() != amendment.receipt_sha256:
        raise _reject("Pending amendment changed after verification.")
    if _timestamp_value(timestamp) <= _timestamp_value(
        _timestamp(amendment_record["prepared_at"], "amendment")
    ):
        raise _reject("Amendment review handoff must follow the pending amendment.")
    if _timestamp_value(timestamp) > datetime.now(timezone.utc):
        raise _reject("Amendment review handoff cannot be future-dated.")
    producer_sha = _git_sha(tool_git_sha)
    if amendment.tool_git_sha != producer_sha:
        raise _reject("Pending amendment and review handoff tool Git SHAs differ.")
    evidence = _object(amendment_record.get("evidence"), "amendment evidence")
    record: dict[str, object] = {
        "algorithm": HANDOFF_ALGORITHM,
        "amendment": {
            "change": _object(amendment_record.get("change"), "amendment change"),
            "evidence": evidence,
            "internal_receipt_sha256": amendment_record["receipt_sha256"],
            "raw_sha256": hashlib.sha256(amendment_raw).hexdigest(),
            "review_status": "pending",
        },
        "benchmark_version": "0.2.1",
        "claims": {
            "model_or_provider_invoked": False,
            "nominal_authority_serialized": False,
            "provider_calls": 0,
            "reviewer_verdict_generated": False,
        },
        "mapping_handoff_raw_sha256": hashlib.sha256(mapping_raw).hexdigest(),
        "prepared_at": timestamp,
        "receipt_sha256": "0" * 64,
        "review_policy": {
            "decision": "approve_or_reject_exact_amendment",
            "oracle_access": "required_for_amendment_review",
            "primary_reviewer_ids": list(primary),
            "semantic_reviewer_ids": list(semantic),
            "tiebreak_reviewer_id": tiebreak,
            "tiebreak_rule": "submit_only_after_primary_disagreement",
        },
        "schema_version": SCHEMA_VERSION,
        "status": "human_review_required_provider_disabled",
        "tool_git_sha": producer_sha,
    }
    record["receipt_sha256"] = _self_hash(record, "receipt_sha256")
    destination = Path(output_path)
    require_private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise _reject("Refusing to overwrite an amendment review handoff.")
    write_bytes_exclusive(destination, _canonical(record) + b"\n")
    return verify_v021_amendment_review_handoff(
        destination,
        amendment_authority=amendment,
        mapping_handoff_path=mapping_handoff_path,
        mapping_preparation_path=mapping_preparation_path,
    )


def verify_v021_amendment_review_handoff(
    path: Path,
    *,
    amendment_authority: VerifiedV02BenchmarkAmendment,
    mapping_handoff_path: Path,
    mapping_preparation_path: Path,
) -> VerifiedV021AmendmentReviewHandoff:
    amendment = require_v02_benchmark_amendment(amendment_authority)
    if amendment.review_status != "pending" or amendment.reviewer_ids:
        raise _reject("Fresh pending amendment authority with no reviewer IDs is required.")
    mapping = verify_v02_mapping_review_handoff(
        mapping_handoff_path, mapping_preparation_path=mapping_preparation_path
    )
    mapping_record, mapping_raw = _load(mapping.receipt_path, "mapping review handoff")
    if hashlib.sha256(mapping_raw).hexdigest() != mapping.sha256:
        raise _reject("Mapping handoff changed after verification.")
    primary, semantic, tiebreak = _roster(
        _object(mapping_record.get("role_plan"), "mapping reviewer role plan")
    )
    amendment_record, amendment_raw = _load(amendment.receipt_path, "pending amendment")
    if hashlib.sha256(amendment_raw).hexdigest() != amendment.receipt_sha256:
        raise _reject("Pending amendment changed after verification.")
    require_private_directory(Path(path).parent)
    record, raw = _load(path, "amendment review handoff")
    expected_amendment = {
        "change": _object(amendment_record.get("change"), "amendment change"),
        "evidence": _object(amendment_record.get("evidence"), "amendment evidence"),
        "internal_receipt_sha256": amendment_record["receipt_sha256"],
        "raw_sha256": hashlib.sha256(amendment_raw).hexdigest(),
        "review_status": "pending",
    }
    expected_policy = {
        "decision": "approve_or_reject_exact_amendment",
        "oracle_access": "required_for_amendment_review",
        "primary_reviewer_ids": list(primary),
        "semantic_reviewer_ids": list(semantic),
        "tiebreak_reviewer_id": tiebreak,
        "tiebreak_rule": "submit_only_after_primary_disagreement",
    }
    _exact_keys(
        record,
        {
            "algorithm",
            "amendment",
            "benchmark_version",
            "claims",
            "mapping_handoff_raw_sha256",
            "prepared_at",
            "receipt_sha256",
            "review_policy",
            "schema_version",
            "status",
            "tool_git_sha",
        },
        "amendment review handoff",
    )
    timestamp = _timestamp(record.get("prepared_at"), "amendment review handoff")
    if (
        record.get("algorithm") != HANDOFF_ALGORITHM
        or record.get("benchmark_version") != "0.2.1"
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("status") != "human_review_required_provider_disabled"
        or record.get("receipt_sha256") != _self_hash(record, "receipt_sha256")
        or record.get("amendment") != expected_amendment
        or record.get("mapping_handoff_raw_sha256") != hashlib.sha256(mapping_raw).hexdigest()
        or record.get("review_policy") != expected_policy
        or record.get("tool_git_sha") != amendment.tool_git_sha
        or record.get("claims")
        != {
            "model_or_provider_invoked": False,
            "nominal_authority_serialized": False,
            "provider_calls": 0,
            "reviewer_verdict_generated": False,
        }
        or _timestamp_value(timestamp)
        <= _timestamp_value(_timestamp(cast(str, mapping_record["prepared_at"]), "mapping handoff"))
        or _timestamp_value(timestamp)
        <= _timestamp_value(_timestamp(cast(str, amendment_record["prepared_at"]), "amendment"))
        or _timestamp_value(timestamp) > datetime.now(timezone.utc)
    ):
        raise _reject(
            "Amendment review handoff identity, evidence, chronology, or claims are invalid."
        )
    return _issue_handoff(Path(path), raw, amendment, primary, semantic, tiebreak, timestamp)


def seal_v021_amendment_review_consensus(
    *,
    handoff_authority: VerifiedV021AmendmentReviewHandoff,
    submissions_root: Path,
    sealed_at: str,
    tool_git_sha: str,
    output_path: Path,
) -> VerifiedV021AmendmentConsensus:
    handoff = require_v021_amendment_review_handoff(handoff_authority)
    sealed = _timestamp(sealed_at, "amendment review consensus")
    if _timestamp_value(sealed) <= _timestamp_value(handoff.prepared_at) or _timestamp_value(
        sealed
    ) > datetime.now(timezone.utc):
        raise _reject("Amendment review consensus chronology is invalid.")
    producer_sha = _git_sha(tool_git_sha)
    if producer_sha != handoff.tool_git_sha:
        raise _reject("Handoff and consensus tool Git SHAs differ.")
    require_private_directory(Path(submissions_root))
    files = sorted(Path(submissions_root).glob("*.json"))
    submissions = [_submission(path, handoff, sealed) for path in files]
    if len(submissions) not in (2, 3):
        raise _reject(
            "Exactly two primary submissions, or one declared tie-break after "
            "disagreement, are required."
        )
    ids = tuple(cast(str, item["reviewer_id"]) for item in submissions)
    if ids[:2] != handoff.primary_reviewer_ids or len(set(ids)) != len(ids):
        raise _reject("Primary reviewer order or independence is invalid.")
    verdicts = [cast(str, item["verdict"]) for item in submissions]
    if verdicts[0] == verdicts[1]:
        if len(submissions) != 2:
            raise _reject("A third reviewer is forbidden when the two primary reviewers agree.")
        verdict, mode = verdicts[0], "two_primary_agreement"
    else:
        if handoff.tiebreak_reviewer_id is None:
            raise _reject("Primary disagreement requires a predeclared tie-break reviewer.")
        if len(submissions) != 3 or ids[2] != handoff.tiebreak_reviewer_id:
            raise _reject("Only the declared tie-break reviewer may resolve primary disagreement.")
        verdict, mode = verdicts[2], "declared_tiebreak"
    record: dict[str, object] = {
        "algorithm": CONSENSUS_ALGORITHM,
        "amendment_handoff_raw_sha256": handoff.sha256,
        "amendment_receipt_sha256": handoff.amendment_receipt_sha256,
        "benchmark_version": "0.2.1",
        "claims": {
            "model_or_provider_invoked": False,
            "nominal_authority_serialized": False,
            "provider_calls": 0,
        },
        "consensus": {"mode": mode, "verdict": verdict},
        "schema_version": SCHEMA_VERSION,
        "seal_sha256": "0" * 64,
        "sealed_at": sealed,
        "status": "approved_provider_disabled"
        if verdict == "approved"
        else "rejected_provider_disabled",
        "submissions": submissions,
        "tool_git_sha": producer_sha,
    }
    record["seal_sha256"] = _self_hash(record, "seal_sha256")
    destination = Path(output_path)
    require_private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise _reject("Refusing to overwrite an amendment review consensus.")
    write_bytes_exclusive(destination, _canonical(record) + b"\n")
    return verify_v021_amendment_review_consensus(destination, handoff_authority=handoff)


def verify_v021_amendment_review_consensus(
    path: Path, *, handoff_authority: VerifiedV021AmendmentReviewHandoff
) -> VerifiedV021AmendmentConsensus:
    handoff = require_v021_amendment_review_handoff(handoff_authority)
    require_private_directory(Path(path).parent)
    record, raw = _load(path, "amendment review consensus")
    _exact_keys(
        record,
        {
            "algorithm",
            "amendment_handoff_raw_sha256",
            "amendment_receipt_sha256",
            "benchmark_version",
            "claims",
            "consensus",
            "schema_version",
            "seal_sha256",
            "sealed_at",
            "status",
            "submissions",
            "tool_git_sha",
        },
        "amendment review consensus",
    )
    sealed = _timestamp(record.get("sealed_at"), "amendment review consensus")
    raw_submissions = record.get("submissions")
    if not isinstance(raw_submissions, list):
        raise _reject("Amendment review submissions are invalid.")
    submissions = [
        _submission_value(_object(value, "amendment review submission"), handoff, sealed)
        for value in raw_submissions
    ]
    ids = tuple(cast(str, item["reviewer_id"]) for item in submissions)
    verdicts = [cast(str, item["verdict"]) for item in submissions]
    if (
        len(submissions) not in (2, 3)
        or ids[:2] != handoff.primary_reviewer_ids
        or len(set(ids)) != len(ids)
    ):
        raise _reject("Sealed amendment review roster is invalid.")
    if verdicts[0] == verdicts[1]:
        if len(submissions) != 2:
            raise _reject("Sealed consensus contains an unnecessary third reviewer.")
        verdict, mode = verdicts[0], "two_primary_agreement"
    else:
        if len(submissions) != 3 or ids[2] != handoff.tiebreak_reviewer_id:
            raise _reject("Sealed consensus lacks its declared tie-break reviewer.")
        verdict, mode = verdicts[2], "declared_tiebreak"
    if (
        record.get("algorithm") != CONSENSUS_ALGORITHM
        or record.get("benchmark_version") != "0.2.1"
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("seal_sha256") != _self_hash(record, "seal_sha256")
        or record.get("amendment_handoff_raw_sha256") != handoff.sha256
        or record.get("amendment_receipt_sha256") != handoff.amendment_receipt_sha256
        or record.get("tool_git_sha") != handoff.tool_git_sha
        or record.get("claims")
        != {
            "model_or_provider_invoked": False,
            "nominal_authority_serialized": False,
            "provider_calls": 0,
        }
        or record.get("consensus") != {"mode": mode, "verdict": verdict}
        or record.get("status")
        != ("approved_provider_disabled" if verdict == "approved" else "rejected_provider_disabled")
        or _timestamp_value(sealed) <= _timestamp_value(handoff.prepared_at)
        or _timestamp_value(sealed) > datetime.now(timezone.utc)
    ):
        raise _reject(
            "Amendment review consensus identity, evidence, chronology, or claims are invalid."
        )
    authority = object.__new__(VerifiedV021AmendmentConsensus)
    for name, value in {
        "path": Path(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "amendment_receipt_sha256": handoff.amendment_receipt_sha256,
        "reviewer_ids": ids,
        "verdict": verdict,
        "tool_git_sha": handoff.tool_git_sha,
        "provider_calls": 0,
        "_issuer": _ISSUER,
    }.items():
        object.__setattr__(authority, name, value)
    return authority


def require_v021_amendment_review_handoff(value: object) -> VerifiedV021AmendmentReviewHandoff:
    if type(value) is not VerifiedV021AmendmentReviewHandoff or value._issuer is not _ISSUER:
        raise _reject("Fresh verifier-issued v0.2.1 amendment review handoff is required.")
    return value


def require_approved_v021_amendment_consensus(value: object) -> VerifiedV021AmendmentConsensus:
    if type(value) is not VerifiedV021AmendmentConsensus or value._issuer is not _ISSUER:
        raise _reject("Fresh verifier-issued v0.2.1 amendment consensus is required.")
    if value.verdict != "approved":
        raise _reject("v0.2.1 amendment review was not approved; execution remains disabled.")
    return value


def _issue_handoff(
    path: Path,
    raw: bytes,
    amendment: VerifiedV02BenchmarkAmendment,
    primary: tuple[str, str],
    semantic: tuple[str, ...],
    tiebreak: str | None,
    prepared_at: str,
) -> VerifiedV021AmendmentReviewHandoff:
    authority = object.__new__(VerifiedV021AmendmentReviewHandoff)
    for name, value in {
        "path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "amendment_receipt_sha256": amendment.receipt_sha256,
        "primary_reviewer_ids": primary,
        "semantic_reviewer_ids": semantic,
        "tiebreak_reviewer_id": tiebreak,
        "prepared_at": prepared_at,
        "tool_git_sha": amendment.tool_git_sha,
        "provider_calls": 0,
        "_issuer": _ISSUER,
    }.items():
        object.__setattr__(authority, name, value)
    return authority


def _roster(role_plan: dict[str, object]) -> tuple[tuple[str, str], tuple[str, ...], str | None]:
    mapping = role_plan.get("mapping_reviewer_ids")
    semantic = role_plan.get("semantic_reviewer_ids")
    if (
        not isinstance(mapping, list)
        or len(mapping) not in (2, 3)
        or not isinstance(semantic, list)
    ):
        raise _reject("Mapping handoff reviewer roster is invalid.")
    values = tuple(_reviewer(item) for item in mapping)
    semantic_ids = tuple(_reviewer(item) for item in semantic)
    if len(set((*values, *semantic_ids))) != len(values) + len(semantic_ids):
        raise _reject("Amendment and semantic reviewer roles must remain disjoint.")
    return cast(tuple[str, str], values[:2]), semantic_ids, values[2] if len(values) == 3 else None


def _submission(
    path: Path, handoff: VerifiedV021AmendmentReviewHandoff, sealed_at: str
) -> dict[str, object]:
    value, _ = _load(path, "amendment review submission", 64 * 1024)
    return _submission_value(value, handoff, sealed_at)


def _submission_value(
    value: dict[str, object], handoff: VerifiedV021AmendmentReviewHandoff, sealed_at: str
) -> dict[str, object]:
    _exact_keys(
        value,
        {
            "amendment_handoff_raw_sha256",
            "declarations",
            "reviewer_id",
            "schema_version",
            "submitted_at",
            "verdict",
        },
        "amendment review submission",
    )
    reviewer = _reviewer(value.get("reviewer_id"))
    submitted = _timestamp(value.get("submitted_at"), "amendment review submission")
    if (
        value.get("amendment_handoff_raw_sha256") != handoff.sha256
        or value.get("schema_version") != SCHEMA_VERSION
    ):
        raise _reject("Amendment review submission binds the wrong handoff.")
    if reviewer not in {*handoff.primary_reviewer_ids, handoff.tiebreak_reviewer_id}:
        raise _reject("Amendment review submission uses an undeclared reviewer.")
    if reviewer in handoff.semantic_reviewer_ids:
        raise _reject("Semantic reviewers cannot review the oracle-aware amendment.")
    if value.get("declarations") != {
        "independent_judgment": True,
        "oracle_access": "review_only",
        "role": "amendment_reviewer",
        "semantic_review_role": "forbidden",
    }:
        raise _reject("Amendment reviewer declarations are incomplete.")
    if value.get("verdict") not in ("approved", "rejected"):
        raise _reject("Amendment reviewer verdict is invalid.")
    if _timestamp_value(submitted) <= _timestamp_value(handoff.prepared_at) or _timestamp_value(
        submitted
    ) > _timestamp_value(sealed_at):
        raise _reject("Amendment reviewer chronology is invalid.")
    return value


def _reviewer(value: object) -> str:
    if (
        not isinstance(value, str)
        or _IDENTIFIER.fullmatch(value) is None
        or _PLACEHOLDER.search(value)
    ):
        raise _reject("Genuine, non-placeholder reviewer identities are required.")
    return value


def _load(path: Path, label: str, maximum: int = MAX_BYTES) -> tuple[dict[str, object], bytes]:
    raw = _read(Path(path), maximum, label)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _reject(f"{label.capitalize()} is invalid JSON.") from exc
    if not isinstance(value, dict) or raw != _canonical(value) + b"\n":
        raise _reject(f"{label.capitalize()} is not canonical JSON.")
    return value, raw


def _read(path: Path, maximum: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as handle:
            raw = handle.read(maximum + 1)
    except OSError as exc:
        raise _reject(f"Cannot safely read {label}.") from exc
    if len(raw) > maximum:
        raise _reject(f"{label.capitalize()} exceeds the byte limit.")
    return raw


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _reject(f"{label.capitalize()} is invalid.")
    return value


def _exact_keys(value: dict[str, object], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise _reject(f"{label.capitalize()} fields are invalid.")


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject(f"{label.capitalize()} timestamp is invalid.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _reject(f"{label.capitalize()} timestamp is invalid.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise _reject(f"{label.capitalize()} timestamp must be UTC.")
    return value


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _git_sha(value: object) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject("Tool Git SHA is invalid.")
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _self_hash(record: dict[str, object], field: str) -> str:
    unsigned = dict(record)
    unsigned[field] = "0" * 64
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v021_amendment_review", message)
