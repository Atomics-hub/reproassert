"""Private, provider-free handoff bundles for genuine human fix-hunk mapping review."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import cast

from reproassert.benchmark_v02_mapping_packets import verify_v02_mapping_packets
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

ALGORITHM = "reproassert-v02-mapping-review-handoff-v1"
SCHEMA_VERSION = "1.0.0"
DIRECTORY = "v02-mapping-review-handoff"
FILENAME = "benchmark-v02-mapping-review-handoff.json"
MAX_BYTES = 4 * 1024 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
_PLACEHOLDER = re.compile(
    r"(?:placeholder|example|tbd|todo|fake|dummy|test[-_.]?reviewer|"
    r"reviewer[-_.]?(?:[0-9]+|[abcxyz]))",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class VerifiedV02MappingReviewHandoff:
    root: Path
    receipt_path: Path
    sha256: str
    reviewer_count: int
    case_bundle_count: int
    conditional_tiebreak_declared: bool
    provider_calls: int = 0


def prepare_v02_mapping_review_handoff(
    *,
    mapping_preparation_path: Path,
    primary_reviewer_ids: tuple[str, str],
    semantic_reviewer_ids: tuple[str, ...],
    output_root: Path,
    prepared_at: str,
    tool_git_sha: str,
    tiebreak_reviewer_id: str | None = None,
) -> VerifiedV02MappingReviewHandoff:
    """Export reviewer-specific patch bundles and deliberately incomplete submissions."""

    prepared = verify_v02_mapping_packets(Path(mapping_preparation_path))
    primary = tuple(_reviewer_id(item) for item in primary_reviewer_ids)
    if len(primary) != 2 or len(set(primary)) != 2:
        raise _reject("Exactly two distinct primary mapping reviewers are required.")
    semantic = tuple(_reviewer_id(item) for item in semantic_reviewer_ids)
    if not 2 <= len(semantic) <= 3 or len(set(semantic)) != len(semantic):
        raise _reject("Two or three distinct semantic reviewer identities must be predeclared.")
    tiebreak = None if tiebreak_reviewer_id is None else _reviewer_id(tiebreak_reviewer_id)
    mapping_ids = (*primary, *((tiebreak,) if tiebreak is not None else ()))
    if len(set(mapping_ids)) != len(mapping_ids):
        raise _reject("Mapping reviewer identities must be distinct.")
    overlap = sorted(set(mapping_ids) & set(semantic))
    if overlap:
        raise _reject("Mapping and semantic reviewer identities must be disjoint.")
    timestamp = _timestamp(prepared_at)
    if timestamp > datetime.now(timezone.utc):
        raise _reject("Mapping review handoff cannot be future-dated.")
    producer_sha = _git_sha(tool_git_sha)
    preparation = _load_json(prepared.receipt_path, MAX_BYTES, "mapping preparation")
    if timestamp <= _timestamp(cast(str, preparation.get("prepared_at"))):
        raise _reject("Mapping review handoff must follow packet preparation.")

    parent = Path(output_root)
    require_private_directory(parent)
    destination = parent / DIRECTORY
    if destination.exists() or destination.is_symlink():
        raise _reject("Refusing to overwrite a mapping review handoff.")
    destination.mkdir(mode=0o700)
    try:
        reviewers: list[dict[str, object]] = []
        assignments = [
            (primary[0], "primary_1"),
            (primary[1], "primary_2"),
            *([(tiebreak, "conditional_tiebreak")] if tiebreak is not None else []),
        ]
        source_cases = cast(list[dict[str, object]], preparation["cases"])
        for ordinal, (reviewer_id, assignment) in enumerate(assignments, start=1):
            directory_name = (
                f"reviewer-{ordinal:02d}-{hashlib.sha256(reviewer_id.encode()).hexdigest()[:12]}"
            )
            reviewer_root = destination / "reviewers" / directory_name
            reviewer_root.mkdir(parents=True, mode=0o700)
            cases: list[dict[str, object]] = []
            readme_rows: list[str] = []
            for source_case in source_cases:
                case_id = cast(str, source_case["case_id"])
                source_packet_ref = _dict(source_case["packet"], "source packet reference")
                source_packet_path = _resolve(prepared.root, cast(str, source_packet_ref["path"]))
                source_packet = _load_json(source_packet_path, MAX_BYTES, "source mapping packet")
                source_patch_ref = _dict(
                    source_packet["production_patch"], "source production patch reference"
                )
                source_patch_path = _resolve(
                    source_packet_path.parent, cast(str, source_patch_ref["path"])
                )
                patch = _read(source_patch_path, MAX_BYTES, "source production patch")
                case_root = reviewer_root / "cases" / case_id
                case_root.mkdir(parents=True, mode=0o700)
                patch_path = case_root / "production.patch"
                write_bytes_exclusive(patch_path, patch)
                patch_ref = _reference(case_root, patch_path)
                packet: dict[str, object] = {
                    "assignment": assignment,
                    "case_id": case_id,
                    "hunk_inventory": source_packet["hunk_inventory"],
                    "instructions": {
                        "approve": "Select every atomic hunk required for the reported symptom.",
                        "independence": "Review independently; do not inspect another review.",
                        "reject": "Reject with an empty selected_hunk_ids array.",
                        "tiebreak": (
                            "Submit only after the two primary decisions disagree."
                            if assignment == "conditional_tiebreak"
                            else "Not applicable to a primary review."
                        ),
                    },
                    "packet_sha256": source_packet["packet_sha256"],
                    "production_patch": patch_ref,
                    "provider_calls": 0,
                    "redaction": {
                        "developer_tests_included": False,
                        "hidden_extraction_identity_included": False,
                        "production_patch_included": True,
                    },
                    "reviewer_id": reviewer_id,
                    "schema_version": SCHEMA_VERSION,
                    "status": "awaiting_independent_human_mapping_review",
                }
                packet["export_sha256"] = _self_hash(packet, "export_sha256")
                packet_path = case_root / "review-packet.json"
                write_bytes_exclusive(packet_path, _canonical(packet) + b"\n")
                template = {
                    "case_id": case_id,
                    "declarations": {
                        "generator_access": "forbidden",
                        "independent_judgment": True,
                        "role": "mapping_reviewer",
                        "semantic_review_role": "forbidden",
                    },
                    "packet_sha256": source_packet["packet_sha256"],
                    "reviewer_id": reviewer_id,
                    "schema_version": SCHEMA_VERSION,
                    "selected_hunk_ids": [],
                    "submitted_at": None,
                    "verdict": None,
                }
                template_path = case_root / "submission.template.json"
                write_bytes_exclusive(template_path, _canonical(template) + b"\n")
                cases.append(
                    {
                        "case_id": case_id,
                        "review_packet": _reference(destination, packet_path),
                        "submission_template": _reference(destination, template_path),
                    }
                )
                readme_rows.append(
                    f"| {case_id} | {len(cast(list[object], source_packet['hunk_inventory']))} | "
                    f"`cases/{case_id}/review-packet.json` |"
                )
            readme = _reviewer_readme(reviewer_id, assignment, readme_rows)
            readme_path = reviewer_root / "README.md"
            write_bytes_exclusive(readme_path, readme.encode())
            reviewers.append(
                {
                    "assignment": assignment,
                    "bundle_directory": directory_name,
                    "cases": cases,
                    "readme": _reference(destination, readme_path),
                    "reviewer_id": reviewer_id,
                }
            )
        record: dict[str, object] = {
            "algorithm": ALGORITHM,
            "benchmark_version": "0.2",
            "case_count": 20,
            "claims": {
                "hidden_artifacts_included": ["production_patch"],
                "model_or_provider_invoked": False,
                "provider_calls": 0,
                "reviewer_identity_generated": False,
                "submission_time_or_verdict_generated": False,
            },
            "mapping_preparation_file_sha256": prepared.receipt_sha256,
            "mapping_preparation_receipt_sha256": preparation["receipt_sha256"],
            "prepared_at": prepared_at,
            "reviewers": reviewers,
            "role_plan": {
                "mapping_reviewer_ids": list(mapping_ids),
                "semantic_reviewer_ids": list(semantic),
                "separation_verified": True,
                "tiebreak_policy": (
                    "predeclared_submit_only_after_primary_disagreement"
                    if tiebreak is not None
                    else "not_predeclared_prepare_later_only_after_primary_disagreement"
                ),
            },
            "schema_version": SCHEMA_VERSION,
            "status": "human_review_handoff_prepared_submissions_blank",
            "tool_git_sha": producer_sha,
        }
        record["receipt_sha256"] = _self_hash(record, "receipt_sha256")
        receipt_path = destination / FILENAME
        write_bytes_exclusive(receipt_path, _canonical(record) + b"\n")
        return verify_v02_mapping_review_handoff(
            receipt_path, mapping_preparation_path=mapping_preparation_path
        )
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def verify_v02_mapping_review_handoff(
    path: Path, *, mapping_preparation_path: Path
) -> VerifiedV02MappingReviewHandoff:
    """Verify exact source bindings, role separation, redaction, and blank submissions."""

    prepared = verify_v02_mapping_packets(Path(mapping_preparation_path))
    receipt_path = Path(path)
    root = receipt_path.parent
    require_private_directory(root)
    record = _load_json(receipt_path, MAX_BYTES, "mapping review handoff")
    _exact_keys(
        record,
        {
            "algorithm",
            "benchmark_version",
            "case_count",
            "claims",
            "mapping_preparation_file_sha256",
            "mapping_preparation_receipt_sha256",
            "prepared_at",
            "receipt_sha256",
            "reviewers",
            "role_plan",
            "schema_version",
            "status",
            "tool_git_sha",
        },
        "mapping review handoff",
    )
    if (
        record.get("algorithm") != ALGORITHM
        or record.get("benchmark_version") != "0.2"
        or record.get("case_count") != 20
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("status") != "human_review_handoff_prepared_submissions_blank"
        or record.get("receipt_sha256") != _self_hash(record, "receipt_sha256")
        or record.get("mapping_preparation_file_sha256") != prepared.receipt_sha256
        or record.get("claims")
        != {
            "hidden_artifacts_included": ["production_patch"],
            "model_or_provider_invoked": False,
            "provider_calls": 0,
            "reviewer_identity_generated": False,
            "submission_time_or_verdict_generated": False,
        }
    ):
        raise _reject("Mapping review handoff identity or trust claims are invalid.")
    _git_sha(cast(str, record.get("tool_git_sha")))
    handoff_time = _timestamp(cast(str, record.get("prepared_at")))
    preparation = _load_json(prepared.receipt_path, MAX_BYTES, "mapping preparation")
    if record.get("mapping_preparation_receipt_sha256") != preparation.get(
        "receipt_sha256"
    ) or handoff_time <= _timestamp(cast(str, preparation.get("prepared_at"))):
        raise _reject("Mapping review handoff chronology or source commitment is invalid.")
    role_plan = _dict(record.get("role_plan"), "reviewer role plan")
    _exact_keys(
        role_plan,
        {
            "mapping_reviewer_ids",
            "semantic_reviewer_ids",
            "separation_verified",
            "tiebreak_policy",
        },
        "reviewer role plan",
    )
    mapping_ids = _reviewer_list(role_plan.get("mapping_reviewer_ids"), 2, 3, "mapping")
    semantic_ids = _reviewer_list(role_plan.get("semantic_reviewer_ids"), 2, 3, "semantic")
    if set(mapping_ids) & set(semantic_ids) or role_plan.get("separation_verified") is not True:
        raise _reject("Mapping and semantic reviewer roles overlap.")
    reviewers = record.get("reviewers")
    if not isinstance(reviewers, list) or len(reviewers) != len(mapping_ids):
        raise _reject("Handoff reviewer bundle count is invalid.")
    expected_assignments = ["primary_1", "primary_2"] + (
        ["conditional_tiebreak"] if len(mapping_ids) == 3 else []
    )
    if [
        row.get("assignment") for row in reviewers if isinstance(row, dict)
    ] != expected_assignments:
        raise _reject("Handoff reviewer assignments are invalid.")
    source_cases = cast(list[dict[str, object]], preparation["cases"])
    bundle_count = 0
    for ordinal, raw_reviewer in enumerate(reviewers):
        reviewer = _dict(raw_reviewer, "reviewer bundle")
        _exact_keys(
            reviewer,
            {"assignment", "bundle_directory", "cases", "readme", "reviewer_id"},
            "reviewer bundle",
        )
        reviewer_id = _reviewer_id(cast(str, reviewer.get("reviewer_id")))
        if reviewer_id != mapping_ids[ordinal]:
            raise _reject("Reviewer bundle identity differs from the role plan.")
        _verify_reference(root, _dict(reviewer.get("readme"), "reviewer readme"))
        cases = reviewer.get("cases")
        if not isinstance(cases, list) or len(cases) != 20:
            raise _reject("Reviewer bundle must contain exactly 20 cases.")
        for source_case, raw_case in zip(source_cases, cases, strict=True):
            case = _dict(raw_case, "reviewer case bundle")
            case_id = cast(str, source_case["case_id"])
            if case.get("case_id") != case_id:
                raise _reject("Reviewer case bundle ordering is invalid.")
            packet_ref = _dict(case.get("review_packet"), "exported review packet")
            template_ref = _dict(case.get("submission_template"), "submission template")
            _verify_reference(root, packet_ref)
            _verify_reference(root, template_ref)
            packet_path = _resolve(root, cast(str, packet_ref["path"]))
            exported = _load_json(packet_path, MAX_BYTES, "exported review packet")
            source_packet_path = _resolve(
                prepared.root,
                cast(str, _dict(source_case["packet"], "source packet reference")["path"]),
            )
            source_packet = _load_json(source_packet_path, MAX_BYTES, "source mapping packet")
            if (
                exported.get("case_id") != case_id
                or exported.get("reviewer_id") != reviewer_id
                or exported.get("assignment") != reviewer["assignment"]
                or exported.get("packet_sha256") != source_packet.get("packet_sha256")
                or exported.get("hunk_inventory") != source_packet.get("hunk_inventory")
                or exported.get("provider_calls") != 0
                or exported.get("status") != "awaiting_independent_human_mapping_review"
                or exported.get("redaction")
                != {
                    "developer_tests_included": False,
                    "hidden_extraction_identity_included": False,
                    "production_patch_included": True,
                }
                or exported.get("export_sha256") != _self_hash(exported, "export_sha256")
            ):
                raise _reject("Exported reviewer packet differs from its verified source.")
            exported_patch = _dict(exported.get("production_patch"), "exported patch")
            _verify_reference(packet_path.parent, exported_patch)
            source_patch = _dict(source_packet.get("production_patch"), "source patch")
            source_patch_path = _resolve(source_packet_path.parent, cast(str, source_patch["path"]))
            exported_patch_path = _resolve(packet_path.parent, cast(str, exported_patch["path"]))
            if _read(exported_patch_path, MAX_BYTES, "exported patch") != _read(
                source_patch_path, MAX_BYTES, "source patch"
            ):
                raise _reject("Reviewer production patch differs from the verified source.")
            template_path = _resolve(root, cast(str, template_ref["path"]))
            template = _load_json(template_path, 64 * 1024, "submission template")
            expected_template = {
                "case_id": case_id,
                "declarations": {
                    "generator_access": "forbidden",
                    "independent_judgment": True,
                    "role": "mapping_reviewer",
                    "semantic_review_role": "forbidden",
                },
                "packet_sha256": source_packet["packet_sha256"],
                "reviewer_id": reviewer_id,
                "schema_version": SCHEMA_VERSION,
                "selected_hunk_ids": [],
                "submitted_at": None,
                "verdict": None,
            }
            if template != expected_template:
                raise _reject("Submission template is not blank and source-bound.")
            bundle_count += 1
    raw = _read(receipt_path, MAX_BYTES, "mapping review handoff")
    return VerifiedV02MappingReviewHandoff(
        root=root,
        receipt_path=receipt_path,
        sha256=hashlib.sha256(raw).hexdigest(),
        reviewer_count=len(mapping_ids),
        case_bundle_count=bundle_count,
        conditional_tiebreak_declared=len(mapping_ids) == 3,
    )


def _reviewer_readme(reviewer_id: str, assignment: str, rows: list[str]) -> str:
    tie = (
        "Do not submit any template unless the two primary reviewers disagree."
        if assignment == "conditional_tiebreak"
        else "Complete your review independently before seeing any other submission."
    )
    return (
        "# ReproAssert mapping review handoff\n\n"
        f"Reviewer: `{reviewer_id}`  \nAssignment: `{assignment}`\n\n"
        f"{tie}\n\n"
        "For each case, inspect only `review-packet.json` and `production.patch`. Fill the bound "
        "template with a real UTC `submitted_at`, `approved` plus every required atomic hunk ID, "
        "or `rejected` plus an empty hunk list. Rename the completed file; never submit the "
        "`.template.json` unchanged.\n\n"
        "| Case | Hunks | Packet |\n|---|---:|---|\n" + "\n".join(rows) + "\n"
    )


def _reviewer_list(value: object, minimum: int, maximum: int, label: str) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise _reject(f"{label.capitalize()} reviewer roster size is invalid.")
    reviewers = [_reviewer_id(cast(str, item)) for item in value]
    if len(set(reviewers)) != len(reviewers):
        raise _reject(f"{label.capitalize()} reviewer identities are not distinct.")
    return reviewers


def _reviewer_id(value: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise _reject("Reviewer identity is invalid.")
    if _PLACEHOLDER.search(value):
        raise _reject("Placeholder reviewer identities are forbidden.")
    return value


def _git_sha(value: str) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject("Tool Git SHA is invalid.")
    return value


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject("Timestamp must be RFC 3339 UTC.")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _reject("Timestamp must be RFC 3339 UTC.") from exc


def _reference(root: Path, path: Path) -> dict[str, object]:
    raw = _read(path, MAX_BYTES, "handoff artifact")
    return {
        "bytes": len(raw),
        "path": path.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _verify_reference(root: Path, value: dict[str, object]) -> None:
    _exact_keys(value, {"bytes", "path", "sha256"}, "artifact reference")
    path = _resolve(root, cast(str, value.get("path")))
    raw = _read(path, MAX_BYTES, "handoff artifact")
    if len(raw) != value.get("bytes") or hashlib.sha256(raw).hexdigest() != value.get("sha256"):
        raise _reject("Handoff artifact reference is invalid.")


def _resolve(root: Path, relative: str) -> Path:
    if not isinstance(relative, str):
        raise _reject("Artifact path is invalid.")
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise _reject("Artifact path traversal is forbidden.")
    resolved_root = root.resolve(strict=True)
    resolved = root.joinpath(*path.parts).resolve(strict=True)
    if resolved_root not in resolved.parents:
        raise _reject("Artifact escapes its verified root.")
    return resolved


def _read(path: Path, limit: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as stream:
            raw = stream.read(limit + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"{label.capitalize()} could not be read safely.") from exc
    if not raw or len(raw) > limit:
        raise _reject(f"{label.capitalize()} exceeds its byte bound.")
    return raw


def _load_json(path: Path, limit: int, label: str) -> dict[str, object]:
    raw = _read(path, limit, label)
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


def _self_hash(value: dict[str, object], field: str) -> str:
    return hashlib.sha256(
        _canonical({key: item for key, item in value.items() if key != field})
    ).hexdigest()


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_mapping_review_handoff", message)
