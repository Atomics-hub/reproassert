"""Seal chronology evidence from public issue responses and verified private metadata."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from reproassert.benchmark_v02_cohort import load_v02_leak_audited_cohort_plan
from reproassert.benchmark_v02_hidden import hidden_case_artifacts, verify_v02_hidden_gold
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

SCHEMA_VERSION = "1.0.0"
ALGORITHM = "reproassert-v02-chronology-evidence-v1"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_BYTES = 256 * 1024

_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")


@dataclass(frozen=True)
class VerifiedV02ChronologyEvidence:
    path: Path
    sha256: str
    case_count: int
    issue_precedes_fix_count: int
    provider_calls: int = 0


def prepare_v02_chronology_evidence(
    *,
    cohort_plan_path: Path,
    hidden_extraction_receipt: Path,
    issue_responses_root: Path,
    captured_at: str,
    tool_git_sha: str,
    output_path: Path,
) -> VerifiedV02ChronologyEvidence:
    """Build a public-safe chronology receipt without network or provider access."""

    destination = Path(output_path)
    require_private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise _reject("Refusing to overwrite chronology evidence.")
    record = _derive_record(
        cohort_plan_path=Path(cohort_plan_path),
        hidden_extraction_receipt=Path(hidden_extraction_receipt),
        issue_responses_root=Path(issue_responses_root),
        captured_at=captured_at,
        tool_git_sha=tool_git_sha,
    )
    record["receipt_sha256"] = _self_hash(record)
    write_bytes_exclusive(destination, _canonical(record) + b"\n")
    return verify_v02_chronology_evidence(
        destination,
        cohort_plan_path=cohort_plan_path,
        hidden_extraction_receipt=hidden_extraction_receipt,
        issue_responses_root=issue_responses_root,
    )


def verify_v02_chronology_evidence(
    path: Path,
    *,
    cohort_plan_path: Path,
    hidden_extraction_receipt: Path,
    issue_responses_root: Path,
) -> VerifiedV02ChronologyEvidence:
    """Rederive all 20 chronology rows from their bound source artifacts."""

    raw = _read_regular(Path(path), MAX_RECEIPT_BYTES, "chronology receipt")
    record = _decode_canonical(raw, "chronology receipt")
    if set(record) != {
        "algorithm",
        "benchmark_version",
        "captured_at",
        "case_count",
        "cases",
        "claims",
        "inputs",
        "receipt_sha256",
        "schema_version",
        "status",
        "tool_git_sha",
    }:
        raise _reject("Chronology receipt fields are invalid.")
    if (
        record.get("algorithm") != ALGORITHM
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("benchmark_version") != "0.2"
        or record.get("case_count") != 20
        or record.get("status") != "issue_precedes_fix_20_of_20"
        or record.get("receipt_sha256") != _self_hash(record)
    ):
        raise _reject("Chronology receipt identity is invalid.")
    expected = _derive_record(
        cohort_plan_path=Path(cohort_plan_path),
        hidden_extraction_receipt=Path(hidden_extraction_receipt),
        issue_responses_root=Path(issue_responses_root),
        captured_at=_timestamp(record.get("captured_at"), "capture timestamp"),
        tool_git_sha=_git_sha(record.get("tool_git_sha")),
    )
    observed_unsigned = dict(record)
    observed_unsigned.pop("receipt_sha256")
    if observed_unsigned != expected:
        raise _reject("Chronology receipt differs from freshly derived evidence.")
    return VerifiedV02ChronologyEvidence(
        path=Path(path),
        sha256=hashlib.sha256(raw).hexdigest(),
        case_count=20,
        issue_precedes_fix_count=20,
    )


def _derive_record(
    *,
    cohort_plan_path: Path,
    hidden_extraction_receipt: Path,
    issue_responses_root: Path,
    captured_at: str,
    tool_git_sha: str,
) -> dict[str, object]:
    captured = _timestamp(captured_at, "capture timestamp")
    captured_value = _timestamp_value(captured)
    if captured_value > datetime.now(timezone.utc):
        raise _reject("Chronology capture cannot be future-dated.")
    producer_sha = _git_sha(tool_git_sha)
    plan = load_v02_leak_audited_cohort_plan(cohort_plan_path)
    cases = cast(list[dict[str, object]], plan["cases"])
    hidden = verify_v02_hidden_gold(hidden_extraction_receipt)
    responses_root = Path(issue_responses_root)
    require_private_directory(responses_root)
    rows: list[dict[str, object]] = []
    response_hashes: list[str] = []
    metadata_hashes: list[str] = []
    for expected_position, case in enumerate(cases, start=1):
        case_id = _case_id(case.get("case_id"))
        if case_id != f"rk-v0.2-{expected_position:03d}":
            raise _reject("Chronology cohort ordering is invalid.")
        repo = _bounded_text(case.get("repo"), "repository", 3, 200)
        issue_url = _bounded_text(case.get("issue_url"), "issue URL", 20, 500)
        issue_number = int(issue_url.rsplit("/", 1)[-1])
        response_path = responses_root / f"{case_id}.json"
        response_raw = _read_regular(response_path, MAX_RESPONSE_BYTES, "GitHub issue response")
        response = _decode_json(response_raw, "GitHub issue response")
        if (
            response.get("number") != issue_number
            or response.get("html_url") != issue_url
            or response.get("repository_url") != f"https://api.github.com/repos/{repo}"
        ):
            raise _reject(f"GitHub issue response identity differs for {case_id}.")
        issue_created = _timestamp(response.get("created_at"), "issue creation timestamp")
        artifacts = hidden_case_artifacts(hidden, case_id)
        metadata_ref = artifacts["metadata"]
        metadata_raw = _read_regular(
            cast(Path, metadata_ref["path"]), MAX_RESPONSE_BYTES, "hidden metadata"
        )
        if (
            len(metadata_raw) != metadata_ref["bytes"]
            or hashlib.sha256(metadata_raw).hexdigest() != metadata_ref["sha256"]
        ):
            raise _reject(f"Hidden metadata commitment differs for {case_id}.")
        metadata = _decode_json(metadata_raw, "hidden metadata")
        if (
            metadata.get("case_id") != case_id
            or metadata.get("repo") != repo
            or metadata.get("base_commit") != case.get("base_sha")
        ):
            raise _reject(f"Hidden chronology metadata identity differs for {case_id}.")
        fix_created = _timestamp(metadata.get("created_at"), "fix artifact creation timestamp")
        issue_value = _timestamp_value(issue_created)
        fix_value = _timestamp_value(fix_created)
        if issue_value >= fix_value:
            raise _reject(f"Issue does not precede the fixing artifact for {case_id}.")
        if captured_value < fix_value:
            raise _reject("Chronology capture predates a bound fixing artifact.")
        response_sha256 = hashlib.sha256(response_raw).hexdigest()
        metadata_sha256 = hashlib.sha256(metadata_raw).hexdigest()
        response_hashes.append(response_sha256)
        metadata_hashes.append(metadata_sha256)
        rows.append(
            {
                "case_id": case_id,
                "fix_artifact_created_at": fix_created,
                "hidden_metadata_sha256": metadata_sha256,
                "issue_created_at": issue_created,
                "issue_response_sha256": response_sha256,
                "issue_url": issue_url,
                "lead_time_seconds": int((fix_value - issue_value).total_seconds()),
                "repo": repo,
                "status": "issue_precedes_fix",
            }
        )
    return {
        "algorithm": ALGORITHM,
        "benchmark_version": "0.2",
        "captured_at": captured,
        "case_count": 20,
        "cases": rows,
        "claims": {
            "chronology_proven_count": 20,
            "hidden_bytes_emitted": False,
            "model_or_provider_invoked": False,
            "provider_calls": 0,
        },
        "inputs": {
            "cohort_plan_sha256": _file_sha256(cohort_plan_path, MAX_RECEIPT_BYTES),
            "hidden_extraction_receipt_sha256": _file_sha256(
                hidden_extraction_receipt, MAX_RECEIPT_BYTES
            ),
            "hidden_metadata_set_sha256": _set_hash(metadata_hashes, "hidden-metadata-v1"),
            "issue_response_set_sha256": _set_hash(response_hashes, "github-issue-response-v1"),
        },
        "schema_version": SCHEMA_VERSION,
        "status": "issue_precedes_fix_20_of_20",
        "tool_git_sha": producer_sha,
    }


def _decode_json(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject(f"{label.capitalize()} is invalid JSON.") from exc
    if not isinstance(value, dict):
        raise _reject(f"{label.capitalize()} must be a JSON object.")
    return cast(dict[str, object], value)


def _decode_canonical(raw: bytes, label: str) -> dict[str, object]:
    value = _decode_json(raw, label)
    if raw != _canonical(value) + b"\n":
        raise _reject(f"{label.capitalize()} is not canonical JSON.")
    return value


def _read_regular(path: Path, limit: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as stream:
            raw = stream.read(limit + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"{label.capitalize()} could not be read safely.") from exc
    if len(raw) > limit:
        raise _reject(f"{label.capitalize()} exceeds its size limit.")
    return raw


def _file_sha256(path: Path, limit: int) -> str:
    return hashlib.sha256(_read_regular(path, limit, "input artifact")).hexdigest()


def _case_id(value: object) -> str:
    if not isinstance(value, str) or _CASE_ID.fullmatch(value) is None:
        raise _reject("Case ID is invalid.")
    return value


def _git_sha(value: object) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject("Tool Git SHA is invalid.")
    return value


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject(f"{label.capitalize()} is invalid.")
    try:
        _timestamp_value(value)
    except ValueError as exc:
        raise _reject(f"{label.capitalize()} is invalid.") from exc
    return value


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _bounded_text(value: object, label: str, minimum: int, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or not value.isprintable()
    ):
        raise _reject(f"{label.capitalize()} is invalid.")
    return value


def _set_hash(values: list[str], algorithm: str) -> str:
    if any(_SHA256.fullmatch(value) is None for value in values):
        raise _reject("Chronology set contains an invalid digest.")
    return hashlib.sha256(_canonical({"algorithm": algorithm, "sha256": values})).hexdigest()


def _self_hash(record: Mapping[str, object]) -> str:
    unsigned = {key: value for key, value in record.items() if key != "receipt_sha256"}
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate key: {key}")
        value[key] = item
    return value


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_chronology", message)
