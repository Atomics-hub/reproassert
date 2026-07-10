from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from reproassert.errors import PolicyRejection
from reproassert.intake import parse_issue_url
from reproassert.safeio import open_regular_file

SNAPSHOT_RECEIPT_SCHEMA_VERSION = "1.0.0"
BENCHMARK_VERSION = "0.2.0-draft"
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_RAW_RECEIPT_BYTES = 8 * 1024 * 1024
MAX_CUTOFF_BASIS_BYTES = 1024 * 1024
MAX_TITLE_BYTES = 4 * 1024
MAX_BODY_BYTES = 64 * 1024
MAX_CANONICAL_BYTES = 144 * 1024
SNAPSHOT_PRODUCER_REDERIVATION_IMPLEMENTED = False

_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,99}")
_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z"
)
_ROOT_KEYS = {
    "schema_version",
    "benchmark_version",
    "identity",
    "capture",
    "history",
    "cutoff",
    "selected_revision",
    "temporal_provenance",
    "content",
    "comments_excluded",
    "redaction",
    "privacy_review",
}
_IDENTITY_KEYS = {"case_id", "repo", "issue_url", "issue_number", "base_sha"}
_CAPTURE_KEYS = {
    "captured_at",
    "source",
    "api",
    "tool",
    "raw_receipt_sha256",
    "raw_receipt_bytes",
}
_API_KEYS = {"kind", "version", "request_sha256"}
_TOOL_KEYS = {"name", "version", "git_sha"}
_HISTORY_KEYS = {
    "complete",
    "current_live_only",
    "body_edits_complete",
    "title_edits_complete",
    "creation_revision_included",
    "deleted_edits_present",
}
_CUTOFF_KEYS = {
    "policy",
    "timestamp",
    "publication_proven",
    "basis_sha256",
    "basis_bytes",
}
_SELECTED_REVISION_KEYS = {
    "provenance",
    "evidence_grade",
    "selected_at",
    "revision_sha256",
}
_TEMPORAL_KEYS = {"status", "issue_created_at", "selected_revision_at", "reason"}
_CONTENT_KEYS = {
    "encoding",
    "canonicalization",
    "title",
    "body",
    "title_bytes",
    "body_bytes",
    "canonical_bytes",
    "title_sha256",
    "body_sha256",
    "snapshot_sha256",
}
_REDACTION_KEYS = {
    "policy",
    "policy_sha256",
    "target_sha256",
    "count",
    "pre_redaction_sha256",
    "post_redaction_sha256",
    "forbidden_backlinks_remaining",
    "oracle_material_detected",
}
_PRIVACY_KEYS = {
    "status",
    "reviewed_at",
    "reviewer_id",
    "checklist_sha256",
    "sensitive_material_excluded",
}

GeneratorSnapshot = dict[str, str]


def load_snapshot_receipt(
    receipt_path: Path,
    *,
    raw_receipt_path: Path,
    cutoff_basis_path: Path,
    expected_case_id: str,
    expected_repo: str,
    expected_issue_url: str,
    expected_base_sha: str,
    allow_unverified_producer: bool = False,
) -> GeneratorSnapshot:
    """Structurally validate a draft receipt; scoring use fails closed by default.

    The current slice does not independently derive revisions/redactions from the raw evidence.
    ``allow_unverified_producer`` exists only for draft fixtures and producer development.
    """

    receipt_bytes = _read_bounded_regular(receipt_path, MAX_RECEIPT_BYTES, "snapshot receipt")
    raw_receipt_bytes = _read_bounded_regular(
        raw_receipt_path, MAX_RAW_RECEIPT_BYTES, "raw snapshot evidence"
    )
    cutoff_basis_bytes = _read_bounded_regular(
        cutoff_basis_path, MAX_CUTOFF_BASIS_BYTES, "snapshot cutoff basis"
    )
    try:
        decoded = json.loads(
            receipt_bytes,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _rejection("Receipt is not strict UTF-8 JSON.") from exc
    if not isinstance(decoded, dict):
        raise _rejection("Receipt root must be an object.")
    return canonicalize_snapshot_receipt(
        decoded,
        raw_receipt_bytes=raw_receipt_bytes,
        cutoff_basis_bytes=cutoff_basis_bytes,
        expected_case_id=expected_case_id,
        expected_repo=expected_repo,
        expected_issue_url=expected_issue_url,
        expected_base_sha=expected_base_sha,
        allow_unverified_producer=allow_unverified_producer,
    )


def canonicalize_snapshot_receipt(
    receipt: Mapping[str, object],
    *,
    raw_receipt_bytes: bytes,
    cutoff_basis_bytes: bytes,
    expected_case_id: str,
    expected_repo: str,
    expected_issue_url: str,
    expected_base_sha: str,
    allow_unverified_producer: bool = False,
) -> GeneratorSnapshot:
    """Validate a draft controller-only receipt and optionally project fixture content."""

    root = _exact_object(receipt, _ROOT_KEYS, "receipt")
    _require_equal(root.get("schema_version"), SNAPSHOT_RECEIPT_SCHEMA_VERSION, "schema version")
    _require_equal(root.get("benchmark_version"), BENCHMARK_VERSION, "benchmark version")

    identity = _exact_object(root.get("identity"), _IDENTITY_KEYS, "identity")
    _validate_identity(
        identity,
        expected_case_id=expected_case_id,
        expected_repo=expected_repo,
        expected_issue_url=expected_issue_url,
        expected_base_sha=expected_base_sha,
    )

    capture = _exact_object(root.get("capture"), _CAPTURE_KEYS, "capture")
    captured_at = _timestamp(capture.get("captured_at"), "capture.captured_at")
    _require_equal(capture.get("source"), "trusted_local_receipt", "capture source")
    api = _exact_object(capture.get("api"), _API_KEYS, "capture.api")
    if api.get("kind") not in {"github_graphql", "trusted_archive"}:
        raise _rejection("Capture API kind is not trusted.")
    _bounded_ascii(api.get("version"), "capture.api.version", _VERSION)
    _sha256(api.get("request_sha256"), "capture.api.request_sha256")
    tool = _exact_object(capture.get("tool"), _TOOL_KEYS, "capture.tool")
    _bounded_ascii(tool.get("name"), "capture.tool.name", _IDENTIFIER)
    _bounded_ascii(tool.get("version"), "capture.tool.version", _VERSION)
    _git_sha(tool.get("git_sha"), "capture.tool.git_sha")
    _verify_external_bytes(
        raw_receipt_bytes,
        expected_size=capture.get("raw_receipt_bytes"),
        expected_sha256=capture.get("raw_receipt_sha256"),
        label="raw snapshot evidence",
    )

    history = _exact_object(root.get("history"), _HISTORY_KEYS, "history")
    required_history = {
        "complete": True,
        "current_live_only": False,
        "body_edits_complete": True,
        "title_edits_complete": True,
        "creation_revision_included": True,
        "deleted_edits_present": False,
    }
    if any(history.get(name) is not value for name, value in required_history.items()):
        raise _rejection("Historical issue evidence is incomplete or current-live-only.")

    cutoff = _exact_object(root.get("cutoff"), _CUTOFF_KEYS, "cutoff")
    _require_equal(cutoff.get("policy"), "pre_solution_pr_publication", "snapshot cutoff policy")
    _require_equal(cutoff.get("publication_proven"), True, "solution PR publication evidence")
    cutoff_at = _timestamp(cutoff.get("timestamp"), "cutoff.timestamp")
    _verify_external_bytes(
        cutoff_basis_bytes,
        expected_size=cutoff.get("basis_bytes"),
        expected_sha256=cutoff.get("basis_sha256"),
        label="snapshot cutoff basis",
    )

    selected = _exact_object(
        root.get("selected_revision"), _SELECTED_REVISION_KEYS, "selected_revision"
    )
    provenance = selected.get("provenance")
    grade = selected.get("evidence_grade")
    allowed_pairs = {
        ("complete_issue_edit_history", "complete_history"),
        ("trusted_archival_snapshot", "trusted_archive"),
    }
    if (provenance, grade) not in allowed_pairs:
        raise _rejection("Selected revision provenance or evidence grade is insufficient.")
    selected_at = _timestamp(selected.get("selected_at"), "selected_revision.selected_at")
    revision_sha256 = _sha256(selected.get("revision_sha256"), "selected_revision.revision_sha256")

    temporal = _exact_object(root.get("temporal_provenance"), _TEMPORAL_KEYS, "temporal_provenance")
    status = temporal.get("status")
    if status not in {"pre_fix_chronology_proven", "pre_fix_chronology_unproven"}:
        raise _rejection("Temporal provenance status is invalid.")
    reason = temporal.get("reason")
    if status == "pre_fix_chronology_proven":
        if reason is not None:
            raise _rejection("Proven chronology must not retain a caveat reason.")
    elif not isinstance(reason, str) or not 1 <= len(reason) <= 500:
        raise _rejection("Unproven pre-fix chronology requires an explicit caveat.")
    issue_created_at = _timestamp(
        temporal.get("issue_created_at"), "temporal_provenance.issue_created_at"
    )
    temporal_selected_at = _timestamp(
        temporal.get("selected_revision_at"), "temporal_provenance.selected_revision_at"
    )
    if temporal_selected_at != selected_at:
        raise _rejection("Temporal provenance does not identify the selected revision.")
    if not issue_created_at <= selected_at < cutoff_at:
        raise _rejection("Selected revision is not proven to precede the solution PR.")
    if captured_at < selected_at:
        raise _rejection("Capture time predates the selected historical revision.")
    if captured_at < cutoff_at:
        raise _rejection("Capture time predates the proven solution publication cutoff.")

    content = _exact_object(root.get("content"), _CONTENT_KEYS, "content")
    _require_equal(content.get("encoding"), "utf-8", "snapshot encoding")
    _require_equal(content.get("canonicalization"), "nfc_lf_v1", "snapshot canonicalization")
    title = _canonical_text(content.get("title"), "content.title", MAX_TITLE_BYTES, title=True)
    body = _canonical_text(content.get("body"), "content.body", MAX_BODY_BYTES, title=False)
    title_bytes = title.encode("utf-8")
    body_bytes = body.encode("utf-8")
    canonical_bytes = canonical_snapshot_content_bytes(title=title, body=body)
    if len(canonical_bytes) > MAX_CANONICAL_BYTES:
        raise _rejection("Canonical snapshot content exceeds the byte limit.")
    _require_equal(content.get("title_bytes"), len(title_bytes), "title byte count")
    _require_equal(content.get("body_bytes"), len(body_bytes), "body byte count")
    _require_equal(content.get("canonical_bytes"), len(canonical_bytes), "snapshot byte count")
    _require_equal(
        content.get("title_sha256"), hashlib.sha256(title_bytes).hexdigest(), "title hash"
    )
    _require_equal(content.get("body_sha256"), hashlib.sha256(body_bytes).hexdigest(), "body hash")
    snapshot_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    _require_equal(content.get("snapshot_sha256"), snapshot_sha256, "snapshot hash")

    if root.get("comments_excluded") is not True:
        raise _rejection("Issue comments must be excluded.")

    redaction = _exact_object(root.get("redaction"), _REDACTION_KEYS, "redaction")
    _require_equal(redaction.get("policy"), "fix_backlinks_v1", "redaction policy")
    _sha256(redaction.get("policy_sha256"), "redaction.policy_sha256")
    _sha256(redaction.get("target_sha256"), "redaction.target_sha256")
    redaction_count = _nonnegative_int(redaction.get("count"), "redaction.count")
    pre_redaction_sha256 = _sha256(
        redaction.get("pre_redaction_sha256"), "redaction.pre_redaction_sha256"
    )
    post_redaction_sha256 = _sha256(
        redaction.get("post_redaction_sha256"), "redaction.post_redaction_sha256"
    )
    if post_redaction_sha256 != snapshot_sha256 or revision_sha256 != pre_redaction_sha256:
        raise _rejection("Redaction hashes do not bind the selected and sanitized revisions.")
    if (redaction_count == 0) is not (pre_redaction_sha256 == post_redaction_sha256):
        raise _rejection("Redaction count does not agree with its pre/post hashes.")
    if redaction.get("forbidden_backlinks_remaining") != 0:
        raise _rejection("Forbidden fixing backlinks remain after redaction.")
    if redaction.get("oracle_material_detected") is not False:
        raise _rejection("Oracle material is present in the generator snapshot.")
    privacy = _exact_object(root.get("privacy_review"), _PRIVACY_KEYS, "privacy_review")
    _require_equal(privacy.get("status"), "approved", "privacy review status")
    reviewed_at = _timestamp(privacy.get("reviewed_at"), "privacy_review.reviewed_at")
    if reviewed_at < captured_at:
        raise _rejection("Privacy review predates the evidence capture.")
    _bounded_ascii(privacy.get("reviewer_id"), "privacy_review.reviewer_id", _IDENTIFIER)
    _sha256(privacy.get("checklist_sha256"), "privacy_review.checklist_sha256")
    if privacy.get("sensitive_material_excluded") is not True:
        raise _rejection("Privacy review did not exclude sensitive material.")

    if SNAPSHOT_PRODUCER_REDERIVATION_IMPLEMENTED is not True and not allow_unverified_producer:
        raise PolicyRejection(
            "benchmark_snapshot_producer_unverified",
            "Snapshot producer derivation is not independently implemented; scoring is blocked.",
        )
    return {"title": title, "body": body, "snapshot_sha256": snapshot_sha256}


def canonical_snapshot_content_bytes(*, title: str, body: str) -> bytes:
    """Return the exact canonical bytes committed by snapshot_sha256."""

    return json.dumps(
        {"body": body, "title": title},
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _validate_identity(
    identity: Mapping[str, object],
    *,
    expected_case_id: str,
    expected_repo: str,
    expected_issue_url: str,
    expected_base_sha: str,
) -> None:
    case_id = _bounded_ascii(identity.get("case_id"), "identity.case_id", _CASE_ID)
    repo = _bounded_ascii(identity.get("repo"), "identity.repo", _REPOSITORY)
    issue_url = identity.get("issue_url")
    if not isinstance(issue_url, str):
        raise _rejection("identity.issue_url must be text.")
    try:
        location = parse_issue_url(issue_url)
    except PolicyRejection as exc:
        raise _rejection("identity.issue_url is not canonical.") from exc
    issue_number = _positive_int(identity.get("issue_number"), "identity.issue_number")
    base_sha = _git_sha(identity.get("base_sha"), "identity.base_sha")
    if repo != f"{location.owner}/{location.repo}" or issue_number != location.number:
        raise _rejection("Receipt issue identity is internally inconsistent.")
    expected = (expected_case_id, expected_repo, expected_issue_url, expected_base_sha)
    actual = (case_id, repo, issue_url, base_sha)
    if actual != expected:
        raise _rejection("Receipt identity does not match the frozen benchmark case.")


def _exact_object(value: object, keys: set[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise _rejection(f"{label} fields do not match the strict receipt contract.")
    return cast(Mapping[str, object], value)


def _canonical_text(value: object, label: str, max_bytes: int, *, title: bool) -> str:
    if not isinstance(value, str) or (title and not value):
        raise _rejection(f"{label} must be canonical text.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _rejection(f"{label} is not valid UTF-8 text.") from exc
    if len(encoded) > max_bytes or "\r" in value or unicodedata.normalize("NFC", value) != value:
        raise _rejection(f"{label} is not bounded NFC/LF text.")
    if title and ("\n" in value or "\t" in value):
        raise _rejection("content.title must be one line.")
    for character in value:
        if character in {"\n", "\t"}:
            continue
        if unicodedata.category(character) in {"Cc", "Cf"}:
            raise _rejection(f"{label} contains a forbidden control character.")
    return value


def _verify_external_bytes(
    content: bytes, *, expected_size: object, expected_sha256: object, label: str
) -> None:
    if _positive_int(expected_size, f"{label} byte count") != len(content):
        raise _rejection(f"{label} byte count does not match.")
    digest = _sha256(expected_sha256, f"{label} hash")
    if digest != hashlib.sha256(content).hexdigest():
        raise _rejection(f"{label} hash does not match.")


def _read_bounded_regular(path: Path, limit: int, label: str) -> bytes:
    with open_regular_file(path) as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise _rejection(f"{label} exceeds its byte limit.")
    return content


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        raise _rejection(f"{label} must be an RFC 3339 UTC timestamp.")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _rejection(f"{label} is not a real timestamp.") from exc


def _bounded_ascii(value: object, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not value.isascii() or pattern.fullmatch(value) is None:
        raise _rejection(f"{label} is invalid.")
    return value


def _sha256(value: object, label: str) -> str:
    return _bounded_ascii(value, label, _SHA256)


def _git_sha(value: object, label: str) -> str:
    return _bounded_ascii(value, label, _GIT_SHA)


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _rejection(f"{label} must be a non-negative integer.")
    return value


def _positive_int(value: object, label: str) -> int:
    result = _nonnegative_int(value, label)
    if result < 1:
        raise _rejection(f"{label} must be positive.")
    return result


def _require_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected or type(actual) is not type(expected):
        raise _rejection(f"{label} does not match the frozen receipt contract.")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _rejection(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_snapshot_receipt", message)
