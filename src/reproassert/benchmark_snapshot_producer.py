from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from reproassert import __version__
from reproassert.benchmark_snapshot import (
    MAX_CUTOFF_BASIS_BYTES,
    MAX_RAW_RECEIPT_BYTES,
    canonical_snapshot_content_bytes,
    canonicalize_snapshot_receipt,
    load_snapshot_receipt,
)
from reproassert.errors import PolicyRejection
from reproassert.intake import parse_issue_url
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

ISSUE_HISTORY_QUERY = """query ReproAssertIssueHistory(
  $owner: String!
  $repo: String!
  $number: Int!
) {
  repository(owner: $owner, name: $repo) {
    nameWithOwner
    issue(number: $number) {
      number
      url
      title
      body
      createdAt
      lastEditedAt
      includesCreatedEdit
      userContentEdits(first: 100) {
        totalCount
        pageInfo { hasNextPage hasPreviousPage startCursor endCursor }
        nodes { id createdAt editedAt deletedAt diff }
      }
      timelineItems(first: 100, itemTypes: [RENAMED_TITLE_EVENT]) {
        totalCount
        pageInfo { hasNextPage hasPreviousPage startCursor endCursor }
        nodes {
          __typename
          ... on RenamedTitleEvent { id createdAt previousTitle currentTitle }
        }
      }
    }
  }
}
"""

SOLUTION_CUTOFF_QUERY = """query ReproAssertSolutionPublication(
  $owner: String!
  $repo: String!
  $number: Int!
) {
  repository(owner: $owner, name: $repo) {
    nameWithOwner
    pullRequest(number: $number) {
      number
      url
      createdAt
      publishedAt
      mergedAt
      isDraft
      baseRepository { nameWithOwner }
    }
  }
}
"""

ISSUE_HISTORY_QUERY_SHA256 = hashlib.sha256(ISSUE_HISTORY_QUERY.encode()).hexdigest()
SOLUTION_CUTOFF_QUERY_SHA256 = hashlib.sha256(SOLUTION_CUTOFF_QUERY.encode()).hexdigest()

REDACTION_REPLACEMENT = "[fix reference removed]"
REDACTION_POLICY = {
    "id": "fix_backlinks_v1",
    "replacement": REDACTION_REPLACEMENT,
    "targets": [
        "canonical_https_pull_url",
        "same_repository_owner_repo_pull_number",
        "same_repository_owner_repo_hash_number",
        "same_repository_bare_hash_number",
    ],
    "matching": "ascii_case_insensitive_exact_repository_and_number",
}
REDACTION_POLICY_SHA256 = hashlib.sha256(
    json.dumps(REDACTION_POLICY, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()

GRAPHQL_CAPTURE_FORMAT = "reproassert-github-graphql-response-v1"
GRAPHQL_API_VERSION = "github-graphql-v4"
PRIVATE_CHRONOLOGY_REASON = (
    "PR publication is proven; private solution authorship timing is not observable."
)
MAX_HISTORY_ITEMS = 100
MAX_NODE_ID_CHARS = 512
MAX_RAW_TEXT_BYTES = 64 * 1024

_ISSUE_ARTIFACT_KEYS = {"format", "query_sha256", "response"}
_RESPONSE_KEYS = {"data"}
_DATA_KEYS = {"repository"}
_ISSUE_REPOSITORY_KEYS = {"nameWithOwner", "issue"}
_ISSUE_KEYS = {
    "number",
    "url",
    "title",
    "body",
    "createdAt",
    "lastEditedAt",
    "includesCreatedEdit",
    "userContentEdits",
    "timelineItems",
}
_CONNECTION_KEYS = {"totalCount", "pageInfo", "nodes"}
_PAGE_INFO_KEYS = {"hasNextPage", "hasPreviousPage", "startCursor", "endCursor"}
_BODY_EDIT_KEYS = {"id", "createdAt", "editedAt", "deletedAt", "diff"}
_TITLE_EDIT_KEYS = {"__typename", "id", "createdAt", "previousTitle", "currentTitle"}
_CUTOFF_REPOSITORY_KEYS = {"nameWithOwner", "pullRequest"}
_PULL_REQUEST_KEYS = {
    "number",
    "url",
    "createdAt",
    "publishedAt",
    "mergedAt",
    "isDraft",
    "baseRepository",
}
_BASE_REPOSITORY_KEYS = {"nameWithOwner"}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,99}")


@dataclass(frozen=True)
class SnapshotIdentity:
    case_id: str
    repository: str
    issue_url: str
    base_sha: str


@dataclass(frozen=True)
class SnapshotProducerMetadata:
    captured_at: str
    tool_git_sha: str
    tool_name: str = "reproassert-snapshot-producer"
    tool_version: str = __version__


@dataclass(frozen=True)
class SnapshotPrivacyReview:
    reviewed_at: str
    reviewer_id: str
    checklist_sha256: str


@dataclass(frozen=True)
class DerivedSnapshot:
    issue_created_at: str
    selected_at: str
    cutoff_at: str
    selected_title: str
    selected_body: str
    sanitized_title: str
    sanitized_body: str
    pre_redaction_sha256: str
    post_redaction_sha256: str
    target_sha256: str
    redaction_count: int


@dataclass(frozen=True)
class ProducedSnapshotReceipt:
    receipt_path: Path
    receipt_sha256: str
    snapshot_sha256: str


@dataclass(frozen=True)
class _BodyRevision:
    edited_at: str
    timestamp: datetime
    body: str


@dataclass(frozen=True)
class _TitleRevision:
    created_at: str
    timestamp: datetime
    previous_title: str
    current_title: str


def produce_snapshot_receipt(
    *,
    identity: SnapshotIdentity,
    raw_issue_evidence_bytes: bytes,
    cutoff_basis_bytes: bytes,
    producer: SnapshotProducerMetadata,
    privacy_review: SnapshotPrivacyReview,
) -> dict[str, object]:
    """Derive a controller-only receipt from offline GitHub evidence.

    This function does not collect live data. The caller must capture and preserve the two
    evaluator-only artifacts separately and explicitly provide the human privacy review.
    """

    location = parse_issue_url(identity.issue_url)
    if identity.repository != f"{location.owner}/{location.repo}":
        raise _rejection("Snapshot identity repository does not match its issue URL.")
    if _GIT_SHA.fullmatch(identity.base_sha) is None:
        raise _rejection("Snapshot identity base SHA is not exact lowercase 40-hex.")
    captured_at = _timestamp(producer.captured_at, "producer capture time")
    reviewed_at = _timestamp(privacy_review.reviewed_at, "privacy review time")
    if reviewed_at < captured_at:
        raise _rejection("Privacy review predates evidence capture.")
    _ascii_identifier(producer.tool_name, "producer tool name", _IDENTIFIER)
    _ascii_identifier(producer.tool_version, "producer tool version", _VERSION)
    if _GIT_SHA.fullmatch(producer.tool_git_sha) is None:
        raise _rejection("Producer tool Git SHA is invalid.")
    _ascii_identifier(privacy_review.reviewer_id, "privacy reviewer", _IDENTIFIER)
    if _SHA256.fullmatch(privacy_review.checklist_sha256) is None:
        raise _rejection("Privacy checklist hash is invalid.")

    derived = derive_snapshot(
        raw_issue_evidence_bytes=raw_issue_evidence_bytes,
        cutoff_basis_bytes=cutoff_basis_bytes,
        expected_repository=identity.repository,
        expected_issue_url=identity.issue_url,
        expected_issue_number=location.number,
    )
    if captured_at < _timestamp(derived.cutoff_at, "derived cutoff time"):
        raise _rejection("Evidence capture predates solution publication.")

    content = _content_record(derived.sanitized_title, derived.sanitized_body)
    return {
        "schema_version": "1.0.0",
        "benchmark_version": "0.2.0-draft",
        "identity": {
            "case_id": identity.case_id,
            "repo": identity.repository,
            "issue_url": identity.issue_url,
            "issue_number": location.number,
            "base_sha": identity.base_sha,
        },
        "capture": {
            "captured_at": producer.captured_at,
            "source": "trusted_local_receipt",
            "api": {
                "kind": "github_graphql",
                "version": GRAPHQL_API_VERSION,
                "request_sha256": ISSUE_HISTORY_QUERY_SHA256,
            },
            "tool": {
                "name": producer.tool_name,
                "version": producer.tool_version,
                "git_sha": producer.tool_git_sha,
            },
            "raw_receipt_sha256": hashlib.sha256(raw_issue_evidence_bytes).hexdigest(),
            "raw_receipt_bytes": len(raw_issue_evidence_bytes),
        },
        "history": _history_record(),
        "cutoff": {
            "policy": "pre_solution_pr_publication",
            "timestamp": derived.cutoff_at,
            "publication_proven": True,
            "basis_sha256": hashlib.sha256(cutoff_basis_bytes).hexdigest(),
            "basis_bytes": len(cutoff_basis_bytes),
        },
        "selected_revision": {
            "provenance": "complete_issue_edit_history",
            "evidence_grade": "complete_history",
            "selected_at": derived.selected_at,
            "revision_sha256": derived.pre_redaction_sha256,
        },
        "temporal_provenance": {
            "status": "pre_fix_chronology_unproven",
            "issue_created_at": derived.issue_created_at,
            "selected_revision_at": derived.selected_at,
            "reason": PRIVATE_CHRONOLOGY_REASON,
        },
        "content": content,
        "comments_excluded": True,
        "redaction": {
            "policy": "fix_backlinks_v1",
            "policy_sha256": REDACTION_POLICY_SHA256,
            "target_sha256": derived.target_sha256,
            "count": derived.redaction_count,
            "pre_redaction_sha256": derived.pre_redaction_sha256,
            "post_redaction_sha256": derived.post_redaction_sha256,
            "forbidden_backlinks_remaining": 0,
            "oracle_material_detected": False,
        },
        "privacy_review": {
            "status": "approved",
            "reviewed_at": privacy_review.reviewed_at,
            "reviewer_id": privacy_review.reviewer_id,
            "checklist_sha256": privacy_review.checklist_sha256,
            "sensitive_material_excluded": True,
        },
    }


def produce_snapshot_receipt_file(
    *,
    identity: SnapshotIdentity,
    raw_issue_evidence_path: Path,
    cutoff_basis_path: Path,
    output_path: Path,
    producer: SnapshotProducerMetadata,
    privacy_review: SnapshotPrivacyReview,
) -> ProducedSnapshotReceipt:
    """Write and strictly round-trip one canonical offline snapshot receipt."""

    destination = Path(output_path)
    require_private_directory(destination.parent)
    raw_issue_evidence_bytes = _read_bounded_regular(
        raw_issue_evidence_path,
        MAX_RAW_RECEIPT_BYTES,
        "raw issue-history evidence",
    )
    cutoff_basis_bytes = _read_bounded_regular(
        cutoff_basis_path,
        MAX_CUTOFF_BASIS_BYTES,
        "solution publication basis",
    )
    receipt = produce_snapshot_receipt(
        identity=identity,
        raw_issue_evidence_bytes=raw_issue_evidence_bytes,
        cutoff_basis_bytes=cutoff_basis_bytes,
        producer=producer,
        privacy_review=privacy_review,
    )

    # Reject any internal producer/validator disagreement before creating an artifact.
    canonicalize_snapshot_receipt(
        receipt,
        raw_receipt_bytes=raw_issue_evidence_bytes,
        cutoff_basis_bytes=cutoff_basis_bytes,
        expected_case_id=identity.case_id,
        expected_repo=identity.repository,
        expected_issue_url=identity.issue_url,
        expected_base_sha=identity.base_sha,
    )

    receipt_bytes = _canonical_json_bytes(receipt) + b"\n"
    write_bytes_exclusive(destination, receipt_bytes)

    # The durable file, not the in-memory value, is the final trust boundary. This deliberately
    # uses the default strict path and independently parses and rederives both raw inputs again.
    try:
        projection = load_snapshot_receipt(
            destination,
            raw_receipt_path=Path(raw_issue_evidence_path),
            cutoff_basis_path=Path(cutoff_basis_path),
            expected_case_id=identity.case_id,
            expected_repo=identity.repository,
            expected_issue_url=identity.issue_url,
            expected_base_sha=identity.base_sha,
        )
        snapshot_sha256 = projection.get("snapshot_sha256")
        if not isinstance(snapshot_sha256, str) or _SHA256.fullmatch(snapshot_sha256) is None:
            raise _rejection("Strict receipt round-trip returned an invalid snapshot commitment.")
    except BaseException:
        # The path was exclusively created in a caller-verified private directory. Never leave a
        # durable artifact behind when its file-level strict round-trip did not complete.
        destination.unlink(missing_ok=True)
        raise
    return ProducedSnapshotReceipt(
        receipt_path=destination,
        receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        snapshot_sha256=snapshot_sha256,
    )


def verify_snapshot_receipt_derivation(
    receipt: Mapping[str, object],
    *,
    raw_issue_evidence_bytes: bytes,
    cutoff_basis_bytes: bytes,
) -> None:
    """Independently rederive every historical/content/redaction receipt claim."""

    identity = _object(receipt.get("identity"), "receipt identity")
    expected_repository = _text(identity.get("repo"), "receipt repository", 256)
    expected_issue_url = _text(identity.get("issue_url"), "receipt issue URL", 1024)
    issue_number = identity.get("issue_number")
    if isinstance(issue_number, bool) or not isinstance(issue_number, int) or issue_number < 1:
        raise _rejection("Receipt issue number is invalid.")

    derived = derive_snapshot(
        raw_issue_evidence_bytes=raw_issue_evidence_bytes,
        cutoff_basis_bytes=cutoff_basis_bytes,
        expected_repository=expected_repository,
        expected_issue_url=expected_issue_url,
        expected_issue_number=issue_number,
    )
    capture = _object(receipt.get("capture"), "receipt capture")
    api = _object(capture.get("api"), "receipt capture API")
    _require_exact(
        api,
        {
            "kind": "github_graphql",
            "version": GRAPHQL_API_VERSION,
            "request_sha256": ISSUE_HISTORY_QUERY_SHA256,
        },
        "capture API",
    )
    if capture.get("raw_receipt_sha256") != hashlib.sha256(
        raw_issue_evidence_bytes
    ).hexdigest() or capture.get("raw_receipt_bytes") != len(raw_issue_evidence_bytes):
        raise _rejection("Receipt capture does not bind the supplied raw issue evidence.")
    _require_exact(receipt.get("history"), _history_record(), "history derivation")
    _require_exact(
        receipt.get("cutoff"),
        {
            "policy": "pre_solution_pr_publication",
            "timestamp": derived.cutoff_at,
            "publication_proven": True,
            "basis_sha256": hashlib.sha256(cutoff_basis_bytes).hexdigest(),
            "basis_bytes": len(cutoff_basis_bytes),
        },
        "cutoff derivation",
    )
    _require_exact(
        receipt.get("selected_revision"),
        {
            "provenance": "complete_issue_edit_history",
            "evidence_grade": "complete_history",
            "selected_at": derived.selected_at,
            "revision_sha256": derived.pre_redaction_sha256,
        },
        "selected revision derivation",
    )
    _require_exact(
        receipt.get("temporal_provenance"),
        {
            "status": "pre_fix_chronology_unproven",
            "issue_created_at": derived.issue_created_at,
            "selected_revision_at": derived.selected_at,
            "reason": PRIVATE_CHRONOLOGY_REASON,
        },
        "temporal provenance derivation",
    )
    _require_exact(
        receipt.get("content"),
        _content_record(derived.sanitized_title, derived.sanitized_body),
        "content derivation",
    )
    _require_exact(
        receipt.get("redaction"),
        {
            "policy": "fix_backlinks_v1",
            "policy_sha256": REDACTION_POLICY_SHA256,
            "target_sha256": derived.target_sha256,
            "count": derived.redaction_count,
            "pre_redaction_sha256": derived.pre_redaction_sha256,
            "post_redaction_sha256": derived.post_redaction_sha256,
            "forbidden_backlinks_remaining": 0,
            "oracle_material_detected": False,
        },
        "redaction derivation",
    )


def derive_snapshot(
    *,
    raw_issue_evidence_bytes: bytes,
    cutoff_basis_bytes: bytes,
    expected_repository: str,
    expected_issue_url: str,
    expected_issue_number: int,
) -> DerivedSnapshot:
    """Derive one pre-publication issue revision from complete offline evidence."""

    issue_artifact = _decode_artifact(raw_issue_evidence_bytes, "issue history evidence")
    issue = _issue_from_artifact(
        issue_artifact,
        expected_repository=expected_repository,
        expected_issue_url=expected_issue_url,
        expected_issue_number=expected_issue_number,
    )
    cutoff_artifact = _decode_artifact(cutoff_basis_bytes, "solution publication basis")
    cutoff_at, cutoff_timestamp, target_sha256, target = _cutoff_from_artifact(
        cutoff_artifact, expected_repository=expected_repository
    )

    issue_created_at = _timestamp_text(issue.get("createdAt"), "issue creation time")
    issue_created_timestamp = _timestamp(issue_created_at, "issue creation time")
    if issue_created_timestamp >= cutoff_timestamp:
        raise _rejection("Issue creation does not precede solution PR publication.")

    body_revisions = _body_revisions(issue, issue_created_timestamp)
    title_revisions, initial_title = _title_revisions(issue, issue_created_timestamp)

    selected_body_revision = next(
        (revision for revision in body_revisions if revision.timestamp < cutoff_timestamp), None
    )
    if selected_body_revision is None:
        raise _rejection("No complete body revision precedes solution publication.")
    selected_title = initial_title
    selected_title_at = issue_created_timestamp
    selected_title_at_text = issue_created_at
    for revision in reversed(title_revisions):
        if revision.timestamp >= cutoff_timestamp:
            continue
        selected_title = revision.current_title
        selected_title_at = revision.timestamp
        selected_title_at_text = revision.created_at

    if selected_body_revision.timestamp >= selected_title_at:
        selected_at = selected_body_revision.edited_at
    else:
        selected_at = selected_title_at_text
    selected_body = selected_body_revision.body
    pre_redaction = canonical_snapshot_content_bytes(title=selected_title, body=selected_body)

    pattern = _target_pattern(expected_repository, target["number"])
    sanitized_title, title_count = pattern.subn(REDACTION_REPLACEMENT, selected_title)
    sanitized_body, body_count = pattern.subn(REDACTION_REPLACEMENT, selected_body)
    if pattern.search(sanitized_title) is not None or pattern.search(sanitized_body) is not None:
        raise _rejection("Fixing pull-request backlinks remain after redaction.")
    post_redaction = canonical_snapshot_content_bytes(title=sanitized_title, body=sanitized_body)
    return DerivedSnapshot(
        issue_created_at=issue_created_at,
        selected_at=selected_at,
        cutoff_at=cutoff_at,
        selected_title=selected_title,
        selected_body=selected_body,
        sanitized_title=sanitized_title,
        sanitized_body=sanitized_body,
        pre_redaction_sha256=hashlib.sha256(pre_redaction).hexdigest(),
        post_redaction_sha256=hashlib.sha256(post_redaction).hexdigest(),
        target_sha256=target_sha256,
        redaction_count=title_count + body_count,
    )


def _issue_from_artifact(
    artifact: Mapping[str, object],
    *,
    expected_repository: str,
    expected_issue_url: str,
    expected_issue_number: int,
) -> Mapping[str, object]:
    _require_keys(artifact, _ISSUE_ARTIFACT_KEYS, "issue history artifact")
    if artifact.get("format") != GRAPHQL_CAPTURE_FORMAT:
        raise _rejection("Issue history capture format is not trusted.")
    if artifact.get("query_sha256") != ISSUE_HISTORY_QUERY_SHA256:
        raise _rejection("Issue history query does not match the frozen producer query.")
    repository = _graphql_repository(artifact.get("response"), "issue history response")
    _require_keys(repository, _ISSUE_REPOSITORY_KEYS, "issue history repository")
    if repository.get("nameWithOwner") != expected_repository:
        raise _rejection("Issue history repository does not match the benchmark case.")
    issue = _exact_object(repository.get("issue"), _ISSUE_KEYS, "issue history issue")
    if (
        issue.get("number") != expected_issue_number
        or issue.get("url") != expected_issue_url
        or isinstance(issue.get("number"), bool)
    ):
        raise _rejection("Issue history identity does not match the benchmark case.")
    if issue.get("includesCreatedEdit") is not True:
        raise _rejection("GitHub did not include the issue creation revision.")
    _canonical_text(issue.get("title"), "current issue title", title=True)
    _canonical_text(issue.get("body"), "current issue body", title=False)
    return issue


def _cutoff_from_artifact(
    artifact: Mapping[str, object], *, expected_repository: str
) -> tuple[str, datetime, str, dict[str, object]]:
    _require_keys(artifact, _ISSUE_ARTIFACT_KEYS, "solution cutoff artifact")
    if artifact.get("format") != GRAPHQL_CAPTURE_FORMAT:
        raise _rejection("Solution cutoff capture format is not trusted.")
    if artifact.get("query_sha256") != SOLUTION_CUTOFF_QUERY_SHA256:
        raise _rejection("Solution cutoff query does not match the frozen producer query.")
    repository = _graphql_repository(artifact.get("response"), "solution cutoff response")
    _require_keys(repository, _CUTOFF_REPOSITORY_KEYS, "solution cutoff repository")
    if repository.get("nameWithOwner") != expected_repository:
        raise _rejection("Solution PR repository does not match the benchmark case.")
    pull = _exact_object(repository.get("pullRequest"), _PULL_REQUEST_KEYS, "solution pull request")
    number = pull.get("number")
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise _rejection("Solution pull-request number is invalid.")
    expected_url = f"https://github.com/{expected_repository}/pull/{number}"
    if pull.get("url") != expected_url:
        raise _rejection("Solution pull-request URL is not canonical.")
    base_repository = _exact_object(
        pull.get("baseRepository"), _BASE_REPOSITORY_KEYS, "solution base repository"
    )
    if base_repository.get("nameWithOwner") != expected_repository:
        raise _rejection("Solution pull request targets a different repository.")
    if pull.get("isDraft") is not False:
        raise _rejection("A draft pull request does not prove solution publication.")
    created_at = _timestamp_text(pull.get("createdAt"), "solution PR creation time")
    published_at = _timestamp_text(pull.get("publishedAt"), "solution PR publication time")
    created_timestamp = _timestamp(created_at, "solution PR creation time")
    published_timestamp = _timestamp(published_at, "solution PR publication time")
    if created_timestamp > published_timestamp:
        raise _rejection("Solution PR publication predates its creation.")
    merged_at = _timestamp_text(pull.get("mergedAt"), "solution PR merge time")
    if _timestamp(merged_at, "solution PR merge time") < published_timestamp:
        raise _rejection("Solution PR merge predates publication.")
    target: dict[str, object] = {
        "number": number,
        "repository": expected_repository,
        "url": expected_url,
    }
    target_sha256 = hashlib.sha256(
        json.dumps(target, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return published_at, published_timestamp, target_sha256, target


def _body_revisions(
    issue: Mapping[str, object], issue_created_timestamp: datetime
) -> tuple[_BodyRevision, ...]:
    connection = _complete_connection(issue.get("userContentEdits"), "body edit history")
    nodes = connection["nodes"]
    if not nodes:
        raise _rejection("Body history does not contain the creation revision.")
    revisions: list[_BodyRevision] = []
    seen_ids: set[str] = set()
    previous_timestamp: datetime | None = None
    for position, value in enumerate(nodes, start=1):
        node = _exact_object(value, _BODY_EDIT_KEYS, f"body edit {position}")
        _unique_node_id(node.get("id"), seen_ids, f"body edit {position}")
        if node.get("deletedAt") is not None:
            raise _rejection("Body edit history contains deleted evidence.")
        _timestamp_text(node.get("createdAt"), f"body edit {position} record time")
        edited_at = _timestamp_text(node.get("editedAt"), f"body edit {position} time")
        timestamp = _timestamp(edited_at, f"body edit {position} time")
        if timestamp < issue_created_timestamp:
            raise _rejection("Body edit predates issue creation.")
        if previous_timestamp is not None and timestamp >= previous_timestamp:
            raise _rejection("Body edits are not a strict newest-first history.")
        body = _canonical_text(node.get("diff"), f"body edit {position} content", title=False)
        revisions.append(_BodyRevision(edited_at=edited_at, timestamp=timestamp, body=body))
        previous_timestamp = timestamp
    if revisions[-1].timestamp != issue_created_timestamp:
        raise _rejection("Oldest body history node is not the issue creation revision.")
    current_body = _canonical_text(issue.get("body"), "current issue body", title=False)
    if revisions[0].body != current_body:
        raise _rejection("Newest body revision does not equal GitHub's current body.")
    last_edited_at = issue.get("lastEditedAt")
    if len(revisions) == 1:
        if last_edited_at is not None:
            raise _rejection("Unedited body history has a last-edited timestamp.")
    elif _timestamp_text(last_edited_at, "issue last-edited time") != revisions[0].edited_at:
        raise _rejection("Issue last-edited timestamp does not identify the newest body revision.")
    return tuple(revisions)


def _title_revisions(
    issue: Mapping[str, object], issue_created_timestamp: datetime
) -> tuple[tuple[_TitleRevision, ...], str]:
    connection = _complete_connection(issue.get("timelineItems"), "title rename history")
    nodes = connection["nodes"]
    revisions: list[_TitleRevision] = []
    seen_ids: set[str] = set()
    for position, value in enumerate(nodes, start=1):
        node = _exact_object(value, _TITLE_EDIT_KEYS, f"title rename {position}")
        if node.get("__typename") != "RenamedTitleEvent":
            raise _rejection("Title history contains a non-rename node.")
        _unique_node_id(node.get("id"), seen_ids, f"title rename {position}")
        created_at = _timestamp_text(node.get("createdAt"), f"title rename {position} time")
        timestamp = _timestamp(created_at, f"title rename {position} time")
        if timestamp < issue_created_timestamp:
            raise _rejection("Title rename predates issue creation.")
        current_title = _canonical_text(
            node.get("currentTitle"), f"title rename {position} current title", title=True
        )
        previous_title = _canonical_text(
            node.get("previousTitle"), f"title rename {position} previous title", title=True
        )
        revisions.append(
            _TitleRevision(
                created_at=created_at,
                timestamp=timestamp,
                previous_title=previous_title,
                current_title=current_title,
            )
        )
    chronological = sorted(revisions, key=lambda revision: revision.timestamp)
    if len({revision.timestamp for revision in chronological}) != len(chronological):
        raise _rejection("Title rename timestamps are ambiguous.")
    current_title = _canonical_text(issue.get("title"), "current issue title", title=True)
    initial_title = chronological[0].previous_title if chronological else current_title
    expected_previous = initial_title
    for revision in chronological:
        if revision.previous_title != expected_previous:
            raise _rejection("Title rename history is not a continuous chain.")
        expected_previous = revision.current_title
    if expected_previous != current_title:
        raise _rejection("Title rename chain does not reach GitHub's current title.")
    return tuple(reversed(chronological)), initial_title


def _complete_connection(value: object, label: str) -> dict[str, Any]:
    connection = _exact_object(value, _CONNECTION_KEYS, label)
    total = connection.get("totalCount")
    nodes = connection.get("nodes")
    if (
        isinstance(total, bool)
        or not isinstance(total, int)
        or total < 0
        or total > MAX_HISTORY_ITEMS
        or not isinstance(nodes, list)
        or len(nodes) != total
    ):
        raise _rejection(f"{label} count is incomplete or out of bounds.")
    page = _exact_object(connection.get("pageInfo"), _PAGE_INFO_KEYS, f"{label} pagination")
    if page.get("hasNextPage") is not False or page.get("hasPreviousPage") is not False:
        raise _rejection(f"{label} is not fully paginated.")
    for cursor_name in ("startCursor", "endCursor"):
        cursor = page.get(cursor_name)
        if cursor is not None:
            _text(cursor, f"{label} {cursor_name}", MAX_NODE_ID_CHARS)
    return {"totalCount": total, "nodes": nodes}


def _graphql_repository(value: object, label: str) -> Mapping[str, object]:
    response = _exact_object(value, _RESPONSE_KEYS, label)
    data = _exact_object(response.get("data"), _DATA_KEYS, f"{label} data")
    return _object(data.get("repository"), f"{label} repository")


def _target_pattern(repository: str, number: object) -> re.Pattern[str]:
    if not isinstance(number, int):
        raise _rejection("Redaction target number is invalid.")
    owner, repo = (re.escape(part) for part in repository.split("/", 1))
    target = str(number)
    full_url = rf"https://github\.com/{owner}/{repo}/pull/{target}(?:[/?#][^\s)\]>]*)?"
    qualified_pull = rf"{owner}/{repo}/pull/{target}(?![0-9])"
    qualified_hash = rf"{owner}/{repo}#{target}(?![0-9])"
    bare_hash = rf"(?<![A-Za-z0-9_/#])#{target}(?![0-9])"
    return re.compile(
        rf"(?:{full_url}|{qualified_pull}|{qualified_hash}|{bare_hash})", re.IGNORECASE
    )


def _content_record(title: str, body: str) -> dict[str, object]:
    title_bytes = title.encode()
    body_bytes = body.encode()
    canonical = canonical_snapshot_content_bytes(title=title, body=body)
    return {
        "encoding": "utf-8",
        "canonicalization": "nfc_lf_v1",
        "title": title,
        "body": body,
        "title_bytes": len(title_bytes),
        "body_bytes": len(body_bytes),
        "canonical_bytes": len(canonical),
        "title_sha256": hashlib.sha256(title_bytes).hexdigest(),
        "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
        "snapshot_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def _history_record() -> dict[str, object]:
    return {
        "complete": True,
        "current_live_only": False,
        "body_edits_complete": True,
        "title_edits_complete": True,
        "creation_revision_included": True,
        "deleted_edits_present": False,
    }


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _rejection("Snapshot receipt cannot be represented as canonical JSON.") from exc


def _read_bounded_regular(path: Path, limit: int, label: str) -> bytes:
    with open_regular_file(Path(path)) as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise _rejection(f"{label} exceeds its byte limit.")
    return content


def _decode_artifact(content: bytes, label: str) -> Mapping[str, object]:
    try:
        decoded = json.loads(
            content,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _rejection(f"{label} is not strict UTF-8 JSON.") from exc
    return _object(decoded, label)


def _canonical_text(value: object, label: str, *, title: bool) -> str:
    if not isinstance(value, str):
        raise _rejection(f"{label} is not bounded text.")
    try:
        encoded = value.encode()
    except UnicodeEncodeError as exc:
        raise _rejection(f"{label} is not valid UTF-8 text.") from exc
    if len(encoded) > MAX_RAW_TEXT_BYTES:
        raise _rejection(f"{label} is not bounded text.")
    text = value
    canonical = unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n"))
    if title and (not canonical or "\n" in canonical or "\t" in canonical):
        raise _rejection(f"{label} is not a non-empty one-line title.")
    limit = 4 * 1024 if title else MAX_RAW_TEXT_BYTES
    if len(canonical.encode()) > limit:
        raise _rejection(f"{label} exceeds its canonical byte limit.")
    for character in canonical:
        if character in {"\n", "\t"}:
            continue
        if unicodedata.category(character) in {"Cc", "Cf"}:
            raise _rejection(f"{label} contains a forbidden control character.")
    return canonical


def _timestamp_text(value: object, label: str) -> str:
    text = _text(value, label, 40)
    _timestamp(text, label)
    return text


def _timestamp(value: str, label: str) -> datetime:
    if (
        re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z",
            value,
        )
        is None
    ):
        raise _rejection(f"{label} is not an RFC 3339 UTC timestamp.")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _rejection(f"{label} is not a real timestamp.") from exc
    if parsed.utcoffset() is None:
        raise _rejection(f"{label} has no UTC offset.")
    return parsed


def _unique_node_id(value: object, seen: set[str], label: str) -> None:
    identifier = _text(value, f"{label} ID", MAX_NODE_ID_CHARS)
    if identifier in seen:
        raise _rejection(f"{label} ID is duplicated.")
    seen.add(identifier)


def _text(value: object, label: str, max_bytes: int) -> str:
    if not isinstance(value, str) or not value:
        raise _rejection(f"{label} is not bounded text.")
    try:
        encoded = value.encode()
    except UnicodeEncodeError as exc:
        raise _rejection(f"{label} is not valid UTF-8 text.") from exc
    if len(encoded) > max_bytes:
        raise _rejection(f"{label} is not bounded text.")
    return value


def _ascii_identifier(value: str, label: str, pattern: re.Pattern[str]) -> None:
    if not value.isascii() or pattern.fullmatch(value) is None:
        raise _rejection(f"{label} is invalid.")


def _object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise _rejection(f"{label} must be an object.")
    return cast(Mapping[str, object], value)


def _exact_object(value: object, keys: set[str], label: str) -> Mapping[str, object]:
    result = _object(value, label)
    _require_keys(result, keys, label)
    return result


def _require_keys(value: Mapping[str, object], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise _rejection(f"{label} fields do not match the frozen evidence contract.")


def _require_exact(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise _rejection(f"Receipt {label} does not match independent evidence derivation.")


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
    return PolicyRejection("benchmark_snapshot_evidence", message)
