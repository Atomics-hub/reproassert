from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reproassert.candidate import ValidatedCandidate, validate_candidate_payload
from reproassert.errors import PolicyRejection
from reproassert.intake import GitHubIssueLocation, parse_issue_url
from reproassert.safeio import sha256_bytes, write_text_exclusive

REPORT_SCHEMA_VERSION = "1.1"
SUPPORTED_REPORT_SCHEMA_VERSIONS = {"1.0", REPORT_SCHEMA_VERSION}
MAX_REPORT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ReplaySpec:
    issue: GitHubIssueLocation
    issue_title: str
    issue_body_sha256: str
    source_sha: str
    archive_sha256: str
    tree_sha256: str | None
    git_tree_oid: str | None
    executed_tree_sha256: str | None
    candidate: ValidatedCandidate
    candidate_sha256: str
    repeats: int


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    encoded = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if len(encoded.encode("utf-8")) > MAX_REPORT_BYTES:
        raise PolicyRejection("report_too_large", "Report exceeds the 1 MiB limit.")
    write_text_exclusive(path, encoded)


def load_replay_spec(report_path: Path) -> ReplaySpec:
    data = _read_regular_bounded(report_path, MAX_REPORT_BYTES)
    try:
        report = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PolicyRejection("invalid_report", "Replay report is not valid JSON.") from exc
    if (
        not isinstance(report, dict)
        or report.get("schema_version") not in SUPPORTED_REPORT_SCHEMA_VERSIONS
    ):
        raise PolicyRejection("invalid_report", "Unsupported report schema.")
    schema_version = report["schema_version"]

    issue_data = _mapping(report.get("issue"), "issue")
    source_data = _mapping(report.get("source"), "source")
    candidate_data = _mapping(report.get("candidate"), "candidate")
    policy_data = _mapping(report.get("policy"), "policy")
    issue = parse_issue_url(_text(issue_data.get("url"), "issue.url"))
    issue_title = _text(issue_data.get("title"), "issue.title")
    if len(issue_title) > 4_096:
        raise PolicyRejection("invalid_report", "issue.title is too long.")
    issue_body_sha256 = _text(issue_data.get("body_sha256"), "issue.body_sha256")
    if len(issue_body_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in issue_body_sha256
    ):
        raise PolicyRejection("invalid_report", "issue.body_sha256 is not a SHA-256 digest.")
    sha = _text(source_data.get("sha"), "source.sha").lower()
    if len(sha) != 40 or any(character not in "0123456789abcdef" for character in sha):
        raise PolicyRejection("invalid_report", "source.sha is not a full commit SHA.")
    repository_url = _text(source_data.get("repository_url"), "source.repository_url")
    if repository_url != issue.repository_url:
        raise PolicyRejection("invalid_report", "Issue and source repository do not match.")
    archive_sha256 = _sha256(source_data.get("archive_sha256"), "source.archive_sha256")
    tree_value = source_data.get("tree_sha256")
    git_tree_value = source_data.get("git_tree_oid")
    executed_tree_value = source_data.get("executed_tree_sha256")
    if tree_value is None and git_tree_value is None:
        tree_sha256 = None
        git_tree_oid = None
    elif tree_value is None or git_tree_value is None:
        raise PolicyRejection("invalid_report", "Source tree attestation fields are incomplete.")
    else:
        tree_sha256 = _sha256(tree_value, "source.tree_sha256")
        git_tree_oid = _sha1(git_tree_value, "source.git_tree_oid")
        if source_data.get("tree_attestation_algorithm") != "reproassert-source-tree-v1":
            raise PolicyRejection("invalid_report", "Source tree attestation algorithm is invalid.")
    executed_tree_sha256 = (
        None
        if executed_tree_value is None
        else _sha256(executed_tree_value, "source.executed_tree_sha256")
    )
    if schema_version == REPORT_SCHEMA_VERSION and executed_tree_sha256 is None:
        raise PolicyRejection(
            "invalid_report", "Report 1.1 requires candidate-applied executed-tree evidence."
        )

    payload = {
        "test_content": _text(candidate_data.get("test_content"), "candidate.test_content"),
        "expected_symptom": _text(
            candidate_data.get("expected_symptom"), "candidate.expected_symptom"
        ),
        "rationale": _text(candidate_data.get("rationale"), "candidate.rationale"),
    }
    candidate = validate_candidate_payload(payload, issue_number=issue.number)
    recorded_hash = _text(candidate_data.get("test_content_sha256"), "candidate hash")
    if recorded_hash != candidate.sha256:
        raise PolicyRejection("invalid_report", "Candidate content hash does not match.")
    repeats = policy_data.get("repeats")
    if not isinstance(repeats, int) or isinstance(repeats, bool) or repeats < 2 or repeats > 10:
        raise PolicyRejection("invalid_report", "Replay repeat count is outside policy.")
    return ReplaySpec(
        issue,
        issue_title,
        issue_body_sha256,
        sha,
        archive_sha256,
        tree_sha256,
        git_tree_oid,
        executed_tree_sha256,
        candidate,
        recorded_hash,
        repeats,
    )


def report_sha256(report: Mapping[str, Any]) -> str:
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256_bytes(encoded.encode("utf-8"))


def _read_regular_bounded(path: Path, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise PolicyRejection("invalid_report", "Report is not a bounded regular file.")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return stream.read(max_bytes + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise PolicyRejection("invalid_report", f"{name} must be an object.")
    return value


def _text(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise PolicyRejection("invalid_report", f"{name} must be text.")
    return value


def _sha256(value: object, name: str) -> str:
    text = _text(value, name)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise PolicyRejection("invalid_report", f"{name} is not a SHA-256 digest.")
    return text


def _sha1(value: object, name: str) -> str:
    text = _text(value, name)
    if len(text) != 40 or any(character not in "0123456789abcdef" for character in text):
        raise PolicyRejection("invalid_report", f"{name} is not a Git object ID.")
    return text
