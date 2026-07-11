from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from reproassert.candidate import MAX_TEST_BYTES, ValidatedCandidate, validate_candidate_payload
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_exclusive_file, open_regular_file
from reproassert.source_attestation import (
    ExpectedGitSpecialEntry,
    SourceTreeAttestation,
    attest_source_tree,
)

_CANDIDATE_NAME = re.compile(r"test_issue_([1-9][0-9]*)\.py")


@dataclass(frozen=True)
class PreparedCandidateWorkspace:
    path: Path
    pristine_tree: SourceTreeAttestation
    candidate_applied_tree: SourceTreeAttestation
    candidate_sha256: str


def prepare_candidate_workspace(
    *,
    source: Path,
    destination: Path,
    relative_path: str,
    candidate: ValidatedCandidate,
    expected_pristine: SourceTreeAttestation,
    expected_special_entries: tuple[ExpectedGitSpecialEntry, ...] = (),
) -> PreparedCandidateWorkspace:
    """Build ``expected pristine tree + exactly one revalidated candidate`` privately."""

    candidate_path, issue_number = _candidate_path(relative_path, candidate.test_function)
    revalidated = validate_candidate_payload(
        {
            "test_content": candidate.test_content,
            "expected_symptom": candidate.expected_symptom,
            "rationale": candidate.rationale,
        },
        issue_number=issue_number,
    )
    if revalidated != candidate:
        raise PolicyRejection(
            "candidate_workspace_policy", "Candidate differs from strict policy revalidation."
        )
    observed = attest_source_tree(
        source,
        expected_git_tree_oid=expected_pristine.expected_git_tree_oid,
        expected_special_entries=expected_special_entries,
    )
    if observed != expected_pristine:
        raise PolicyRejection(
            "candidate_workspace_source_changed",
            "Source tree differs from the exact pristine controller attestation.",
        )
    _require_reserved_directory_absent(source, candidate_path)
    try:
        shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2)
    except OSError as exc:
        raise PolicyRejection(
            "candidate_workspace_copy", "Unable to create a private candidate workspace."
        ) from exc
    copied = attest_source_tree(
        destination,
        expected_git_tree_oid=expected_pristine.expected_git_tree_oid,
        expected_special_entries=expected_special_entries,
    )
    if copied != expected_pristine:
        raise PolicyRejection(
            "candidate_workspace_source_changed", "Source tree changed while it was copied."
        )
    _require_reserved_directory_absent(destination, candidate_path)
    target = destination.joinpath(*candidate_path.parts)
    target.parent.mkdir(parents=True, mode=0o700)
    content = candidate.test_content.encode("utf-8")
    with open_exclusive_file(target) as stream:
        stream.write(content)
    _require_exact_candidate(target, content)
    _require_single_candidate_artifact(destination, candidate_path)
    applied = attest_source_tree(destination, expected_special_entries=expected_special_entries)
    _require_exact_candidate(target, content)
    return PreparedCandidateWorkspace(
        path=destination,
        pristine_tree=copied,
        candidate_applied_tree=applied,
        candidate_sha256=candidate.sha256,
    )


def _candidate_path(value: str, test_function: str) -> tuple[PurePosixPath, int]:
    path = PurePosixPath(value)
    match = _CANDIDATE_NAME.fullmatch(path.name)
    if (
        path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
        or "\\" in value
        or len(path.parts) != 3
        or path.parts[:2] != ("tests", "reproassert")
        or match is None
    ):
        raise PolicyRejection(
            "candidate_workspace_path", "Candidate path is outside the reserved test tree."
        )
    issue_number = int(match.group(1))
    if test_function != f"test_issue_{issue_number}_reproduction":
        raise PolicyRejection(
            "candidate_workspace_path", "Candidate path and test function do not match."
        )
    return path, issue_number


def _require_reserved_directory_absent(root: Path, candidate_path: PurePosixPath) -> None:
    reserved = root.joinpath(*candidate_path.parent.parts)
    if os.path.lexists(reserved):
        raise PolicyRejection(
            "candidate_workspace_reserved_path",
            "Pristine source already contains the reserved candidate directory.",
        )


def _require_exact_candidate(path: Path, expected: bytes) -> None:
    with open_regular_file(path) as stream:
        metadata = os.fstat(stream.fileno())
        content = stream.read(MAX_TEST_BYTES + 1)
    if metadata.st_nlink != 1 or content != expected:
        raise PolicyRejection(
            "candidate_workspace_candidate_changed", "Candidate bytes changed in the workspace."
        )


def _require_single_candidate_artifact(root: Path, candidate_path: PurePosixPath) -> None:
    directory = root.joinpath(*candidate_path.parent.parts)
    try:
        entries = list(directory.iterdir())
    except OSError as exc:
        raise PolicyRejection(
            "candidate_workspace_candidate_changed", "Candidate directory is unavailable."
        ) from exc
    if len(entries) != 1 or entries[0].name != candidate_path.name:
        raise PolicyRejection(
            "candidate_workspace_candidate_changed",
            "Candidate directory must contain exactly the submitted test.",
        )
