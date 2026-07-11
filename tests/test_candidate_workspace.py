from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

import pytest

from reproassert.candidate import ValidatedCandidate, validate_candidate_payload
from reproassert.candidate_workspace import prepare_candidate_workspace
from reproassert.errors import PolicyRejection
from reproassert.source_attestation import ExpectedGitSpecialEntry, attest_source_tree


def _candidate() -> ValidatedCandidate:
    return validate_candidate_payload(
        {
            "test_content": (
                "from example_project import normalize\n\n"
                "def test_issue_4_reproduction():\n"
                "    assert normalize('a--b') == 'a-b', 'duplicate separators remain'\n"
            ),
            "expected_symptom": "duplicate separators remain",
            "rationale": "Exercises the public normalization behavior.",
        },
        issue_number=4,
    )


def _source(root: Path) -> Path:
    source = root / "source"
    source.mkdir()
    (source / "example_project.py").write_text("def normalize(value):\n    return value\n")
    return source


def _blob_oid(content: bytes) -> str:
    digest = hashlib.sha1(f"blob {len(content)}\0".encode(), usedforsecurity=False)
    digest.update(content)
    return digest.hexdigest()


def test_builds_exact_pristine_plus_candidate_without_mutating_source(tmp_path: Path) -> None:
    source = _source(tmp_path)
    pristine = attest_source_tree(source)
    candidate = _candidate()

    prepared = prepare_candidate_workspace(
        source=source,
        destination=tmp_path / "prepared",
        relative_path="tests/reproassert/test_issue_4.py",
        candidate=candidate,
        expected_pristine=pristine,
    )

    assert attest_source_tree(source) == pristine
    assert prepared.pristine_tree == pristine
    assert prepared.candidate_sha256 == candidate.sha256
    assert prepared.candidate_applied_tree != pristine
    assert (
        prepared.path / "tests" / "reproassert" / "test_issue_4.py"
    ).read_text() == candidate.test_content


def test_builds_candidate_workspace_with_plan_bound_special_entries(tmp_path: Path) -> None:
    source = _source(tmp_path)
    target = "example_project.py"
    os.symlink(target, source / "module-link")
    (source / "vendor").mkdir()
    specials = (
        ExpectedGitSpecialEntry("module-link", "120000", _blob_oid(target.encode()), target),
        ExpectedGitSpecialEntry("vendor", "160000", "1" * 40),
    )
    pristine = attest_source_tree(source, expected_special_entries=specials)

    prepared = prepare_candidate_workspace(
        source=source,
        destination=tmp_path / "prepared-special",
        relative_path="tests/reproassert/test_issue_4.py",
        candidate=_candidate(),
        expected_pristine=pristine,
        expected_special_entries=specials,
    )

    assert os.readlink(prepared.path / "module-link") == target
    assert not any((prepared.path / "vendor").iterdir())
    assert prepared.candidate_applied_tree.algorithm.endswith("special-v1")


def test_rejects_forged_candidate_dataclass_before_copy(tmp_path: Path) -> None:
    source = _source(tmp_path)
    forged = ValidatedCandidate(
        test_content="def test_issue_4_reproduction():\n    assert False\n",
        test_function="test_issue_4_reproduction",
        expected_symptom="duplicate separators remain",
        rationale="forged",
    )

    with pytest.raises(PolicyRejection):
        prepare_candidate_workspace(
            source=source,
            destination=tmp_path / "prepared",
            relative_path="tests/reproassert/test_issue_4.py",
            candidate=forged,
            expected_pristine=attest_source_tree(source),
        )

    assert not (tmp_path / "prepared").exists()


def test_rejects_reserved_candidate_directory_in_pristine_source(tmp_path: Path) -> None:
    source = _source(tmp_path)
    (source / "tests" / "reproassert").mkdir(parents=True)
    pristine = attest_source_tree(source)

    with pytest.raises(PolicyRejection, match="reserved candidate directory"):
        prepare_candidate_workspace(
            source=source,
            destination=tmp_path / "prepared",
            relative_path="tests/reproassert/test_issue_4.py",
            candidate=_candidate(),
            expected_pristine=pristine,
        )


def test_rejects_source_drift_during_private_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _source(tmp_path)
    pristine = attest_source_tree(source)
    real_copytree = shutil.copytree

    def drifting_copy(source_path: Path, destination: Path, **kwargs: object) -> Path:
        copied = real_copytree(source_path, destination, **kwargs)  # type: ignore[arg-type]
        (copied / "example_project.py").write_text("VALUE = 'drifted'\n")
        return copied

    monkeypatch.setattr(shutil, "copytree", drifting_copy)

    with pytest.raises(PolicyRejection, match="changed while it was copied"):
        prepare_candidate_workspace(
            source=source,
            destination=tmp_path / "prepared",
            relative_path="tests/reproassert/test_issue_4.py",
            candidate=_candidate(),
            expected_pristine=pristine,
        )
