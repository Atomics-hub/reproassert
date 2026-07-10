from __future__ import annotations

import json
from pathlib import Path

import pytest

from reproassert.errors import PolicyRejection
from reproassert.report import load_replay_spec, write_report


def valid_report() -> dict[str, object]:
    content = (
        "from fixture_project import normalize\n\n"
        "def test_issue_7_reproduction():\n"
        "    assert normalize('a--b') == 'a-b', 'duplicate separators remain'\n"
    )
    import hashlib

    return {
        "schema_version": "1.0",
        "issue": {
            "url": "https://github.com/owner/repo/issues/7",
            "title": "Duplicate separators",
            "body_sha256": "b" * 64,
        },
        "source": {
            "repository_url": "https://github.com/owner/repo",
            "sha": "a" * 40,
            "archive_sha256": "c" * 64,
        },
        "candidate": {
            "test_content": content,
            "test_content_sha256": hashlib.sha256(content.encode()).hexdigest(),
            "expected_symptom": "duplicate separators remain",
            "rationale": "One assertion encodes the symptom.",
        },
        "policy": {"repeats": 3},
        "replay": {"display_command": "touch /tmp/never-run"},
    }


def test_replay_parses_data_but_ignores_command_fields(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    write_report(path, valid_report())

    spec = load_replay_spec(path)

    assert spec.issue.repo == "repo"
    assert spec.issue_title == "Duplicate separators"
    assert spec.issue_body_sha256 == "b" * 64
    assert spec.archive_sha256 == "c" * 64
    assert spec.tree_sha256 is None
    assert spec.repeats == 3
    assert spec.candidate.test_function == "test_issue_7_reproduction"


def test_replay_rejects_mismatched_repository(tmp_path: Path) -> None:
    report = valid_report()
    source = report["source"]
    assert isinstance(source, dict)
    source["repository_url"] = "https://github.com/other/repo"
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))

    with pytest.raises(PolicyRejection):
        load_replay_spec(path)


def test_replay_parses_complete_tree_attestation_and_rejects_partial_fields(
    tmp_path: Path,
) -> None:
    report = valid_report()
    source = report["source"]
    assert isinstance(source, dict)
    source.update(
        tree_attestation_algorithm="reproassert-source-tree-v1",
        tree_sha256="d" * 64,
        git_tree_oid="e" * 40,
    )
    path = tmp_path / "attested.json"
    write_report(path, report)

    spec = load_replay_spec(path)
    assert spec.tree_sha256 == "d" * 64
    assert spec.git_tree_oid == "e" * 40

    partial = valid_report()
    partial_source = partial["source"]
    assert isinstance(partial_source, dict)
    partial_source["tree_sha256"] = "d" * 64
    partial_path = tmp_path / "partial.json"
    write_report(partial_path, partial)
    with pytest.raises(PolicyRejection, match="incomplete"):
        load_replay_spec(partial_path)


def test_report_writer_refuses_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    write_report(path, valid_report())
    with pytest.raises(PolicyRejection):
        write_report(path, valid_report())


def test_replay_rejects_deeply_nested_json_as_a_policy_error(tmp_path: Path) -> None:
    path = tmp_path / "deep.json"
    path.write_text("[" * 2_000 + "0" + "]" * 2_000)

    with pytest.raises(PolicyRejection) as rejected:
        load_replay_spec(path)

    assert rejected.value.code == "invalid_report"
