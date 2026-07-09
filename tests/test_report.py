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


def test_report_writer_refuses_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    write_report(path, valid_report())
    with pytest.raises(PolicyRejection):
        write_report(path, valid_report())
