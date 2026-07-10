from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

import reproassert.benchmark_snapshot_producer as snapshot_producer
from reproassert.benchmark_snapshot import MAX_RAW_RECEIPT_BYTES, load_snapshot_receipt
from reproassert.benchmark_snapshot_producer import (
    GRAPHQL_CAPTURE_FORMAT,
    ISSUE_HISTORY_QUERY_SHA256,
    SOLUTION_CUTOFF_QUERY_SHA256,
)
from reproassert.cli import main
from reproassert.errors import PolicyRejection

CASE_ID = "rk-v0.2-004"
REPOSITORY = "owner/repo"
ISSUE_URL = "https://github.com/owner/repo/issues/7"
BASE_SHA = "a" * 40
TITLE = "Duplicate separators survive normalization"
BODY = "normalize('a--b') still returns a--b; see #9."
CREATED_AT = "2024-01-01T00:00:00Z"
CUTOFF_AT = "2024-03-01T00:00:00Z"


def _page(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "totalCount": len(nodes),
        "pageInfo": {
            "hasNextPage": False,
            "hasPreviousPage": False,
            "startCursor": "start" if nodes else None,
            "endCursor": "end" if nodes else None,
        },
        "nodes": nodes,
    }


def _issue_artifact() -> dict[str, Any]:
    return {
        "format": GRAPHQL_CAPTURE_FORMAT,
        "query_sha256": ISSUE_HISTORY_QUERY_SHA256,
        "response": {
            "data": {
                "repository": {
                    "nameWithOwner": REPOSITORY,
                    "issue": {
                        "number": 7,
                        "url": ISSUE_URL,
                        "title": TITLE,
                        "body": BODY,
                        "createdAt": CREATED_AT,
                        "lastEditedAt": None,
                        "includesCreatedEdit": True,
                        "userContentEdits": _page(
                            [
                                {
                                    "id": "creation",
                                    "createdAt": CREATED_AT,
                                    "editedAt": CREATED_AT,
                                    "deletedAt": None,
                                    "diff": BODY,
                                }
                            ]
                        ),
                        "timelineItems": _page([]),
                    },
                }
            }
        },
    }


def _cutoff_artifact() -> dict[str, Any]:
    return {
        "format": GRAPHQL_CAPTURE_FORMAT,
        "query_sha256": SOLUTION_CUTOFF_QUERY_SHA256,
        "response": {
            "data": {
                "repository": {
                    "nameWithOwner": REPOSITORY,
                    "pullRequest": {
                        "number": 9,
                        "url": "https://github.com/owner/repo/pull/9",
                        "createdAt": "2024-02-25T00:00:00Z",
                        "publishedAt": CUTOFF_AT,
                        "mergedAt": "2024-03-02T00:00:00Z",
                        "isDraft": False,
                        "baseRepository": {"nameWithOwner": REPOSITORY},
                    },
                }
            }
        },
    }


def _write_evidence(tmp_path: Path) -> tuple[Path, Path]:
    raw = tmp_path / "issue-history.json"
    cutoff = tmp_path / "cutoff-basis.json"
    raw.write_text(json.dumps(_issue_artifact()))
    cutoff.write_text(json.dumps(_cutoff_artifact()))
    return raw, cutoff


def _arguments(raw: Path, cutoff: Path, output: Path) -> list[str]:
    return [
        "benchmark",
        "produce-snapshot",
        CASE_ID,
        "--repository",
        REPOSITORY,
        "--issue-url",
        ISSUE_URL,
        "--base-sha",
        BASE_SHA,
        "--raw-history",
        str(raw),
        "--cutoff-basis",
        str(cutoff),
        "--captured-at",
        "2026-07-10T12:00:00Z",
        "--tool-name",
        "snapshot-capture-v1",
        "--tool-version",
        "1.0.0",
        "--tool-git-sha",
        "b" * 40,
        "--privacy-reviewed-at",
        "2026-07-10T13:00:00Z",
        "--privacy-reviewer-id",
        "reviewer-001",
        "--privacy-checklist-sha256",
        "c" * 64,
        "--output",
        str(output),
    ]


def test_produce_snapshot_writes_canonical_exclusive_receipt_and_strictly_round_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, cutoff = _write_evidence(tmp_path)
    output = tmp_path / "private" / "benchmark-snapshot-receipt.json"
    original_load = load_snapshot_receipt
    calls: list[dict[str, object]] = []

    def strict_load(*args: object, **kwargs: object) -> dict[str, str]:
        assert "allow_unverified_producer" not in kwargs
        calls.append(dict(kwargs))
        return original_load(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(snapshot_producer, "load_snapshot_receipt", strict_load)

    result = CliRunner().invoke(main, _arguments(raw, cutoff, output))

    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    payload = json.loads(result.output)
    assert payload == {
        "campaign_readiness_changed": False,
        "case_id": CASE_ID,
        "derivation_reverified": True,
        "offline_only": True,
        "receipt": str(output),
        "receipt_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "snapshot_sha256": json.loads(output.read_text())["content"]["snapshot_sha256"],
    }
    receipt = json.loads(output.read_text())
    canonical = (
        json.dumps(
            receipt,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    assert output.read_bytes() == canonical
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert stat.S_IMODE(output.parent.stat().st_mode) == 0o700
    assert "[fix reference removed]" in receipt["content"]["body"]
    for evaluator_only_value in (BODY, "https://github.com/owner/repo/pull/9", "creation"):
        assert evaluator_only_value not in result.output


def test_produce_snapshot_refuses_to_overwrite_an_existing_receipt(tmp_path: Path) -> None:
    raw, cutoff = _write_evidence(tmp_path)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    output = private / "receipt.json"
    output.write_text("owner data")

    result = CliRunner().invoke(main, _arguments(raw, cutoff, output))

    assert result.exit_code == 1
    assert "Refusing to overwrite" in result.output
    assert output.read_text() == "owner data"


def test_produce_snapshot_rejects_non_private_output_directory(tmp_path: Path) -> None:
    raw, cutoff = _write_evidence(tmp_path)
    output_parent = tmp_path / "shared"
    output_parent.mkdir()
    output_parent.chmod(0o755)
    output = output_parent / "receipt.json"

    result = CliRunner().invoke(main, _arguments(raw, cutoff, output))

    assert result.exit_code == 1
    assert "mode 0700" in result.output
    assert not output.exists()


@pytest.mark.parametrize("input_name", ["raw", "cutoff"])
def test_produce_snapshot_rejects_symlinked_evaluator_input(
    tmp_path: Path, input_name: str
) -> None:
    raw, cutoff = _write_evidence(tmp_path)
    target = raw if input_name == "raw" else cutoff
    link = tmp_path / f"{input_name}-link.json"
    link.symlink_to(target)
    output = tmp_path / "private" / "receipt.json"
    arguments = _arguments(
        link if input_name == "raw" else raw, link if input_name == "cutoff" else cutoff, output
    )

    result = CliRunner().invoke(main, arguments)

    assert result.exit_code == 1
    assert "unsafe_input_path" in result.output
    assert not output.exists()


def test_produce_snapshot_rejects_oversized_raw_evidence_before_output(tmp_path: Path) -> None:
    raw, cutoff = _write_evidence(tmp_path)
    raw.write_bytes(b" " * (MAX_RAW_RECEIPT_BYTES + 1))
    output = tmp_path / "private" / "receipt.json"

    result = CliRunner().invoke(main, _arguments(raw, cutoff, output))

    assert result.exit_code == 1
    assert "exceeds its byte limit" in result.output
    assert not output.exists()


def test_produce_snapshot_rejects_unverifiable_history_without_partial_receipt(
    tmp_path: Path,
) -> None:
    raw, cutoff = _write_evidence(tmp_path)
    artifact = _issue_artifact()
    artifact["response"]["data"]["repository"]["issue"]["includesCreatedEdit"] = False
    raw.write_text(json.dumps(artifact))
    output = tmp_path / "private" / "receipt.json"

    result = CliRunner().invoke(main, _arguments(raw, cutoff, output))

    assert result.exit_code == 1
    assert "did not include the issue creation revision" in result.output
    assert not output.exists()


def test_produce_snapshot_removes_receipt_when_file_round_trip_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, cutoff = _write_evidence(tmp_path)
    output = tmp_path / "private" / "receipt.json"

    def reject_round_trip(*_args: object, **_kwargs: object) -> dict[str, str]:
        raise PolicyRejection("round_trip_test", "strict round-trip rejected")

    monkeypatch.setattr(snapshot_producer, "load_snapshot_receipt", reject_round_trip)

    result = CliRunner().invoke(main, _arguments(raw, cutoff, output))

    assert result.exit_code == 1
    assert "strict round-trip rejected" in result.output
    assert not output.exists()


def test_produce_snapshot_removes_receipt_when_post_write_commitment_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, cutoff = _write_evidence(tmp_path)
    output = tmp_path / "private" / "receipt.json"
    monkeypatch.setattr(
        snapshot_producer,
        "load_snapshot_receipt",
        lambda *_args, **_kwargs: {"snapshot_sha256": "invalid"},
    )

    result = CliRunner().invoke(main, _arguments(raw, cutoff, output))

    assert result.exit_code == 1
    assert "invalid snapshot commitment" in result.output
    assert not output.exists()


def test_produce_snapshot_help_exposes_only_offline_explicit_inputs() -> None:
    result = CliRunner().invoke(main, ["benchmark", "produce-snapshot", "--help"])

    assert result.exit_code == 0, result.output
    for option in (
        "--raw-history",
        "--cutoff-basis",
        "--captured-at",
        "--tool-git-sha",
        "--privacy-reviewed-at",
        "--privacy-checklist-sha256",
        "--output",
    ):
        assert option in result.output
    for forbidden in ("--token", "--provider", "--model", "--network"):
        assert forbidden not in result.output
