from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jsonschema
import pytest
from click.testing import CliRunner

import reproassert.benchmark_v02_chronology as chronology
import reproassert.cli as cli
from reproassert.cli import main
from reproassert.errors import PolicyRejection


def _write_json(path: Path, value: object) -> bytes:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    path.write_bytes(raw)
    return raw


def _fixtures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, Path, list[dict[str, object]]]:
    os.chmod(tmp_path, 0o700)
    responses = tmp_path / "responses"
    metadata = tmp_path / "metadata"
    responses.mkdir(mode=0o700)
    metadata.mkdir(mode=0o700)
    cases: list[dict[str, object]] = []
    metadata_refs: dict[str, dict[str, dict[str, object]]] = {}
    for position in range(1, 21):
        case_id = f"rk-v0.2-{position:03d}"
        repo = f"owner/repository-{position}"
        issue_url = f"https://github.com/{repo}/issues/{position}"
        base_sha = f"{position:x}" * 40
        cases.append(
            {
                "base_sha": base_sha,
                "case_id": case_id,
                "issue_url": issue_url,
                "repo": repo,
            }
        )
        _write_json(
            responses / f"{case_id}.json",
            {
                "created_at": "2024-01-01T00:00:00Z",
                "html_url": issue_url,
                "number": position,
                "repository_url": f"https://api.github.com/repos/{repo}",
            },
        )
        metadata_raw = _write_json(
            metadata / f"{case_id}.json",
            {
                "base_commit": base_sha,
                "case_id": case_id,
                "created_at": "2025-01-01T00:00:00Z",
                "repo": repo,
            },
        )
        metadata_refs[case_id] = {
            "metadata": {
                "bytes": len(metadata_raw),
                "path": metadata / f"{case_id}.json",
                "sha256": chronology.hashlib.sha256(metadata_raw).hexdigest(),
            }
        }
    cohort_path = tmp_path / "cohort.json"
    cohort_path.write_bytes(b"cohort fixture\n")
    hidden_path = tmp_path / "hidden.json"
    hidden_path.write_bytes(b"hidden fixture\n")
    verified_hidden = object()
    monkeypatch.setattr(
        chronology, "load_v02_leak_audited_cohort_plan", lambda _path: {"cases": cases}
    )
    monkeypatch.setattr(chronology, "verify_v02_hidden_gold", lambda _path: verified_hidden)

    def artifacts(authority: object, case_id: str) -> dict[str, dict[str, object]]:
        assert authority is verified_hidden
        return metadata_refs[case_id]

    monkeypatch.setattr(chronology, "hidden_case_artifacts", artifacts)
    return cohort_path, hidden_path, responses, cases


def test_chronology_receipt_rederives_all_20_without_hidden_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cohort, hidden, responses, _cases = _fixtures(tmp_path, monkeypatch)
    output = tmp_path / "chronology.json"

    verified = chronology.prepare_v02_chronology_evidence(
        cohort_plan_path=cohort,
        hidden_extraction_receipt=hidden,
        issue_responses_root=responses,
        captured_at="2026-01-01T00:00:00Z",
        tool_git_sha="a" * 40,
        output_path=output,
    )

    assert verified.case_count == verified.issue_precedes_fix_count == 20
    assert verified.provider_calls == 0
    record = json.loads(output.read_text())
    assert record["status"] == "issue_precedes_fix_20_of_20"
    assert record["claims"] == {
        "chronology_proven_count": 20,
        "hidden_bytes_emitted": False,
        "model_or_provider_invoked": False,
        "provider_calls": 0,
    }
    assert all(row["lead_time_seconds"] == 31_622_400 for row in record["cases"])
    assert "metadata/" not in output.read_text()
    assert (
        chronology.verify_v02_chronology_evidence(
            output,
            cohort_plan_path=cohort,
            hidden_extraction_receipt=hidden,
            issue_responses_root=responses,
        ).sha256
        == verified.sha256
    )
    public_schema = Path("schemas/benchmark-v02-chronology-evidence.schema.json")
    packaged_schema = Path("src/reproassert/schemas/benchmark-v02-chronology-evidence.schema.json")
    assert public_schema.read_bytes() == packaged_schema.read_bytes()
    jsonschema.validate(record, json.loads(public_schema.read_text()))


def test_chronology_rejects_late_issue_and_tampered_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cohort, hidden, responses, cases = _fixtures(tmp_path, monkeypatch)
    first = cases[0]
    _write_json(
        responses / "rk-v0.2-001.json",
        {
            "created_at": "2025-01-02T00:00:00Z",
            "html_url": first["issue_url"],
            "number": 1,
            "repository_url": f"https://api.github.com/repos/{first['repo']}",
        },
    )
    with pytest.raises(PolicyRejection, match="does not precede"):
        chronology.prepare_v02_chronology_evidence(
            cohort_plan_path=cohort,
            hidden_extraction_receipt=hidden,
            issue_responses_root=responses,
            captured_at="2026-01-01T00:00:00Z",
            tool_git_sha="a" * 40,
            output_path=tmp_path / "rejected.json",
        )

    _write_json(
        responses / "rk-v0.2-001.json",
        {
            "created_at": "2024-01-01T00:00:00Z",
            "html_url": first["issue_url"],
            "number": 1,
            "repository_url": f"https://api.github.com/repos/{first['repo']}",
        },
    )
    output = tmp_path / "chronology.json"
    chronology.prepare_v02_chronology_evidence(
        cohort_plan_path=cohort,
        hidden_extraction_receipt=hidden,
        issue_responses_root=responses,
        captured_at="2026-01-01T00:00:00Z",
        tool_git_sha="a" * 40,
        output_path=output,
    )
    value: dict[str, Any] = json.loads(output.read_text())
    value["cases"][0]["issue_created_at"] = "2023-01-01T00:00:00Z"
    value["receipt_sha256"] = chronology._self_hash(value)
    output.write_bytes(chronology._canonical(value) + b"\n")
    with pytest.raises(PolicyRejection, match="freshly derived"):
        chronology.verify_v02_chronology_evidence(
            output,
            cohort_plan_path=cohort,
            hidden_extraction_receipt=hidden,
            issue_responses_root=responses,
        )


def test_public_capture_uses_bounded_credential_free_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _cohort, _hidden, _responses, cases = _fixtures(tmp_path, monkeypatch)
    parent = tmp_path / "capture"
    parent.mkdir(mode=0o700)
    observed: list[str] = []

    def transport(path: str) -> bytes:
        observed.append(path)
        position = int(path.rsplit("/", 1)[-1])
        case = cases[position - 1]
        return json.dumps(
            {
                "created_at": "2024-01-01T00:00:00Z",
                "html_url": case["issue_url"],
                "number": position,
                "repository_url": f"https://api.github.com/repos/{case['repo']}",
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

    captured = chronology.capture_v02_public_issue_responses(
        cohort_plan_path=tmp_path / "cohort.json",
        output_root=parent,
        transport=transport,
    )

    assert len(observed) == 20
    assert observed[0] == "/repos/owner/repository-1/issues/1"
    assert observed[-1] == "/repos/owner/repository-20/issues/20"
    assert len(tuple(captured.glob("*.json"))) == 20
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in captured.glob("*.json"))


def test_chronology_cli_reports_provider_free_capture_prepare_and_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    os.chmod(tmp_path, 0o700)
    cohort = tmp_path / "cohort.json"
    hidden = tmp_path / "hidden.json"
    cohort.write_text("{}")
    hidden.write_text("{}")
    responses = tmp_path / "responses"
    responses.mkdir(mode=0o700)
    receipt = tmp_path / "chronology.json"
    receipt.write_text("{}")
    verified = SimpleNamespace(
        case_count=20,
        issue_precedes_fix_count=20,
        provider_calls=0,
        sha256="a" * 64,
    )
    monkeypatch.setattr(cli, "capture_v02_public_issue_responses", lambda **_kwargs: responses)
    monkeypatch.setattr(cli, "prepare_v02_chronology_evidence", lambda **_kwargs: verified)
    monkeypatch.setattr(cli, "verify_v02_chronology_evidence", lambda *_args, **_kwargs: verified)
    runner = CliRunner()

    capture = runner.invoke(
        main,
        [
            "benchmark",
            "capture-v02-chronology",
            "--cohort-plan",
            str(cohort),
            "--output-root",
            str(tmp_path / "capture"),
        ],
    )
    assert capture.exit_code == 0, capture.output
    assert json.loads(capture.output)["credentials_sent"] is False

    prepare = runner.invoke(
        main,
        [
            "benchmark",
            "prepare-v02-chronology",
            "--cohort-plan",
            str(cohort),
            "--hidden-extraction-receipt",
            str(hidden),
            "--issue-responses-root",
            str(responses),
            "--captured-at",
            "2026-01-01T00:00:00Z",
            "--tool-git-sha",
            "a" * 40,
            "--output",
            str(tmp_path / "prepared.json"),
        ],
    )
    assert prepare.exit_code == 0, prepare.output
    assert json.loads(prepare.output)["issue_precedes_fix_count"] == 20

    verify = runner.invoke(
        main,
        [
            "benchmark",
            "verify-v02-chronology",
            str(receipt),
            "--cohort-plan",
            str(cohort),
            "--hidden-extraction-receipt",
            str(hidden),
            "--issue-responses-root",
            str(responses),
        ],
    )
    assert verify.exit_code == 0, verify.output
    assert json.loads(verify.output)["verified"] is True
