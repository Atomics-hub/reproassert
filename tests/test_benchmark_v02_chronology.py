from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

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


def test_public_capture_rejects_identity_mismatch_and_removes_partial_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _cohort, _hidden, _responses, cases = _fixtures(tmp_path, monkeypatch)
    parent = tmp_path / "capture"
    parent.mkdir(mode=0o700)

    def transport(path: str) -> bytes:
        position = int(path.rsplit("/", 1)[-1])
        case = cases[position - 1]
        return json.dumps(
            {
                "created_at": "2024-01-01T00:00:00Z",
                "html_url": "https://github.com/attacker/wrong/issues/1",
                "number": position,
                "repository_url": f"https://api.github.com/repos/{case['repo']}",
            }
        ).encode()

    with pytest.raises(PolicyRejection, match="response identity differs"):
        chronology.capture_v02_public_issue_responses(
            cohort_plan_path=tmp_path / "cohort.json",
            output_root=parent,
            transport=transport,
        )

    assert not (parent / "github-issue-responses").exists()


def test_public_capture_rejects_existing_destination_and_nonbytes_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fixtures(tmp_path, monkeypatch)
    parent = tmp_path / "capture"
    parent.mkdir(mode=0o700)
    destination = parent / "github-issue-responses"
    destination.mkdir(mode=0o700)
    with pytest.raises(PolicyRejection, match="Refusing to overwrite"):
        chronology.capture_v02_public_issue_responses(
            cohort_plan_path=tmp_path / "cohort.json", output_root=parent, transport=lambda _: b"{}"
        )

    destination.rmdir()
    with pytest.raises(PolicyRejection, match="transport contract"):
        chronology.capture_v02_public_issue_responses(
            cohort_plan_path=tmp_path / "cohort.json",
            output_root=parent,
            transport=lambda _: "not bytes",  # type: ignore[return-value]
        )
    assert not destination.exists()


class _FakeGitHubResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.body = body

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


class _FakeGitHubConnection:
    instances: ClassVar[list[_FakeGitHubConnection]] = []
    status = 200
    body = b"{}"
    failure: BaseException | None = None

    def __init__(self, host: str, timeout: float) -> None:
        self.host = host
        self.timeout = timeout
        self.closed = False
        self.request_args: tuple[object, ...] | None = None
        type(self).instances.append(self)

    def request(self, *args: object, **kwargs: object) -> None:
        self.request_args = (*args, kwargs)
        if self.failure is not None:
            raise self.failure

    def getresponse(self) -> _FakeGitHubResponse:
        return _FakeGitHubResponse(self.status, self.body)

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("status", "body", "failure", "message"),
    [
        (403, b"{}", None, "HTTP 403"),
        (200, b"x" * (chronology.MAX_RESPONSE_BYTES + 1), None, "size limit"),
        (200, b"{}", OSError("network denied"), "bounded transport"),
        (200, b"{}", http.client.HTTPException("bad response"), "bounded transport"),
    ],
)
def test_bounded_github_transport_fails_closed_and_always_closes(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    body: bytes,
    failure: BaseException | None,
    message: str,
) -> None:
    _FakeGitHubConnection.instances.clear()
    _FakeGitHubConnection.status = status
    _FakeGitHubConnection.body = body
    _FakeGitHubConnection.failure = failure
    monkeypatch.setattr(chronology.http.client, "HTTPSConnection", _FakeGitHubConnection)

    with pytest.raises(PolicyRejection, match=message):
        chronology._fetch_public_github_json("/repos/owner/repository/issues/1")

    connection = _FakeGitHubConnection.instances[0]
    assert connection.host == "api.github.com"
    assert connection.timeout == 20.0
    assert connection.closed is True


@pytest.mark.parametrize("path", ["/users/owner", "/repos/o/r/issues/1\rInjected: yes", ""])
def test_bounded_github_transport_rejects_non_allowlisted_paths(path: str) -> None:
    with pytest.raises(PolicyRejection, match="API path is invalid"):
        chronology._fetch_public_github_json(path)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b'{"b":1,"a":2}\n', "not canonical"),
        (b'{"a":1,"a":2}\n', "invalid JSON"),
        (b"[]\n", "must be a JSON object"),
        (b'{"a":1}', "not canonical"),
    ],
)
def test_chronology_receipt_decoder_rejects_ambiguous_or_noncanonical_json(
    raw: bytes, message: str
) -> None:
    with pytest.raises(PolicyRejection, match=message):
        chronology._decode_canonical(raw, "chronology receipt")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("response_identity", "response identity differs"),
        ("metadata_commitment", "metadata commitment differs"),
        ("metadata_identity", "metadata identity differs"),
        ("capture_predates_fix", "capture predates"),
        ("future_capture", "future-dated"),
    ],
)
def test_chronology_derivation_rejects_unbound_or_impossible_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    message: str,
) -> None:
    cohort, hidden, responses, _cases = _fixtures(tmp_path, monkeypatch)
    captured_at = "2026-01-01T00:00:00Z"
    if mutation == "response_identity":
        response_path = responses / "rk-v0.2-001.json"
        response = json.loads(response_path.read_text())
        response["number"] = 999
        _write_json(response_path, response)
    elif mutation == "metadata_commitment":
        (tmp_path / "metadata/rk-v0.2-001.json").write_bytes(b"{}\n")
    elif mutation == "metadata_identity":
        metadata_path = tmp_path / "metadata/rk-v0.2-001.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["repo"] = "attacker/wrong"
        metadata_raw = _write_json(metadata_path, metadata)

        def artifacts(_authority: object, case_id: str) -> dict[str, dict[str, object]]:
            path = tmp_path / "metadata" / f"{case_id}.json"
            raw = path.read_bytes()
            return {
                "metadata": {
                    "bytes": len(raw),
                    "path": path,
                    "sha256": chronology.hashlib.sha256(raw).hexdigest(),
                }
            }

        assert metadata_raw
        monkeypatch.setattr(chronology, "hidden_case_artifacts", artifacts)
    elif mutation == "capture_predates_fix":
        captured_at = "2024-06-01T00:00:00Z"
    else:
        captured_at = "2099-01-01T00:00:00Z"

    with pytest.raises(PolicyRejection, match=message):
        chronology.prepare_v02_chronology_evidence(
            cohort_plan_path=cohort,
            hidden_extraction_receipt=hidden,
            issue_responses_root=responses,
            captured_at=captured_at,
            tool_git_sha="a" * 40,
            output_path=tmp_path / "rejected-chronology.json",
        )


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
