from __future__ import annotations

import hashlib
import json
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

import reproassert.workflow as workflow
from reproassert.candidate import ValidatedCandidate, validate_candidate_payload
from reproassert.errors import PolicyRejection
from reproassert.generator import StaticGenerator
from reproassert.intake import (
    ArchiveDownload,
    CommitTreeMetadata,
    ExtractedArchive,
    IssueDocument,
)
from reproassert.models import ClaimLevel, IssueRef
from reproassert.sandbox import DockerDoctor, DockerRunResult, SandboxPolicy
from reproassert.source_attestation import SOURCE_TREE_ALGORITHM, SourceTreeAttestation
from reproassert.verifier import VerificationOutcome
from reproassert.workflow import WorkflowResult


def candidate() -> ValidatedCandidate:
    return validate_candidate_payload(
        {
            "test_content": (
                "from fixture_project import reproduce\n\n"
                "def test_issue_3_reproduction():\n"
                "    assert reproduce() == 2, 'fixture mismatch remains'\n"
            ),
            "expected_symptom": "fixture mismatch remains",
            "rationale": "One deterministic fixture assertion.",
        },
        issue_number=3,
    )


class FakeSandbox:
    def __init__(self) -> None:
        self.policy = SandboxPolicy(image="fixture-image")
        self.cleaned = 0

    def cleanup(self) -> None:
        self.cleaned += 1

    def require_ready(self) -> DockerDoctor:
        return DockerDoctor(True, True, True, "29", "sha256:image")

    def runner_facts(self) -> dict[str, str]:
        return {
            "python_version": "3.12.11",
            "python_implementation": "CPython",
            "pytest_version": "9.1.1",
            "platform_system": "Linux",
            "platform_release": "fixture",
            "machine": "x86_64",
        }


def docker_result(phase: str) -> DockerRunResult:
    return DockerRunResult(
        phase=phase,
        exit_code=0 if phase == "collect" else 1,
        duration_seconds=0.1,
        output="bounded",
        timed_out=False,
        oom_killed=False,
        output_truncated=False,
        junit_xml=None,
        container_name="gone",
        argv=("/usr/local/bin/python", "-m", "pytest", "fixture::test"),
    )


def accepted_outcome() -> VerificationOutcome:
    return VerificationOutcome(
        accepted=True,
        claim_level=ClaimLevel.REPEATABLE_BASE_FAILURE,
        outcome="repeatable_base_failure",
        fingerprint="f" * 64,
        collection=docker_result("collect"),
        runs=(docker_result("verify_1"), docker_result("verify_2"), docker_result("verify_3")),
    )


def source_attestation() -> SourceTreeAttestation:
    return SourceTreeAttestation(
        algorithm=SOURCE_TREE_ALGORITHM,
        tree_sha256="e" * 64,
        reconstructed_git_tree_oid="f" * 40,
        expected_git_tree_oid="f" * 40,
        member_count=3,
        file_count=2,
        directory_count=1,
        total_bytes=100,
        executable_count=0,
        git_metadata_absent=True,
    )


@pytest.mark.parametrize(
    "metadata",
    [
        {"unknown": "value"},
        {"model": ""},
        {"request_duration_seconds": True},
        {"input_tokens": -1},
    ],
)
def test_generation_record_rejects_unbounded_or_unknown_metadata(
    metadata: dict[str, object],
) -> None:
    with pytest.raises(PolicyRejection, match=r"metadata|duration"):
        workflow._generation_record("adapter", metadata)


def test_verify_and_write_creates_patch_and_authoritative_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "run with 'quote"
    run_dir.mkdir(mode=0o700)
    source = run_dir / "source"
    source.mkdir(mode=0o700)
    sandbox = FakeSandbox()
    monkeypatch.setattr(workflow, "verify_candidate", lambda **_kwargs: accepted_outcome())

    result = workflow._verify_and_write(
        run_dir=run_dir,
        report_id="a" * 32,
        issue_url="https://github.com/owner/repo/issues/3",
        issue_title="Fixture mismatch",
        issue_body_sha256="b" * 64,
        repository_url="https://github.com/owner/repo",
        requested_ref="HEAD",
        sha="a" * 40,
        archive_sha256="c" * 64,
        archive_size_bytes=90,
        source_attestation=source_attestation(),
        source_root=source,
        candidate=candidate(),
        generator_name="fixture",
        generation_metadata={},
        sandbox=sandbox,  # type: ignore[arg-type]
        repeats=3,
    )

    report = json.loads(result.report_path.read_text())
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas" / "reproassert-report.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(report)
    partial_source = json.loads(json.dumps(report))
    partial_source["source"].pop("directory_count")
    assert list(validator.iter_errors(partial_source))
    assert result.outcome == "repeatable_base_failure"
    assert result.patch_path.read_text().startswith("diff --git")
    assert report["source"]["sha"] == "a" * 40
    assert report["source"]["tree_sha256"] == "e" * 64
    assert report["source"]["git_tree_oid"] == "f" * 40
    assert report["source"]["git_metadata_absent"] is True
    assert report["candidate"]["generator"] == "fixture"
    assert report["generation"] == {"adapter": "fixture"}
    assert report["runner"]["image_id"] == "sha256:image"
    assert report["runner"]["verification_environment"]["pytest_version"] == "9.1.1"
    assert report["collection"]["argv"][:3] == ["/usr/local/bin/python", "-m", "pytest"]
    assert report["policy"]["environment"]["PYTHONHASHSEED"] == "0"
    assert "junit_xml" not in report["runs"][0]
    assert shlex.split(result.replay_command) == [
        "reproassert",
        "replay",
        str(result.report_path),
    ]


def test_issue_workflow_orchestrates_bounded_inputs_and_cleans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_base = tmp_path / "runs"
    source_root = tmp_path / "prepared-source"
    source_root.mkdir()
    archive_file = tmp_path / "download.tar.gz"
    archive_file.write_bytes(b"archive")
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    issue = IssueDocument(
        ref=IssueRef(
            url="https://github.com/owner/repo/issues/3",
            owner="owner",
            repo="repo",
            number=3,
            title="Fixture mismatch",
            body_sha256="d" * 64,
        ),
        body="Expected stable output.",
    )
    sandbox = FakeSandbox()
    final = WorkflowResult(
        run_dir=tmp_path,
        report_path=tmp_path / "report.json",
        patch_path=tmp_path / "patch",
        claim_level="repeatable_base_failure",
        outcome="repeatable_base_failure",
        replay_command="reproassert replay report.json",
    )
    monkeypatch.setattr(workflow, "fetch_issue", lambda _url: issue)
    monkeypatch.setattr(workflow, "resolve_commit_sha", lambda *_args: "a" * 40)
    monkeypatch.setattr(
        workflow,
        "fetch_commit_tree_metadata",
        lambda *_args: CommitTreeMetadata("a" * 40, "f" * 40),
    )
    monkeypatch.setattr(
        workflow,
        "download_source_archive",
        lambda *_args, **_kwargs: ArchiveDownload(
            archive_file, hashlib.sha256(b"archive").hexdigest(), 7
        ),
    )
    monkeypatch.setattr(
        workflow,
        "extract_source_archive",
        lambda *_args, **_kwargs: ExtractedArchive(extraction, source_root, 3, 2, 100, 1),
    )
    monkeypatch.setattr(
        workflow, "attest_source_tree", lambda *_args, **_kwargs: source_attestation()
    )
    monkeypatch.setattr(
        workflow, "build_source_context", lambda *_args, **_kwargs: SimpleNamespace()
    )
    monkeypatch.setattr(workflow, "_verify_and_write", lambda **_kwargs: final)

    result = workflow.run_issue_workflow(
        issue.ref.url,
        requested_ref="HEAD",
        generator=StaticGenerator(candidate()),
        sandbox=sandbox,  # type: ignore[arg-type]
        run_base=run_base,
    )

    assert result is final
    assert sandbox.cleaned >= 1
    assert not archive_file.exists()
    assert not extraction.exists()


def test_replay_workflow_regenerates_from_schema_not_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_report = workflow._report_dict(
        report_id="b" * 32,
        issue_url="https://github.com/owner/repo/issues/3",
        issue_title="Fixture mismatch",
        issue_body_sha256="d" * 64,
        repository_url="https://github.com/owner/repo",
        requested_ref="HEAD",
        sha="a" * 40,
        archive_sha256="c" * 64,
        archive_size_bytes=7,
        source_attestation=source_attestation(),
        candidate=candidate(),
        relative_path="tests/reproassert/test_issue_3.py",
        generator_name="fixture",
        generation_metadata={
            "provider": "openai",
            "requested_model": "gpt-5.4-mini",
            "response_model": "gpt-5.4-mini-2026-03-17",
            "endpoint_host": "api.openai.com",
            "request_duration_seconds": 0.25,
            "response_id": "resp_test",
            "input_tokens": 120,
            "cached_input_tokens": 20,
            "output_tokens": 40,
            "total_tokens": 160,
        },
        verification=accepted_outcome(),
        sandbox=FakeSandbox(),  # type: ignore[arg-type]
        image_id="sha256:image",
        server_version="29",
        runner_facts=FakeSandbox().runner_facts(),
        repeats=3,
        patch="fixture patch\n",
        replay_command="reproassert replay input.json",
    )
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas" / "reproassert-report.schema.json").read_text()
    )
    Draft202012Validator(schema).validate(input_report)
    assert input_report["generation"]["input_tokens"] == 120
    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps(input_report))
    archive = tmp_path / "archive.tar.gz"
    archive.write_bytes(b"archive")
    extracted_dir = tmp_path / "extracted"
    extracted_dir.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    sandbox = FakeSandbox()
    monkeypatch.setattr(
        workflow,
        "download_source_archive",
        lambda *_args, **_kwargs: ArchiveDownload(archive, "c" * 64, 7),
    )
    monkeypatch.setattr(
        workflow,
        "fetch_commit_tree_metadata",
        lambda *_args: CommitTreeMetadata("a" * 40, "f" * 40),
    )
    monkeypatch.setattr(
        workflow,
        "extract_source_archive",
        lambda *_args, **_kwargs: ExtractedArchive(extracted_dir, source, 3, 2, 100, 1),
    )
    monkeypatch.setattr(
        workflow, "attest_source_tree", lambda *_args, **_kwargs: source_attestation()
    )
    monkeypatch.setattr(workflow, "verify_candidate", lambda **_kwargs: accepted_outcome())

    result = workflow.run_replay_workflow(
        input_path,
        sandbox=sandbox,  # type: ignore[arg-type]
        run_base=tmp_path / "runs",
    )

    replay_report = json.loads(result.report_path.read_text())
    Draft202012Validator(schema).validate(replay_report)
    assert replay_report["issue"]["title"] == "Fixture mismatch"
    assert replay_report["issue"]["body_sha256"] == "d" * 64
    assert replay_report["source"]["tree_sha256"] == "e" * 64
    assert sandbox.cleaned >= 1
    assert not archive.exists()
    assert not extracted_dir.exists()

    mismatch_archive = tmp_path / "mismatched-archive.tar.gz"
    mismatch_archive.write_bytes(b"changed archive")
    monkeypatch.setattr(
        workflow,
        "download_source_archive",
        lambda *_args, **_kwargs: ArchiveDownload(mismatch_archive, "0" * 64, 15),
    )
    with pytest.raises(PolicyRejection) as mismatch:
        workflow.run_replay_workflow(
            input_path,
            sandbox=sandbox,  # type: ignore[arg-type]
            run_base=tmp_path / "mismatch-runs",
        )
    assert mismatch.value.code == "source_archive_mismatch"
    assert not mismatch_archive.exists()


def test_candidate_from_file_rejects_symlink_and_bad_encoding(tmp_path: Path) -> None:
    valid = tmp_path / "candidate.py"
    valid.write_text(
        "from fixture_project import reproduce\n\n"
        "def test_issue_3_reproduction():\n"
        "    assert reproduce() == 2, 'fixture mismatch remains'\n"
    )
    loaded = workflow.candidate_from_file(
        valid,
        issue_number=3,
        expected_symptom="fixture mismatch remains",
        rationale="fixture",
    )
    assert loaded.test_function == "test_issue_3_reproduction"

    link = tmp_path / "link.py"
    link.symlink_to(valid)
    with pytest.raises(PolicyRejection):
        workflow.candidate_from_file(
            link,
            issue_number=3,
            expected_symptom="fixture mismatch remains",
            rationale="fixture",
        )
    invalid = tmp_path / "invalid.py"
    invalid.write_bytes(b"\xff")
    with pytest.raises(PolicyRejection):
        workflow.candidate_from_file(
            invalid,
            issue_number=3,
            expected_symptom="fixture mismatch remains",
            rationale="fixture",
        )
