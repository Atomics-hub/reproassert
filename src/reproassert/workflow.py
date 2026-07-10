from __future__ import annotations

import platform
import shlex
import shutil
import tempfile
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from reproassert import __version__
from reproassert.candidate import (
    ValidatedCandidate,
    candidate_path,
    render_new_file_patch,
    validate_candidate_payload,
)
from reproassert.candidate_workspace import prepare_candidate_workspace
from reproassert.context import build_source_context
from reproassert.errors import PolicyRejection
from reproassert.generator import CandidateGenerator, GenerationRequest
from reproassert.intake import (
    ExtractionLimits,
    download_source_archive,
    extract_source_archive,
    fetch_commit_tree_metadata,
    fetch_issue,
    parse_issue_url,
    resolve_commit_sha,
)
from reproassert.report import REPORT_SCHEMA_VERSION, load_replay_spec, write_report
from reproassert.safeio import (
    create_private_run_dir,
    open_regular_file,
    sha256_text,
    write_text_exclusive,
)
from reproassert.sandbox import DockerRunResult, DockerSandbox
from reproassert.source_attestation import SourceTreeAttestation, attest_source_tree
from reproassert.verifier import VerificationOutcome, verify_candidate


@dataclass(frozen=True)
class WorkflowResult:
    run_dir: Path
    report_path: Path
    patch_path: Path
    claim_level: str
    outcome: str
    replay_command: str


def run_issue_workflow(
    issue_url: str,
    *,
    requested_ref: str,
    generator: CandidateGenerator,
    sandbox: DockerSandbox,
    run_base: Path,
    repeats: int = 3,
) -> WorkflowResult:
    report_id = uuid.uuid4().hex
    run_dir = create_private_run_dir(run_base, prefix="issue-")
    archive_path: Path | None = None
    extraction_path: Path | None = None
    try:
        issue = fetch_issue(issue_url)
        sha = resolve_commit_sha(issue.ref.owner, issue.ref.repo, requested_ref)
        commit_tree = fetch_commit_tree_metadata(issue.ref.owner, issue.ref.repo, sha)
        archive = download_source_archive(issue.ref.owner, issue.ref.repo, sha, run_dir)
        archive_path = archive.path
        extracted = extract_source_archive(archive.path, run_dir, limits=ExtractionLimits())
        extraction_path = extracted.destination
        source_attestation = attest_source_tree(
            extracted.source_root,
            expected_git_tree_oid=commit_tree.tree_sha,
        )
        _reconcile_extraction(extracted.file_count, extracted.unpacked_bytes, source_attestation)
        context = build_source_context(
            extracted.source_root, issue_title=issue.ref.title, issue_body=issue.body
        )
        candidate = generator.generate(
            GenerationRequest(
                issue_url=issue.ref.url,
                issue_number=issue.ref.number,
                issue_title=issue.ref.title,
                issue_body=issue.body,
                source_sha=sha,
                source_context=context,
            )
        )
        generation_metadata = getattr(generator, "metadata", {})
        if not isinstance(generation_metadata, Mapping):
            raise PolicyRejection("generator_metadata", "Generator metadata must be an object.")
        result = _verify_and_write(
            run_dir=run_dir,
            report_id=report_id,
            issue_url=issue.ref.url,
            issue_title=issue.ref.title,
            issue_body_sha256=issue.ref.body_sha256,
            repository_url=f"https://github.com/{issue.ref.owner}/{issue.ref.repo}",
            requested_ref=requested_ref,
            sha=sha,
            archive_sha256=archive.sha256,
            archive_size_bytes=archive.size_bytes,
            source_attestation=source_attestation,
            source_root=extracted.source_root,
            candidate=candidate,
            generator_name=generator.name,
            generation_metadata=generation_metadata,
            sandbox=sandbox,
            repeats=repeats,
        )
        return result
    finally:
        sandbox.cleanup()
        if extraction_path is not None:
            shutil.rmtree(extraction_path, ignore_errors=True)
        if archive_path is not None:
            archive_path.unlink(missing_ok=True)


def run_replay_workflow(
    report_path: Path,
    *,
    sandbox: DockerSandbox,
    run_base: Path,
) -> WorkflowResult:
    spec = load_replay_spec(report_path)
    report_id = uuid.uuid4().hex
    run_dir = create_private_run_dir(run_base, prefix="replay-")
    archive_path: Path | None = None
    extraction_path: Path | None = None
    try:
        commit_tree = fetch_commit_tree_metadata(spec.issue.owner, spec.issue.repo, spec.source_sha)
        if spec.git_tree_oid is not None and spec.git_tree_oid != commit_tree.tree_sha:
            raise PolicyRejection(
                "source_tree_metadata_mismatch",
                "Recorded Git tree does not match the exact commit metadata.",
            )
        archive = download_source_archive(
            spec.issue.owner, spec.issue.repo, spec.source_sha, run_dir
        )
        archive_path = archive.path
        if archive.sha256 != spec.archive_sha256:
            raise PolicyRejection(
                "source_archive_mismatch", "Downloaded source archive differs from the report."
            )
        extracted = extract_source_archive(archive.path, run_dir)
        extraction_path = extracted.destination
        source_attestation = attest_source_tree(
            extracted.source_root,
            expected_git_tree_oid=commit_tree.tree_sha,
        )
        _reconcile_extraction(extracted.file_count, extracted.unpacked_bytes, source_attestation)
        if spec.tree_sha256 is not None and spec.tree_sha256 != source_attestation.tree_sha256:
            raise PolicyRejection(
                "source_tree_digest_mismatch", "Extracted source tree differs from the report."
            )
        return _verify_and_write(
            run_dir=run_dir,
            report_id=report_id,
            issue_url=spec.issue.url,
            issue_title=spec.issue_title,
            issue_body_sha256=spec.issue_body_sha256,
            repository_url=spec.issue.repository_url,
            requested_ref=spec.source_sha,
            sha=spec.source_sha,
            archive_sha256=archive.sha256,
            archive_size_bytes=archive.size_bytes,
            source_attestation=source_attestation,
            source_root=extracted.source_root,
            candidate=spec.candidate,
            generator_name="replay",
            generation_metadata={},
            sandbox=sandbox,
            repeats=spec.repeats,
            expected_executed_tree_sha256=spec.executed_tree_sha256,
        )
    finally:
        sandbox.cleanup()
        if extraction_path is not None:
            shutil.rmtree(extraction_path, ignore_errors=True)
        if archive_path is not None:
            archive_path.unlink(missing_ok=True)


def candidate_from_file(
    path: Path, *, issue_number: int, expected_symptom: str, rationale: str
) -> ValidatedCandidate:
    with open_regular_file(path) as stream:
        encoded = stream.read(32 * 1024 + 1)
    if len(encoded) > 32 * 1024:
        raise PolicyRejection("candidate_size", "Candidate file exceeds 32 KiB.")
    try:
        content = encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyRejection("candidate_encoding", "Candidate file must be UTF-8.") from exc
    return validate_candidate_payload(
        {
            "test_content": content,
            "expected_symptom": expected_symptom,
            "rationale": rationale,
        },
        issue_number=issue_number,
    )


def _verify_and_write(
    *,
    run_dir: Path,
    report_id: str,
    issue_url: str,
    issue_title: str,
    issue_body_sha256: str,
    repository_url: str,
    requested_ref: str,
    sha: str,
    archive_sha256: str,
    archive_size_bytes: int,
    source_attestation: SourceTreeAttestation,
    source_root: Path,
    candidate: ValidatedCandidate,
    generator_name: str,
    generation_metadata: Mapping[str, object],
    sandbox: DockerSandbox,
    repeats: int,
    expected_executed_tree_sha256: str | None = None,
) -> WorkflowResult:
    issue_location = parse_issue_url(issue_url)
    relative_path = candidate_path(issue_location.number)
    status = sandbox.require_ready()
    runner_facts = sandbox.runner_facts()
    with tempfile.TemporaryDirectory(prefix="candidate-", dir=run_dir) as temporary:
        destination = Path(temporary).resolve(strict=True) / "workspace"
        prepared = prepare_candidate_workspace(
            source=source_root,
            destination=destination,
            relative_path=relative_path,
            candidate=candidate,
            expected_pristine=source_attestation,
        )
        if (
            expected_executed_tree_sha256 is not None
            and prepared.candidate_applied_tree.tree_sha256 != expected_executed_tree_sha256
        ):
            raise PolicyRejection(
                "replay_executed_tree_mismatch",
                "Candidate-applied source tree differs from the recorded replay evidence.",
            )
        verification = verify_candidate(
            sandbox=sandbox,
            source=prepared.path,
            relative_path=relative_path,
            candidate=candidate,
            expected_source_tree=prepared.candidate_applied_tree,
            run_id=report_id,
            repeats=repeats,
        )
    if (
        verification.candidate_sha256 != candidate.sha256
        or verification.executed_tree_sha256 != prepared.candidate_applied_tree.tree_sha256
    ):
        raise PolicyRejection(
            "verification_evidence_binding",
            "Verifier evidence does not match the submitted candidate workspace.",
        )
    patch = render_new_file_patch(relative_path, candidate.test_content)
    patch_path = run_dir / "candidate.patch"
    write_text_exclusive(patch_path, patch)
    report_path = run_dir / "reproassert-report.json"
    replay_command = shlex.join(["reproassert", "replay", str(report_path)])
    report = _report_dict(
        report_id=report_id,
        issue_url=issue_url,
        issue_title=issue_title,
        issue_body_sha256=issue_body_sha256,
        repository_url=repository_url,
        requested_ref=requested_ref,
        sha=sha,
        archive_sha256=archive_sha256,
        archive_size_bytes=archive_size_bytes,
        source_attestation=source_attestation,
        candidate=candidate,
        relative_path=relative_path,
        generator_name=generator_name,
        generation_metadata=generation_metadata,
        verification=verification,
        sandbox=sandbox,
        image_id=status.image_id,
        server_version=status.server_version,
        runner_facts=runner_facts,
        repeats=repeats,
        patch=patch,
        replay_command=replay_command,
    )
    write_report(report_path, report)
    return WorkflowResult(
        run_dir=run_dir,
        report_path=report_path,
        patch_path=patch_path,
        claim_level=verification.claim_level.value,
        outcome=verification.outcome,
        replay_command=replay_command,
    )


def _report_dict(
    *,
    report_id: str,
    issue_url: str,
    issue_title: str,
    issue_body_sha256: str,
    repository_url: str,
    requested_ref: str,
    sha: str,
    archive_sha256: str,
    archive_size_bytes: int,
    source_attestation: SourceTreeAttestation,
    candidate: ValidatedCandidate,
    relative_path: str,
    generator_name: str,
    generation_metadata: Mapping[str, object],
    verification: VerificationOutcome,
    sandbox: DockerSandbox,
    image_id: str | None,
    server_version: str | None,
    runner_facts: dict[str, str],
    repeats: int,
    patch: str,
    replay_command: str,
) -> dict[str, object]:
    policy = sandbox.policy
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_id": report_id,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tool": {"name": "reproassert", "version": __version__},
        "claim_level": verification.claim_level.value,
        "outcome": verification.outcome,
        "issue": {
            "url": issue_url,
            "title": issue_title,
            "body_sha256": issue_body_sha256,
        },
        "source": {
            "repository_url": repository_url,
            "requested_ref": requested_ref,
            "sha": sha,
            "archive_sha256": archive_sha256,
            "archive_size_bytes": archive_size_bytes,
            "tree_attestation_algorithm": source_attestation.algorithm,
            "tree_sha256": source_attestation.tree_sha256,
            "executed_tree_sha256": verification.executed_tree_sha256,
            "git_tree_oid": source_attestation.reconstructed_git_tree_oid,
            "member_count": source_attestation.member_count,
            "file_count": source_attestation.file_count,
            "directory_count": source_attestation.directory_count,
            "unpacked_bytes": source_attestation.total_bytes,
            "executable_file_count": source_attestation.executable_count,
            "git_metadata_absent": source_attestation.git_metadata_absent,
        },
        "candidate": {
            "relative_path": relative_path,
            "test_function": candidate.test_function,
            "test_content": candidate.test_content,
            "test_content_sha256": candidate.sha256,
            "expected_symptom": candidate.expected_symptom,
            "rationale": candidate.rationale,
            "generator": generator_name,
        },
        "generation": _generation_record(generator_name, generation_metadata),
        "runner": {
            "backend": "docker",
            "server_version": server_version,
            "image": policy.image,
            "image_id": image_id,
            "controller": {
                "python_version": platform.python_version(),
                "python_implementation": platform.python_implementation(),
                "platform_system": platform.system(),
                "platform_release": platform.release(),
                "machine": platform.machine(),
            },
            "verification_environment": runner_facts,
        },
        "policy": {
            "profile": "strict-python-pytest-v1",
            "repeats": repeats,
            "network": {"intake": "github-fixed-hosts", "verification": "none"},
            "mounts": ["controller-owned Docker volume, read-only during verification"],
            "environment": {
                "HOME": "/tmp/home",  # noqa: S108 - path is inside container
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
                "PYTHONPATH": "/workspace:/workspace/src:/workspace/.reproassert-deps",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                "TZ": "UTC",
            },
            "limits": {
                "timeout_seconds": policy.timeout_seconds,
                "max_output_bytes": policy.max_output_bytes,
                "memory_bytes": policy.memory_bytes,
                "cpus": policy.cpus,
                "pids": policy.pids,
                "tmpfs_bytes": policy.tmpfs_bytes,
                "tmpfs_inodes": policy.tmpfs_inodes,
            },
        },
        "collection": _docker_result(verification.collection),
        "runs": [_docker_result(run) for run in verification.runs],
        "failure_fingerprint": verification.fingerprint,
        "artifacts": {
            "candidate_patch": "candidate.patch",
            "candidate_patch_sha256": sha256_text(patch),
            "report": "reproassert-report.json",
        },
        "replay": {
            "display_command": replay_command,
            "execution_policy": "controller_regenerates_argv_and_ignores_report_commands",
        },
        "limitations": [
            "Repeatable failure is not semantic correctness or maintainer acceptance.",
            (
                "Repository code can forge in-process pytest detail; results are bounded "
                "evidence, not proof."
            ),
            "Docker shares a kernel on Linux; Docker Desktop shares its VM across containers.",
            (
                "This strict profile performs no dependency installation and may reject "
                "valid repositories."
            ),
            (
                "Generation metadata covers only the candidate that reached verification; "
                "provider work spent on aborted generation attempts is not recorded here."
            ),
            (
                "Commit-to-tree provenance trusts GitHub's API, codeload service, TLS, and Git's "
                "SHA-1 object identity; an independent source mirror is not consulted."
            ),
        ],
    }


def _reconcile_extraction(
    extracted_file_count: int,
    extracted_bytes: int,
    attestation: SourceTreeAttestation,
) -> None:
    if extracted_file_count != attestation.file_count or extracted_bytes != attestation.total_bytes:
        raise PolicyRejection(
            "source_extraction_mismatch",
            "Archive extraction counts do not match the attested source tree.",
        )


def _docker_result(result: DockerRunResult) -> dict[str, object]:
    values: dict[str, object] = asdict(result)
    values.pop("junit_xml", None)
    values.pop("container_name", None)
    values["argv"] = list(result.argv)
    return values


def _generation_record(adapter: str, metadata: Mapping[str, object]) -> dict[str, object]:
    record: dict[str, object] = {"adapter": adapter}
    if not metadata:
        return record
    allowed_text = {
        "provider",
        "requested_model",
        "response_model",
        "endpoint_host",
        "response_id",
    }
    allowed_counts = {
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "total_tokens",
    }
    if set(metadata) - allowed_text - allowed_counts - {"request_duration_seconds"}:
        raise PolicyRejection("generator_metadata", "Generator metadata contains unknown fields.")
    for name in allowed_text:
        value = metadata.get(name)
        if value is not None:
            if not isinstance(value, str) or not 1 <= len(value) <= 200:
                raise PolicyRejection(
                    "generator_metadata", f"Generator metadata {name} is invalid."
                )
            record[name] = value
    duration = metadata.get("request_duration_seconds")
    if duration is not None:
        if (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not 0 <= duration <= 600
        ):
            raise PolicyRejection("generator_metadata", "Generator request duration is invalid.")
        record["request_duration_seconds"] = duration
    for name in allowed_counts:
        value = metadata.get(name)
        if value is not None:
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**31 - 1:
                raise PolicyRejection(
                    "generator_metadata", f"Generator metadata {name} is invalid."
                )
            record[name] = value
    return record
