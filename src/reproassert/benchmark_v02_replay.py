"""Bundle-backed, exact-source replay for published v0.2 reproduction cases."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from reproassert.candidate import ValidatedCandidate, candidate_path, validate_candidate_payload
from reproassert.candidate_workspace import prepare_candidate_workspace
from reproassert.dependency_executor import DependencyExecutor
from reproassert.dependency_prep import DependencyPlan, load_dependency_plan
from reproassert.errors import PolicyRejection
from reproassert.intake import (
    download_source_archive,
    extract_source_archive,
    fetch_commit_tree_metadata,
    parse_issue_url,
)
from reproassert.safeio import create_private_run_dir, open_regular_file, write_bytes_exclusive
from reproassert.sandbox import DEFAULT_IMAGE, DockerRunResult, DockerSandbox, SandboxPolicy
from reproassert.source_attestation import attest_source_tree
from reproassert.verifier import VerificationOutcome, verify_candidate

REPLAY_BUNDLE_ALGORITHM = "reproassert-v02-public-replay-bundle-v1"
REPLAY_RESULT_ALGORITHM = "reproassert-v02-public-replay-result-v1"
MAX_REPLAY_BUNDLE_BYTES = 2 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class V02ReplayBundle:
    raw: Mapping[str, object]
    sha256: str
    case_id: str
    repo: str
    issue_url: str
    base_sha: str
    archive_sha256: str
    root_tree_oid: str
    source_tree_sha256: str
    candidate: ValidatedCandidate
    candidate_relative_path: str
    dependency_plan: Mapping[str, object] | None
    dependency_plan_sha256: str | None
    dependency_tree_sha256: str | None
    dependency_image_id: str | None
    tool_git_sha: str
    repeats: int
    expected_outcome: str
    expected_fingerprint: str


@dataclass(frozen=True)
class V02ReplayResult:
    run_dir: Path
    result_path: Path
    outcome: str
    claim_level: str
    fingerprint: str | None


def load_v02_replay_bundle(path: Path) -> V02ReplayBundle:
    """Load one canonical, self-hashed public replay bundle."""

    encoded = _read_bounded(path)
    try:
        value = json.loads(
            encoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject("Replay bundle is invalid JSON.") from exc
    if not isinstance(value, Mapping) or encoded != _canonical(value) + b"\n":
        raise _reject("Replay bundle is not canonical JSON.")
    _exact(
        value,
        {
            "algorithm",
            "bundle_sha256",
            "candidate",
            "case",
            "dependency",
            "expected",
            "repeats",
            "schema_version",
            "source",
            "tool",
        },
        "replay bundle",
    )
    if value["schema_version"] != "0.1.0" or value["algorithm"] != REPLAY_BUNDLE_ALGORITHM:
        raise _reject("Replay bundle identity is invalid.")
    observed_sha = _digest(value["bundle_sha256"], "replay bundle")
    if observed_sha != _self_hash(value, "bundle_sha256"):
        raise _reject("Replay bundle digest is invalid.")

    case = _mapping(value["case"], "replay case")
    _exact(case, {"base_sha", "id", "issue_url", "repo"}, "replay case")
    case_id = _text_pattern(case["id"], _CASE_ID, "case ID")
    repo = _repo(case["repo"])
    issue_url = _text(case["issue_url"], "issue URL", 500)
    issue = parse_issue_url(issue_url)
    if f"{issue.owner}/{issue.repo}" != repo:
        raise _reject("Replay issue URL and repository differ.")
    base_sha = _text_pattern(case["base_sha"], _GIT_SHA, "base SHA")

    source = _mapping(value["source"], "replay source")
    _exact(source, {"archive_sha256", "root_tree_oid", "tree_sha256"}, "replay source")
    archive_sha256 = _digest(source["archive_sha256"], "source archive")
    root_tree_oid = _text_pattern(source["root_tree_oid"], _GIT_SHA, "root tree OID")
    source_tree_sha256 = _digest(source["tree_sha256"], "source tree")

    candidate_record = _mapping(value["candidate"], "replay candidate")
    _exact(
        candidate_record,
        {
            "expected_symptom",
            "rationale",
            "relative_path",
            "test_content",
            "test_content_sha256",
        },
        "replay candidate",
    )
    candidate = validate_candidate_payload(
        {
            "test_content": candidate_record["test_content"],
            "expected_symptom": candidate_record["expected_symptom"],
            "rationale": candidate_record["rationale"],
        },
        issue_number=issue.number,
    )
    relative_path = _text(candidate_record["relative_path"], "candidate path", 300)
    if (
        relative_path != candidate_path(issue.number)
        or candidate_record["test_content_sha256"] != candidate.sha256
    ):
        raise _reject("Replay candidate path or digest is invalid.")

    dependency = value["dependency"]
    plan_record: Mapping[str, object] | None = None
    plan_sha256: str | None = None
    tree_sha256: str | None = None
    image_id: str | None = None
    if dependency is not None:
        dependency_record = _mapping(dependency, "replay dependency")
        _exact(
            dependency_record,
            {"image_id", "plan", "plan_sha256", "tree_sha256"},
            "replay dependency",
        )
        plan_record = _mapping(dependency_record["plan"], "dependency plan")
        plan_sha256 = _digest(dependency_record["plan_sha256"], "dependency plan")
        tree_sha256 = _digest(dependency_record["tree_sha256"], "dependency tree")
        image_id = _text_pattern(dependency_record["image_id"], _IMAGE_ID, "dependency image")
        if hashlib.sha256(_canonical(plan_record)).hexdigest() != plan_sha256:
            raise _reject("Embedded dependency plan digest is invalid.")

    tool = _mapping(value["tool"], "replay tool")
    _exact(tool, {"git_sha"}, "replay tool")
    tool_git_sha = _text_pattern(tool["git_sha"], _GIT_SHA, "tool Git SHA")
    repeats = value["repeats"]
    if type(repeats) is not int or not 2 <= repeats <= 10:
        raise _reject("Replay repeat count is invalid.")
    expected = _mapping(value["expected"], "replay expectation")
    _exact(expected, {"failure_fingerprint", "outcome"}, "replay expectation")
    expected_outcome = _text(expected["outcome"], "expected outcome", 100)
    expected_fingerprint = _digest(expected["failure_fingerprint"], "failure fingerprint")
    if expected_outcome != "repeatable_base_failure":
        raise _reject("A published replay bundle must expect repeatable_base_failure.")

    return V02ReplayBundle(
        raw=value,
        sha256=observed_sha,
        case_id=case_id,
        repo=repo,
        issue_url=issue_url,
        base_sha=base_sha,
        archive_sha256=archive_sha256,
        root_tree_oid=root_tree_oid,
        source_tree_sha256=source_tree_sha256,
        candidate=candidate,
        candidate_relative_path=relative_path,
        dependency_plan=plan_record,
        dependency_plan_sha256=plan_sha256,
        dependency_tree_sha256=tree_sha256,
        dependency_image_id=image_id,
        tool_git_sha=tool_git_sha,
        repeats=repeats,
        expected_outcome=expected_outcome,
        expected_fingerprint=expected_fingerprint,
    )


def run_v02_replay_bundle(bundle_path: Path, *, run_base: Path) -> V02ReplayResult:
    """Reacquire exact source, rebuild locked dependencies, and rerun the candidate."""

    bundle = load_v02_replay_bundle(bundle_path)
    issue = parse_issue_url(bundle.issue_url)
    run_dir = create_private_run_dir(run_base, prefix="v02-replay-")
    archive_path: Path | None = None
    extraction_path: Path | None = None
    sandbox: DockerSandbox | None = None
    try:
        commit = fetch_commit_tree_metadata(issue.owner, issue.repo, bundle.base_sha)
        if commit.commit_sha != bundle.base_sha or commit.tree_sha != bundle.root_tree_oid:
            raise _reject("Remote commit metadata differs from the replay bundle.")
        archive = download_source_archive(issue.owner, issue.repo, bundle.base_sha, run_dir)
        archive_path = archive.path
        if archive.sha256 != bundle.archive_sha256:
            raise _reject("Downloaded source archive differs from the replay bundle.")
        extracted = extract_source_archive(archive.path, run_dir)
        extraction_path = extracted.destination
        source = attest_source_tree(
            extracted.source_root,
            expected_git_tree_oid=bundle.root_tree_oid,
        )
        if (
            source.tree_sha256 != bundle.source_tree_sha256
            or extracted.file_count != source.file_count
            or extracted.unpacked_bytes != source.total_bytes
        ):
            raise _reject("Exact source tree differs from the replay bundle.")
        with tempfile.TemporaryDirectory(prefix="candidate-", dir=run_dir) as temporary:
            prepared = prepare_candidate_workspace(
                source=extracted.source_root,
                destination=Path(temporary).resolve(strict=True) / "workspace",
                relative_path=bundle.candidate_relative_path,
                candidate=bundle.candidate,
                expected_pristine=source,
            )
            if bundle.dependency_plan is None:
                sandbox = DockerSandbox()
                sandbox.require_ready()
                outcome = verify_candidate(
                    sandbox=sandbox,
                    source=prepared.path,
                    relative_path=bundle.candidate_relative_path,
                    candidate=bundle.candidate,
                    expected_source_tree=prepared.candidate_applied_tree,
                    run_id=f"v02-replay-{uuid.uuid4().hex}",
                    repeats=bundle.repeats,
                )
                dependency_result = None
            else:
                plan_path = run_dir / "dependency-plan.json"
                write_bytes_exclusive(plan_path, _canonical(bundle.dependency_plan) + b"\n")
                plan = load_dependency_plan(plan_path)
                _bind_dependency_plan(bundle, plan)
                sandbox = DockerSandbox(SandboxPolicy(image=plan.runner_image))
                sandbox.require_ready()
                with DependencyExecutor(plan_path, policy=sandbox.policy) as executor:
                    execution = executor.prepare(tool_git_sha=bundle.tool_git_sha)
                    if (
                        execution.image_id != bundle.dependency_image_id
                        or execution.dependency_tree.tree_sha256 != bundle.dependency_tree_sha256
                    ):
                        raise _reject("Rebuilt dependency evidence differs from the replay bundle.")
                    outcome = verify_candidate(
                        sandbox=sandbox,
                        source=prepared.path,
                        relative_path=bundle.candidate_relative_path,
                        candidate=bundle.candidate,
                        expected_source_tree=prepared.candidate_applied_tree,
                        run_id=f"v02-replay-{uuid.uuid4().hex}",
                        repeats=bundle.repeats,
                        dependency_handle=execution.dependency_handle,
                    )
                    dependency_result = {
                        "execution_receipt_sha256": (
                            execution.dependency_handle.execution_receipt_sha256
                        ),
                        "image_id": execution.image_id,
                        "plan_sha256": plan.canonical_sha256,
                        "tree_sha256": execution.dependency_tree.tree_sha256,
                    }
        _require_expected_outcome(bundle, outcome)
        result = _result_record(bundle, source.tree_sha256, outcome, dependency_result)
        result_path = run_dir / "reproassert-v02-replay-result.json"
        write_bytes_exclusive(result_path, _canonical(result) + b"\n")
        return V02ReplayResult(
            run_dir=run_dir,
            result_path=result_path,
            outcome=outcome.outcome,
            claim_level=outcome.claim_level.value,
            fingerprint=outcome.fingerprint,
        )
    finally:
        if sandbox is not None:
            sandbox.cleanup()
        if extraction_path is not None:
            shutil.rmtree(extraction_path, ignore_errors=True)
        if archive_path is not None:
            archive_path.unlink(missing_ok=True)


def _bind_dependency_plan(bundle: V02ReplayBundle, plan: DependencyPlan) -> None:
    if (
        plan.runner_image != DEFAULT_IMAGE
        or plan.case_id != bundle.case_id
        or plan.base_sha != bundle.base_sha
        or plan.source_tree_sha256 != bundle.source_tree_sha256
        or plan.canonical_sha256 != bundle.dependency_plan_sha256
    ):
        raise _reject(
            "Dependency plan differs from the trusted runner, exact replay source, or case."
        )


def _require_expected_outcome(bundle: V02ReplayBundle, outcome: VerificationOutcome) -> None:
    if (
        outcome.outcome != bundle.expected_outcome
        or outcome.fingerprint != bundle.expected_fingerprint
        or outcome.accepted is not True
    ):
        raise _reject("Replay result differs from the published expected failure.")


def _result_record(
    bundle: V02ReplayBundle,
    source_tree_sha256: str,
    outcome: VerificationOutcome,
    dependency: Mapping[str, object] | None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "algorithm": REPLAY_RESULT_ALGORITHM,
        "bundle_sha256": bundle.sha256,
        "candidate_sha256": bundle.candidate.sha256,
        "case_id": bundle.case_id,
        "claim_level": outcome.claim_level.value,
        "collection": _run_record(outcome.collection),
        "declared_tool_git_sha": bundle.tool_git_sha,
        "dependency": dependency,
        "failure_fingerprint": outcome.fingerprint,
        "outcome": outcome.outcome,
        "runs": [_run_record(run) for run in outcome.runs],
        "schema_version": "0.1.0",
        "source_tree_sha256": source_tree_sha256,
    }
    record["result_sha256"] = hashlib.sha256(_canonical(record)).hexdigest()
    return record


def _run_record(run: DockerRunResult) -> dict[str, object]:
    return {
        "argv": list(run.argv),
        "duration_seconds": run.duration_seconds,
        "exit_code": run.exit_code,
        "junit_sha256": (
            hashlib.sha256(run.junit_xml).hexdigest() if run.junit_xml is not None else None
        ),
        "oom_killed": run.oom_killed,
        "output_sha256": hashlib.sha256(run.output.encode("utf-8")).hexdigest(),
        "output_truncated": run.output_truncated,
        "phase": run.phase,
        "timed_out": run.timed_out,
    }


def _read_bounded(path: Path) -> bytes:
    with open_regular_file(Path(path)) as stream:
        encoded = stream.read(MAX_REPLAY_BUNDLE_BYTES + 1)
    if len(encoded) > MAX_REPLAY_BUNDLE_BYTES:
        raise _reject("Replay bundle exceeds its size limit.")
    return encoded


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _self_hash(value: Mapping[str, object], field: str) -> str:
    unsigned = dict(value)
    unsigned.pop(field, None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"invalid JSON constant: {value}")


def _exact(value: Mapping[str, object], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise _reject(f"{label.capitalize()} fields are not exact.")


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _reject(f"{label.capitalize()} is invalid.")
    return cast(Mapping[str, object], value)


def _text(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or "\x00" in value:
        raise _reject(f"{label.capitalize()} is invalid.")
    return value


def _text_pattern(value: object, pattern: re.Pattern[str], label: str) -> str:
    text = _text(value, label, 500)
    if pattern.fullmatch(text) is None:
        raise _reject(f"{label.capitalize()} is invalid.")
    return text


def _digest(value: object, label: str) -> str:
    return _text_pattern(value, _SHA256, label)


def _repo(value: object) -> str:
    text = _text(value, "repository", 200)
    parts = text.split("/")
    if len(parts) != 2 or any(re.fullmatch(r"[A-Za-z0-9_.-]+", part) is None for part in parts):
        raise _reject("Repository identity is invalid.")
    return text


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("v02_replay_bundle", message)
