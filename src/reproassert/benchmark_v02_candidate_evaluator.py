"""Strict, provider-disabled candidate evaluation in frozen instance images."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from defusedxml import ElementTree

from reproassert.benchmark_v02_instance_executor import (
    InstancePytestResult,
    InstanceRuntimeExecutor,
)
from reproassert.benchmark_v02_instance_runtime import (
    InstanceRuntimeManifest,
    load_instance_runtime_manifest,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, write_bytes_exclusive
from reproassert.sandbox import SandboxPolicy

SCHEMA_VERSION = "1.0.0"
ALGORITHM = "reproassert-v02-instance-candidate-evaluation-v1"
POLICY_PROFILE = "reproassert-v02-instance-candidate-evaluation-resources-v1"
MAX_CANDIDATE_BYTES = 256 * 1024
MAX_HIDDEN_PATCH_BYTES = 2 * 1024 * 1024
BASE_RUNS = 3
FIXED_RUNS = 3
RUN_ORDER: tuple[Literal["base", "fixed"], ...] = (
    "base",
    "fixed",
    "fixed",
    "base",
    "base",
    "fixed",
)

_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
_TEST_FUNCTION = re.compile(r"test_[A-Za-z_][A-Za-z0-9_]{0,199}\Z")
_INFRASTRUCTURE_MARKERS = (
    "modulenotfounderror",
    "importerror while importing test module",
    "internalerror>",
    "no tests ran",
    "collected 0 items",
    "permission denied",
    "no such file or directory",
    "network is unreachable",
    "temporary failure in name resolution",
    "name or service not known",
    "failed to establish a new connection",
    "connectionerror",
    "socket.gaierror",
)


@dataclass(frozen=True)
class CandidateArtifact:
    """Public generated test bytes; never includes production or gold oracle data."""

    relative_path: str
    content: bytes
    test_function: str | None = None


@dataclass(frozen=True)
class HiddenEvaluatorInputs:
    """Private evaluator-only oracle material."""

    production_patch: bytes
    gold_test_patch: bytes
    gold_targets: tuple[str, ...]


@dataclass(frozen=True)
class CandidateEvaluationReceipt:
    path: Path
    sha256: str
    case_id: str
    classification: str
    accepted: bool


ExecutorFactory = Callable[[InstanceRuntimeManifest, str, SandboxPolicy], InstanceRuntimeExecutor]


def evaluate_instance_candidate(
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    case_id: str,
    candidate: CandidateArtifact,
    hidden: HiddenEvaluatorInputs,
    output_path: Path,
    executed_at: str,
    tool_git_sha: str,
    executor_factory: ExecutorFactory | None = None,
) -> CandidateEvaluationReceipt:
    """Evaluate one candidate without invoking a model or exposing hidden bytes.

    The hidden gold test/fix pair first attests the evaluator environment. The candidate must then
    collect on both trees, fail in every base run, and pass in every fixed run. This establishes a
    deterministic L1 causal signal only; semantic review and all remaining L2 controls are separate.
    """

    checked_case = _case_id(case_id)
    manifest = load_instance_runtime_manifest(manifest_path)
    if manifest.sha256 != _digest(expected_manifest_sha256, "manifest commitment"):
        raise _reject("Instance runtime manifest differs from its explicit commitment.")
    matches = tuple(entry for entry in manifest.entries if entry.case_id == checked_case)
    if len(matches) != 1:
        raise _reject("Case does not bind exactly one frozen instance runtime.")
    runtime = matches[0]
    if runtime.test_command_profile != "pytest-v1":
        raise _reject("The candidate evaluator currently accepts only frozen pytest-v1 cases.")

    candidate_path, candidate_target = _candidate_contract(candidate)
    production_patch = _hidden_bytes(hidden.production_patch, "production patch")
    gold_patch = _hidden_bytes(hidden.gold_test_patch, "gold test patch")
    if (
        not isinstance(hidden.gold_targets, tuple)
        or not 1 <= len(hidden.gold_targets) <= 64
        or len(set(hidden.gold_targets)) != len(hidden.gold_targets)
    ):
        raise _reject("Hidden gold targets must be a bounded unique tuple.")

    policy = _evaluation_policy(runtime.image_id)
    factory = executor_factory or _executor_factory
    phases: dict[str, object] = {}
    classification = "controller_failure"
    accepted = False
    reason = "The evaluator did not complete all required phases."

    with factory(manifest, checked_case, policy) as executor:
        executor.acquire()
        executor.prepare_workspaces(fixed_patch=production_patch)
        executor.apply_patch(workspace="base", patch=gold_patch)
        executor.apply_patch(workspace="fixed", patch=gold_patch)

        gold_base_collect = executor.run_test_command(
            workspace="base", targets=hidden.gold_targets, collect_only=True
        )
        gold_fixed_collect = executor.run_test_command(
            workspace="fixed", targets=hidden.gold_targets, collect_only=True
        )
        phases["gold_base_collect"] = _evidence(gold_base_collect)
        phases["gold_fixed_collect"] = _evidence(gold_fixed_collect)
        _require_clean_collection(gold_base_collect, gold_fixed_collect, "hidden gold")

        gold_base = executor.run_test_command(workspace="base", targets=hidden.gold_targets)
        gold_fixed = executor.run_test_command(workspace="fixed", targets=hidden.gold_targets)
        phases["gold_base"] = _evidence(gold_base)
        phases["gold_fixed"] = _evidence(gold_fixed)
        _require_gold_pair(gold_base, gold_fixed)

    candidate_runs: list[dict[str, object]] = []
    base_results: list[InstancePytestResult] = []
    fixed_results: list[InstancePytestResult] = []
    base_fingerprints: list[str | None] = []
    for workspace in RUN_ORDER:
        # Each scored observation receives new base/fixed volumes. Nothing from a prior collect or
        # test process can survive into the next observation.
        with factory(manifest, checked_case, policy) as executor:
            executor.acquire()
            executor.prepare_workspaces(fixed_patch=production_patch)
            executor.stage_candidate(relative_path=candidate_path, content=candidate.content)
            collect = executor.run_pytest(
                workspace=workspace,
                targets=(candidate_target,),
                collect_only=True,
            )
            _require_clean_collection(collect, collect, "candidate")
            result = executor.run_pytest(workspace=workspace, targets=(candidate_target,))
            fingerprint = _candidate_fingerprint_or_none(result)
            candidate_runs.append(
                {
                    "collection": _evidence(collect),
                    "failure_fingerprint_sha256": fingerprint,
                    "result": _evidence(result),
                    "workspace": workspace,
                }
            )
            if workspace == "base":
                base_results.append(result)
                base_fingerprints.append(fingerprint)
            else:
                fixed_results.append(result)
    phases["candidate_runs"] = candidate_runs
    classification, accepted, reason = _classify_candidate(
        tuple(base_results), tuple(fixed_results), tuple(base_fingerprints)
    )

    candidate_sha256 = hashlib.sha256(candidate.content).hexdigest()
    record: dict[str, object] = {
        "algorithm": ALGORITHM,
        "benchmark_version": "0.2",
        "case_id": checked_case,
        "candidate": {
            "bytes": len(candidate.content),
            "relative_path": candidate_path,
            "sha256": candidate_sha256,
            "target": candidate_target,
        },
        "causal_controls": {
            "candidate_on_fixed": "pass" if accepted else "fail",
            "l2_causal_controls_passed": False,
            "remaining_required_controls": [
                "fix_minus_issue_relevant_hunks",
                "base_plus_issue_relevant_hunks",
            ],
            "semantic_review_required": True,
        },
        "claims": {
            "hidden_bytes_emitted": False,
            "model_or_provider_invoked": False,
            "network_during_sandbox_execution": False,
            "provider_calls": 0,
        },
        "executed_at": _timestamp(executed_at),
        "hidden_inputs": {
            "gold_target_count": len(hidden.gold_targets),
            "gold_targets_sha256": _sha256_json(list(hidden.gold_targets)),
            "gold_test_patch_bytes": len(gold_patch),
            "gold_test_patch_sha256": hashlib.sha256(gold_patch).hexdigest(),
            "production_patch_bytes": len(production_patch),
            "production_patch_sha256": hashlib.sha256(production_patch).hexdigest(),
        },
        "inputs": {"instance_runtime_manifest_sha256": manifest.sha256},
        "outcome": {
            "accepted": accepted,
            "base_consistency": f"{sum(r.exit_code == 1 for r in base_results)}/{BASE_RUNS}",
            "classification": classification,
            "fixed_consistency": f"{sum(r.exit_code == 0 for r in fixed_results)}/{FIXED_RUNS}",
            "reason": reason,
        },
        "phases": phases,
        "policy": {
            "base_runs": BASE_RUNS,
            "fixed_runs": FIXED_RUNS,
            "profile": POLICY_PROFILE,
            "sandbox": {
                "capabilities": "drop_all",
                "network_mode": "none",
                "no_new_privileges": True,
                "read_only_root": True,
                "test_user": "65532:65532",
            },
        },
        "receipt_sha256": "0" * 64,
        "schema_version": SCHEMA_VERSION,
        "tool_git_sha": _git_sha(tool_git_sha),
    }
    record["receipt_sha256"] = _self_hash(record)
    encoded = _canonical(record) + b"\n"
    write_bytes_exclusive(output_path, encoded)
    return CandidateEvaluationReceipt(
        path=output_path,
        sha256=hashlib.sha256(encoded).hexdigest(),
        case_id=checked_case,
        classification=classification,
        accepted=accepted,
    )


def verify_instance_candidate_receipt(path: Path) -> CandidateEvaluationReceipt:
    """Verify canonical encoding, self-commitment, redaction claims, and outcome invariants."""

    with open_regular_file(path) as stream:
        raw = stream.read(512 * 1024 + 1)
    if len(raw) > 512 * 1024:
        raise _reject("Candidate evaluation receipt exceeds the verifier limit.")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _reject("Candidate evaluation receipt is invalid JSON.") from exc
    if not isinstance(value, dict) or raw != _canonical(value) + b"\n":
        raise _reject("Candidate evaluation receipt is not canonical JSON.")
    required = {
        "algorithm",
        "benchmark_version",
        "case_id",
        "candidate",
        "causal_controls",
        "claims",
        "executed_at",
        "hidden_inputs",
        "inputs",
        "outcome",
        "phases",
        "policy",
        "receipt_sha256",
        "schema_version",
        "tool_git_sha",
    }
    if (
        set(value) != required
        or value.get("algorithm") != ALGORITHM
        or value.get("benchmark_version") != "0.2"
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("receipt_sha256") != _self_hash(value)
    ):
        raise _reject("Candidate evaluation receipt identity is invalid.")
    case_id = _case_id(value.get("case_id"))
    _timestamp(value.get("executed_at"))
    _git_sha(value.get("tool_git_sha"))
    claims = value.get("claims")
    if claims != {
        "hidden_bytes_emitted": False,
        "model_or_provider_invoked": False,
        "network_during_sandbox_execution": False,
        "provider_calls": 0,
    }:
        raise _reject("Candidate evaluation trust claims are invalid.")
    outcome = value.get("outcome")
    controls = value.get("causal_controls")
    if not isinstance(outcome, dict) or not isinstance(controls, dict):
        raise _reject("Candidate evaluation outcome is invalid.")
    accepted = outcome.get("accepted") is True
    if accepted != (outcome.get("classification") == "verified_reproduction"):
        raise _reject("Candidate acceptance and classification disagree.")
    if controls.get("l2_causal_controls_passed") is not False:
        raise _reject("An individual candidate receipt cannot assert completed L2 controls.")
    if set(controls) != {
        "candidate_on_fixed",
        "l2_causal_controls_passed",
        "remaining_required_controls",
        "semantic_review_required",
    } or controls.get("remaining_required_controls") != [
        "fix_minus_issue_relevant_hunks",
        "base_plus_issue_relevant_hunks",
    ]:
        raise _reject("Candidate causal-control projection is invalid.")
    if controls.get("semantic_review_required") is not True or controls.get(
        "candidate_on_fixed"
    ) != ("pass" if accepted else "fail"):
        raise _reject("Candidate causal-control outcome is invalid.")
    candidate = value.get("candidate")
    hidden = value.get("hidden_inputs")
    if not isinstance(candidate, dict) or not isinstance(hidden, dict):
        raise _reject("Candidate evaluation commitments are invalid.")
    _digest(candidate.get("sha256"), "candidate")
    _digest(hidden.get("gold_targets_sha256"), "gold targets")
    _digest(hidden.get("gold_test_patch_sha256"), "gold test patch")
    _digest(hidden.get("production_patch_sha256"), "production patch")
    policy = value.get("policy")
    if policy != {
        "base_runs": BASE_RUNS,
        "fixed_runs": FIXED_RUNS,
        "profile": POLICY_PROFILE,
        "sandbox": {
            "capabilities": "drop_all",
            "network_mode": "none",
            "no_new_privileges": True,
            "read_only_root": True,
            "test_user": "65532:65532",
        },
    }:
        raise _reject("Candidate evaluation policy is invalid.")
    phases = value.get("phases")
    if not isinstance(phases, dict) or set(phases) != {
        "gold_base_collect",
        "gold_fixed_collect",
        "gold_base",
        "gold_fixed",
        "candidate_runs",
    }:
        raise _reject("Candidate evaluation phases are invalid.")
    for name in (
        "gold_base_collect",
        "gold_fixed_collect",
        "gold_base",
        "gold_fixed",
    ):
        _verify_evidence(phases[name])
    runs = phases["candidate_runs"]
    if not isinstance(runs, list) or len(runs) != len(RUN_ORDER):
        raise _reject("Candidate repeat evidence is invalid.")
    if [run.get("workspace") if isinstance(run, dict) else None for run in runs] != list(RUN_ORDER):
        raise _reject("Candidate repeat order is invalid.")
    base_fingerprints: list[str] = []
    for run in runs:
        if not isinstance(run, dict) or set(run) != {
            "collection",
            "failure_fingerprint_sha256",
            "result",
            "workspace",
        }:
            raise _reject("Candidate run evidence is invalid.")
        _verify_evidence(run["collection"])
        _verify_evidence(run["result"])
        fingerprint = run["failure_fingerprint_sha256"]
        if run["workspace"] == "base":
            if fingerprint is None and not accepted:
                continue
            base_fingerprints.append(_digest(fingerprint, "base failure fingerprint"))
        elif fingerprint is not None and accepted:
            raise _reject("Fixed candidate run contains a failure fingerprint.")
    if accepted and len(set(base_fingerprints)) != 1:
        raise _reject("Accepted candidate base fingerprints are inconsistent.")
    return CandidateEvaluationReceipt(
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        case_id=case_id,
        classification=str(outcome.get("classification")),
        accepted=accepted,
    )


def _classify_candidate(
    base: tuple[InstancePytestResult, ...],
    fixed: tuple[InstancePytestResult, ...],
    base_fingerprints: tuple[str | None, ...],
) -> tuple[str, bool, str]:
    all_results = (*base, *fixed)
    if any(result.timed_out for result in all_results):
        return "timeout", False, "At least one bounded candidate run timed out."
    if any(result.oom_killed for result in all_results):
        return "oom_killed", False, "At least one candidate sandbox exceeded its memory limit."
    if any(result.output_truncated for result in all_results):
        return "output_limit", False, "At least one candidate run exceeded the output limit."
    if any(_has_infrastructure_marker(result.output) for result in all_results):
        return (
            "infrastructure_failure",
            False,
            "Candidate output contains a setup or infrastructure failure.",
        )
    if any(result.exit_code not in {0, 1} for result in all_results):
        return "generic_crash", False, "Candidate produced a non-test pytest exit code."
    base_codes = {result.exit_code for result in base}
    fixed_codes = {result.exit_code for result in fixed}
    if len(base_codes) != 1 or len(fixed_codes) != 1:
        return "flaky", False, "Repeated candidate outcomes were inconsistent."
    if base_codes != {1}:
        return "does_not_fail_on_base", False, "Candidate did not fail on every buggy-base run."
    if fixed_codes != {0}:
        return "does_not_pass_on_fixed", False, "Candidate did not pass on every fixed-tree run."
    if None in base_fingerprints or len(set(base_fingerprints)) != 1:
        return (
            "wrong_or_flaky_failure",
            False,
            "Base runs did not preserve one normalized failure fingerprint.",
        )
    return (
        "verified_reproduction",
        True,
        "Candidate collected and failed 3/3 on base and passed 3/3 on fixed.",
    )


def _require_clean_collection(
    base: InstancePytestResult, fixed: InstancePytestResult, label: str
) -> None:
    for result in (base, fixed):
        if result.timed_out or result.output_truncated or result.exit_code != 0:
            raise _reject(f"{label.capitalize()} collection did not complete cleanly.")
        if _has_infrastructure_marker(result.output):
            raise _reject(
                f"{label.capitalize()} collection contains infrastructure failure evidence."
            )


def _require_gold_pair(base: InstancePytestResult, fixed: InstancePytestResult) -> None:
    if any(result.timed_out or result.output_truncated for result in (base, fixed)):
        raise _reject("Hidden gold execution exceeded a runtime bound.")
    if any(_has_infrastructure_marker(result.output) for result in (base, fixed)):
        raise _reject("Hidden gold execution contains infrastructure failure evidence.")
    if base.exit_code != 1 or fixed.exit_code != 0:
        raise _reject("Hidden gold tests do not attest the frozen buggy/fixed pair.")


def _candidate_contract(candidate: CandidateArtifact) -> tuple[str, str]:
    if not isinstance(candidate.content, bytes) or not (
        1 <= len(candidate.content) <= MAX_CANDIDATE_BYTES
    ):
        raise _reject("Candidate content is empty or exceeds the byte limit.")
    try:
        source = candidate.content.decode("utf-8")
        ast.parse(source)
    except (UnicodeDecodeError, SyntaxError, ValueError) as exc:
        raise _reject("Candidate must be valid UTF-8 Python syntax.") from exc
    path = PurePosixPath(candidate.relative_path)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.suffix != ".py"
        or not path.name.startswith("test_")
        or (path.parts[0] not in {"tests", "test"} and len(path.parts) != 1)
    ):
        raise _reject("Candidate path must be a safe pytest test_*.py path.")
    function = candidate.test_function
    if not isinstance(function, str) or _TEST_FUNCTION.fullmatch(function) is None:
        raise _reject("Candidate must name exactly one valid pytest test function.")
    text = path.as_posix()
    return text, f"{text}::{function}"


def _hidden_bytes(value: bytes, label: str) -> bytes:
    if not isinstance(value, bytes) or not 1 <= len(value) <= MAX_HIDDEN_PATCH_BYTES:
        raise _reject(f"Hidden {label} is empty or exceeds the evaluator limit.")
    return value


def _evidence(result: InstancePytestResult) -> dict[str, object]:
    encoded = result.output.encode("utf-8", errors="replace")
    return {
        "exit_code": result.exit_code,
        "output_bytes": len(encoded),
        "output_sha256": hashlib.sha256(encoded).hexdigest(),
        "junit_sha256": (
            hashlib.sha256(result.junit_xml).hexdigest() if result.junit_xml is not None else None
        ),
        "oom_killed": result.oom_killed,
        "output_stored": False,
        "output_truncated": result.output_truncated,
        "timed_out": result.timed_out,
    }


def _junit_fingerprint(result: InstancePytestResult, *, expected_failure: bool) -> str | None:
    if result.junit_xml is None:
        raise _reject("Candidate execution did not return required JUnit evidence.")
    try:
        root = ElementTree.fromstring(result.junit_xml)
    except (ElementTree.ParseError, ValueError) as exc:
        raise _reject("Candidate JUnit evidence is invalid XML.") from exc
    testcases = list(root.iter("testcase"))
    if len(testcases) != 1:
        raise _reject("Candidate JUnit evidence does not contain exactly one test case.")
    testcase = testcases[0]
    failures = list(testcase.findall("failure"))
    errors = list(testcase.findall("error"))
    skipped = list(testcase.findall("skipped"))
    if errors or skipped or len(failures) != (1 if expected_failure else 0):
        raise _reject("Candidate JUnit outcome is not one clean assertion result.")
    if not expected_failure:
        return None
    failure = failures[0]
    raw = "\n".join((failure.get("type") or "", failure.get("message") or "", failure.text or ""))
    normalized = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", raw)
    normalized = re.sub(r"[ \t]+", " ", normalized).strip()
    if not normalized:
        raise _reject("Candidate base failure has no attributable assertion evidence.")
    return hashlib.sha256(normalized.encode()).hexdigest()


def _candidate_fingerprint_or_none(result: InstancePytestResult) -> str | None:
    if (
        result.timed_out
        or result.oom_killed
        or result.output_truncated
        or _has_infrastructure_marker(result.output)
        or result.exit_code not in {0, 1}
    ):
        return None
    return _junit_fingerprint(result, expected_failure=result.exit_code == 1)


def _verify_evidence(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "exit_code",
        "junit_sha256",
        "oom_killed",
        "output_bytes",
        "output_sha256",
        "output_stored",
        "output_truncated",
        "timed_out",
    }:
        raise _reject("Candidate phase evidence is invalid.")
    exit_code = value.get("exit_code")
    output_bytes = value.get("output_bytes")
    if (
        type(exit_code) is not int
        or not 0 <= exit_code <= 255
        or type(output_bytes) is not int
        or not 0 <= output_bytes <= 2 * 1024 * 1024
        or value.get("output_stored") is not False
        or type(value.get("oom_killed")) is not bool
        or type(value.get("output_truncated")) is not bool
        or type(value.get("timed_out")) is not bool
    ):
        raise _reject("Candidate phase evidence values are invalid.")
    _digest(value.get("output_sha256"), "phase output")
    junit_sha256 = value.get("junit_sha256")
    if junit_sha256 is not None:
        _digest(junit_sha256, "JUnit")


def _has_infrastructure_marker(output: str) -> bool:
    lowered = output.lower()
    return any(marker in lowered for marker in _INFRASTRUCTURE_MARKERS)


def _evaluation_policy(image: str) -> SandboxPolicy:
    return SandboxPolicy(
        image=image,
        timeout_seconds=600.0,
        max_output_bytes=2 * 1024 * 1024,
        memory_bytes=4 * 1024 * 1024 * 1024,
        cpus=2.0,
        pids=512,
        tmpfs_bytes=512 * 1024 * 1024,
        tmpfs_inodes=32_768,
    )


def _executor_factory(
    manifest: InstanceRuntimeManifest, case_id: str, policy: SandboxPolicy
) -> InstanceRuntimeExecutor:
    return InstanceRuntimeExecutor(manifest, case_id=case_id, policy=policy)


def _case_id(value: object) -> str:
    if not isinstance(value, str) or _CASE_ID.fullmatch(value) is None:
        raise _reject("Case ID is invalid.")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _reject(f"{label.capitalize()} SHA-256 is invalid.")
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject("Execution timestamp is invalid.")
    return value


def _git_sha(value: object) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject("Tool Git SHA is invalid.")
    return value


def _self_hash(record: dict[str, object]) -> str:
    unsigned = dict(record)
    unsigned["receipt_sha256"] = "0" * 64
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_candidate_evaluator", message)
