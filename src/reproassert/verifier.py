from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from defusedxml import ElementTree

from reproassert.candidate import MAX_TEST_BYTES, ValidatedCandidate, validate_candidate_payload
from reproassert.errors import PolicyRejection
from reproassert.models import ClaimLevel
from reproassert.safeio import open_regular_file
from reproassert.sandbox import DockerRunResult, DockerSandbox
from reproassert.source_attestation import SourceTreeAttestation, attest_source_tree

_DYNAMIC_HEX = re.compile(r"0x[0-9a-fA-F]+")
_DYNAMIC_PATH = re.compile(r"/(?:tmp|private/tmp)/[^\s:]+")
_DURATION = re.compile(r"\b\d+(?:\.\d+)?s\b")
_EXCEPTION_HEADER = re.compile(r"^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*):(?:\s|$)")


@dataclass(frozen=True)
class JunitCase:
    name: str
    classname: str
    failure_type: str | None
    failure_message: str
    failure_text: str


@dataclass(frozen=True)
class JunitSummary:
    tests: int
    failures: int
    errors: int
    skipped: int
    cases: tuple[JunitCase, ...]


@dataclass(frozen=True)
class VerificationOutcome:
    accepted: bool
    claim_level: ClaimLevel
    outcome: str
    fingerprint: str | None
    collection: DockerRunResult
    runs: tuple[DockerRunResult, ...]
    candidate_sha256: str | None = None
    executed_tree_sha256: str | None = None


def verify_candidate(
    *,
    sandbox: DockerSandbox,
    source: Path,
    relative_path: str,
    candidate: ValidatedCandidate,
    expected_source_tree: SourceTreeAttestation,
    run_id: str,
    repeats: int = 3,
) -> VerificationOutcome:
    if repeats < 2 or repeats > 10:
        raise ValueError("repeats must be between 2 and 10")
    issue_number = _candidate_issue_number(relative_path, candidate.test_function)
    revalidated = validate_candidate_payload(
        {
            "test_content": candidate.test_content,
            "expected_symptom": candidate.expected_symptom,
            "rationale": candidate.rationale,
        },
        issue_number=issue_number,
    )
    if revalidated != candidate:
        raise PolicyRejection(
            "verification_candidate", "Candidate differs from strict policy revalidation."
        )
    target_path = source.joinpath(*relative_path.split("/"))
    _require_candidate_bytes(target_path, candidate.test_content.encode("utf-8"))
    source_tree = attest_source_tree(source)
    if source_tree != expected_source_tree:
        raise PolicyRejection(
            "verification_source_tree",
            "Verification workspace differs from the controller-applied candidate tree.",
        )
    _require_candidate_bytes(target_path, candidate.test_content.encode("utf-8"))
    target = f"{relative_path}::{candidate.test_function}"
    volume = sandbox.stage_attested_source(
        source,
        run_id=run_id,
        expected=source_tree,
    )
    try:
        collection = sandbox.run_pytest(
            volume=volume,
            target=target,
            phase="collect",
            run_id=run_id,
            collect_only=True,
        )
        collection_rejection = classify_collection_run(collection, target)
        if collection_rejection:
            return VerificationOutcome(
                False,
                ClaimLevel.REJECTED,
                collection_rejection,
                None,
                collection,
                (),
                candidate.sha256,
                source_tree.tree_sha256,
            )

        runs = tuple(
            sandbox.run_pytest(
                volume=volume,
                target=target,
                phase=f"verify_{attempt}",
                run_id=run_id,
            )
            for attempt in range(1, repeats + 1)
        )
        outcome, fingerprint = classify_base_runs(
            runs,
            expected_symptom=candidate.expected_symptom,
            test_function=candidate.test_function,
        )
        accepted = outcome == "repeatable_base_failure"
        return VerificationOutcome(
            accepted,
            ClaimLevel.REPEATABLE_BASE_FAILURE if accepted else ClaimLevel.COLLECTED,
            outcome,
            fingerprint,
            collection,
            runs,
            candidate.sha256,
            source_tree.tree_sha256,
        )
    finally:
        sandbox.cleanup()


def _candidate_issue_number(relative_path: str, test_function: str) -> int:
    match = re.fullmatch(r"tests/reproassert/test_issue_([1-9][0-9]*)\.py", relative_path)
    if match is None:
        raise PolicyRejection(
            "verification_candidate_path", "Candidate path is outside the reserved test tree."
        )
    issue_number = int(match.group(1))
    if test_function != f"test_issue_{issue_number}_reproduction":
        raise PolicyRejection(
            "verification_candidate_path", "Candidate path and function do not match."
        )
    return issue_number


def _require_candidate_bytes(path: Path, expected: bytes) -> None:
    with open_regular_file(path) as stream:
        metadata = os.fstat(stream.fileno())
        content = stream.read(MAX_TEST_BYTES + 1)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or content != expected:
        raise PolicyRejection(
            "verification_candidate_changed", "Candidate bytes differ from the submitted test."
        )


def parse_junit(data: bytes | None) -> JunitSummary | None:
    if not data or len(data) > 1024 * 1024:
        return None
    try:
        root = ElementTree.fromstring(data)
    except (ElementTree.ParseError, ValueError):
        return None
    elements = list(root.iter())
    if len(elements) > 1_000:
        return None
    if root.tag == "testsuite":
        suites = [root]
    elif root.tag == "testsuites" and all(child.tag == "testsuite" for child in root):
        suites = list(root)
    else:
        return None
    if not suites:
        return None
    cases: list[JunitCase] = []
    total_tests = 0
    total_failures = 0
    total_errors = 0
    total_skipped = 0
    for suite in suites:
        counts = tuple(
            _strict_count(suite.attrib.get(name))
            for name in ("tests", "failures", "errors", "skipped")
        )
        if any(value is None for value in counts):
            return None
        tests, failures, errors, skipped = counts
        if tests is None or failures is None or errors is None or skipped is None:
            return None
        suite_cases = list(suite.findall("testcase"))
        if tests != len(suite_cases):
            return None
        observed_failures = 0
        observed_errors = 0
        observed_skipped = 0
        for case in suite_cases:
            failures_found = list(case.findall("failure"))
            errors_found = list(case.findall("error"))
            skipped_found = list(case.findall("skipped"))
            if len(failures_found) + len(errors_found) + len(skipped_found) > 1:
                return None
            failure = failures_found[0] if failures_found else None
            error = errors_found[0] if errors_found else None
            skip = skipped_found[0] if skipped_found else None
            observed_failures += int(failure is not None)
            observed_errors += int(error is not None)
            observed_skipped += int(skip is not None)
            failure_message = failure.attrib.get("message", "") if failure is not None else ""
            failure_text = failure.text or "" if failure is not None else ""
            failure_type = (
                _junit_failure_type(failure.attrib.get("type"), failure_message)
                if failure is not None
                else None
            )
            if failure is not None and failure_type is None:
                if not failure_message.strip() and not failure_text.strip():
                    return None
                failure_type = "UnknownFailure"
            cases.append(
                JunitCase(
                    name=case.attrib.get("name", ""),
                    classname=case.attrib.get("classname", ""),
                    failure_type=failure_type,
                    failure_message=failure_message,
                    failure_text=failure_text,
                )
            )
        if (failures, errors, skipped) != (
            observed_failures,
            observed_errors,
            observed_skipped,
        ):
            return None
        total_tests += tests
        total_failures += failures
        total_errors += errors
        total_skipped += skipped
    return JunitSummary(
        tests=total_tests,
        failures=total_failures,
        errors=total_errors,
        skipped=total_skipped,
        cases=tuple(cases),
    )


def classify_collection_run(run: DockerRunResult, target: str) -> str | None:
    """Return a conservative rejection code for one collection execution."""

    if run.timed_out:
        return "collect_timeout"
    if run.oom_killed:
        return "collect_oom"
    if run.output_truncated:
        return "collect_output_limit"
    if run.exit_code != 0:
        lowered = run.output.casefold()
        if "importerror" in lowered or "modulenotfounderror" in lowered:
            return "setup_failure"
        return "collect_failure"
    if target not in run.output and target.split("::", 1)[1] not in run.output:
        return "no_tests_collected"
    return None


def classify_base_runs(
    runs: tuple[DockerRunResult, ...], *, expected_symptom: str, test_function: str
) -> tuple[str, str | None]:
    """Classify repeated buggy-base executions under the strict pytest contract."""

    if any(run.timed_out for run in runs):
        return "timeout", None
    if any(run.oom_killed for run in runs):
        return "oom", None
    if any(run.output_truncated for run in runs):
        return "output_limit", None
    if all(run.exit_code == 0 for run in runs):
        return "pass_on_base", None
    if len({run.exit_code for run in runs}) != 1:
        return "flaky_base", None
    if any(run.exit_code != 1 for run in runs):
        return "generic_crash", None

    fingerprints: list[str] = []
    symptom = expected_symptom.casefold()
    for run in runs:
        summary = parse_junit(run.junit_xml)
        if summary is None:
            return "untrusted_or_missing_test_report", None
        if summary.errors:
            return "setup_or_test_error", None
        if summary.skipped:
            return "skipped_or_xfailed", None
        if summary.tests != 1 or summary.failures != 1 or len(summary.cases) != 1:
            return "unrelated_or_multiple_failure", None
        case = summary.cases[0]
        if case.name != test_function:
            return "unrelated_failure", None
        if not case.failure_type or case.failure_type.rsplit(".", 1)[-1] != "AssertionError":
            return "generic_crash", None
        evidence = f"{run.output}\n{case.failure_message}\n{case.failure_text}".casefold()
        if symptom not in evidence:
            return "wrong_failure", None
        fingerprints.append(_fingerprint(case))
    if len(set(fingerprints)) != 1:
        return "flaky_base", None
    return "repeatable_base_failure", fingerprints[0]


def _fingerprint(case: JunitCase) -> str:
    text = f"{case.failure_type or ''}\n{case.failure_message}\n{case.failure_text}"
    text = _DYNAMIC_HEX.sub("0xADDR", text)
    text = _DYNAMIC_PATH.sub("<TMP_PATH>", text)
    text = _DURATION.sub("TIME", text)
    text = "\n".join(line.strip() for line in text.splitlines() if line.strip())
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _strict_count(value: str | None) -> int | None:
    try:
        result = int(value or "")
    except ValueError:
        return None
    return result if 0 <= result <= 10_000 else None


def _junit_failure_type(declared: str | None, message: str) -> str | None:
    declared_value = declared if declared and _EXCEPTION_HEADER.fullmatch(f"{declared}:") else None
    matched = _EXCEPTION_HEADER.match(message)
    derived = matched.group(1) if matched is not None else None
    if (
        declared_value is not None
        and derived is not None
        and declared_value.rsplit(".", 1)[-1] != derived.rsplit(".", 1)[-1]
    ):
        return None
    return declared_value or derived
