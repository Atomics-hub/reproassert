from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from defusedxml import ElementTree

from reproassert.models import ClaimLevel
from reproassert.sandbox import DockerRunResult, DockerSandbox

_DYNAMIC_HEX = re.compile(r"0x[0-9a-fA-F]+")
_DYNAMIC_PATH = re.compile(r"/(?:tmp|private/tmp)/[^\s:]+")
_DURATION = re.compile(r"\b\d+(?:\.\d+)?s\b")


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


def verify_candidate(
    *,
    sandbox: DockerSandbox,
    source: Path,
    relative_path: str,
    test_function: str,
    expected_symptom: str,
    run_id: str,
    repeats: int = 3,
) -> VerificationOutcome:
    if repeats < 2 or repeats > 10:
        raise ValueError("repeats must be between 2 and 10")
    target = f"{relative_path}::{test_function}"
    volume = sandbox.stage_source(source, run_id=run_id)
    try:
        collection = sandbox.run_pytest(
            volume=volume,
            target=target,
            phase="collect",
            run_id=run_id,
            collect_only=True,
        )
        collection_rejection = _collection_rejection(collection, target)
        if collection_rejection:
            return VerificationOutcome(
                False,
                ClaimLevel.REJECTED,
                collection_rejection,
                None,
                collection,
                (),
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
        outcome, fingerprint = _classify_runs(
            runs, expected_symptom=expected_symptom, test_function=test_function
        )
        accepted = outcome == "repeatable_base_failure"
        return VerificationOutcome(
            accepted,
            ClaimLevel.REPEATABLE_BASE_FAILURE if accepted else ClaimLevel.COLLECTED,
            outcome,
            fingerprint,
            collection,
            runs,
        )
    finally:
        sandbox.cleanup()


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
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    if not suites:
        return None
    cases: list[JunitCase] = []
    for suite in suites:
        for case in suite.findall("testcase"):
            failure = case.find("failure")
            cases.append(
                JunitCase(
                    name=case.attrib.get("name", ""),
                    classname=case.attrib.get("classname", ""),
                    failure_type=failure.attrib.get("type") if failure is not None else None,
                    failure_message=failure.attrib.get("message", "")
                    if failure is not None
                    else "",
                    failure_text=failure.text or "" if failure is not None else "",
                )
            )
    return JunitSummary(
        tests=sum(_safe_count(suite.attrib.get("tests")) for suite in suites),
        failures=sum(_safe_count(suite.attrib.get("failures")) for suite in suites),
        errors=sum(_safe_count(suite.attrib.get("errors")) for suite in suites),
        skipped=sum(_safe_count(suite.attrib.get("skipped")) for suite in suites),
        cases=tuple(cases),
    )


def _collection_rejection(run: DockerRunResult, target: str) -> str | None:
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


def _classify_runs(
    runs: tuple[DockerRunResult, ...], *, expected_symptom: str, test_function: str
) -> tuple[str, str | None]:
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
            stdout_outcome, stdout_fingerprint = _classify_pytest_stdout(
                run.output,
                expected_symptom=expected_symptom,
                test_function=test_function,
            )
            if stdout_outcome is not None:
                return stdout_outcome, None
            if stdout_fingerprint is None:
                return "untrusted_or_missing_test_report", None
            fingerprints.append(stdout_fingerprint)
            continue
        if summary.errors:
            return "setup_or_test_error", None
        if summary.skipped:
            return "skipped_or_xfailed", None
        if summary.tests != 1 or summary.failures != 1 or len(summary.cases) != 1:
            return "unrelated_or_multiple_failure", None
        case = summary.cases[0]
        if case.name != test_function:
            return "unrelated_failure", None
        if not case.failure_type or not case.failure_type.endswith("AssertionError"):
            return "generic_crash", None
        evidence = f"{run.output}\n{case.failure_message}\n{case.failure_text}".casefold()
        if symptom not in evidence:
            return "wrong_failure", None
        fingerprints.append(_fingerprint(case))
    if len(set(fingerprints)) != 1:
        return "flaky_base", None
    return "repeatable_base_failure", fingerprints[0]


def _classify_pytest_stdout(
    output: str, *, expected_symptom: str, test_function: str
) -> tuple[str | None, str | None]:
    """Conservative fallback when tmpfs-backed JUnit data cannot leave the container."""

    lowered = output.casefold()
    if "error collecting" in lowered or " errors " in lowered or " error " in lowered:
        return "setup_or_test_error", None
    if " skipped" in lowered or " xfailed" in lowered or " xpassed" in lowered:
        return "skipped_or_xfailed", None
    node_marker = f"::{test_function}"
    failure_summaries = [line.strip() for line in output.splitlines() if line.startswith("FAILED ")]
    if (
        len(failure_summaries) != 1
        or node_marker not in failure_summaries[0]
        or "1 failed" not in lowered
    ):
        return "unrelated_or_multiple_failure", None
    exception_headers = re.findall(
        r"^E\s+([^\W\d]\w*(?:\.[^\W\d]\w*)*)(?:\s*:|\s*$)",
        output,
        flags=re.MULTILINE,
    )
    exception_types = {header.rsplit(".", 1)[-1] for header in exception_headers}
    if exception_types != {"AssertionError"}:
        return "generic_crash", None
    if expected_symptom.casefold() not in lowered:
        return "wrong_failure", None
    normalized = _normalize_failure_text(output)
    return None, hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _fingerprint(case: JunitCase) -> str:
    text = f"{case.failure_type or ''}\n{case.failure_message}\n{case.failure_text}"
    text = _DYNAMIC_HEX.sub("0xADDR", text)
    text = _DYNAMIC_PATH.sub("<TMP_PATH>", text)
    text = _DURATION.sub("TIME", text)
    text = "\n".join(line.strip() for line in text.splitlines() if line.strip())
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _normalize_failure_text(text: str) -> str:
    text = _DYNAMIC_HEX.sub("0xADDR", text)
    text = _DYNAMIC_PATH.sub("<TMP_PATH>", text)
    text = _DURATION.sub("TIME", text)
    return "\n".join(line.rstrip() for line in text.splitlines() if line.strip())


def _safe_count(value: str | None) -> int:
    try:
        result = int(value or "0")
    except ValueError:
        return 0
    return result if 0 <= result <= 10_000 else 0
