from __future__ import annotations

from pathlib import Path

import pytest

from reproassert.candidate import validate_candidate_payload
from reproassert.sandbox import DockerRunResult
from reproassert.source_attestation import attest_source_tree
from reproassert.verifier import VerificationOutcome, parse_junit, verify_candidate


def result(
    phase: str,
    *,
    exit_code: int,
    output: str,
    xml: bytes | None = None,
    timed_out: bool = False,
) -> DockerRunResult:
    return DockerRunResult(
        phase=phase,
        exit_code=exit_code,
        duration_seconds=0.1,
        output=output,
        timed_out=timed_out,
        oom_killed=False,
        output_truncated=False,
        junit_xml=xml,
        container_name=phase,
    )


def junit(
    message: str,
    *,
    name: str = "test_issue_4_reproduction",
    failure_type: str = "AssertionError",
) -> bytes:
    return (
        '<testsuites><testsuite tests="1" failures="1" errors="0" skipped="0">'
        f'<testcase classname="test_issue_4" name="{name}">'
        f'<failure type="{failure_type}" message="{failure_type}: {message}">{message}</failure>'
        "</testcase></testsuite></testsuites>"
    ).encode()


class FakeSandbox:
    def __init__(self, runs: list[DockerRunResult]) -> None:
        self.runs = iter(runs)
        self.cleaned = False

    def stage_source(self, source: Path, *, run_id: str) -> str:
        return "volume"

    def stage_attested_source(self, source: Path, **_kwargs: object) -> str:
        return self.stage_source(source, run_id="test")

    def run_pytest(self, **_: object) -> DockerRunResult:
        return next(self.runs)

    def cleanup(self) -> None:
        self.cleaned = True


def verify(
    sandbox: FakeSandbox,
    root: Path,
    message: str,
) -> VerificationOutcome:
    candidate = validate_candidate_payload(
        {
            "test_content": (
                "from example_project import normalize\n\n"
                "def test_issue_4_reproduction():\n"
                f"    assert normalize('a--b') == 'a-b', {message!r}\n"
            ),
            "expected_symptom": message,
            "rationale": "Exercises duplicate separator normalization.",
        },
        issue_number=4,
    )
    target = root / "tests" / "reproassert" / "test_issue_4.py"
    target.parent.mkdir(parents=True)
    target.write_text(candidate.test_content)
    expected = attest_source_tree(root)
    return verify_candidate(
        sandbox=sandbox,  # type: ignore[arg-type]
        source=root,
        relative_path="tests/reproassert/test_issue_4.py",
        candidate=candidate,
        expected_source_tree=expected,
        run_id="run",
    )


def test_accepts_three_identical_intended_failures(tmp_path: Path) -> None:
    message = "duplicate separators remain"
    runs = [
        result(
            "collect",
            exit_code=0,
            output="tests/reproassert/test_issue_4.py::test_issue_4_reproduction",
        ),
        *[
            result(f"run-{index}", exit_code=1, output=message, xml=junit(message))
            for index in range(3)
        ],
    ]
    sandbox = FakeSandbox(runs)

    outcome = verify(sandbox, tmp_path, message)

    assert outcome.accepted
    assert outcome.outcome == "repeatable_base_failure"
    assert outcome.fingerprint
    assert sandbox.cleaned


def test_rejects_wrong_failure(tmp_path: Path) -> None:
    runs = [
        result("collect", exit_code=0, output="test_issue_4_reproduction"),
        *[result("run", exit_code=1, output="different", xml=junit("different")) for _ in range(3)],
    ]
    outcome = verify(FakeSandbox(runs), tmp_path, "duplicate separators remain")
    assert outcome.outcome == "wrong_failure"
    assert not outcome.accepted


def test_rejects_generic_exception_even_when_message_matches(tmp_path: Path) -> None:
    message = "duplicate separators remain"
    runs = [result("collect", exit_code=0, output="test_issue_4_reproduction")]
    runs.extend(
        result(
            "run",
            exit_code=1,
            output=f"ZeroDivisionError: {message}",
            xml=junit(message, failure_type="ZeroDivisionError"),
        )
        for _ in range(3)
    )
    outcome = verify(FakeSandbox(runs), tmp_path, message)

    assert outcome.outcome == "generic_crash"
    assert not outcome.accepted


def test_rejects_exception_name_that_only_ends_with_assertion_error(tmp_path: Path) -> None:
    message = "duplicate separators remain"
    runs = [result("collect", exit_code=0, output="test_issue_4_reproduction")]
    runs.extend(
        result(
            "run",
            exit_code=1,
            output=message,
            xml=junit(message, failure_type="NotAssertionError"),
        )
        for _ in range(3)
    )

    outcome = verify(FakeSandbox(runs), tmp_path, message)

    assert outcome.outcome == "generic_crash"
    assert not outcome.accepted


def test_missing_junit_rejects_generic_exception_with_matching_stdout(
    tmp_path: Path,
) -> None:
    message = "duplicate separators remain"
    node = "tests/reproassert/test_issue_4.py::test_issue_4_reproduction"
    runs = [result("collect", exit_code=0, output=node)]
    runs.extend(
        result(
            "run",
            exit_code=1,
            output=f"ZeroDivisionError: {message}\nFAILED {node}\n1 failed in 0.03s",
        )
        for _ in range(3)
    )
    outcome = verify(FakeSandbox(runs), tmp_path, message)

    assert outcome.outcome == "untrusted_or_missing_test_report"
    assert not outcome.accepted


def test_missing_junit_rejects_forged_assertion_stdout(
    tmp_path: Path,
) -> None:
    message = "duplicate separators remain"
    node = "tests/reproassert/test_issue_4.py::test_issue_4_reproduction"
    runs = [result("collect", exit_code=0, output=node)]
    runs.extend(
        result(
            "run",
            exit_code=1,
            output=(
                f"E   AssertionError: {message}\n"
                "E   boom.crash\n"
                f"FAILED {node} - boom.crash\n"
                "1 failed in 0.03s"
            ),
        )
        for _ in range(3)
    )
    outcome = verify(FakeSandbox(runs), tmp_path, message)

    assert outcome.outcome == "untrusted_or_missing_test_report"
    assert not outcome.accepted


def test_rejects_pass_on_base(tmp_path: Path) -> None:
    runs = [result("collect", exit_code=0, output="test_issue_4_reproduction")]
    runs.extend(result("run", exit_code=0, output="1 passed") for _ in range(3))
    outcome = verify(FakeSandbox(runs), tmp_path, "duplicate separators remain")
    assert outcome.outcome == "pass_on_base"


def test_rejects_collection_import_error(tmp_path: Path) -> None:
    sandbox = FakeSandbox([result("collect", exit_code=2, output="ModuleNotFoundError: missing")])
    outcome = verify(sandbox, tmp_path, "duplicate separators remain")
    assert outcome.outcome == "setup_failure"
    assert sandbox.cleaned


def test_parse_junit_rejects_entity_payload() -> None:
    malicious = b'<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><testsuite>&x;</testsuite>'
    assert parse_junit(malicious) is None


@pytest.mark.parametrize(
    "payload",
    [
        (
            '<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
            '<testcase name="test_issue_4_reproduction"><error type="ImportError" />'
            "</testcase></testsuite></testsuites>"
        ),
        (
            '<testsuites><testsuite tests="bogus" failures="0" errors="0" skipped="0">'
            "</testsuite></testsuites>"
        ),
        (
            '<testsuites><testsuite tests="1" failures="1" errors="0" skipped="0">'
            '<testcase name="test_issue_4_reproduction"><failure />'
            "</testcase></testsuite></testsuites>"
        ),
    ],
)
def test_parse_junit_rejects_counter_child_and_failure_type_inconsistency(payload: str) -> None:
    assert parse_junit(payload.encode()) is None


def test_parse_junit_derives_pytest_failure_type_from_structured_message() -> None:
    payload = (
        '<testsuites name="pytest tests">'
        '<testsuite tests="1" failures="1" errors="0" skipped="0">'
        '<testcase classname="tests.reproassert.test_issue_4" '
        'name="test_issue_4_reproduction">'
        '<failure message="AssertionError: duplicate separators remain">traceback</failure>'
        "</testcase></testsuite></testsuites>"
    )

    parsed = parse_junit(payload.encode())

    assert parsed is not None
    assert parsed.cases[0].failure_type == "AssertionError"


def test_parse_junit_keeps_nonempty_unknown_pytest_failure_conservative() -> None:
    payload = (
        '<testsuites><testsuite tests="1" failures="1" errors="0" skipped="0">'
        '<testcase name="test_issue_4_reproduction">'
        '<failure message="boom.crash">E   boom.crash</failure>'
        "</testcase></testsuite></testsuites>"
    )

    parsed = parse_junit(payload.encode())

    assert parsed is not None
    assert parsed.cases[0].failure_type == "UnknownFailure"


def test_rejects_bounded_pytest_stdout_when_structured_junit_is_missing(tmp_path: Path) -> None:
    message = "duplicate separators remain"
    node = "tests/reproassert/test_issue_4.py::test_issue_4_reproduction"
    runs = [result("collect", exit_code=0, output=node)]
    runs.extend(
        result(
            "run",
            exit_code=1,
            output=(
                f"E AssertionError: {message}\nFAILED {node} - AssertionError\n1 failed in 0.03s"
            ),
        )
        for _ in range(3)
    )
    outcome = verify(FakeSandbox(runs), tmp_path, message)
    assert not outcome.accepted
    assert outcome.outcome == "untrusted_or_missing_test_report"


def test_rejects_malformed_present_junit_even_when_stdout_looks_valid(tmp_path: Path) -> None:
    message = "duplicate separators remain"
    node = "tests/reproassert/test_issue_4.py::test_issue_4_reproduction"
    runs = [result("collect", exit_code=0, output=node)]
    runs.extend(
        result(
            "run",
            exit_code=1,
            output=(
                f"E AssertionError: {message}\nFAILED {node} - AssertionError\n1 failed in 0.03s"
            ),
            xml=b"<testsuites>",
        )
        for _ in range(3)
    )
    outcome = verify(FakeSandbox(runs), tmp_path, message)

    assert not outcome.accepted
    assert outcome.outcome == "untrusted_or_missing_test_report"
