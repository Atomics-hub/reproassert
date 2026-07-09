from __future__ import annotations

from pathlib import Path

from reproassert.sandbox import DockerRunResult
from reproassert.verifier import parse_junit, verify_candidate


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

    def run_pytest(self, **_: object) -> DockerRunResult:
        return next(self.runs)

    def cleanup(self) -> None:
        self.cleaned = True


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

    outcome = verify_candidate(
        sandbox=sandbox,  # type: ignore[arg-type]
        source=tmp_path,
        relative_path="tests/reproassert/test_issue_4.py",
        test_function="test_issue_4_reproduction",
        expected_symptom=message,
        run_id="run",
    )

    assert outcome.accepted
    assert outcome.outcome == "repeatable_base_failure"
    assert outcome.fingerprint
    assert sandbox.cleaned


def test_rejects_wrong_failure(tmp_path: Path) -> None:
    runs = [
        result("collect", exit_code=0, output="test_issue_4_reproduction"),
        *[result("run", exit_code=1, output="different", xml=junit("different")) for _ in range(3)],
    ]
    outcome = verify_candidate(
        sandbox=FakeSandbox(runs),  # type: ignore[arg-type]
        source=tmp_path,
        relative_path="tests/reproassert/test_issue_4.py",
        test_function="test_issue_4_reproduction",
        expected_symptom="duplicate separators remain",
        run_id="run",
    )
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
    outcome = verify_candidate(
        sandbox=FakeSandbox(runs),  # type: ignore[arg-type]
        source=tmp_path,
        relative_path="tests/reproassert/test_issue_4.py",
        test_function="test_issue_4_reproduction",
        expected_symptom=message,
        run_id="run",
    )

    assert outcome.outcome == "generic_crash"
    assert not outcome.accepted


def test_stdout_fallback_rejects_generic_exception_with_matching_message(
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
    outcome = verify_candidate(
        sandbox=FakeSandbox(runs),  # type: ignore[arg-type]
        source=tmp_path,
        relative_path="tests/reproassert/test_issue_4.py",
        test_function="test_issue_4_reproduction",
        expected_symptom=message,
        run_id="run",
    )

    assert outcome.outcome == "generic_crash"
    assert not outcome.accepted


def test_stdout_fallback_rejects_forged_assertion_text_before_generic_exception(
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
    outcome = verify_candidate(
        sandbox=FakeSandbox(runs),  # type: ignore[arg-type]
        source=tmp_path,
        relative_path="tests/reproassert/test_issue_4.py",
        test_function="test_issue_4_reproduction",
        expected_symptom=message,
        run_id="run",
    )

    assert outcome.outcome == "generic_crash"
    assert not outcome.accepted


def test_rejects_pass_on_base(tmp_path: Path) -> None:
    runs = [result("collect", exit_code=0, output="test_issue_4_reproduction")]
    runs.extend(result("run", exit_code=0, output="1 passed") for _ in range(3))
    outcome = verify_candidate(
        sandbox=FakeSandbox(runs),  # type: ignore[arg-type]
        source=tmp_path,
        relative_path="tests/reproassert/test_issue_4.py",
        test_function="test_issue_4_reproduction",
        expected_symptom="duplicate separators remain",
        run_id="run",
    )
    assert outcome.outcome == "pass_on_base"


def test_rejects_collection_import_error(tmp_path: Path) -> None:
    sandbox = FakeSandbox([result("collect", exit_code=2, output="ModuleNotFoundError: missing")])
    outcome = verify_candidate(
        sandbox=sandbox,  # type: ignore[arg-type]
        source=tmp_path,
        relative_path="tests/reproassert/test_issue_4.py",
        test_function="test_issue_4_reproduction",
        expected_symptom="duplicate separators remain",
        run_id="run",
    )
    assert outcome.outcome == "setup_failure"
    assert sandbox.cleaned


def test_parse_junit_rejects_entity_payload() -> None:
    malicious = b'<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><testsuite>&x;</testsuite>'
    assert parse_junit(malicious) is None


def test_accepts_bounded_pytest_stdout_when_tmpfs_junit_is_gone(tmp_path: Path) -> None:
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
    outcome = verify_candidate(
        sandbox=FakeSandbox(runs),  # type: ignore[arg-type]
        source=tmp_path,
        relative_path="tests/reproassert/test_issue_4.py",
        test_function="test_issue_4_reproduction",
        expected_symptom=message,
        run_id="run",
    )
    assert outcome.outcome == "repeatable_base_failure"
