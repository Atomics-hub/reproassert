from __future__ import annotations

import os
from pathlib import Path

import pytest

from reproassert.sandbox import DockerSandbox
from reproassert.verifier import verify_candidate

pytestmark = pytest.mark.integration


@pytest.mark.skipif(
    os.environ.get("REPROASSERT_RUN_DOCKER_TESTS") != "1",
    reason="set REPROASSERT_RUN_DOCKER_TESTS=1 after building the sandbox image",
)
def test_buggy_fixture_is_repeatable_fixed_passes_and_generic_crash_is_rejected() -> None:
    repository = Path(__file__).parents[2]
    buggy = repository / "examples" / "fixtures" / "buggy_slug"
    fixed = repository / "examples" / "fixtures" / "fixed_slug"
    generic_crash = repository / "examples" / "fixtures" / "generic_crash"
    sandbox = DockerSandbox()

    buggy_outcome = verify_candidate(
        sandbox=sandbox,
        source=buggy,
        relative_path="tests/reproassert/test_issue_1.py",
        test_function="test_issue_1_reproduction",
        expected_symptom="duplicate separators remain",
        run_id="integration-buggy",
        repeats=3,
    )
    fixed_outcome = verify_candidate(
        sandbox=sandbox,
        source=fixed,
        relative_path="tests/reproassert/test_issue_1.py",
        test_function="test_issue_1_reproduction",
        expected_symptom="duplicate separators remain",
        run_id="integration-fixed",
        repeats=3,
    )
    generic_crash_outcome = verify_candidate(
        sandbox=sandbox,
        source=generic_crash,
        relative_path="tests/reproassert/test_issue_1.py",
        test_function="test_issue_1_reproduction",
        expected_symptom="duplicate separators remain",
        run_id="integration-generic-crash",
        repeats=3,
    )

    assert buggy_outcome.outcome == "repeatable_base_failure"
    assert buggy_outcome.accepted
    assert fixed_outcome.outcome == "pass_on_base"
    assert not fixed_outcome.accepted
    assert generic_crash_outcome.outcome == "generic_crash"
    assert not generic_crash_outcome.accepted
