from __future__ import annotations

import os
from pathlib import Path

import pytest

from reproassert.candidate import validate_candidate_payload
from reproassert.sandbox import DockerSandbox
from reproassert.source_attestation import attest_source_tree
from reproassert.verifier import VerificationOutcome, verify_candidate

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

    def run_fixture(source: Path, run_id: str) -> VerificationOutcome:
        content = (source / "tests" / "reproassert" / "test_issue_1.py").read_text()
        candidate = validate_candidate_payload(
            {
                "test_content": content,
                "expected_symptom": "duplicate separators remain",
                "rationale": "Exercises repeated whitespace through the public slug function.",
            },
            issue_number=1,
        )
        expected = attest_source_tree(source)
        return verify_candidate(
            sandbox=sandbox,
            source=source,
            relative_path="tests/reproassert/test_issue_1.py",
            candidate=candidate,
            expected_source_tree=expected,
            run_id=run_id,
            repeats=3,
        )

    buggy_outcome = run_fixture(buggy, "integration-buggy")
    fixed_outcome = run_fixture(fixed, "integration-fixed")
    generic_crash_outcome = run_fixture(generic_crash, "integration-generic-crash")

    assert buggy_outcome.outcome == "repeatable_base_failure"
    assert buggy_outcome.accepted
    assert fixed_outcome.outcome == "pass_on_base"
    assert not fixed_outcome.accepted
    assert generic_crash_outcome.outcome == "generic_crash"
    assert not generic_crash_outcome.accepted
