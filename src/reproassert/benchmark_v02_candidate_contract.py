"""Single public-safe candidate path and command contract for the v0.2 cohort."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from reproassert.candidate import candidate_function, candidate_path
from reproassert.errors import PolicyRejection

PYTEST_PROFILE: Literal["pytest-v1"] = "pytest-v1"
SYMPY_PROFILE: Literal["sympy-native-v1"] = "sympy-native-v1"
_SYMPY_CASES = {"rk-v0.2-016", "rk-v0.2-017"}
_CASE_ID = re.compile(r"rk-v0\.2-(?:00[1-9]|01[0-9]|020)\Z")


@dataclass(frozen=True)
class V02CandidateContract:
    profile: Literal["pytest-v1", "sympy-native-v1"]
    relative_path: str
    test_function: str
    target: str
    test_command: str


def v02_candidate_contract(*, case_id: str, issue_number: int) -> V02CandidateContract:
    """Resolve the only candidate identity and reproduction command for one frozen case."""

    if _CASE_ID.fullmatch(case_id) is None:
        raise PolicyRejection("v02_candidate_contract", "Candidate case ID is invalid.")
    if isinstance(issue_number, bool) or not isinstance(issue_number, int) or issue_number < 1:
        raise PolicyRejection("v02_candidate_contract", "Candidate issue number is invalid.")
    if case_id in _SYMPY_CASES:
        suffix = case_id.rsplit("-", 1)[1]
        relative_path = f"sympy/reproassert/tests/test_issue_{suffix}.py"
        test_function = f"test_reproassert_issue_{suffix}"
        target = f"{relative_path}::{test_function}"
        return V02CandidateContract(
            profile=SYMPY_PROFILE,
            relative_path=relative_path,
            test_function=test_function,
            target=target,
            test_command=f"python bin/test -C --verbose {relative_path} -k {test_function}",
        )
    relative_path = candidate_path(issue_number)
    test_function = candidate_function(issue_number)
    target = f"{relative_path}::{test_function}"
    return V02CandidateContract(
        profile=PYTEST_PROFILE,
        relative_path=relative_path,
        test_function=test_function,
        target=target,
        test_command=f"pytest -q {target}",
    )
