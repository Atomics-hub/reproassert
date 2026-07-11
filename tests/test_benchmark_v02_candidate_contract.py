from __future__ import annotations

import pytest

from reproassert.benchmark_v02_candidate_contract import v02_candidate_contract
from reproassert.errors import PolicyRejection


@pytest.mark.parametrize("case_id", ["rk-v0.2-001", "rk-v0.2-015", "rk-v0.2-020"])
def test_pytest_candidate_contract_is_one_exact_path_target_and_command(case_id: str) -> None:
    contract = v02_candidate_contract(case_id=case_id, issue_number=123)

    assert contract.profile == "pytest-v1"
    assert contract.relative_path == "tests/reproassert/test_issue_123.py"
    assert contract.test_function == "test_issue_123_reproduction"
    assert contract.target == f"{contract.relative_path}::{contract.test_function}"
    assert contract.test_command == f"pytest -q {contract.target}"


@pytest.mark.parametrize("case_id", ["rk-v0.2-016", "rk-v0.2-017"])
def test_sympy_candidate_contract_uses_native_path_and_command(case_id: str) -> None:
    suffix = case_id[-3:]
    contract = v02_candidate_contract(case_id=case_id, issue_number=999)

    assert contract.profile == "sympy-native-v1"
    assert contract.relative_path == f"sympy/reproassert/tests/test_issue_{suffix}.py"
    assert contract.test_function == f"test_reproassert_issue_{suffix}"
    assert contract.target == f"{contract.relative_path}::{contract.test_function}"
    assert contract.test_command == (
        f"python bin/test -C --verbose {contract.relative_path} -k {contract.test_function}"
    )


@pytest.mark.parametrize(
    ("case_id", "issue_number"),
    [("rk-v0.2-000", 1), ("rk-v0.2-021", 1), ("rk-v0.2-001", 0), ("rk-v0.2-001", True)],
)
def test_candidate_contract_rejects_out_of_cohort_or_invalid_identity(
    case_id: str, issue_number: int
) -> None:
    with pytest.raises(PolicyRejection, match=r"Candidate (case ID|issue number) is invalid"):
        v02_candidate_contract(case_id=case_id, issue_number=issue_number)
