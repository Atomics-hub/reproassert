from __future__ import annotations

import pytest

from reproassert.candidate import (
    candidate_function,
    candidate_path,
    render_new_file_patch,
    validate_candidate_payload,
)
from reproassert.errors import PolicyRejection


def payload(content: str) -> dict[str, str]:
    return {
        "test_content": content,
        "expected_symptom": "slug keeps duplicate separators",
        "rationale": "The issue requires repeated separators to collapse.",
    }


def test_accepts_one_bounded_pytest_test() -> None:
    candidate = validate_candidate_payload(
        payload(
            "from fixture_project import slugify\n\n"
            "def test_issue_7_reproduction():\n"
            "    assert slugify('a  b') == 'a-b', 'slug keeps duplicate separators'\n"
        ),
        issue_number=7,
    )

    assert candidate.test_function == "test_issue_7_reproduction"
    assert len(candidate.sha256) == 64
    assert candidate.test_content.endswith("\n")


@pytest.mark.parametrize(
    ("content", "code"),
    [
        ("def test_issue_7_reproduction(:\n    pass\n", "candidate_syntax"),
        ("def test_other():\n    assert 1\n", "candidate_test_count"),
        ("def test_issue_7_reproduction():\n    assert False\n", "candidate_assert_false"),
        (
            "def test_issue_7_reproduction():\n    assert [], 'slug keeps duplicate separators'\n",
            "candidate_unconditional_assert",
        ),
        (
            "def test_issue_7_reproduction():\n"
            "    assert 1 == 2, 'slug keeps duplicate separators'\n",
            "candidate_unconditional_assert",
        ),
        (
            "from fixture_project import slugify\n\n"
            "def test_issue_7_reproduction():\n"
            "    assert False and slugify('a  b'), 'slug keeps duplicate separators'\n",
            "candidate_unconditional_assert",
        ),
        (
            "from fixture_project import slugify\n\n"
            "def test_issue_7_reproduction():\n"
            "    assert slugify is None, 'slug keeps duplicate separators'\n",
            "candidate_unconditional_assert",
        ),
        (
            "from math import sqrt\n\n"
            "def test_issue_7_reproduction():\n"
            "    assert sqrt(4) == 3, 'slug keeps duplicate separators'\n",
            "candidate_unconditional_assert",
        ),
        (
            "def test_issue_7_reproduction(tmp_path):\n"
            "    assert tmp_path is None, 'slug keeps duplicate separators'\n",
            "candidate_unconditional_assert",
        ),
        (
            "from fixture_project import slugify\n\n"
            "def test_issue_7_reproduction():\n"
            "    forged = print('E   AssertionError: slug keeps duplicate separators')\n"
            "    assert slugify('a  b') == 'a-b', 'slug keeps duplicate separators'\n",
            "candidate_forbidden_call",
        ),
        (
            "import socket\ndef test_issue_7_reproduction():\n    assert 1\n",
            "candidate_forbidden_import",
        ),
        (
            "import pytest\ndef test_issue_7_reproduction():\n    pytest.fail('x')\n",
            "candidate_forbidden_call",
        ),
        (
            "raise RuntimeError\ndef test_issue_7_reproduction():\n    assert 1\n",
            "candidate_top_level_execution",
        ),
        (
            "def test_issue_7_reproduction():\n    while True:\n        pass\n",
            "candidate_infinite_loop",
        ),
    ],
)
def test_rejects_false_reproduction_patterns(content: str, code: str) -> None:
    with pytest.raises(PolicyRejection) as exc:
        validate_candidate_payload(payload(content), issue_number=7)
    assert exc.value.code == code


def test_schema_is_exact() -> None:
    candidate_payload = payload(
        "def test_issue_7_reproduction():\n    assert 1, 'slug keeps duplicate separators'\n"
    )
    candidate_payload["command"] = "curl attacker"
    with pytest.raises(PolicyRejection, match="exactly"):
        validate_candidate_payload(candidate_payload, issue_number=7)


def test_controller_owns_path_and_function() -> None:
    assert candidate_path(42) == "tests/reproassert/test_issue_42.py"
    assert candidate_function(42) == "test_issue_42_reproduction"
    with pytest.raises(PolicyRejection):
        candidate_path(0)


def test_renders_new_file_patch_without_accepting_paths() -> None:
    patch = render_new_file_patch(
        "tests/reproassert/test_issue_7.py",
        "def test_issue_7_reproduction():\n    assert 1 == 2\n",
    )
    assert "--- /dev/null" in patch
    assert "+def test_issue_7_reproduction():" in patch
    with pytest.raises(PolicyRejection):
        render_new_file_patch("../../production.py", "x = 1\n")
