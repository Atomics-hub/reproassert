from boom import reproduce


def test_issue_1_reproduction() -> None:
    assert reproduce() == 1, "duplicate separators remain"
