from slugger import slugify


def test_issue_1_reproduction() -> None:
    assert slugify("Alpha  Beta") == "alpha-beta", "duplicate separators remain"
