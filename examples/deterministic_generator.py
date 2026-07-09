#!/usr/bin/env python3
"""Offline JSON-protocol adapter for the documented slug fixture only."""

from __future__ import annotations

import json
import sys


def main() -> None:
    request = json.load(sys.stdin)
    issue_number = int(request["issue"]["number"])
    function = request["candidate_contract"]["required_test_function"]
    if function != f"test_issue_{issue_number}_reproduction":
        raise SystemExit("controller contract mismatch")
    response = {
        "test_content": (
            "from examples.fixtures.buggy_slug.slugger import slugify\n\n\n"
            f"def {function}() -> None:\n"
            '    assert slugify("Alpha  Beta") == "alpha-beta", '
            '"duplicate separators remain"\n'
        ),
        "expected_symptom": "duplicate separators remain",
        "rationale": "Two adjacent spaces should collapse to one slug separator.",
    }
    json.dump(response, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
