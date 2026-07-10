#!/usr/bin/env python3
"""Fail-safe change scoping for the required pull-request workflow."""

from __future__ import annotations

import argparse
import re
import subprocess
from collections.abc import Iterable
from pathlib import Path

_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")


def classify_paths(paths: Iterable[str]) -> dict[str, bool]:
    changed = {path for path in paths if path}
    python_prefixes = ("src/", "tests/", "schemas/", "scripts/")
    python_files = {"pyproject.toml", "uv.lock", ".github/workflows/ci.yml"}
    site_prefixes = ("site/",)
    site_files = {
        "schemas/reproassert-report.schema.json",
        "schemas/benchmark-v02-replay-bundle.schema.json",
        "schemas/benchmark-v02-replay-result.schema.json",
        ".github/workflows/ci.yml",
    }
    docker_prefixes = (
        "src/reproassert/assets/",
        "src/reproassert/benchmark_v02_",
        "src/reproassert/dependency_",
        "tests/integration/",
    )
    docker_files = {
        "src/reproassert/candidate_workspace.py",
        "src/reproassert/differential.py",
        "src/reproassert/sandbox.py",
        "src/reproassert/semantic_issuer.py",
        "src/reproassert/verifier.py",
        "src/reproassert/workflow.py",
        ".github/workflows/ci.yml",
    }

    def selected(prefixes: tuple[str, ...], files: set[str]) -> bool:
        return any(path in files or path.startswith(prefixes) for path in changed)

    return {
        "python_changed": selected(python_prefixes, python_files),
        "site_changed": selected(site_prefixes, site_files),
        "docker_changed": selected(docker_prefixes, docker_files),
    }


def determine_scope(*, event_name: str, base_sha: str) -> dict[str, bool]:
    if event_name == "workflow_dispatch" or _GIT_SHA.fullmatch(base_sha) is None:
        return {"python_changed": True, "site_changed": True, "docker_changed": True}
    output = subprocess.check_output(
        ["git", "diff", "--name-only", f"{base_sha}...HEAD"],
        text=True,
    )
    return classify_paths(output.splitlines())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    parser.add_argument("--base-sha", default="")
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()
    values = determine_scope(event_name=args.event, base_sha=args.base_sha)
    with args.github_output.open("a", encoding="utf-8") as stream:
        for name, value in values.items():
            stream.write(f"{name}={str(value).lower()}\n")
    for name, value in values.items():
        print(f"{name}={str(value).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
