from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def _load_scope_module() -> ModuleType:
    path = Path(__file__).parents[1] / "scripts" / "ci_change_scope.py"
    spec = importlib.util.spec_from_file_location("ci_change_scope", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load CI scope helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_SCOPE = _load_scope_module()
classify_paths = _SCOPE.classify_paths
determine_scope = _SCOPE.determine_scope


def test_docs_only_change_has_no_optional_package_site_or_docker_scope() -> None:
    assert classify_paths(["docs/architecture.md", "README.md"]) == {
        "python_changed": False,
        "site_changed": False,
        "docker_changed": False,
    }


def test_python_site_and_docker_surfaces_are_independent() -> None:
    assert classify_paths(["src/reproassert/generator.py"]) == {
        "python_changed": True,
        "site_changed": False,
        "docker_changed": False,
    }
    assert classify_paths(["site/app/page.tsx"]) == {
        "python_changed": False,
        "site_changed": True,
        "docker_changed": False,
    }
    assert classify_paths(["src/reproassert/benchmark_v02_runner.py"]) == {
        "python_changed": True,
        "site_changed": False,
        "docker_changed": True,
    }


def test_report_schema_and_workflow_changes_fail_safe() -> None:
    assert classify_paths(["schemas/reproassert-report.schema.json"]) == {
        "python_changed": True,
        "site_changed": True,
        "docker_changed": False,
    }
    assert classify_paths([".github/workflows/ci.yml"]) == {
        "python_changed": True,
        "site_changed": True,
        "docker_changed": True,
    }


def test_manual_or_unbound_execution_runs_every_lane() -> None:
    expected = {"python_changed": True, "site_changed": True, "docker_changed": True}
    assert determine_scope(event_name="workflow_dispatch", base_sha="") == expected
    assert determine_scope(event_name="pull_request", base_sha="not-a-sha") == expected
