from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from reproassert.dependency_execution_receipt import verify_dependency_execution_receipt
from reproassert.dependency_executor import (
    CleanupOwnership,
    DependencyExecutor,
    MountExpectation,
)
from reproassert.sandbox import DockerSandbox, SandboxPolicy

pytestmark = pytest.mark.integration

SIX_WHEEL_SHA256 = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274"


def _write_plan(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "0.1.0",
                "case_id": "rk-v0.2-001",
                "source": {"base_sha": "a" * 40, "tree_sha256": "b" * 64},
                "runtime": {
                    "python_version": "3.12.13",
                    "runner_image": "reproassert-sandbox:0.1.0",
                },
                "index_policy": "pypi-hash-locked-wheels-v1",
                "packages": [{"name": "six", "version": "1.17.0", "sha256": [SIX_WHEEL_SHA256]}],
            },
            sort_keys=True,
        )
        + "\n"
    )


@pytest.mark.skipif(
    os.environ.get("REPROASSERT_RUN_DOCKER_TESTS") != "1"
    or os.environ.get("REPROASSERT_RUN_DEPENDENCY_NETWORK_TESTS") != "1",
    reason=(
        "set REPROASSERT_RUN_DOCKER_TESTS=1 and "
        "REPROASSERT_RUN_DEPENDENCY_NETWORK_TESTS=1 for the opt-in PyPI canary"
    ),
)
def test_real_docker_downloads_then_installs_offline_and_revalidates_handle(
    tmp_path: Path,
) -> None:
    plan_path = tmp_path / "dependency-plan.json"
    _write_plan(plan_path)
    policy = SandboxPolicy(image="reproassert-sandbox:0.1.0", timeout_seconds=120)

    with DependencyExecutor(plan_path, policy=policy) as executor:
        execution = executor.prepare(tool_git_sha="e" * 40)
        handle = execution.dependency_handle
        validation = handle.revalidate_for_mount()
        verified_receipt = verify_dependency_execution_receipt(
            execution.receipt,
            expected_plan_path=plan_path,
            expected_case_id="rk-v0.2-001",
            expected_base_sha="a" * 40,
            expected_source_tree_sha256="b" * 64,
            expected_plan_sha256=executor.plan.canonical_sha256,
            expected_image_id=execution.image_id,
            expected_tool_name="reproassert",
            expected_tool_git_sha="e" * 40,
        )

        assert handle.cleanup_ownership is CleanupOwnership.EXECUTOR_CONTEXT
        assert validation.image_id == execution.image_id
        assert (
            validation.execution_receipt_sha256
            == hashlib.sha256(execution.canonical_receipt).hexdigest()
        )
        assert validation.labels == handle.labels
        assert validation.quota.type == "tmpfs"
        assert validation.quota.size_bytes == 512 * 1024 * 1024
        assert validation.quota.max_inodes == 32_768
        assert validation.tree_attestation == execution.dependency_tree
        assert execution.receipt["campaign_readiness_changed"] is False
        assert len(execution.canonical_receipt) < 1024 * 1024
        assert verified_receipt.campaign_readiness_changed is False

        imported = executor._run_helper(
            role="canary-import",
            image_id=handle.image_id,
            mounts=(MountExpectation("dependencies", handle.name, "/dependencies", False),),
            entrypoint="/usr/bin/env",
            command=(
                "-i",
                "HOME=/tmp/home",
                "LANG=C.UTF-8",
                "LC_ALL=C.UTF-8",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "/usr/local/bin/python",
                "-I",
                "-c",
                (
                    "import sys; sys.path.insert(0, '/dependencies'); "
                    "import six; print(six.__version__)"
                ),
            ),
        )
        assert imported.output.strip() == "1.17.0"

        source = tmp_path / "borrowed-volume-source"
        test_path = source / "tests" / "reproassert" / "test_issue_1.py"
        test_path.parent.mkdir(parents=True)
        test_path.write_text(
            "def test_issue_1_reproduction():\n"
            "    import six\n"
            "    assert six.__version__ == '1.17.0'\n",
            encoding="utf-8",
        )
        sandbox = DockerSandbox(policy)
        workspace_volume = sandbox.stage_source(source, run_id="dependency-borrow-canary")
        with sandbox.borrow_dependency_volume(handle) as dependency_volume:
            mounted = sandbox.run_pytest(
                volume=workspace_volume,
                dependency_volume=dependency_volume,
                target="tests/reproassert/test_issue_1.py::test_issue_1_reproduction",
                phase="dependency_borrow_canary",
                run_id="dependency-borrow-canary",
            )
            assert mounted.exit_code == 0
        sandbox.cleanup()
        assert not sandbox._containers
        assert not sandbox._volumes
        assert not sandbox._borrowed_dependency_volumes
        volume_name = handle.name

    missing = subprocess.run(
        ["docker", "volume", "inspect", volume_name],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    exact_list = subprocess.run(
        [
            "docker",
            "volume",
            "ls",
            "--quiet",
            "--filter",
            f"name=^{volume_name}$",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert missing.returncode != 0
    assert exact_list.stdout == ""


@pytest.mark.skipif(
    os.environ.get("REPROASSERT_RUN_DOCKER_TESTS") != "1",
    reason="set REPROASSERT_RUN_DOCKER_TESTS=1 after building the sandbox image",
)
def test_real_tmpfs_inode_quota_fails_with_enospc_and_cleans_up(tmp_path: Path) -> None:
    plan_path = tmp_path / "dependency-plan.json"
    _write_plan(plan_path)
    with DependencyExecutor(plan_path) as executor:
        image_id = executor._resolve_image_id()
        executor._create_role_volumes()
        executor._start_volume_anchors(image_id)
        input_volume = executor._volumes["input"]
        result = executor._run_helper(
            role="inode-quota-canary",
            image_id=image_id,
            mounts=(MountExpectation("input", input_volume.name, "/data", True),),
            entrypoint="/usr/bin/env",
            command=(
                "-i",
                "HOME=/tmp/home",
                "LANG=C.UTF-8",
                "LC_ALL=C.UTF-8",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "/usr/local/bin/python",
                "-I",
                "-c",
                (
                    "import errno,json,os; created=0\n"
                    "try:\n"
                    "  for i in range(256):\n"
                    "    fd=os.open(f'/data/{i}',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o400);"
                    " os.close(fd); created+=1\n"
                    "except OSError as exc:\n"
                    "  print(json.dumps({'created':created,'errno':exc.errno},sort_keys=True,"
                    "separators=(',',':')))\n"
                    "  raise SystemExit(0 if exc.errno==errno.ENOSPC else 1)\n"
                    "raise SystemExit(1)"
                ),
            ),
        )
        evidence = json.loads(result.output)
        assert evidence["errno"] == 28
        assert evidence["created"] < 64
