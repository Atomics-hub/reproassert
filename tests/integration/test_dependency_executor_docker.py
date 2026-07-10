from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import reproassert.benchmark_v02_replay as replay
from reproassert.candidate import validate_candidate_payload
from reproassert.candidate_workspace import prepare_candidate_workspace
from reproassert.dependency_execution_receipt import verify_dependency_execution_receipt
from reproassert.dependency_executor import (
    CleanupOwnership,
    DependencyExecutor,
    MountExpectation,
)
from reproassert.sandbox import DockerSandbox, SandboxPolicy
from reproassert.source_attestation import attest_source_tree
from reproassert.verifier import verify_candidate

pytestmark = pytest.mark.integration

SIX_WHEEL_SHA256 = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274"


def _write_plan(path: Path, *, source_tree_sha256: str = "b" * 64) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "0.1.0",
                "case_id": "rk-v0.2-001",
                "source": {"base_sha": "a" * 40, "tree_sha256": source_tree_sha256},
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
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    pristine = tmp_path / "pristine-source"
    pristine.mkdir()
    (pristine / "product.py").write_text(
        "import six\n\ndef render(value):\n    return six.ensure_str(value)\n"
    )
    pristine_tree = attest_source_tree(pristine)
    plan_path = tmp_path / "dependency-plan.json"
    _write_plan(plan_path, source_tree_sha256=pristine_tree.tree_sha256)
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
            expected_source_tree_sha256=pristine_tree.tree_sha256,
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

        candidate = validate_candidate_payload(
            {
                "test_content": (
                    "from product import render\n\n"
                    "def test_issue_1_reproduction():\n"
                    "    observed = render(b'x')\n"
                    "    assert observed == 'wrong', 'installed dependency conversion remains x'\n"
                ),
                "expected_symptom": "installed dependency conversion remains x",
                "rationale": "Exercises one exact package from the reviewed dependency plan.",
            },
            issue_number=1,
        )
        prepared = prepare_candidate_workspace(
            source=pristine,
            destination=tmp_path / "candidate-source",
            relative_path="tests/reproassert/test_issue_1.py",
            candidate=candidate,
            expected_pristine=pristine_tree,
        )
        replay_outcome = verify_candidate(
            sandbox=DockerSandbox(policy),
            source=prepared.path,
            relative_path="tests/reproassert/test_issue_1.py",
            candidate=candidate,
            expected_source_tree=prepared.candidate_applied_tree,
            run_id="dependency-aware-replay-canary",
            dependency_handle=handle,
        )
        assert replay_outcome.outcome == "repeatable_base_failure"
        assert replay_outcome.accepted is True

        plan = json.loads(plan_path.read_text())
        bundle: dict[str, object] = {
            "algorithm": replay.REPLAY_BUNDLE_ALGORITHM,
            "candidate": {
                "expected_symptom": candidate.expected_symptom,
                "rationale": candidate.rationale,
                "relative_path": "tests/reproassert/test_issue_1.py",
                "test_content": candidate.test_content,
                "test_content_sha256": candidate.sha256,
            },
            "case": {
                "base_sha": "a" * 40,
                "id": "rk-v0.2-001",
                "issue_url": "https://github.com/owner/repo/issues/1",
                "repo": "owner/repo",
            },
            "dependency": {
                "image_id": execution.image_id,
                "plan": plan,
                "plan_sha256": executor.plan.canonical_sha256,
                "tree_sha256": execution.dependency_tree.tree_sha256,
            },
            "expected": {
                "failure_fingerprint": replay_outcome.fingerprint,
                "outcome": "repeatable_base_failure",
            },
            "repeats": 3,
            "schema_version": "0.1.0",
            "source": {
                "archive_sha256": "d" * 64,
                "root_tree_oid": pristine_tree.reconstructed_git_tree_oid,
                "tree_sha256": pristine_tree.tree_sha256,
            },
            "tool": {"git_sha": "e" * 40},
        }
        bundle["bundle_sha256"] = replay._self_hash(bundle, "bundle_sha256")
        bundle_path = tmp_path / "replay-bundle.json"
        bundle_path.write_bytes(replay._canonical(bundle) + b"\n")
        archive_path = tmp_path / "source.tar.gz"
        archive_path.write_bytes(b"archive")
        acquired = tmp_path / "acquired"

        monkeypatch.setattr(
            replay,
            "fetch_commit_tree_metadata",
            lambda *_args: SimpleNamespace(
                commit_sha="a" * 40,
                tree_sha=pristine_tree.reconstructed_git_tree_oid,
            ),
        )
        monkeypatch.setattr(
            replay,
            "download_source_archive",
            lambda *_args: SimpleNamespace(path=archive_path, sha256="d" * 64),
        )

        def extract(*_args: object) -> object:
            source = shutil.copytree(pristine, acquired / "source")
            return SimpleNamespace(
                destination=acquired,
                source_root=source,
                file_count=pristine_tree.file_count,
                unpacked_bytes=pristine_tree.total_bytes,
            )

        monkeypatch.setattr(replay, "extract_source_archive", extract)

        replay_result = replay.run_v02_replay_bundle(
            bundle_path,
            run_base=tmp_path / "replay-runs",
        )
        assert replay_result.outcome == "repeatable_base_failure"
        assert replay_result.fingerprint == replay_outcome.fingerprint

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
