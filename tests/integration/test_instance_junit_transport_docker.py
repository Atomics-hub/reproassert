from __future__ import annotations

import os
import uuid

import pytest

from reproassert.benchmark_v02_instance_executor import InstanceRuntimeExecutor
from reproassert.benchmark_v02_instance_runtime import InstanceRuntime, InstanceRuntimeManifest
from reproassert.dependency_executor import SubprocessDockerRunner
from reproassert.sandbox import SandboxPolicy

pytestmark = pytest.mark.integration

_IMAGE_ID = "sha256:0409bc2843724ebb54401bfe3f1577c52cc6dc4b5ede88571fd90e3ac7c52b6d"


@pytest.mark.skipif(
    os.environ.get("REPROASSERT_RUN_DOCKER_TESTS") != "1",
    reason="set REPROASSERT_RUN_DOCKER_TESTS=1 with the frozen case image loaded",
)
def test_junit_survives_exact_image_test_container_exit() -> None:
    """Regression: Docker discards /tmp tmpfs bytes when a test container stops."""

    runner = SubprocessDockerRunner()
    inspected = runner.run(
        ["image", "inspect", _IMAGE_ID],
        timeout_seconds=20,
        max_output_bytes=64 * 1024,
    )
    if inspected.returncode != 0:
        pytest.skip("frozen case image is not loaded")
    runtime = InstanceRuntime(
        case_id="rk-v0.2-003",
        instance_id="astropy__astropy-12907",
        base_sha="d16bfe05a744909de4b27f5875fe0d4ed41ce607",
        base_tree_oid="4d9ea46e57a9bc539b358a59c526dfd933f98aba",
        spec_sha256="08e9a6c3ba08e96937af1fbb273c51ab546d7bb5263a8d793366d434584ed0a1",
        image_tag="swebench/sweb.eval.x86_64.astropy_1776_astropy-12907:v1",
        image_digest="sha256:0409bc2843724ebb54401bfe3f1577c52cc6dc4b5ede88571fd90e3ac7c52b6d",
        image_id=_IMAGE_ID,
        test_command_profile="pytest-v1",
    )
    executor = InstanceRuntimeExecutor(
        InstanceRuntimeManifest(
            harness_git_sha="0" * 40,
            harness_specs_sha256="1" * 64,
            entries=(runtime,),
            sha256="2" * 64,
        ),
        case_id=runtime.case_id,
        policy=SandboxPolicy(image=runtime.image_id),
        runner=runner,
    )
    writer = f"reproassert-junit-regression-{uuid.uuid4().hex[:12]}"
    volume = executor._create_result_volume()
    anchor = executor._start_result_anchor(volume)
    try:
        created = executor._run(
            [
                "create",
                "--name",
                writer,
                "--network",
                "none",
                "--platform",
                "linux/amd64",
                "--read-only",
                "--user",
                "65532:65532",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--mount",
                f"type=volume,src={volume},dst=/results",
                "--entrypoint",
                "/bin/sh",
                runtime.image_id,
                "-c",
                "printf '<testsuite tests=\"1\"><testcase/></testsuite>' > /results/junit.xml",
            ],
            timeout=30,
        )
        assert created.output.strip()
        executor._containers.add(writer)
        executor._run(["start", "--attach", writer], timeout=30)

        junit = executor._read_junit(anchor)

        assert junit == b'<testsuite tests="1"><testcase/></testsuite>'
    finally:
        executor.cleanup()
