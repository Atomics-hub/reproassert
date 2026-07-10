from __future__ import annotations

import hashlib
import json
import os
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

import reproassert.dependency_prep as dependency_prep_module
from reproassert.dependency_prep import (
    DEPENDENCY_POLICY_ID,
    EVALUATOR_PACKAGE_ALGORITHM,
    DependencyPlan,
    WheelhouseAttestation,
    attest_wheelhouse,
    build_dependency_receipt,
    canonical_receipt_bytes,
    dependency_download_create_args,
    dependency_install_create_args,
    dependency_preparation_policy,
    load_dependency_plan,
    render_requirements_lock,
)
from reproassert.errors import PolicyRejection
from reproassert.sandbox import SandboxPolicy
from reproassert.source_attestation import SOURCE_TREE_ALGORITHM, SourceTreeAttestation


def _wheel_bytes(
    *,
    name: str = "example-dep",
    version: str = "1.2.3",
    extra_members: dict[str, bytes] | None = None,
) -> bytes:
    import io

    output = io.BytesIO()
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n",
        )
        archive.writestr(f"{name.replace('-', '_')}/__init__.py", b"VALUE = 1\n")
        for path, content in (extra_members or {}).items():
            archive.writestr(path, content)
    return output.getvalue()


def _write_plan(
    tmp_path: Path,
    wheel_sha256: str,
    *,
    packages: list[dict[str, object]] | None = None,
) -> Path:
    value = {
        "schema_version": "0.1.0",
        "case_id": "rk-v0.2-001",
        "source": {"base_sha": "a" * 40, "tree_sha256": "b" * 64},
        "runtime": {
            "python_version": "3.12.13",
            "runner_image": "reproassert-sandbox:0.1.0",
        },
        "index_policy": DEPENDENCY_POLICY_ID,
        "packages": packages
        or [{"name": "example-dep", "version": "1.2.3", "sha256": [wheel_sha256]}],
    }
    path = tmp_path / "dependency-plan.json"
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return path


def _plan_and_wheelhouse(tmp_path: Path) -> tuple[DependencyPlan, WheelhouseAttestation]:
    wheelhouse_path = tmp_path / "wheelhouse"
    wheelhouse_path.mkdir()
    wheel = _wheel_bytes()
    (wheelhouse_path / "example_dep-1.2.3-py3-none-any.whl").write_bytes(wheel)
    plan = load_dependency_plan(_write_plan(tmp_path, hashlib.sha256(wheel).hexdigest()))
    return plan, attest_wheelhouse(wheelhouse_path, plan)


def _tree() -> SourceTreeAttestation:
    return SourceTreeAttestation(
        algorithm=SOURCE_TREE_ALGORITHM,
        tree_sha256="c" * 64,
        reconstructed_git_tree_oid="d" * 40,
        expected_git_tree_oid=None,
        member_count=4,
        file_count=2,
        directory_count=2,
        total_bytes=100,
        executable_count=0,
        git_metadata_absent=True,
    )


def test_plan_is_strict_hash_complete_and_renders_fixed_requirements(tmp_path: Path) -> None:
    wheel_sha256 = "1" * 64
    path = _write_plan(tmp_path, wheel_sha256)

    plan = load_dependency_plan(path)

    assert plan.case_id == "rk-v0.2-001"
    assert plan.raw_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert len(plan.canonical_sha256) == 64
    assert render_requirements_lock(plan) == (
        b"example-dep==1.2.3 --hash=sha256:" + wheel_sha256.encode() + b"\n"
    )


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":"0.1.0","schema_version":"0.1.0"}',
        b"[" * 70 + b"]" * 70,
        b"\xff",
    ],
)
def test_plan_rejects_duplicate_deep_or_non_utf8_json(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "dependency-plan.json"
    path.write_bytes(raw)
    with pytest.raises(PolicyRejection):
        load_dependency_plan(path)


def test_plan_rejects_unsorted_packages_hashes_and_requirement_injection(tmp_path: Path) -> None:
    valid_hash = "1" * 64
    packages: list[dict[str, object]] = [
        {"name": "z-package", "version": "1.0", "sha256": [valid_hash]},
        {"name": "a-package", "version": "1.0", "sha256": [valid_hash]},
    ]
    with pytest.raises(PolicyRejection, match="sorted"):
        load_dependency_plan(_write_plan(tmp_path, valid_hash, packages=packages))

    packages = [{"name": "safe;--index-url=evil", "version": "1.0", "sha256": [valid_hash]}]
    with pytest.raises(PolicyRejection, match="name"):
        load_dependency_plan(_write_plan(tmp_path, valid_hash, packages=packages))

    packages = [{"name": "safe", "version": "1.0", "sha256": ["f" * 64, "0" * 64]}]
    with pytest.raises(PolicyRejection, match="sorted"):
        load_dependency_plan(_write_plan(tmp_path, valid_hash, packages=packages))


def test_network_exists_only_for_trusted_wheel_download_and_source_is_absent(
    tmp_path: Path,
) -> None:
    plan = load_dependency_plan(_write_plan(tmp_path, "1" * 64))
    policy = SandboxPolicy(image=plan.runner_image)

    download = dependency_download_create_args(
        plan,
        name="download",
        input_volume="input",
        wheelhouse_volume="wheels",
        run_id="run",
        policy=policy,
    )
    install = dependency_install_create_args(
        plan,
        name="install",
        input_volume="input",
        wheelhouse_volume="wheels",
        dependency_volume="deps",
        run_id="run",
        policy=policy,
    )
    download_joined = " ".join(download)
    install_joined = " ".join(install)

    assert "--network bridge" in download_joined
    assert "pip download" in download_joined
    assert "--require-hashes" in download
    assert "--only-binary=:all:" in download
    assert "--no-deps" in download
    assert "type=volume,src=input,dst=/input,readonly" in download
    assert "type=volume,src=wheels,dst=/wheelhouse" in download
    assert "/workspace" not in download_joined
    assert "type=bind" not in download_joined
    assert "GITHUB_TOKEN" not in download_joined
    assert "SSH_AUTH_SOCK" not in download_joined
    assert "HTTP_PROXY" not in download_joined
    assert "/var/run/docker.sock" not in download_joined

    assert "--network none" in install_joined
    assert "pip install" in install_joined
    assert "--no-index" in install
    assert "type=volume,src=wheels,dst=/wheelhouse,readonly" in install
    assert "type=volume,src=deps,dst=/dependencies" in install
    assert "--read-only" in install
    assert "--cap-drop ALL" in install_joined
    assert "no-new-privileges=true" in install
    assert "--memory 1073741824" in install_joined
    assert "--pids-limit 128" in install_joined
    assert "max-size=128k" in install


def test_plan_image_and_policy_image_must_match(tmp_path: Path) -> None:
    plan = load_dependency_plan(_write_plan(tmp_path, "1" * 64))
    with pytest.raises(PolicyRejection, match="image"):
        dependency_download_create_args(
            plan,
            name="download",
            input_volume="input",
            wheelhouse_volume="wheels",
            run_id="run",
            policy=SandboxPolicy(image="different:latest"),
        )

    with pytest.raises(PolicyRejection, match="Docker token"):
        dependency_download_create_args(
            plan,
            name="download",
            input_volume="input,dst=/host",
            wheelhouse_volume="wheels",
            run_id="run",
        )


def test_wheelhouse_is_bound_to_reviewed_metadata_and_hash(tmp_path: Path) -> None:
    plan, attestation = _plan_and_wheelhouse(tmp_path)

    assert attestation.file_count == 1
    assert attestation.files[0].package == "example-dep"
    assert attestation.files[0].version == "1.2.3"
    assert attestation.files[0].unpacked_bytes > 0
    assert attestation.total_unpacked_bytes == attestation.files[0].unpacked_bytes
    assert len(attestation.sha256) == 64
    assert plan.packages[0].sha256 == (attestation.files[0].sha256,)


def test_wheelhouse_rejects_unreviewed_bytes_extras_and_filesystem_links(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    wheel = _wheel_bytes()
    wheel_path = wheelhouse / "example_dep-1.2.3-py3-none-any.whl"
    wheel_path.write_bytes(wheel)
    plan = load_dependency_plan(_write_plan(tmp_path, "0" * 64))
    with pytest.raises(PolicyRejection, match="digest"):
        attest_wheelhouse(wheelhouse, plan)

    plan = load_dependency_plan(_write_plan(tmp_path, hashlib.sha256(wheel).hexdigest()))
    (wheelhouse / "extra.whl").write_bytes(wheel)
    with pytest.raises(PolicyRejection):
        attest_wheelhouse(wheelhouse, plan)

    (wheelhouse / "extra.whl").unlink()
    wheel_path.unlink()
    os.symlink(tmp_path / "outside.whl", wheel_path)
    with pytest.raises(PolicyRejection, match="non-regular"):
        attest_wheelhouse(wheelhouse, plan)


def test_wheelhouse_rejects_link_members_and_duplicate_metadata(tmp_path: Path) -> None:
    import io

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(
            "example_dep-1.2.3.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: example-dep\nVersion: 1.2.3\n\n",
        )
        link = zipfile.ZipInfo("example_dep/link")
        link.external_attr = (stat_mode := 0o120777) << 16
        assert stat_mode
        archive.writestr(link, "target")
    wheel = output.getvalue()
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    (wheelhouse / "example_dep-1.2.3-py3-none-any.whl").write_bytes(wheel)
    plan = load_dependency_plan(_write_plan(tmp_path, hashlib.sha256(wheel).hexdigest()))
    with pytest.raises(PolicyRejection, match="link"):
        attest_wheelhouse(wheelhouse, plan)

    duplicate = _wheel_bytes(
        extra_members={
            "other-1.2.3.dist-info/METADATA": (
                b"Metadata-Version: 2.1\nName: other\nVersion: 1.2.3\n\n"
            )
        }
    )
    (wheelhouse / "example_dep-1.2.3-py3-none-any.whl").write_bytes(duplicate)
    plan = load_dependency_plan(_write_plan(tmp_path, hashlib.sha256(duplicate).hexdigest()))
    with pytest.raises(PolicyRejection, match="exactly one"):
        attest_wheelhouse(wheelhouse, plan)


def test_wheelhouse_rejects_aggregate_declared_unpacked_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    first = _wheel_bytes(name="a-package", version="1.0")
    second = _wheel_bytes(name="b-package", version="1.0")
    (wheelhouse / "a_package-1.0-py3-none-any.whl").write_bytes(first)
    (wheelhouse / "b_package-1.0-py3-none-any.whl").write_bytes(second)
    plan = load_dependency_plan(
        _write_plan(
            tmp_path,
            "0" * 64,
            packages=[
                {
                    "name": "a-package",
                    "version": "1.0",
                    "sha256": [hashlib.sha256(first).hexdigest()],
                },
                {
                    "name": "b-package",
                    "version": "1.0",
                    "sha256": [hashlib.sha256(second).hexdigest()],
                },
            ],
        )
    )
    first_unpacked = len(b"Metadata-Version: 2.1\nName: a-package\nVersion: 1.0\n\n") + len(
        b"VALUE = 1\n"
    )
    second_unpacked = len(b"Metadata-Version: 2.1\nName: b-package\nVersion: 1.0\n\n") + len(
        b"VALUE = 1\n"
    )
    assert first_unpacked == second_unpacked
    monkeypatch.setattr(dependency_prep_module, "MAX_WHEELHOUSE_UNPACKED_BYTES", first_unpacked)

    with pytest.raises(PolicyRejection, match="aggregate"):
        attest_wheelhouse(wheelhouse, plan)


def test_receipt_binds_image_plan_policy_wheels_and_installed_tree_without_time(
    tmp_path: Path,
) -> None:
    plan, wheelhouse = _plan_and_wheelhouse(tmp_path)
    receipt = build_dependency_receipt(
        plan,
        runner_image_id="sha256:" + "e" * 64,
        wheelhouse=wheelhouse,
        dependency_tree=_tree(),
        tool_git_sha="f" * 40,
    )
    repeated = build_dependency_receipt(
        plan,
        runner_image_id="sha256:" + "e" * 64,
        wheelhouse=wheelhouse,
        dependency_tree=_tree(),
        tool_git_sha="f" * 40,
    )

    assert receipt == repeated
    assert canonical_receipt_bytes(receipt) == canonical_receipt_bytes(repeated)
    assert receipt["campaign_readiness_changed"] is False
    assert "timestamp" not in canonical_receipt_bytes(receipt).decode()
    package = receipt["evaluator_package"]
    assert isinstance(package, dict)
    assert package["algorithm"] == EVALUATOR_PACKAGE_ALGORITHM
    assert len(package["sha256"]) == 64
    assert package["verification_network"] == "none"
    preparation = receipt["preparation"]
    assert isinstance(preparation, dict)
    assert preparation["host_credentials_forwarded"] is False
    assert preparation["source_mounted_during_network_phase"] is False
    wheelhouse_record = receipt["wheelhouse"]
    assert isinstance(wheelhouse_record, dict)
    assert wheelhouse_record["total_unpacked_bytes"] == wheelhouse.total_unpacked_bytes


def test_receipt_rejects_tampered_wheelhouse_or_git_bound_dependency_tree(
    tmp_path: Path,
) -> None:
    plan, wheelhouse = _plan_and_wheelhouse(tmp_path)
    with pytest.raises(PolicyRejection, match="digest"):
        build_dependency_receipt(
            plan,
            runner_image_id="sha256:" + "e" * 64,
            wheelhouse=replace(wheelhouse, sha256="0" * 64),
            dependency_tree=_tree(),
            tool_git_sha="f" * 40,
        )

    with pytest.raises(PolicyRejection, match="byte count"):
        build_dependency_receipt(
            plan,
            runner_image_id="sha256:" + "e" * 64,
            wheelhouse=replace(
                wheelhouse, total_unpacked_bytes=wheelhouse.total_unpacked_bytes + 1
            ),
            dependency_tree=_tree(),
            tool_git_sha="f" * 40,
        )

    forged_artifact = replace(wheelhouse.files[0], sha256="0" * 64)
    with pytest.raises(PolicyRejection, match="unreviewed"):
        build_dependency_receipt(
            plan,
            runner_image_id="sha256:" + "e" * 64,
            wheelhouse=replace(wheelhouse, files=(forged_artifact,)),
            dependency_tree=_tree(),
            tool_git_sha="f" * 40,
        )

    with pytest.raises(PolicyRejection, match="Git"):
        build_dependency_receipt(
            plan,
            runner_image_id="sha256:" + "e" * 64,
            wheelhouse=wheelhouse,
            dependency_tree=replace(_tree(), expected_git_tree_oid="a" * 40),
            tool_git_sha="f" * 40,
        )

    with pytest.raises(PolicyRejection, match="inconsistent"):
        build_dependency_receipt(
            plan,
            runner_image_id="sha256:" + "e" * 64,
            wheelhouse=wheelhouse,
            dependency_tree=replace(_tree(), algorithm="unknown"),
            tool_git_sha="f" * 40,
        )


def test_policy_explicitly_names_process_only_egress_enforcement() -> None:
    policy = dependency_preparation_policy()
    network = policy["network_acquisition"]
    assert isinstance(network, dict)
    assert network["source_mounted"] is False
    assert network["credentials"] == "none"
    assert network["egress_enforcement"].endswith("not_network_acl")
    assert policy["offline_install"]["network"] == "none"  # type: ignore[index]


def test_module_has_no_generator_campaign_result_or_ledger_dependency() -> None:
    source = Path(__file__).parents[1] / "src" / "reproassert" / "dependency_prep.py"
    text = source.read_text()
    for forbidden in (
        "reproassert.generator",
        "reproassert.benchmark",
        "campaign.json",
        "results.jsonl",
        "smoke-events.jsonl",
        "scored-events.jsonl",
    ):
        assert forbidden not in text
