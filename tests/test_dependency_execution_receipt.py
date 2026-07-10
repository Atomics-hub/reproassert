from __future__ import annotations

import copy
import hashlib
import json
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from reproassert import __version__
from reproassert.dependency_command_contract import (
    dependency_phase_command,
    dependency_phase_command_sha256,
)
from reproassert.dependency_execution_receipt import (
    DEPENDENCY_EXECUTION_RECEIPT_SCHEMA_FILENAME,
    dependency_execution_receipt_schema_text,
    load_dependency_execution_receipt,
    verify_dependency_execution_receipt,
)
from reproassert.dependency_executor import (
    DEPENDENCY_VOLUME_QUOTA_CONTRACT,
    EffectivePhasePolicy,
    PhaseOutcome,
    VolumeFileEvidence,
    VolumeProbe,
    VolumeSpec,
    _build_execution_receipt,
    _canonical_json_bytes,
)
from reproassert.dependency_prep import (
    DependencyPlan,
    WheelhouseAttestation,
    attest_wheelhouse,
    build_dependency_receipt,
    dependency_download_create_args,
    dependency_install_create_args,
    load_dependency_plan,
    render_requirements_lock,
)
from reproassert.errors import PolicyRejection
from reproassert.sandbox import SandboxPolicy
from reproassert.source_attestation import SourceTreeAttestation, attest_source_tree

IMAGE_ID = "sha256:" + "a" * 64
TOOL_GIT_SHA = "b" * 40
EMPTY_PROBE_SHA256 = hashlib.sha256(b"reproassert-volume-probe-v1\0").hexdigest()


def _wheel_bytes() -> bytes:
    import io

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "example_dep-1.2.3.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: example-dep\nVersion: 1.2.3\n\n",
        )
        archive.writestr("example_dep/__init__.py", "VALUE = 1\n")
    return output.getvalue()


def _plan_and_artifacts(
    tmp_path: Path,
    *,
    python_version: str = "3.12.13",
) -> tuple[DependencyPlan, WheelhouseAttestation, SourceTreeAttestation]:
    wheel = _wheel_bytes()
    wheel_sha256 = hashlib.sha256(wheel).hexdigest()
    plan_path = tmp_path / "dependency-plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "schema_version": "0.1.0",
                "case_id": "rk-v0.2-001",
                "source": {"base_sha": "c" * 40, "tree_sha256": "d" * 64},
                "runtime": {
                    "python_version": python_version,
                    "runner_image": "reproassert-sandbox:0.1.0",
                },
                "index_policy": "pypi-hash-locked-wheels-v1",
                "packages": [
                    {
                        "name": "example-dep",
                        "version": "1.2.3",
                        "sha256": [wheel_sha256],
                    }
                ],
            },
            sort_keys=True,
        )
        + "\n"
    )
    plan = load_dependency_plan(plan_path)
    wheelhouse_path = tmp_path / "wheelhouse"
    wheelhouse_path.mkdir()
    (wheelhouse_path / "example_dep-1.2.3-py3-none-any.whl").write_bytes(wheel)
    wheelhouse = attest_wheelhouse(wheelhouse_path, plan)
    dependencies = tmp_path / "dependencies"
    (dependencies / "example_dep").mkdir(parents=True)
    (dependencies / "example_dep" / "__init__.py").write_text("VALUE = 1\n")
    tree = attest_source_tree(dependencies)
    return plan, wheelhouse, tree


def _probe(
    digest: str,
    *,
    members: int = 0,
    files: int = 0,
    directories: int = 0,
    total_bytes: int = 0,
) -> VolumeProbe:
    return VolumeProbe(
        algorithm="reproassert-volume-probe-v1",
        tree_sha256=digest,
        member_count=members,
        file_count=files,
        directory_count=directories,
        total_bytes=total_bytes,
        root_uid=65532,
        root_gid=65532,
        root_mode=0o700,
        single_file_path=None,
        single_file_sha256=None,
        files=(),
    )


def _phase(
    policy: SandboxPolicy,
    *,
    phase: str,
    network: str,
    mounts: tuple[tuple[str, str, bool], ...],
) -> EffectivePhasePolicy:
    assert phase in {"download", "install"}
    command_sha256 = dependency_phase_command_sha256(phase)  # type: ignore[arg-type]
    normalized = {
        "phase": phase,
        "image_id": IMAGE_ID,
        "network_mode": network,
        "user": "65532:65532",
        "read_only_root": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "healthcheck_disabled": True,
        "trusted_phase_command": True,
        "pids": policy.pids,
        "memory_bytes": policy.memory_bytes,
        "memory_swap_bytes": policy.memory_bytes,
        "nano_cpus": int(policy.cpus * 1_000_000_000),
        "mounts": [list(item) for item in mounts],
        "command_sha256": command_sha256,
    }
    return EffectivePhasePolicy(
        phase=phase,
        image_id=IMAGE_ID,
        network_mode=network,
        user="65532:65532",
        read_only_root=True,
        cap_drop=("ALL",),
        no_new_privileges=True,
        healthcheck_disabled=True,
        trusted_phase_command=True,
        pids=policy.pids,
        memory_bytes=policy.memory_bytes,
        memory_swap_bytes=policy.memory_bytes,
        nano_cpus=int(policy.cpus * 1_000_000_000),
        mounts=mounts,
        command_sha256=command_sha256,
        config_sha256=hashlib.sha256(_canonical_json_bytes(normalized)).hexdigest(),
    )


def _receipt(
    tmp_path: Path,
    *,
    planned_python: str = "3.12.13",
    observed_python: str = "3.12.13",
) -> tuple[dict[str, object], DependencyPlan]:
    plan, wheelhouse, tree = _plan_and_artifacts(
        tmp_path,
        python_version=planned_python,
    )
    policy = SandboxPolicy(image=plan.runner_image)
    base = build_dependency_receipt(
        plan,
        runner_image_id=IMAGE_ID,
        wheelhouse=wheelhouse,
        dependency_tree=tree,
        tool_git_sha=TOOL_GIT_SHA,
        policy=policy,
    )
    specs = {
        role: VolumeSpec(role, f"not-emitted-{role}", size, inodes, ())
        for role, size, inodes in DEPENDENCY_VOLUME_QUOTA_CONTRACT
    }
    empty = {role: _probe(EMPTY_PROBE_SHA256) for role in specs}
    requirements_sha256 = hashlib.sha256(render_requirements_lock(plan)).hexdigest()
    input_probe = replace(
        _probe("1" * 64, members=1, files=1, total_bytes=100),
        single_file_path="requirements.lock",
        single_file_sha256=requirements_sha256,
        files=(VolumeFileEvidence("requirements.lock", requirements_sha256),),
    )
    wheel_probe = _probe(
        "2" * 64,
        members=wheelhouse.file_count,
        files=wheelhouse.file_count,
        total_bytes=wheelhouse.total_bytes,
    )
    dependency_probe = _probe(
        "3" * 64,
        members=tree.member_count,
        files=tree.file_count,
        directories=tree.directory_count,
        total_bytes=tree.total_bytes,
    )
    download = _phase(
        policy,
        phase="download",
        network="bridge",
        mounts=(("input", "/input", False), ("wheelhouse", "/wheelhouse", True)),
    )
    install = _phase(
        policy,
        phase="install",
        network="none",
        mounts=(
            ("dependencies", "/dependencies", True),
            ("input", "/input", False),
            ("wheelhouse", "/wheelhouse", False),
        ),
    )
    receipt = _build_execution_receipt(
        base_receipt=base,
        image_id=IMAGE_ID,
        runtime_version=observed_python,
        volume_specs=specs,
        empty_probes=empty,
        input_probe=input_probe,
        download_policy=download,
        download_outcome=PhaseOutcome("download", 0, False, False, False),
        wheel_probe=wheel_probe,
        wheelhouse=wheelhouse,
        dependency_preinstall=empty["dependencies"],
        install_policy=install,
        install_outcome=PhaseOutcome("install", 0, False, False, False),
        dependency_probe=dependency_probe,
        dependency_tree=tree,
    )
    verify_dependency_execution_receipt(receipt)
    decoded = json.loads(_canonical_json_bytes(receipt))
    assert isinstance(decoded, dict)
    return decoded, plan


def _write_receipt(path: Path, receipt: dict[str, object]) -> bytes:
    raw = _canonical_json_bytes(receipt) + b"\n"
    path.write_bytes(raw)
    return raw


def test_loader_recomputes_receipt_and_binds_all_expected_identities(tmp_path: Path) -> None:
    receipt, plan = _receipt(tmp_path)
    path = tmp_path / "dependency-execution-receipt.json"
    raw = _write_receipt(path, receipt)

    verified = load_dependency_execution_receipt(
        path,
        expected_receipt_sha256=hashlib.sha256(raw).hexdigest(),
        expected_plan_path=tmp_path / "dependency-plan.json",
        expected_case_id=plan.case_id,
        expected_base_sha=plan.base_sha,
        expected_source_tree_sha256=plan.source_tree_sha256,
        expected_plan_raw_sha256=plan.raw_sha256,
        expected_plan_sha256=plan.canonical_sha256,
        expected_image_id=IMAGE_ID,
        expected_tool_name="reproassert",
        expected_tool_version=__version__,
        expected_tool_git_sha=TOOL_GIT_SHA,
    )

    assert verified.receipt_sha256 == hashlib.sha256(raw).hexdigest()
    assert verified.plan_sha256 == plan.canonical_sha256
    assert verified.image_id == IMAGE_ID
    assert verified.campaign_readiness_changed is False


def test_verifier_accepts_observed_patch_version_for_minor_only_plan(tmp_path: Path) -> None:
    receipt, plan = _receipt(
        tmp_path,
        planned_python="3.12",
        observed_python="3.12.13",
    )
    path = tmp_path / "dependency-execution-receipt.json"
    _write_receipt(path, receipt)

    verified = load_dependency_execution_receipt(
        path,
        expected_plan_path=tmp_path / "dependency-plan.json",
    )

    assert verified.plan_sha256 == plan.canonical_sha256


def test_command_contract_matches_dependency_container_builders(tmp_path: Path) -> None:
    plan, _wheelhouse, _tree = _plan_and_artifacts(tmp_path)
    policy = SandboxPolicy(image=plan.runner_image)
    download = dependency_download_create_args(
        plan,
        name="download",
        input_volume="input",
        wheelhouse_volume="wheelhouse",
        run_id="run",
        policy=policy,
    )
    install = dependency_install_create_args(
        plan,
        name="install",
        input_volume="input",
        wheelhouse_volume="wheelhouse",
        dependency_volume="dependencies",
        run_id="run",
        policy=policy,
    )

    assert tuple(download[download.index(plan.runner_image) + 1 :]) == dependency_phase_command(
        "download"
    )
    assert tuple(install[install.index(plan.runner_image) + 1 :]) == dependency_phase_command(
        "install"
    )


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("expected_case_id", "rk-v0.2-999"),
        ("expected_base_sha", "0" * 40),
        ("expected_source_tree_sha256", "0" * 64),
        ("expected_plan_raw_sha256", "0" * 64),
        ("expected_plan_sha256", "0" * 64),
        ("expected_image_id", "sha256:" + "0" * 64),
        ("expected_tool_name", "other-tool"),
        ("expected_tool_version", "9.9.9"),
        ("expected_tool_git_sha", "0" * 40),
    ],
)
def test_loader_rejects_expected_identity_mismatch(
    tmp_path: Path, field: str, expected: str
) -> None:
    receipt, _plan = _receipt(tmp_path)
    path = tmp_path / "dependency-execution-receipt.json"
    _write_receipt(path, receipt)

    with pytest.raises(PolicyRejection, match="expected identity"):
        load_dependency_execution_receipt(path, **{field: expected})


def _mutate(receipt: dict[str, object], mutation: str) -> None:
    preparation = receipt["dependency_preparation"]
    execution = receipt["execution"]
    assert isinstance(preparation, dict)
    assert isinstance(execution, dict)
    if mutation == "policy_hash":
        preparation["preparation"]["policy_sha256"] = "0" * 64
    elif mutation == "policy_value":
        preparation["preparation"]["policy"]["container"]["cpus"] = 2.0
    elif mutation == "wheel_digest":
        preparation["wheelhouse"]["files"][0]["sha256"] = "0" * 64
    elif mutation == "wheel_total":
        preparation["wheelhouse"]["total_bytes"] += 1
    elif mutation == "tree_count":
        preparation["dependencies"]["attestation"]["member_count"] += 1
    elif mutation == "package_identity":
        preparation["evaluator_package"]["identity"]["dependency_tree_sha256"] = "0" * 64
    elif mutation == "package_digest":
        preparation["evaluator_package"]["sha256"] = "0" * 64
    elif mutation == "volume_inodes":
        execution["volume_policy"]["dependencies"]["max_inodes"] += 1
    elif mutation == "phase_config":
        execution["install"]["config_sha256"] = "0" * 64
    elif mutation == "phase_command_coordinated":
        install = execution["install"]
        install["command_sha256"] = "0" * 64
        normalized = {
            key: value for key, value in install.items() if key not in {"config_sha256", "outcome"}
        }
        install["config_sha256"] = hashlib.sha256(_canonical_json_bytes(normalized)).hexdigest()
        events = execution["causality"]["events"]
        events[4]["phase_policy_sha256"] = install["config_sha256"]
        execution["causality"]["sequence_sha256"] = hashlib.sha256(
            _canonical_json_bytes(events)
        ).hexdigest()
    elif mutation == "phase_mount":
        execution["install"]["mounts"][2][2] = True
    elif mutation == "phase_outcome":
        execution["install"]["outcome"]["oom_killed"] = True
    elif mutation == "event_cross_identity":
        execution["causality"]["events"][5]["wheelhouse_sha256"] = "0" * 64
    elif mutation == "event_sequence":
        execution["causality"]["sequence_sha256"] = "0" * 64
    elif mutation == "empty_dependency_probe_coordinated":
        events = execution["causality"]["events"]
        events[5]["dependency_probe_sha256"] = EMPTY_PROBE_SHA256
        execution["causality"]["sequence_sha256"] = hashlib.sha256(
            _canonical_json_bytes(events)
        ).hexdigest()
    elif mutation == "causality_boolean":
        execution["causality"]["requirements_unchanged"] = False
    elif mutation == "cleanup_boolean":
        execution["cleanup"]["blind_force_volume_removal"] = True
    elif mutation == "campaign_readiness":
        receipt["campaign_readiness_changed"] = True
    elif mutation == "ephemeral_name":
        preparation["tool"]["name"] = "reproassert-dep-forged-resource"
    else:  # pragma: no cover - parametrization is frozen
        raise AssertionError(mutation)


@pytest.mark.parametrize(
    "mutation",
    [
        "policy_hash",
        "policy_value",
        "wheel_digest",
        "wheel_total",
        "tree_count",
        "package_identity",
        "package_digest",
        "volume_inodes",
        "phase_config",
        "phase_command_coordinated",
        "phase_mount",
        "phase_outcome",
        "event_cross_identity",
        "event_sequence",
        "empty_dependency_probe_coordinated",
        "causality_boolean",
        "cleanup_boolean",
        "campaign_readiness",
        "ephemeral_name",
    ],
)
def test_verifier_rejects_adversarial_receipt_mutations(tmp_path: Path, mutation: str) -> None:
    receipt, _plan = _receipt(tmp_path)
    mutated = copy.deepcopy(receipt)
    _mutate(mutated, mutation)

    with pytest.raises(PolicyRejection):
        verify_dependency_execution_receipt(mutated)


def test_strict_plan_binding_rejects_self_consistent_unreviewed_wheel(tmp_path: Path) -> None:
    receipt, _plan = _receipt(tmp_path)
    mutated = copy.deepcopy(receipt)
    preparation = mutated["dependency_preparation"]
    execution = mutated["execution"]
    files = preparation["wheelhouse"]["files"]
    files[0]["sha256"] = "0" * 64
    wheelhouse_sha256 = hashlib.sha256(_canonical_json_bytes(files)).hexdigest()
    preparation["wheelhouse"]["sha256"] = wheelhouse_sha256
    identity = preparation["evaluator_package"]["identity"]
    identity["wheelhouse_sha256"] = wheelhouse_sha256
    preparation["evaluator_package"]["sha256"] = hashlib.sha256(
        _canonical_json_bytes(identity)
    ).hexdigest()
    events = execution["causality"]["events"]
    events[3]["wheelhouse_sha256"] = wheelhouse_sha256
    events[5]["wheelhouse_sha256"] = wheelhouse_sha256
    execution["causality"]["sequence_sha256"] = hashlib.sha256(
        _canonical_json_bytes(events)
    ).hexdigest()
    path = tmp_path / "dependency-execution-receipt.json"
    _write_receipt(path, mutated)

    verify_dependency_execution_receipt(mutated)
    with pytest.raises(PolicyRejection, match="strict dependency plan"):
        load_dependency_execution_receipt(
            path,
            expected_plan_path=tmp_path / "dependency-plan.json",
        )


def test_loader_rejects_duplicate_noncanonical_oversized_and_nonfinite_json(
    tmp_path: Path,
) -> None:
    receipt, _plan = _receipt(tmp_path)
    canonical = _canonical_json_bytes(receipt) + b"\n"
    path = tmp_path / "dependency-execution-receipt.json"

    path.write_bytes(
        canonical.replace(
            b'"kind":"dependency_execution_receipt"',
            b'"kind":"dependency_execution_receipt","kind":"dependency_execution_receipt"',
            1,
        )
    )
    with pytest.raises(PolicyRejection, match="strict bounded"):
        load_dependency_execution_receipt(path)

    path.write_text(json.dumps(receipt, indent=2) + "\n")
    with pytest.raises(PolicyRejection, match="canonical JSON"):
        load_dependency_execution_receipt(path)

    path.write_bytes(b"{" + b" " * (1024 * 1024) + b"}")
    with pytest.raises(PolicyRejection, match="exceeds 1 MiB"):
        load_dependency_execution_receipt(path)

    path.write_bytes(b'{"value":NaN}\n')
    with pytest.raises(PolicyRejection, match="strict bounded"):
        load_dependency_execution_receipt(path)


def test_root_and_bundled_schema_are_identical_strict_and_accept_emitted_receipt(
    tmp_path: Path,
) -> None:
    repository = Path(__file__).parents[1]
    root_schema_path = repository / "schemas" / DEPENDENCY_EXECUTION_RECEIPT_SCHEMA_FILENAME
    bundled_schema_path = (
        repository
        / "src"
        / "reproassert"
        / "schemas"
        / DEPENDENCY_EXECUTION_RECEIPT_SCHEMA_FILENAME
    )
    assert root_schema_path.read_bytes() == bundled_schema_path.read_bytes()
    assert dependency_execution_receipt_schema_text() == root_schema_path.read_text()
    schema = json.loads(root_schema_path.read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    receipt, _plan = _receipt(tmp_path)

    validator.validate(receipt)

    mutated = copy.deepcopy(receipt)
    mutated["execution"]["volume_policy"]["dependencies"]["max_inodes"] = 32769
    with pytest.raises(ValidationError):
        validator.validate(mutated)

    mutated = copy.deepcopy(receipt)
    mutated["execution"]["cleanup"]["unexpected"] = True
    with pytest.raises(ValidationError):
        validator.validate(mutated)
