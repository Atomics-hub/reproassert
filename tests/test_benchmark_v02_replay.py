from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

import reproassert.benchmark_v02_replay as replay
import reproassert.cli as cli
from reproassert.errors import PolicyRejection
from reproassert.models import ClaimLevel
from reproassert.sandbox import DockerRunResult
from reproassert.source_attestation import attest_source_tree
from reproassert.verifier import VerificationOutcome


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _candidate() -> dict[str, object]:
    content = (
        "from slugger import slugify\n\n"
        "def test_issue_1_reproduction():\n"
        "    assert slugify('a  b') == 'a-b', 'duplicate separators remain'\n"
    )
    return {
        "expected_symptom": "duplicate separators remain",
        "rationale": "Exercises repeated whitespace through the public slug function.",
        "relative_path": "tests/reproassert/test_issue_1.py",
        "test_content": content,
        "test_content_sha256": hashlib.sha256(content.encode()).hexdigest(),
    }


def _plan(tree_sha256: str) -> dict[str, object]:
    return {
        "case_id": "rk-v0.2-001",
        "index_policy": "pypi-hash-locked-wheels-v1",
        "packages": [{"name": "six", "sha256": ["7" * 64], "version": "1.17.0"}],
        "runtime": {
            "python_version": "3.12.13",
            "runner_image": "reproassert-sandbox:0.1.0",
        },
        "schema_version": "0.1.0",
        "source": {"base_sha": "a" * 40, "tree_sha256": tree_sha256},
    }


def _bundle(
    *,
    source_tree_sha256: str = "b" * 64,
    root_tree_oid: str = "c" * 40,
    dependency: bool = False,
) -> dict[str, object]:
    dependency_record: dict[str, object] | None = None
    if dependency:
        plan = _plan(source_tree_sha256)
        dependency_record = {
            "image_id": f"sha256:{'8' * 64}",
            "plan": plan,
            "plan_sha256": hashlib.sha256(_canonical(plan)).hexdigest(),
            "tree_sha256": "9" * 64,
        }
    value: dict[str, object] = {
        "algorithm": replay.REPLAY_BUNDLE_ALGORITHM,
        "candidate": _candidate(),
        "case": {
            "base_sha": "a" * 40,
            "id": "rk-v0.2-001",
            "issue_url": "https://github.com/owner/repo/issues/1",
            "repo": "owner/repo",
        },
        "dependency": dependency_record,
        "expected": {
            "failure_fingerprint": "f" * 64,
            "outcome": "repeatable_base_failure",
        },
        "repeats": 3,
        "schema_version": "0.1.0",
        "source": {
            "archive_sha256": "d" * 64,
            "root_tree_oid": root_tree_oid,
            "tree_sha256": source_tree_sha256,
        },
        "tool": {"git_sha": "e" * 40},
    }
    value["bundle_sha256"] = hashlib.sha256(_canonical(value)).hexdigest()
    return value


def _write(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _run(phase: str = "verify") -> DockerRunResult:
    return DockerRunResult(
        phase=phase,
        exit_code=1,
        duration_seconds=0.1,
        output="AssertionError: duplicate separators remain",
        timed_out=False,
        oom_killed=False,
        output_truncated=False,
        junit_xml=b"<testsuite/>",
        container_name=phase,
        argv=("python", "-m", "pytest"),
    )


def test_loads_canonical_bundle_and_rejects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "bundle.json"
    value = _bundle(dependency=True)
    schema = json.loads(Path("schemas/benchmark-v02-replay-bundle.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(value)
    _write(path, value)

    loaded = replay.load_v02_replay_bundle(path)

    assert loaded.case_id == "rk-v0.2-001"
    assert loaded.dependency_plan_sha256 == value["dependency"]["plan_sha256"]  # type: ignore[index]
    value["repeats"] = 4
    _write(path, value)
    with pytest.raises(PolicyRejection, match="digest"):
        replay.load_v02_replay_bundle(path)


def test_rejects_noncanonical_duplicate_and_unbound_dependency(tmp_path: Path) -> None:
    path = tmp_path / "bundle.json"
    path.write_text('{"schema_version":"0.1.0","schema_version":"0.1.0"}\n')
    with pytest.raises(PolicyRejection, match="invalid JSON"):
        replay.load_v02_replay_bundle(path)

    value = _bundle(dependency=True)
    value["dependency"]["plan_sha256"] = "0" * 64  # type: ignore[index]
    value["bundle_sha256"] = replay._self_hash(value, "bundle_sha256")
    _write(path, value)
    with pytest.raises(PolicyRejection, match="plan digest"):
        replay.load_v02_replay_bundle(path)


def test_runs_exact_source_bundle_without_provider(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_root = tmp_path / "extracted" / "source"
    source_root.mkdir(parents=True)
    (source_root / "slugger.py").write_text("def slugify(value): return value.replace(' ', '-')\n")
    source = attest_source_tree(source_root)
    bundle_path = tmp_path / "bundle.json"
    _write(
        bundle_path,
        _bundle(
            source_tree_sha256=source.tree_sha256,
            root_tree_oid=source.reconstructed_git_tree_oid,
        ),
    )
    archive_path = tmp_path / "source.tar.gz"
    archive_path.write_bytes(b"archive")

    class FakeSandbox:
        def require_ready(self) -> None:
            return None

        def cleanup(self) -> None:
            return None

    monkeypatch.setattr(
        replay,
        "fetch_commit_tree_metadata",
        lambda *_args: SimpleNamespace(
            commit_sha="a" * 40, tree_sha=source.reconstructed_git_tree_oid
        ),
    )
    monkeypatch.setattr(
        replay,
        "download_source_archive",
        lambda *_args: SimpleNamespace(path=archive_path, sha256="d" * 64),
    )
    monkeypatch.setattr(
        replay,
        "extract_source_archive",
        lambda *_args: SimpleNamespace(
            destination=source_root.parent,
            source_root=source_root,
            file_count=source.file_count,
            unpacked_bytes=source.total_bytes,
        ),
    )
    monkeypatch.setattr(replay, "DockerSandbox", FakeSandbox)
    monkeypatch.setattr(
        replay,
        "verify_candidate",
        lambda **_kwargs: VerificationOutcome(
            accepted=True,
            claim_level=ClaimLevel.REPEATABLE_BASE_FAILURE,
            outcome="repeatable_base_failure",
            fingerprint="f" * 64,
            collection=_run("collect"),
            runs=(_run("verify_1"), _run("verify_2"), _run("verify_3")),
        ),
    )

    result = replay.run_v02_replay_bundle(bundle_path, run_base=tmp_path / "runs")

    assert result.outcome == "repeatable_base_failure"
    record = json.loads(result.result_path.read_text())
    result_schema = json.loads(Path("schemas/benchmark-v02-replay-result.schema.json").read_text())
    Draft202012Validator.check_schema(result_schema)
    Draft202012Validator(result_schema).validate(record)
    assert record["bundle_sha256"] == replay.load_v02_replay_bundle(bundle_path).sha256
    assert record["dependency"] is None
    assert record["collection"]["phase"] == "collect"
    assert record["collection"]["argv"] == ["python", "-m", "pytest"]
    assert record["collection"]["junit_sha256"] == hashlib.sha256(b"<testsuite/>").hexdigest()
    assert record["result_sha256"] == replay._self_hash(record, "result_sha256")


def test_dependency_plan_must_bind_case_source_and_plan_hash(tmp_path: Path) -> None:
    path = tmp_path / "bundle.json"
    _write(path, _bundle(dependency=True))
    bundle = replay.load_v02_replay_bundle(path)
    plan_path = tmp_path / "plan.json"
    _write(plan_path, bundle.dependency_plan)
    plan = replay.load_dependency_plan(plan_path)

    replay._bind_dependency_plan(bundle, plan)

    object.__setattr__(plan, "base_sha", "0" * 40)
    with pytest.raises(PolicyRejection, match="differs"):
        replay._bind_dependency_plan(bundle, plan)

    object.__setattr__(plan, "base_sha", bundle.base_sha)
    object.__setattr__(plan, "runner_image", "hostile-local-image:latest")
    with pytest.raises(PolicyRejection, match="trusted runner"):
        replay._bind_dependency_plan(bundle, plan)


def test_rebuilds_bound_dependency_plan_before_verification(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_root = tmp_path / "extracted-dependency" / "source"
    source_root.mkdir(parents=True)
    (source_root / "slugger.py").write_text("def slugify(value): return value.replace(' ', '-')\n")
    source = attest_source_tree(source_root)
    bundle_path = tmp_path / "bundle.json"
    _write(
        bundle_path,
        _bundle(
            source_tree_sha256=source.tree_sha256,
            root_tree_oid=source.reconstructed_git_tree_oid,
            dependency=True,
        ),
    )
    archive_path = tmp_path / "source.tar.gz"
    archive_path.write_bytes(b"archive")
    observed_handle: list[object] = []
    handle = SimpleNamespace(execution_receipt_sha256="6" * 64)

    class FakeSandbox:
        def __init__(self, policy: object) -> None:
            self.policy = policy

        def require_ready(self) -> None:
            return None

        def cleanup(self) -> None:
            return None

    class FakeExecutor:
        def __init__(self, _path: Path, *, policy: object) -> None:
            self.policy = policy

        def __enter__(self) -> FakeExecutor:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def prepare(self, *, tool_git_sha: str) -> object:
            assert tool_git_sha == "e" * 40
            return SimpleNamespace(
                dependency_handle=handle,
                dependency_tree=SimpleNamespace(tree_sha256="9" * 64),
                image_id=f"sha256:{'8' * 64}",
            )

    monkeypatch.setattr(
        replay,
        "fetch_commit_tree_metadata",
        lambda *_args: SimpleNamespace(
            commit_sha="a" * 40, tree_sha=source.reconstructed_git_tree_oid
        ),
    )
    monkeypatch.setattr(
        replay,
        "download_source_archive",
        lambda *_args: SimpleNamespace(path=archive_path, sha256="d" * 64),
    )
    monkeypatch.setattr(
        replay,
        "extract_source_archive",
        lambda *_args: SimpleNamespace(
            destination=source_root.parent,
            source_root=source_root,
            file_count=source.file_count,
            unpacked_bytes=source.total_bytes,
        ),
    )
    monkeypatch.setattr(replay, "DockerSandbox", FakeSandbox)
    monkeypatch.setattr(replay, "DependencyExecutor", FakeExecutor)

    def verify(**kwargs: object) -> VerificationOutcome:
        observed_handle.append(kwargs["dependency_handle"])
        return VerificationOutcome(
            accepted=True,
            claim_level=ClaimLevel.REPEATABLE_BASE_FAILURE,
            outcome="repeatable_base_failure",
            fingerprint="f" * 64,
            collection=_run("collect"),
            runs=(_run("verify_1"), _run("verify_2"), _run("verify_3")),
        )

    monkeypatch.setattr(replay, "verify_candidate", verify)

    result = replay.run_v02_replay_bundle(bundle_path, run_base=tmp_path / "runs")

    record = json.loads(result.result_path.read_text())
    assert observed_handle == [handle]
    assert record["dependency"]["tree_sha256"] == "9" * 64
    assert record["dependency"]["image_id"] == f"sha256:{'8' * 64}"


def test_expected_replay_outcome_is_fail_closed() -> None:
    bundle = SimpleNamespace(
        expected_outcome="repeatable_base_failure", expected_fingerprint="f" * 64
    )
    outcome = VerificationOutcome(
        accepted=False,
        claim_level=ClaimLevel.COLLECTED,
        outcome="flaky_failure",
        fingerprint="f" * 64,
        collection=_run("collect"),
        runs=(),
    )
    with pytest.raises(PolicyRejection, match="differs"):
        replay._require_expected_outcome(bundle, outcome)  # type: ignore[arg-type]


def test_replay_cli_emits_bounded_machine_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bundle = tmp_path / "bundle.json"
    bundle.write_text("{}\n")
    result_path = tmp_path / "result.json"
    monkeypatch.setattr(
        cli,
        "run_v02_replay_bundle",
        lambda *_args, **_kwargs: replay.V02ReplayResult(
            run_dir=tmp_path,
            result_path=result_path,
            outcome="repeatable_base_failure",
            claim_level="repeatable_base_failure",
            fingerprint="f" * 64,
        ),
    )

    result = CliRunner().invoke(
        cli.main,
        ["benchmark", "replay-v02-case", str(bundle), "--run-base", str(tmp_path)],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["model_or_provider_invoked"] is False
    assert output["result_path"] == str(result_path)
