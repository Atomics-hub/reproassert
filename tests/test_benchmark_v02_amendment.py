from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest
from click.testing import CliRunner

import reproassert.benchmark_v02_amendment as amendment
from reproassert.benchmark_v02_instance_controller import GoldSmokeReceipt, GoldSmokeSpec
from reproassert.cli import main
from reproassert.errors import PolicyRejection


def _specs() -> tuple[GoldSmokeSpec, ...]:
    rows = []
    for number in range(1, 21):
        instance = amendment.AMENDED_INSTANCE_ID if number == 14 else f"org__repo-{number}"
        fail = tuple(f"test_{number}_{index}" for index in range(6 if number == 14 else 1))
        rows.append(GoldSmokeSpec(instance, "1.0", fail, (f"pass_{number}",)))
    return tuple(rows)


def _amended_specs(original: tuple[GoldSmokeSpec, ...]) -> tuple[GoldSmokeSpec, ...]:
    rows = list(original)
    before = rows[13]
    rows[13] = GoldSmokeSpec(
        before.instance_id, before.version, (before.fail_to_pass[2],), before.pass_to_pass
    )
    return tuple(rows)


def _smoke(*, amended: bool, manifest_sha: str, hidden_sha: str) -> dict[str, object]:
    return {
        "claims": {"model_or_provider_invoked": False, "provider_calls": 0},
        "counts": {
            "infrastructure_failure": 0 if amended else 1,
            "not_run": 0,
            "selected": 20,
            "semantic_valid": 20 if amended else 19,
        },
        "executed_at": "2026-07-11T14:34:00Z" if amended else "2026-07-11T14:01:27Z",
        "inputs": {
            "gold_specs_sha256": (
                amendment.AMENDED_GOLD_SPECS_SHA256
                if amended
                else amendment.LEGACY_GOLD_SPECS_SHA256
            ),
            "hidden_extraction_receipt_sha256": hidden_sha,
            "instance_runtime_manifest_sha256": manifest_sha,
        },
        "policy": {"sandbox": {"network_mode": "none"}},
        "receipt_sha256": ("e" if amended else "d") * 64,
        "selection": "all",
        "status": "complete",
        "tool_git_sha": "a" * 40,
    }


def _installed_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[dict[str, Path], str]:
    original_raw = b"original\n"
    amended_raw = b"amended\n"
    monkeypatch.setattr(
        amendment, "LEGACY_GOLD_SPECS_SHA256", hashlib.sha256(original_raw).hexdigest()
    )
    monkeypatch.setattr(
        amendment, "AMENDED_GOLD_SPECS_SHA256", hashlib.sha256(amended_raw).hexdigest()
    )
    original_specs = _specs()
    amended_specs = _amended_specs(original_specs)
    monkeypatch.setattr(
        amendment,
        "_load_gold_specs",
        lambda raw: original_specs if raw == original_raw else amended_specs,
    )
    manifest_sha = "b" * 64
    entries = tuple(
        SimpleNamespace(case_id=f"rk-v0.2-{number:03d}", instance_id=spec.instance_id)
        for number, spec in enumerate(original_specs, start=1)
    )
    monkeypatch.setattr(
        amendment,
        "load_instance_runtime_manifest",
        lambda _path: SimpleNamespace(sha256=manifest_sha, entries=entries),
    )
    hidden_raw = amendment._canonical({"receipt_sha256": "c" * 64}) + b"\n"
    hidden_sha = hashlib.sha256(hidden_raw).hexdigest()
    old = _smoke(amended=False, manifest_sha=manifest_sha, hidden_sha=hidden_sha)
    new = _smoke(amended=True, manifest_sha=manifest_sha, hidden_sha=hidden_sha)
    old_raw = amendment._canonical(old) + b"\n"
    new_raw = amendment._canonical(new) + b"\n"
    paths = {
        "original_gold_specs": tmp_path / "original-specs.json",
        "amended_gold_specs": tmp_path / "amended-specs.json",
        "original_gold_smoke_receipt": tmp_path / "original-smoke.json",
        "amended_gold_smoke_receipt": tmp_path / "amended-smoke.json",
        "instance_runtime_manifest": tmp_path / "manifest.json",
        "hidden_extraction_receipt": tmp_path / "hidden.json",
    }
    for path, raw in (
        (paths["original_gold_specs"], original_raw),
        (paths["amended_gold_specs"], amended_raw),
        (paths["original_gold_smoke_receipt"], old_raw),
        (paths["amended_gold_smoke_receipt"], new_raw),
        (paths["instance_runtime_manifest"], b"manifest\n"),
        (paths["hidden_extraction_receipt"], hidden_raw),
    ):
        path.write_bytes(raw)

    def verify_smoke(path: Path) -> GoldSmokeReceipt:
        raw = path.read_bytes()
        record = json.loads(raw)
        return GoldSmokeReceipt(
            path,
            hashlib.sha256(raw).hexdigest(),
            20,
            record["counts"]["semantic_valid"],
            record["counts"]["infrastructure_failure"],
        )

    monkeypatch.setattr(amendment, "verify_instance_gold_smoke_receipt", verify_smoke)
    monkeypatch.setattr(
        amendment,
        "verify_v02_hidden_gold",
        lambda _path: SimpleNamespace(prepared=SimpleNamespace(receipt_sha256=hidden_sha)),
    )
    return paths, manifest_sha


def _prepare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, amendment.VerifiedV02BenchmarkAmendment, dict[str, Path], str]:
    paths, manifest_sha = _installed_inputs(tmp_path, monkeypatch)
    output = tmp_path / "amendment.json"
    verified = amendment.prepare_v02_benchmark_amendment(
        **paths,
        expected_runtime_manifest_sha256=manifest_sha,
        prepared_at="2026-07-11T15:00:00Z",
        tool_git_sha="d" * 40,
        review_status="pending",
        reviewer_ids=(),
        output_path=output,
    )
    return output, verified, paths, manifest_sha


def test_amendment_is_verifier_issued_canonical_self_hashed_and_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, verified, _, _ = _prepare(tmp_path, monkeypatch)
    with pytest.raises(TypeError, match="verifier-issued"):
        amendment.VerifiedV02BenchmarkAmendment()
    assert amendment.require_v02_benchmark_amendment(verified) is verified
    with pytest.raises(PolicyRejection, match="review is pending"):
        amendment.require_approved_v02_benchmark_amendment(verified)
    record = json.loads(output.read_bytes())
    assert record["receipt_sha256"] == amendment._self_hash(record)
    assert record["claims"]["provider_calls"] == 0
    assert record["claims"]["nominal_authority_serialized"] is False
    encoded = output.read_text()
    assert "test_14" not in encoded
    assert str(tmp_path) not in encoded
    assert "output_sha256" not in encoded
    public = Path("schemas/benchmark-v02-amendment.schema.json")
    packaged = Path("src/reproassert/schemas/benchmark-v02-amendment.schema.json")
    assert public.read_bytes() == packaged.read_bytes()
    schema = json.loads(public.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)


def test_spec_delta_rejects_addition_wrong_case_pass_to_pass_and_order() -> None:
    original = _specs()
    amended_specs = list(_amended_specs(original))
    target = amended_specs[13]

    amended_specs[13] = GoldSmokeSpec(
        target.instance_id,
        target.version,
        (*target.fail_to_pass, "addition"),
        target.pass_to_pass,
    )
    with pytest.raises(PolicyRejection, match="strict-subset"):
        amendment._verify_spec_delta(original, tuple(amended_specs))

    wrong = list(original)
    wrong[0] = GoldSmokeSpec(wrong[0].instance_id, "1.0", ("changed",), wrong[0].pass_to_pass)
    with pytest.raises(PolicyRejection, match="strict-subset"):
        amendment._verify_spec_delta(original, tuple(wrong))

    changed_p2p = list(_amended_specs(original))
    target = changed_p2p[13]
    changed_p2p[13] = GoldSmokeSpec(target.instance_id, target.version, target.fail_to_pass, ())
    with pytest.raises(PolicyRejection, match="strict-subset"):
        amendment._verify_spec_delta(original, tuple(changed_p2p))

    reordered = list(_amended_specs(original))
    reordered[0], reordered[1] = reordered[1], reordered[0]
    with pytest.raises(PolicyRejection, match="reorder"):
        amendment._verify_spec_delta(original, tuple(reordered))


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("swap_specs", "19/1 to 20/0"),
        ("tool", "different tool revisions"),
        ("time", "chronologically follow"),
        ("network", "19/1 to 20/0"),
        ("provider", "19/1 to 20/0"),
    ],
)
def test_smoke_pair_rejects_swaps_tool_time_and_policy(mutation: str, message: str) -> None:
    manifest_sha = "b" * 64
    hidden_sha = "c" * 64
    old = _smoke(amended=False, manifest_sha=manifest_sha, hidden_sha=hidden_sha)
    new = _smoke(amended=True, manifest_sha=manifest_sha, hidden_sha=hidden_sha)
    if mutation == "swap_specs":
        old["inputs"]["gold_specs_sha256"] = amendment.AMENDED_GOLD_SPECS_SHA256  # type: ignore[index]
    elif mutation == "tool":
        new["tool_git_sha"] = "f" * 40
    elif mutation == "time":
        new["executed_at"] = old["executed_at"]
    elif mutation == "network":
        new["policy"]["sandbox"]["network_mode"] = "bridge"  # type: ignore[index]
    else:
        new["claims"]["provider_calls"] = 1  # type: ignore[index]
    with pytest.raises(PolicyRejection, match=message):
        amendment._verify_smoke_pair(old, new, manifest_sha)


def test_verifier_rejects_selfhash_tool_time_and_input_toctou(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, _, paths, manifest_sha = _prepare(tmp_path, monkeypatch)
    record = json.loads(output.read_bytes())
    record["receipt_sha256"] = "0" * 64
    output.write_bytes(amendment._canonical(record) + b"\n")
    with pytest.raises(PolicyRejection, match="identity"):
        amendment.verify_v02_benchmark_amendment(
            output, **paths, expected_runtime_manifest_sha256=manifest_sha
        )

    record["receipt_sha256"] = amendment._self_hash(record)
    record["tool_git_sha"] = "not-a-sha"
    record["receipt_sha256"] = amendment._self_hash(record)
    output.write_bytes(amendment._canonical(record) + b"\n")
    with pytest.raises(PolicyRejection, match="tool Git SHA"):
        amendment.verify_v02_benchmark_amendment(
            output, **paths, expected_runtime_manifest_sha256=manifest_sha
        )

    output.unlink()
    output, _, paths, manifest_sha = _prepare(tmp_path, monkeypatch)
    record = json.loads(output.read_bytes())
    record["prepared_at"] = "2026-07-11T14:00:00Z"
    record["receipt_sha256"] = amendment._self_hash(record)
    output.write_bytes(amendment._canonical(record) + b"\n")
    with pytest.raises(PolicyRejection, match="predates"):
        amendment.verify_v02_benchmark_amendment(
            output, **paths, expected_runtime_manifest_sha256=manifest_sha
        )

    monkeypatch.setattr(
        amendment,
        "verify_instance_gold_smoke_receipt",
        lambda path: GoldSmokeReceipt(path, "0" * 64, 20, 19, 1),
    )
    with pytest.raises(PolicyRejection, match="changed after verification"):
        amendment.verify_v02_benchmark_amendment(
            output, **paths, expected_runtime_manifest_sha256=manifest_sha
        )


def test_amendment_cli_contract_is_exposed() -> None:
    runner = CliRunner()
    for command in ("prepare-v02-amendment", "verify-v02-amendment"):
        result = runner.invoke(main, ["benchmark", command, "--help"])
        assert result.exit_code == 0, result.output
        assert "--original-gold-specs" in result.output
        assert "--amended-gold-smoke-receipt" in result.output
