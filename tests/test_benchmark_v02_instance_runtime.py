from __future__ import annotations

import json
from pathlib import Path

import pytest

from reproassert.benchmark_v02_instance_runtime import (
    InstanceRuntime,
    instance_runtime_manifest_bytes,
    load_instance_runtime_manifest,
)
from reproassert.errors import PolicyRejection


def _entry(number: int, digit: str) -> InstanceRuntime:
    return InstanceRuntime(
        case_id=f"rk-v0.2-{number:03d}",
        instance_id=f"project__repo-{1000 + number}",
        base_sha=digit * 40,
        base_tree_oid=chr(ord(digit) + 1) * 40,
        spec_sha256=digit * 64,
        image_tag=f"swebench/sweb.eval.x86_64.project_repo-{1000 + number}:latest",
        image_digest=f"sha256:{digit * 64}",
        image_id=f"sha256:{chr(ord(digit) + 1) * 64}",
    )


def _manifest(tmp_path: Path) -> Path:
    path = tmp_path / "instance-runtimes.json"
    path.write_bytes(
        instance_runtime_manifest_bytes(
            harness_git_sha="a" * 40,
            harness_specs_sha256="b" * 64,
            entries=(_entry(1, "c"), _entry(2, "e")),
        )
    )
    return path


def test_loads_and_requires_exact_instance_image_identity(tmp_path: Path) -> None:
    manifest = load_instance_runtime_manifest(_manifest(tmp_path))
    selected = manifest.entries[0]

    observed = manifest.require(
        case_id=selected.case_id,
        instance_id=selected.instance_id,
        image_tag=selected.image_tag,
        observed_image_digest=selected.image_digest,
        observed_image_id=selected.image_id,
        observed_platform="linux/amd64",
    )

    assert observed == selected
    assert manifest.harness_git_sha == "a" * 40


@pytest.mark.parametrize("mutation", ["case", "tag", "digest", "id", "platform"])
def test_runtime_resolution_fails_closed(tmp_path: Path, mutation: str) -> None:
    manifest = load_instance_runtime_manifest(_manifest(tmp_path))
    selected = manifest.entries[0]
    arguments = {
        "case_id": selected.case_id,
        "instance_id": selected.instance_id,
        "image_tag": selected.image_tag,
        "observed_image_digest": selected.image_digest,
        "observed_image_id": selected.image_id,
        "observed_platform": "linux/amd64",
    }
    arguments[
        {
            "case": "case_id",
            "tag": "image_tag",
            "digest": "observed_image_digest",
            "id": "observed_image_id",
            "platform": "observed_platform",
        }[mutation]
    ] = {
        "case": "rk-v0.2-020",
        "tag": "swebench/other:latest",
        "digest": f"sha256:{'9' * 64}",
        "id": f"sha256:{'8' * 64}",
        "platform": "linux/arm64",
    }[mutation]

    with pytest.raises(PolicyRejection):
        manifest.require(**arguments)


def test_rejects_tampering_duplicate_keys_and_weakened_policy(tmp_path: Path) -> None:
    path = _manifest(tmp_path)
    value = json.loads(path.read_bytes())
    value["entries"][0]["image_digest"] = f"sha256:{'9' * 64}"
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(PolicyRejection, match="digest"):
        load_instance_runtime_manifest(path)

    path.write_text('{"algorithm":"x","algorithm":"y"}\n')
    with pytest.raises(PolicyRejection, match="invalid JSON"):
        load_instance_runtime_manifest(path)

    path = _manifest(tmp_path)
    value = json.loads(path.read_bytes())
    value["policy"]["network_mode"] = "bridge"
    value["manifest_sha256"] = "0" * 64
    unsigned = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    import hashlib

    value["manifest_sha256"] = hashlib.sha256(unsigned).hexdigest()
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(PolicyRejection, match="policy"):
        load_instance_runtime_manifest(path)


def test_rejects_ambiguous_case_or_instance(tmp_path: Path) -> None:
    first = _entry(1, "c")
    second = InstanceRuntime(
        case_id="rk-v0.2-002",
        instance_id=first.instance_id,
        base_sha="e" * 40,
        base_tree_oid="f" * 40,
        spec_sha256="e" * 64,
        image_tag="swebench/second:latest",
        image_digest=f"sha256:{'e' * 64}",
        image_id=f"sha256:{'f' * 64}",
    )
    path = tmp_path / "ambiguous.json"
    path.write_bytes(
        instance_runtime_manifest_bytes(
            harness_git_sha="a" * 40,
            harness_specs_sha256="b" * 64,
            entries=(first, second),
        )
    )
    with pytest.raises(PolicyRejection, match="ambiguous"):
        load_instance_runtime_manifest(path)
