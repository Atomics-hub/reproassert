from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

import reproassert.benchmark_v02_upstream as upstream
from reproassert.errors import PolicyRejection


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _object(kind: str, payload: bytes) -> dict[str, str]:
    oid = hashlib.sha1(
        f"{kind} {len(payload)}\0".encode() + payload, usedforsecurity=False
    ).hexdigest()
    return {
        "oid": oid,
        "payload_base64": base64.b64encode(payload).decode(),
        "type": kind,
    }


def _tree(entries: list[tuple[bytes, bytes, str]]) -> dict[str, str]:
    payload = b"".join(
        mode + b" " + name + b"\0" + bytes.fromhex(oid) for mode, name, oid in entries
    )
    return _object("tree", payload)


def _repository(path: str, blob: bytes, repository_url: str) -> dict[str, object]:
    terminal = _object("blob", blob)
    objects: list[dict[str, str]] = [terminal]
    current = terminal["oid"]
    components = path.split("/")
    for index, component in reversed(list(enumerate(components))):
        mode = b"100644" if index == len(components) - 1 else b"40000"
        tree = _tree([(mode, component.encode(), current)])
        objects.insert(0, tree)
        current = tree["oid"]
    commit = _object("commit", f"tree {current}\n\nauthentic fixture\n".encode())
    objects.insert(0, commit)
    return {
        "commit_oid": commit["oid"],
        "objects": objects,
        "path": path,
        "repository_url": repository_url,
        "root_tree_oid": current,
    }


def _fixture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[dict[str, object], Path, Path]:
    ids = b"owner__repo-1\r\nowner__repo-2"
    artifact = b"PAR1exact-artifactPAR1"
    artifact_sha = hashlib.sha256(artifact).hexdigest()
    pointer = (
        "version https://git-lfs.github.com/spec/v1\n"
        f"oid sha256:{artifact_sha}\n"
        f"size {len(artifact)}\n"
    ).encode()
    tdd = _repository("id_list.txt", ids, upstream.TDD_BENCH_REPOSITORY_URL)
    source = _repository(
        "default/test/0000.parquet", artifact and pointer, upstream.SOURCE_DATASET_REPOSITORY_URL
    )
    tdd_objects = cast(list[dict[str, str]], tdd["objects"])
    source_objects = cast(list[dict[str, str]], source["objects"])
    monkeypatch.setattr(upstream, "OFFICIAL_TDD_BENCH_GIT_SHA", tdd["commit_oid"])
    monkeypatch.setattr(upstream, "OFFICIAL_TDD_BENCH_ROOT_TREE_OID", tdd["root_tree_oid"])
    monkeypatch.setattr(upstream, "OFFICIAL_TDD_ID_LIST_BLOB_OID", tdd_objects[-1]["oid"])
    monkeypatch.setattr(upstream, "OFFICIAL_TDD_ID_LIST_BYTES", len(ids))
    monkeypatch.setattr(upstream, "OFFICIAL_TDD_ID_LIST_SHA256", hashlib.sha256(ids).hexdigest())
    monkeypatch.setattr(upstream, "OFFICIAL_SOURCE_DATASET_GIT_SHA", source["commit_oid"])
    monkeypatch.setattr(upstream, "OFFICIAL_SOURCE_DATASET_ROOT_TREE_OID", source["root_tree_oid"])
    monkeypatch.setattr(upstream, "OFFICIAL_SOURCE_DATASET_GIT_BLOB_OID", source_objects[-1]["oid"])
    monkeypatch.setattr(upstream, "OFFICIAL_SOURCE_DATASET_LFS_SHA256", artifact_sha)
    monkeypatch.setattr(upstream, "OFFICIAL_SOURCE_DATASET_BYTES", len(artifact))
    monkeypatch.setattr(upstream, "OFFICIAL_SOURCE_DATASET_XET_SHA256", "9" * 64)
    monkeypatch.setattr(
        upstream,
        "SOURCE_DATASET_RESOLVE_URL",
        f"{upstream.SOURCE_DATASET_REPOSITORY_URL}/resolve/{source['commit_oid']}/"
        "default/test/0000.parquet",
    )
    witness: dict[str, object] = {
        "algorithm": upstream.UPSTREAM_OBJECT_WITNESS_ALGORITHM,
        "source_dataset": source,
        "tdd_bench": tdd,
        "xet_resolution": {
            "artifact_bytes": len(artifact),
            "artifact_etag": "9" * 64,
            "artifact_sha256": artifact_sha,
            "redirect_url_without_query": "https://us.aws.cdn.hf.co/xet/repo/" + "9" * 64,
            "request_url": upstream.SOURCE_DATASET_RESOLVE_URL,
            "resolved_commit": source["commit_oid"],
            "transferable_cryptographic_proof": False,
            "transport_authentication": "https_tls_at_collection",
            "xet_hash": "9" * 64,
        },
    }
    id_path = tmp_path / "id_list.txt"
    artifact_path = tmp_path / "0000.parquet"
    id_path.write_bytes(ids)
    artifact_path.write_bytes(artifact)
    return witness, id_path, artifact_path


def _write(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def test_verifier_rederives_complete_git_graph_lfs_and_xet_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    witness, ids, artifact = _fixture(monkeypatch, tmp_path)
    path = tmp_path / "witness.json"
    _write(path, witness)

    verified = upstream.verify_v02_upstream_provenance(
        path, tdd_id_list_path=ids, source_dataset_path=artifact
    )

    assert upstream.require_v02_upstream_provenance(verified) is verified
    assert verified.git_graph_verified is True
    assert verified.lfs_artifact_verified is True
    assert verified.xet_resolution_cross_bound is True
    assert verified.xet_resolution_transferable_cryptographic_proof is False


@pytest.mark.parametrize("mutation", ["commit", "tree", "blob", "path"])
def test_verifier_rejects_git_graph_forgery(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mutation: str
) -> None:
    witness, ids, artifact = _fixture(monkeypatch, tmp_path)
    source = cast(dict[str, object], witness["source_dataset"])
    objects = cast(list[dict[str, str]], source["objects"])
    if mutation == "path":
        source["path"] = "default/test/not-the-file.parquet"
    else:
        position = {"commit": 0, "tree": 1, "blob": -1}[mutation]
        objects[position]["payload_base64"] = base64.b64encode(b"forged").decode()
    path = tmp_path / "witness.json"
    _write(path, witness)
    with pytest.raises(PolicyRejection, match=r"Git object|pinned source"):
        upstream.verify_v02_upstream_provenance(
            path, tdd_id_list_path=ids, source_dataset_path=artifact
        )


@pytest.mark.parametrize("mutation", ["lfs", "xet", "redirect", "canonical"])
def test_verifier_rejects_artifact_or_transport_forgery(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mutation: str
) -> None:
    witness, ids, artifact = _fixture(monkeypatch, tmp_path)
    resolution = cast(dict[str, object], witness["xet_resolution"])
    if mutation == "lfs":
        artifact.write_bytes(b"different")
    elif mutation == "xet":
        resolution["xet_hash"] = "8" * 64
    elif mutation == "redirect":
        resolution["redirect_url_without_query"] = "https://evil.example/" + "9" * 64
    path = tmp_path / "witness.json"
    if mutation == "canonical":
        path.write_text(json.dumps(witness, indent=2))
    else:
        _write(path, witness)
    with pytest.raises(PolicyRejection):
        upstream.verify_v02_upstream_provenance(
            path, tdd_id_list_path=ids, source_dataset_path=artifact
        )
