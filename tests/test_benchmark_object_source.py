from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import tarfile
from pathlib import Path
from typing import Any

import jsonschema  # type: ignore[import-untyped]
import pytest
from click.testing import CliRunner

import reproassert.benchmark_object_source as object_source
import reproassert.cli as cli
import reproassert.github_blobs as github_blobs
from reproassert.benchmark_object_source import (
    OBJECT_SOURCE_DIRECTORY_SUFFIX,
    OBJECT_SOURCE_POLICY_SHA256,
    OBJECT_SOURCE_RECEIPT_FILENAME,
    prepare_object_source_case,
    verify_object_source_receipt,
)
from reproassert.benchmark_source import SOURCE_ARCHIVE_FILENAME, load_frozen_manifest
from reproassert.errors import PolicyRejection
from reproassert.git_objects import GitObjectSnapshot, parse_recursive_git_tree
from reproassert.intake import ArchiveDownload, CommitTreeMetadata

REPOSITORY_ROOT = Path(__file__).parents[1]
MANIFEST_PATH = REPOSITORY_ROOT / "benchmarks" / "v0.1" / "manifest.json"
ROOT_SCHEMA = REPOSITORY_ROOT / "schemas" / "benchmark-object-source-receipt.schema.json"
BUNDLED_SCHEMA = (
    REPOSITORY_ROOT
    / "src"
    / "reproassert"
    / "schemas"
    / "benchmark-object-source-receipt.schema.json"
)
GITLINK_OID = "7f11678c03286f72acc9bab77868dabaeb368fda"


def _blob_oid(content: bytes) -> str:
    digest = hashlib.sha1(f"blob {len(content)}\0".encode(), usedforsecurity=False)
    digest.update(content)
    return digest.hexdigest()


def _tree_oid(children: list[tuple[bytes, str, str]]) -> str:
    records: list[tuple[bytes, bytes]] = []
    for name, mode, oid in children:
        serialized_mode = b"40000" if mode == "040000" else mode.encode()
        sort_key = name + (b"/" if mode == "040000" else b"")
        records.append((sort_key, serialized_mode + b" " + name + b"\0" + bytes.fromhex(oid)))
    body = b"".join(record for _, record in sorted(records))
    digest = hashlib.sha1(f"tree {len(body)}\0".encode(), usedforsecurity=False)
    digest.update(body)
    return digest.hexdigest()


def _object_fixture() -> tuple[GitObjectSnapshot, dict[str, bytes], str]:
    files = {
        "exact.txt": ("100644", b"exact\n"),
        ".git_archival.txt": ("100644", b"ref: $Format:%H$\n"),
        "dir/target.txt": ("100644", b"target\n"),
        "dir/link.txt": ("120000", b"target.txt"),
    }
    blobs: dict[str, bytes] = {}
    leaves: list[dict[str, object]] = []
    for path, (mode, content) in files.items():
        oid = _blob_oid(content)
        blobs[oid] = content
        leaves.append(
            {"path": path, "mode": mode, "type": "blob", "sha": oid, "size": len(content)}
        )
    leaves.append(
        {
            "path": "helper",
            "mode": "160000",
            "type": "commit",
            "sha": GITLINK_OID,
        }
    )
    directory_children = [
        (Path(str(entry["path"])).name.encode(), str(entry["mode"]), str(entry["sha"]))
        for entry in leaves
        if str(entry["path"]).startswith("dir/")
    ]
    directory_oid = _tree_oid(directory_children)
    root_children = [
        (str(entry["path"]).encode(), str(entry["mode"]), str(entry["sha"]))
        for entry in leaves
        if "/" not in str(entry["path"])
    ]
    root_children.append((b"dir", "040000", directory_oid))
    root_oid = _tree_oid(root_children)
    payload = {
        "sha": root_oid,
        "truncated": False,
        "tree": [
            *leaves,
            {"path": "dir", "mode": "040000", "type": "tree", "sha": directory_oid},
        ],
    }
    return parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid), blobs, root_oid


def _write_transport_archive(
    path: Path, snapshot: GitObjectSnapshot, blobs: dict[str, bytes]
) -> Path:
    root = "fixture-deadbeef"
    with tarfile.open(path, "w:gz") as archive:
        for directory in (root, f"{root}/dir", f"{root}/helper"):
            member = tarfile.TarInfo(f"{directory}/")
            member.type = tarfile.DIRTYPE
            archive.addfile(member)
        for entry in snapshot.entries:
            if entry.is_tree or entry.is_gitlink:
                continue
            content = blobs[entry.oid]
            if entry.path == ".git_archival.txt":
                content = b"x" * len(content)
            member = tarfile.TarInfo(f"{root}/{entry.path}")
            if entry.is_symlink:
                member.type = tarfile.SYMTYPE
                member.linkname = content.decode()
                archive.addfile(member)
            else:
                member.type = tarfile.REGTYPE
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
    return path


def _install_fakes(
    monkeypatch: pytest.MonkeyPatch,
    archive_fixture: Path,
    snapshot: GitObjectSnapshot,
    case_sha: str,
) -> None:
    def fake_commit(
        _owner: str, _repo: str, sha: str, *, timeout_seconds: float
    ) -> CommitTreeMetadata:
        assert sha == case_sha
        assert timeout_seconds == 15.0
        return CommitTreeMetadata(case_sha, snapshot.root_tree_oid)

    def fake_tree(
        _owner: str,
        _repo: str,
        root_oid: str,
        *,
        timeout_seconds: float,
        limits: object,
    ) -> GitObjectSnapshot:
        assert root_oid == snapshot.root_tree_oid
        assert timeout_seconds == 15.0
        assert limits == object_source.DEFAULT_OBJECT_LIMITS
        return snapshot

    def fake_archive(
        _owner: str,
        _repo: str,
        sha: str,
        run_dir: Path,
        *,
        timeout_seconds: float,
    ) -> ArchiveDownload:
        assert sha == case_sha
        assert timeout_seconds == 15.0
        destination = run_dir / SOURCE_ARCHIVE_FILENAME
        shutil.copyfile(archive_fixture, destination)
        content = destination.read_bytes()
        return ArchiveDownload(destination, hashlib.sha256(content).hexdigest(), len(content))

    monkeypatch.setattr(object_source, "fetch_commit_tree_metadata", fake_commit)
    monkeypatch.setattr(object_source, "fetch_recursive_git_tree", fake_tree)
    monkeypatch.setattr(object_source, "download_source_archive", fake_archive)


def test_prepare_and_fresh_verify_are_deterministic_inert_and_schema_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = load_frozen_manifest(MANIFEST_PATH)
    case = manifest.require_case("rk-v0.1-001")
    snapshot, blobs, _ = _object_fixture()
    archive_fixture = _write_transport_archive(tmp_path / "fixture.tar.gz", snapshot, blobs)
    _install_fakes(monkeypatch, archive_fixture, snapshot, case.base_sha)
    archival = next(entry for entry in snapshot.entries if entry.path == ".git_archival.txt")
    calls: list[tuple[str, str, str, dict[str, object]]] = []

    def fetch_blob(owner: str, repo: str, oid: str, **kwargs: object) -> bytes:
        calls.append((owner, repo, oid, kwargs))
        return blobs[oid]

    roots = [tmp_path / "first", tmp_path / "second"]
    for root in roots:
        root.mkdir(mode=0o700)
        os.chmod(root, 0o700)
    v1_dir = roots[0] / case.id
    v1_dir.mkdir(mode=0o700)
    v1_receipt = v1_dir / "benchmark-source-receipt.json"
    v1_receipt.write_text("v1 remains untouched\n")

    first = prepare_object_source_case(
        MANIFEST_PATH,
        case.id,
        roots[0],
        tool_git_sha="a" * 40,
        blob_fetcher=fetch_blob,
    )
    second = prepare_object_source_case(
        MANIFEST_PATH,
        case.id,
        roots[1],
        tool_git_sha="a" * 40,
        blob_fetcher=fetch_blob,
    )

    assert first.name == OBJECT_SOURCE_RECEIPT_FILENAME
    assert first.parent.name == f"{case.id}{OBJECT_SOURCE_DIRECTORY_SUFFIX}"
    assert first.read_bytes() == second.read_bytes()
    assert v1_receipt.read_text() == "v1 remains untouched\n"
    assert (first.parent / SOURCE_ARCHIVE_FILENAME).is_file()
    assert not (first.parent / object_source.OBJECT_SOURCE_WORKSPACE_NAME).exists()
    receipt = json.loads(first.read_bytes())
    jsonschema.Draft202012Validator(json.loads(ROOT_SCHEMA.read_text())).validate(receipt)
    assert receipt["campaign_readiness_changed"] is False
    assert receipt["acquisition"]["policy_sha256"] == OBJECT_SOURCE_POLICY_SHA256
    assert receipt["source"]["object_snapshot"]["symlink_count"] == 1
    assert receipt["source"]["object_snapshot"]["gitlink_count"] == 1
    assert receipt["source"]["transport"]["fallback_blob_oids"] == [archival.oid]
    assert receipt["source"]["verified_workspace"]["workspace_retained"] is False
    expected_canonical = (
        json.dumps(
            receipt, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode()
        + b"\n"
    )
    assert first.read_bytes() == expected_canonical

    scratch_root = tmp_path / "scratch"
    scratch_root.mkdir(mode=0o700)
    os.chmod(scratch_root, 0o700)
    verified = verify_object_source_receipt(
        first,
        manifest_path=MANIFEST_PATH,
        expected_case_id=case.id,
        expected_receipt_sha256=hashlib.sha256(first.read_bytes()).hexdigest(),
        scratch_root=scratch_root,
        blob_fetcher=fetch_blob,
    )
    assert verified == receipt
    assert list(scratch_root.iterdir()) == []
    assert len(calls) == 3
    assert all(call[2] == archival.oid for call in calls)
    assert all(call[3]["expected_size"] == archival.size for call in calls)
    assert all(call[3]["timeout_seconds"] == 15.0 for call in calls)


def test_failures_cleanup_outputs_and_strict_parser_rejects_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = load_frozen_manifest(MANIFEST_PATH)
    case = manifest.require_case("rk-v0.1-001")
    snapshot, blobs, _ = _object_fixture()
    archive_fixture = _write_transport_archive(tmp_path / "fixture.tar.gz", snapshot, blobs)
    _install_fakes(monkeypatch, archive_fixture, snapshot, case.base_sha)
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)

    with pytest.raises(PolicyRejection):
        prepare_object_source_case(
            MANIFEST_PATH,
            case.id,
            root,
            tool_git_sha="b" * 40,
            blob_fetcher=lambda *_args, **_kwargs: b"wrong",
        )
    case_dir = root / f"{case.id}{OBJECT_SOURCE_DIRECTORY_SUFFIX}"
    assert not case_dir.exists()

    receipt = prepare_object_source_case(
        MANIFEST_PATH,
        case.id,
        root,
        tool_git_sha="b" * 40,
        blob_fetcher=lambda _owner, _repo, oid, **_kwargs: blobs[oid],
    )
    decoded = json.loads(receipt.read_bytes())
    decoded["unexpected"] = True
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(decoded, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(PolicyRejection):
        verify_object_source_receipt(
            tampered,
            manifest_path=MANIFEST_PATH,
            expected_case_id=case.id,
            blob_fetcher=lambda _owner, _repo, oid, **_kwargs: blobs[oid],
        )

    archive = receipt.parent / SOURCE_ARCHIVE_FILENAME
    archive.write_bytes(archive.read_bytes() + b"tampered")
    with pytest.raises(PolicyRejection):
        verify_object_source_receipt(
            receipt,
            manifest_path=MANIFEST_PATH,
            expected_case_id=case.id,
            blob_fetcher=lambda _owner, _repo, oid, **_kwargs: blobs[oid],
        )


def test_producer_validates_and_bounds_receipt_before_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = load_frozen_manifest(MANIFEST_PATH)
    case = manifest.require_case("rk-v0.1-001")
    snapshot, blobs, _ = _object_fixture()
    archive_fixture = _write_transport_archive(tmp_path / "fixture.tar.gz", snapshot, blobs)
    _install_fakes(monkeypatch, archive_fixture, snapshot, case.base_sha)
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)

    monkeypatch.setattr(object_source, "MAX_RECEIPT_BYTES", 1)
    with pytest.raises(PolicyRejection, match="byte limit"):
        prepare_object_source_case(
            MANIFEST_PATH,
            case.id,
            root,
            tool_git_sha="b" * 40,
            blob_fetcher=lambda _owner, _repo, oid, **_kwargs: blobs[oid],
        )
    assert not (root / f"{case.id}{OBJECT_SOURCE_DIRECTORY_SUFFIX}").exists()


def test_receipt_shape_accepts_bounded_utf8_git_repair_paths() -> None:
    snapshot, _, _ = _object_fixture()
    repair_entry = next(entry for entry in snapshot.entries if entry.path == ".git_archival.txt")
    receipt: dict[str, object] = {
        "schema_version": "2.0.0",
        "kind": "benchmark_object_source_receipt",
        "benchmark_version": "0.1.0",
        "case": {
            "id": "rk-v0.1-001",
            "repository": "owner/repo",
            "issue_url": "https://github.com/owner/repo/issues/1",
            "issue_number": 1,
            "base_sha": "a" * 40,
        },
        "manifest": {"raw_sha256": "b" * 64, "case_entry_sha256": "c" * 64},
        "source": {
            "repository_url": "https://github.com/owner/repo",
            "base_sha": "a" * 40,
            "github_root_tree_oid": snapshot.root_tree_oid,
            "object_snapshot": {
                "algorithm": snapshot.algorithm,
                "manifest_sha256": snapshot.manifest_sha256,
                "entry_count": snapshot.entry_count,
                "blob_count": snapshot.blob_count,
                "regular_file_count": snapshot.regular_file_count,
                "directory_count": snapshot.directory_count,
                "symlink_count": snapshot.symlink_count,
                "gitlink_count": snapshot.gitlink_count,
                "total_blob_bytes": snapshot.total_blob_bytes,
            },
            "transport": {
                "path": SOURCE_ARCHIVE_FILENAME,
                "sha256": "d" * 64,
                "bytes": 1,
                "member_count": 1,
                "regular_count": 1,
                "directory_count": 0,
                "symlink_count": 0,
                "exact_blob_count": 0,
                "repairs": [
                    {
                        "path": "données/éxport.txt",
                        "expected_oid": repair_entry.oid,
                        "reason": "missing",
                        "observed_oid": None,
                    }
                ],
                "fallback_blob_oids": [repair_entry.oid],
            },
            "verified_workspace": {
                "algorithm": "reproassert-git-object-content-tree-v1",
                "tree_sha256": "e" * 64,
                "git_root_tree_oid": snapshot.root_tree_oid,
                "object_manifest_sha256": snapshot.manifest_sha256,
                "regular_file_count": snapshot.regular_file_count,
                "directory_count": snapshot.directory_count,
                "symlink_count": snapshot.symlink_count,
                "gitlink_count": snapshot.gitlink_count,
                "git_metadata_absent": True,
                "symlinks_root_confined": True,
                "gitlinks_uninitialized": True,
                "workspace_retained": False,
            },
        },
        "acquisition": {
            "policy": object_source.object_source_acquisition_policy(),
            "policy_sha256": OBJECT_SOURCE_POLICY_SHA256,
            "runtime": {"http_timeout_seconds": 15.0},
        },
        "tool": {"name": "reproassert", "version": "0.1.0", "git_sha": "f" * 40},
        "campaign_readiness_changed": False,
    }

    assert object_source._validate_receipt_shape(receipt) == receipt
    transport = receipt["source"]
    assert isinstance(transport, dict)
    transport = transport["transport"]
    assert isinstance(transport, dict)
    repairs = transport["repairs"]
    assert isinstance(repairs, list)
    assert isinstance(repairs[0], dict)
    original_fallback = transport["fallback_blob_oids"]
    transport["fallback_blob_oids"] = [{}]
    with pytest.raises(PolicyRejection, match="Fallback blob oid"):
        object_source._validate_receipt_shape(receipt)
    transport["fallback_blob_oids"] = original_fallback
    repairs[0]["path"] = "é" * 2049
    with pytest.raises(PolicyRejection, match="UTF-8 byte limit"):
        object_source._validate_receipt_shape(receipt)


class _FakeResponse:
    def __init__(self, url: str, content: bytes, *, declared_size: int | None = None) -> None:
        self._url = url
        self._content = content
        self._offset = 0
        self.headers = {
            "Content-Length": str(len(content) if declared_size is None else declared_size)
        }
        self.closed = False

    def geturl(self) -> str:
        return self._url

    def read(self, size: int) -> bytes:
        chunk = self._content[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True


class _FakeOpener:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response
        self.request: Any = None
        self.timeout: float | None = None

    def open(self, request: Any, *, timeout: float) -> _FakeResponse:
        self.request = request
        self.timeout = timeout
        return self.response


def test_raw_blob_fetch_is_fixed_unauthenticated_bounded_and_oid_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"exact blob\n"
    oid = _blob_oid(content)
    url = f"https://api.github.com/repos/owner/repo/git/blobs/{oid}"
    response = _FakeResponse(url, content)
    opener = _FakeOpener(response)
    monkeypatch.setattr(github_blobs, "_build_opener", lambda: opener)

    observed = github_blobs.fetch_raw_git_blob(
        "owner", "repo", oid, expected_size=len(content), timeout_seconds=9
    )

    assert observed == content
    assert opener.request.full_url == url
    assert opener.request.get_header("Accept") == "application/vnd.github.raw+json"
    assert opener.request.get_header("Authorization") is None
    assert opener.timeout == 9.0
    assert response.closed is True


@pytest.mark.parametrize("failure", ["wrong_oid", "wrong_size", "redirect", "bad_repo"])
def test_raw_blob_fetch_fails_closed(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    content = b"exact blob\n"
    oid = _blob_oid(content)
    url = f"https://api.github.com/repos/owner/repo/git/blobs/{oid}"
    response_url = "https://example.com/escape" if failure == "redirect" else url
    declared = len(content) + 1 if failure == "wrong_size" else len(content)
    response_content = b"x" * len(content) if failure == "wrong_oid" else content
    opener = _FakeOpener(_FakeResponse(response_url, response_content, declared_size=declared))
    monkeypatch.setattr(github_blobs, "_build_opener", lambda: opener)

    with pytest.raises((PolicyRejection, ValueError)):
        github_blobs.fetch_raw_git_blob(
            "bad/repo" if failure == "bad_repo" else "owner",
            "repo",
            oid,
            expected_size=len(content),
        )


def test_schema_bundle_and_cli_commands_are_preparation_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root_schema = ROOT_SCHEMA.read_bytes()
    assert root_schema == BUNDLED_SCHEMA.read_bytes()
    jsonschema.Draft202012Validator.check_schema(json.loads(root_schema))
    schema_result = CliRunner().invoke(
        cli.main, ["schema", "--name", "benchmark-object-source-receipt"]
    )
    assert schema_result.exit_code == 0, schema_result.output
    assert schema_result.output.encode() == root_schema

    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    output_root = tmp_path / "prepared"
    receipt = output_root / "rk-v0.1-001-object-v2" / OBJECT_SOURCE_RECEIPT_FILENAME

    def fake_prepare(*_args: object, **_kwargs: object) -> Path:
        receipt.parent.mkdir(mode=0o700)
        receipt.write_text("{}")
        return receipt

    monkeypatch.setattr(cli, "prepare_object_source_case", fake_prepare)
    prepared = CliRunner().invoke(
        cli.main,
        [
            "benchmark",
            "prepare-object-source",
            "rk-v0.1-001",
            "--manifest",
            str(manifest),
            "--output-root",
            str(output_root),
            "--tool-git-sha",
            "a" * 40,
        ],
    )
    assert prepared.exit_code == 0, prepared.output
    assert json.loads(prepared.output)["campaign_readiness_changed"] is False

    monkeypatch.setattr(
        cli,
        "verify_object_source_receipt",
        lambda *_args, **_kwargs: {
            "source": {
                "github_root_tree_oid": "b" * 40,
                "transport": {"sha256": "c" * 64},
                "verified_workspace": {"tree_sha256": "d" * 64},
            }
        },
    )
    verified = CliRunner().invoke(
        cli.main,
        [
            "benchmark",
            "verify-object-source",
            str(receipt),
            "--manifest",
            str(manifest),
            "--case-id",
            "rk-v0.1-001",
        ],
    )
    assert verified.exit_code == 0, verified.output
    output = json.loads(verified.output)
    assert output["verified"] is True
    assert output["campaign_readiness_changed"] is False
