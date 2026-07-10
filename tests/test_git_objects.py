from __future__ import annotations

import copy
import hashlib
import io
import os
import tarfile
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import reproassert.git_objects as git_objects
from reproassert.codeload_transport import (
    complete_codeload_repairs,
    plan_codeload_repairs,
)
from reproassert.errors import PolicyRejection
from reproassert.git_objects import (
    GIT_OBJECT_SNAPSHOT_ALGORITHM,
    MAX_GIT_TREE_JSON_BYTES,
    GitObjectEntry,
    GitObjectLimits,
    GitObjectSnapshot,
    fetch_recursive_git_tree,
    materialize_git_workspace,
    parse_recursive_git_tree,
    verify_git_object_blobs,
)

GITLINK_OID = "7f11678c03286f72acc9bab77868dabaeb368fda"


def _blob_oid(content: bytes) -> str:
    digest = hashlib.sha1(f"blob {len(content)}\0".encode(), usedforsecurity=False)
    digest.update(content)
    return digest.hexdigest()


def _tree_oid(children: list[tuple[bytes, str, str]]) -> str:
    records: list[tuple[bytes, bytes]] = []
    for name, mode, oid in children:
        sort_key = name + (b"/" if mode == "040000" else b"")
        serialized_mode = b"40000" if mode == "040000" else mode.encode()
        record = serialized_mode + b" " + name + b"\0" + bytes.fromhex(oid)
        records.append((sort_key, record))
    body = b"".join(record for _, record in sorted(records))
    digest = hashlib.sha1(f"tree {len(body)}\0".encode(), usedforsecurity=False)
    digest.update(body)
    return digest.hexdigest()


def _fixture_payload(
    *,
    symlink_target: bytes = b"back.svg",
    extra_symlinks: Mapping[str, bytes] | None = None,
) -> tuple[dict[str, object], dict[str, bytes], str]:
    file_specs: dict[str, tuple[str, bytes]] = {
        ".gitattributes": ("100644", b".git_archival.txt export-subst\n"),
        ".git_archival.txt": ("100644", b"ref-names: $Format:%D$\n"),
        "pkg/data/back.svg": ("100644", b"<svg/>\n"),
        "pkg/data/back-symbolic.svg": ("120000", symlink_target),
        "run.sh": ("100755", b"#!/bin/sh\nexit 0\n"),
    }
    for path, target in (extra_symlinks or {}).items():
        file_specs[path] = ("120000", target)
    leaves: dict[str, dict[str, object]] = {}
    blobs: dict[str, bytes] = {}
    for path, (mode, content) in file_specs.items():
        oid = _blob_oid(content)
        blobs[oid] = content
        leaves[path] = {
            "path": path,
            "mode": mode,
            "type": "blob",
            "sha": oid,
            "size": len(content),
            "url": f"https://api.github.com/blob/{oid}",
        }
    leaves["vendor/helper"] = {
        "path": "vendor/helper",
        "mode": "160000",
        "type": "commit",
        "sha": GITLINK_OID,
    }

    directories: set[str] = set()
    for path in leaves:
        parts = path.split("/")
        directories.update("/".join(parts[:depth]) for depth in range(1, len(parts)))
    tree_oids: dict[str, str] = {}
    for directory in sorted(directories, key=lambda item: (item.count("/"), item), reverse=True):
        prefix = f"{directory}/"
        children: list[tuple[bytes, str, str]] = []
        for path, value in leaves.items():
            if path.startswith(prefix) and "/" not in path[len(prefix) :]:
                children.append(
                    (
                        path[len(prefix) :].encode(),
                        str(value["mode"]),
                        str(value["sha"]),
                    )
                )
        for child, oid in tree_oids.items():
            if child.startswith(prefix) and "/" not in child[len(prefix) :]:
                children.append((child[len(prefix) :].encode(), "040000", oid))
        tree_oids[directory] = _tree_oid(children)

    root_children: list[tuple[bytes, str, str]] = []
    for path, value in leaves.items():
        if "/" not in path:
            root_children.append((path.encode(), str(value["mode"]), str(value["sha"])))
    for directory, oid in tree_oids.items():
        if "/" not in directory:
            root_children.append((directory.encode(), "040000", oid))
    root_oid = _tree_oid(root_children)
    tree_entries = [
        {
            "path": path,
            "mode": "040000",
            "type": "tree",
            "sha": oid,
        }
        for path, oid in tree_oids.items()
    ]
    payload: dict[str, object] = {
        "sha": root_oid,
        "url": "https://api.github.com/tree",
        "tree": [*leaves.values(), *tree_entries],
        "truncated": False,
    }
    return payload, blobs, root_oid


def _rejection_code(call: Any) -> str:
    with pytest.raises(PolicyRejection) as rejected:
        call()
    return rejected.value.code


def test_exact_object_plan_preserves_symlink_gitlink_and_unexpanded_blob(
    tmp_path: Path,
) -> None:
    payload, blobs, root_oid = _fixture_payload()
    snapshot = parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid)
    calls: list[str] = []

    def load_blob(entry: GitObjectEntry) -> bytes:
        calls.append(entry.oid)
        return blobs[entry.oid]

    plan = verify_git_object_blobs(snapshot, load_blob)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    os.chmod(private, 0o700)
    workspace = materialize_git_workspace(plan, private / "source")

    assert snapshot.algorithm == GIT_OBJECT_SNAPSHOT_ALGORITHM
    assert snapshot.root_tree_oid == root_oid
    assert snapshot.entry_count == 9
    assert snapshot.regular_file_count == 4
    assert snapshot.directory_count == 3
    assert snapshot.symlink_count == snapshot.gitlink_count == 1
    assert len(calls) == len(set(calls)) == snapshot.blob_count
    assert workspace.root_tree_oid == root_oid
    assert workspace.manifest_sha256 == snapshot.manifest_sha256
    assert workspace.tree_sha256 == plan.tree_sha256
    assert len(plan.tree_sha256) == 64
    assert (workspace.path / ".git_archival.txt").read_bytes() == blobs[
        next(entry.oid for entry in snapshot.entries if entry.path == ".git_archival.txt")
    ]
    link = workspace.path / "pkg/data/back-symbolic.svg"
    assert link.is_symlink()
    assert os.readlink(link) == "back.svg"
    assert (workspace.path / "vendor/helper").is_dir()
    assert not any((workspace.path / "vendor/helper").iterdir())
    assert not (workspace.path / ".git").exists()
    assert stat_mode(workspace.path / "run.sh") == 0o700
    assert stat_mode(workspace.path / ".gitattributes") == 0o600


def test_export_subst_archive_bytes_fail_object_verification() -> None:
    payload, blobs, root_oid = _fixture_payload()
    snapshot = parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid)
    archival_entry = next(entry for entry in snapshot.entries if entry.path == ".git_archival.txt")
    transformed = dict(blobs)
    transformed[archival_entry.oid] = b"x" * len(transformed[archival_entry.oid])

    assert (
        _rejection_code(
            lambda: verify_git_object_blobs(snapshot, lambda entry: transformed[entry.oid])
        )
        == "git_object_blob_mismatch"
    )


def test_verified_content_tree_sha256_changes_with_exact_content() -> None:
    first_payload, first_blobs, first_root = _fixture_payload()
    second_payload, second_blobs, second_root = _fixture_payload(symlink_target=b"other.svg")
    first = parse_recursive_git_tree(first_payload, expected_root_tree_oid=first_root)
    second = parse_recursive_git_tree(second_payload, expected_root_tree_oid=second_root)

    first_plan = verify_git_object_blobs(first, lambda entry: first_blobs[entry.oid])
    second_plan = verify_git_object_blobs(second, lambda entry: second_blobs[entry.oid])

    assert first_plan.tree_sha256 != second_plan.tree_sha256
    assert first.manifest_sha256 != second.manifest_sha256


def test_codeload_bulk_transport_repairs_only_missing_and_mutated_blobs(
    tmp_path: Path,
) -> None:
    payload, blobs, root_oid = _fixture_payload()
    snapshot = parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid)
    archive = _write_codeload_archive(
        tmp_path / "source.tar.gz",
        snapshot,
        blobs,
        mutate={".git_archival.txt"},
        omit={"run.sh"},
    )

    repair_plan = plan_codeload_repairs(snapshot, archive)
    repairs = {repair.path: repair for repair in repair_plan.repairs}
    calls: list[str] = []

    def fallback(oid: str) -> bytes:
        calls.append(oid)
        return blobs[oid]

    acquisition = complete_codeload_repairs(snapshot, repair_plan, fallback)

    assert repair_plan.archive_sha256 == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert repair_plan.archive_bytes == archive.stat().st_size
    assert repairs[".git_archival.txt"].reason == "blob_oid_mismatch"
    assert repairs[".git_archival.txt"].observed_oid is not None
    assert repairs["run.sh"].reason == "missing"
    assert repairs["run.sh"].observed_oid is None
    assert calls == list(repair_plan.repair_oids)
    assert acquisition.fallback_blob_count == 2
    assert acquisition.verified_plan.tree_sha256
    archival = next(entry for entry in snapshot.entries if entry.path == ".git_archival.txt")
    assert acquisition.verified_plan.blob_bytes(archival.oid) == blobs[archival.oid]


@pytest.mark.parametrize(
    ("variant", "code"),
    [
        ("extra", "codeload_extra_path"),
        ("special", "codeload_special_member"),
        ("duplicate", "codeload_path_collision"),
        ("second_root", "codeload_unsafe_root"),
        ("traversal", "codeload_unsafe_path"),
        ("git_metadata", "codeload_git_metadata"),
    ],
)
def test_codeload_rejects_unexpected_or_unsafe_members(
    tmp_path: Path, variant: str, code: str
) -> None:
    payload, blobs, root_oid = _fixture_payload()
    snapshot = parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid)
    archive = _write_codeload_archive(
        tmp_path / f"{variant}.tar.gz", snapshot, blobs, variant=variant
    )

    assert _rejection_code(lambda: plan_codeload_repairs(snapshot, archive)) == code


def test_codeload_limits_and_fallback_verification_fail_closed(tmp_path: Path) -> None:
    payload, blobs, root_oid = _fixture_payload()
    snapshot = parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid)
    archive = _write_codeload_archive(
        tmp_path / "source.tar.gz",
        snapshot,
        blobs,
        mutate={".git_archival.txt"},
    )
    assert (
        _rejection_code(
            lambda: plan_codeload_repairs(snapshot, archive, limits=GitObjectLimits(max_entries=1))
        )
        == "codeload_member_limit"
    )
    assert (
        _rejection_code(
            lambda: plan_codeload_repairs(
                snapshot, archive, limits=GitObjectLimits(max_total_blob_bytes=1)
            )
        )
        == "codeload_total_bytes"
    )

    repair_plan = plan_codeload_repairs(snapshot, archive)
    assert _rejection_code(
        lambda: complete_codeload_repairs(snapshot, repair_plan, lambda oid: b"wrong")
    ) in {"git_object_blob_size_mismatch", "git_object_blob_mismatch"}
    calls: list[str] = []
    forged_plan = replace(repair_plan, repair_oids=("0" * 40,))

    def unexpected_fallback(oid: str) -> bytes:
        calls.append(oid)
        return b"ignored"

    assert (
        _rejection_code(
            lambda: complete_codeload_repairs(
                snapshot,
                forged_plan,
                unexpected_fallback,
            )
        )
        == "codeload_plan_mismatch"
    )
    assert calls == []


def test_forged_snapshot_and_verified_plan_are_rejected_before_materialization(
    tmp_path: Path,
) -> None:
    payload, blobs, root_oid = _fixture_payload()
    snapshot = parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid)
    forged_snapshot = replace(snapshot, manifest_sha256="0" * 64)
    assert (
        _rejection_code(
            lambda: verify_git_object_blobs(forged_snapshot, lambda entry: blobs[entry.oid])
        )
        == "invalid_git_object_tree"
    )

    plan = verify_git_object_blobs(snapshot, lambda entry: blobs[entry.oid])
    forged_verified_plan = replace(plan, tree_sha256="0" * 64)
    private = tmp_path / "private-plan"
    private.mkdir(mode=0o700)
    os.chmod(private, 0o700)
    assert (
        _rejection_code(lambda: materialize_git_workspace(forged_verified_plan, private / "source"))
        == "invalid_git_object_tree"
    )
    assert not (private / "source").exists()


@pytest.mark.parametrize(
    "target",
    [
        b"/etc/passwd",
        b"../../../etc/passwd",
        b"..\\..\\etc\\passwd",
        b".git/config",
        b"",
        b"bad\x00target",
        b"bad\xfftarget",
    ],
)
def test_unsafe_symlink_targets_fail_closed(target: bytes) -> None:
    payload, blobs, root_oid = _fixture_payload(symlink_target=target)
    snapshot = parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid)

    assert (
        _rejection_code(lambda: verify_git_object_blobs(snapshot, lambda entry: blobs[entry.oid]))
        == "git_object_unsafe_symlink"
    )


def test_root_confined_parent_symlink_is_supported() -> None:
    payload, blobs, root_oid = _fixture_payload(symlink_target=b"../data/back.svg")
    snapshot = parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid)

    plan = verify_git_object_blobs(snapshot, lambda entry: blobs[entry.oid])

    assert plan.symlink_target("pkg/data/back-symbolic.svg") == "../data/back.svg"


def test_symlink_resolution_rejects_multihop_escape_and_cycle() -> None:
    payload, blobs, root_oid = _fixture_payload(
        symlink_target=b"pivot/../../../etc",
        extra_symlinks={"pkg/data/pivot": b"."},
    )
    snapshot = parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid)
    assert (
        _rejection_code(lambda: verify_git_object_blobs(snapshot, lambda entry: blobs[entry.oid]))
        == "git_object_unsafe_symlink"
    )

    payload, blobs, root_oid = _fixture_payload(
        symlink_target=b"pivot",
        extra_symlinks={"pkg/data/pivot": b"back-symbolic.svg"},
    )
    snapshot = parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid)
    assert (
        _rejection_code(lambda: verify_git_object_blobs(snapshot, lambda entry: blobs[entry.oid]))
        == "git_object_unsafe_symlink"
    )


def test_recursive_tree_requires_complete_consistent_hierarchy() -> None:
    payload, _, root_oid = _fixture_payload()

    wrong_root = copy.deepcopy(payload)
    wrong_root["sha"] = "0" * 40
    assert (
        _rejection_code(
            lambda: parse_recursive_git_tree(wrong_root, expected_root_tree_oid=root_oid)
        )
        == "git_object_root_mismatch"
    )

    truncated = copy.deepcopy(payload)
    truncated["truncated"] = True
    assert (
        _rejection_code(
            lambda: parse_recursive_git_tree(truncated, expected_root_tree_oid=root_oid)
        )
        == "git_object_tree_truncated"
    )

    missing_ancestor = copy.deepcopy(payload)
    missing_ancestor["tree"] = [
        entry for entry in entries(missing_ancestor) if entry.get("path") != "pkg"
    ]
    assert (
        _rejection_code(
            lambda: parse_recursive_git_tree(missing_ancestor, expected_root_tree_oid=root_oid)
        )
        == "git_object_invalid_hierarchy"
    )

    bad_subtree = copy.deepcopy(payload)
    next(entry for entry in entries(bad_subtree) if entry.get("path") == "pkg/data")["sha"] = (
        "0" * 40
    )
    assert (
        _rejection_code(
            lambda: parse_recursive_git_tree(bad_subtree, expected_root_tree_oid=root_oid)
        )
        == "git_object_subtree_mismatch"
    )


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda entry: entry.update({"mode": "100664"}), "git_object_mode"),
        (lambda entry: entry.update({"type": "commit"}), "git_object_type"),
        (lambda entry: entry.update({"size": -1}), "git_object_size"),
        (lambda entry: entry.update({"sha": "A" * 40}), "git_object_invalid_oid"),
        (lambda entry: entry.update({"path": ".git/config"}), "git_object_git_metadata"),
    ],
)
def test_invalid_entry_metadata_fails_before_blob_loading(mutation: Any, code: str) -> None:
    payload, _, root_oid = _fixture_payload()
    mutation(entries(payload)[0])

    assert (
        _rejection_code(lambda: parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid))
        == code
    )


def test_duplicate_and_case_colliding_paths_are_rejected() -> None:
    payload, _, root_oid = _fixture_payload()
    payload["tree"] = [*entries(payload), copy.deepcopy(entries(payload)[0])]
    assert (
        _rejection_code(lambda: parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid))
        == "git_object_path_collision"
    )

    payload, _, root_oid = _fixture_payload()
    duplicate = copy.deepcopy(entries(payload)[0])
    duplicate["path"] = str(duplicate["path"]).upper()
    payload["tree"] = [*entries(payload), duplicate]
    assert (
        _rejection_code(lambda: parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid))
        == "git_object_path_collision"
    )


def test_limits_cover_entries_blobs_paths_and_total_bytes() -> None:
    payload, _, root_oid = _fixture_payload()
    cases = [
        (GitObjectLimits(max_entries=1), "git_object_entry_limit"),
        (GitObjectLimits(max_blobs=1), "git_object_blob_limit"),
        (GitObjectLimits(max_blob_bytes=1), "git_object_blob_too_large"),
        (GitObjectLimits(max_total_blob_bytes=1), "git_object_total_bytes"),
        (GitObjectLimits(max_path_bytes=1), "git_object_path_too_long"),
        (GitObjectLimits(max_component_bytes=1), "git_object_component_too_long"),
    ]
    for limits, code in cases:
        assert (
            _rejection_code(
                lambda limits=limits: parse_recursive_git_tree(
                    payload, expected_root_tree_oid=root_oid, limits=limits
                )
            )
            == code
        )


def test_fetch_uses_fixed_unauthenticated_api_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    payload, _, root_oid = _fixture_payload()
    observed: dict[str, object] = {}

    def fake_fetch_json(
        url: str, *, expected_host: str, max_bytes: int, timeout_seconds: float
    ) -> dict[str, Any]:
        observed.update(
            url=url,
            expected_host=expected_host,
            max_bytes=max_bytes,
            timeout_seconds=timeout_seconds,
        )
        return payload

    monkeypatch.setattr(git_objects, "_fetch_json", fake_fetch_json)
    snapshot = fetch_recursive_git_tree("owner", "repo", root_oid, timeout_seconds=12)

    assert snapshot.root_tree_oid == root_oid
    assert observed == {
        "url": f"https://api.github.com/repos/owner/repo/git/trees/{root_oid}?recursive=1",
        "expected_host": "api.github.com",
        "max_bytes": MAX_GIT_TREE_JSON_BYTES,
        "timeout_seconds": 12.0,
    }


@pytest.mark.parametrize("timeout", [0, -1, 301, float("inf"), float("nan"), True])
def test_fetch_rejects_unbounded_or_invalid_timeout(timeout: object) -> None:
    with pytest.raises(ValueError):
        fetch_recursive_git_tree(
            "owner",
            "repo",
            "0" * 40,
            timeout_seconds=timeout,  # type: ignore[arg-type]
        )


def test_materialization_refuses_reuse_and_cleans_partial_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, blobs, root_oid = _fixture_payload()
    snapshot = parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid)
    plan = verify_git_object_blobs(snapshot, lambda entry: blobs[entry.oid])
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    os.chmod(private, 0o700)
    existing = private / "existing"
    existing.mkdir()

    assert _rejection_code(lambda: materialize_git_workspace(plan, existing)) == "output_exists"

    def fail_symlink(target: str, path: Path) -> None:
        raise OSError(f"synthetic failure for {target} at {path}")

    monkeypatch.setattr(os, "symlink", fail_symlink)
    partial = private / "partial"
    with pytest.raises(OSError, match="synthetic failure"):
        materialize_git_workspace(plan, partial)
    assert not partial.exists()


def test_materialization_fails_closed_when_executable_mode_is_not_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, blobs, root_oid = _fixture_payload()
    snapshot = parse_recursive_git_tree(payload, expected_root_tree_oid=root_oid)
    plan = verify_git_object_blobs(snapshot, lambda entry: blobs[entry.oid])
    private = tmp_path / "private-mode"
    private.mkdir(mode=0o700)
    os.chmod(private, 0o700)
    monkeypatch.setattr(os, "chmod", lambda *_args, **_kwargs: None)

    assert (
        _rejection_code(lambda: materialize_git_workspace(plan, private / "source"))
        == "git_workspace_changed"
    )
    assert not (private / "source").exists()


def _write_codeload_archive(
    path: Path,
    snapshot: GitObjectSnapshot,
    blobs: Mapping[str, bytes],
    *,
    mutate: set[str] | None = None,
    omit: set[str] | None = None,
    variant: str | None = None,
) -> Path:
    root = "fixture-deadbeef"
    omitted = set(omit or ())
    if variant == "special":
        omitted.add(".gitattributes")
    with tarfile.open(path, mode="w:gz") as archive:
        root_member = tarfile.TarInfo(f"{root}/")
        root_member.type = tarfile.DIRTYPE
        root_member.mode = 0o755
        archive.addfile(root_member)
        directories = [entry for entry in snapshot.entries if entry.is_tree or entry.is_gitlink]
        for entry in sorted(directories, key=lambda item: (len(item.parts), item.path)):
            member = tarfile.TarInfo(f"{root}/{entry.path}/")
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            archive.addfile(member)
        leaves = [entry for entry in snapshot.entries if entry.is_regular or entry.is_symlink]
        for entry in leaves:
            if entry.path in omitted:
                continue
            content = blobs[entry.oid]
            if entry.path in (mutate or set()):
                content = b"x" * len(content)
            member = tarfile.TarInfo(f"{root}/{entry.path}")
            if entry.is_symlink:
                member.type = tarfile.SYMTYPE
                member.linkname = content.decode("utf-8")
                member.mode = 0o777
                archive.addfile(member)
            else:
                member.type = tarfile.REGTYPE
                member.mode = 0o755 if entry.mode == "100755" else 0o644
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))

        if variant == "extra":
            _add_regular_member(archive, f"{root}/extra.txt", b"extra")
        elif variant == "special":
            member = tarfile.TarInfo(f"{root}/.gitattributes")
            member.type = tarfile.FIFOTYPE
            archive.addfile(member)
        elif variant == "duplicate":
            _add_regular_member(
                archive, f"{root}/.gitattributes", b".git_archival.txt export-subst\n"
            )
        elif variant == "second_root":
            _add_regular_member(archive, "other-root/evil", b"evil")
        elif variant == "traversal":
            _add_regular_member(archive, f"{root}/../evil", b"evil")
        elif variant == "git_metadata":
            _add_regular_member(archive, f"{root}/.git/config", b"evil")
    return path


def _add_regular_member(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.type = tarfile.REGTYPE
    member.mode = 0o644
    member.size = len(content)
    archive.addfile(member, io.BytesIO(content))


def entries(payload: Mapping[str, object]) -> list[dict[str, object]]:
    value = payload["tree"]
    assert isinstance(value, list)
    return value


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777
