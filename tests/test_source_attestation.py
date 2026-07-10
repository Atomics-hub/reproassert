from __future__ import annotations

import os
import socket
import tempfile
from pathlib import Path

import pytest

import reproassert.source_attestation as source_attestation
from reproassert.errors import PolicyRejection
from reproassert.source_attestation import (
    SOURCE_TREE_ALGORITHM,
    SourceAttestationLimits,
    attest_source_tree,
)

FIXTURE_GIT_TREE_OID = "35e743fd030cbaf0f148c2916d2d2873b4bb5e13"
FIXTURE_TREE_SHA256 = "71fcdd8224634607e3bd0db8ad143588eceff098845df608697c90575d73be94"
EMPTY_GIT_TREE_OID = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _write_sort_fixture(root: Path, *, permissive_modes: bool = False) -> None:
    (root / "foo").mkdir(parents=True)
    (root / "foo.bar").write_bytes(b"sibling\n")
    (root / "foo" / "inside.txt").write_bytes(b"child\n")
    (root / "run.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
    (root / "foo").chmod(0o755 if permissive_modes else 0o700)
    (root / "foo.bar").chmod(0o644 if permissive_modes else 0o600)
    (root / "foo" / "inside.txt").chmod(0o644 if permissive_modes else 0o600)
    (root / "run.sh").chmod(0o755 if permissive_modes else 0o700)


def _assert_rejected(root: Path, code: str, **kwargs: object) -> None:
    with pytest.raises(PolicyRejection) as exc:
        attest_source_tree(root, **kwargs)  # type: ignore[arg-type]
    assert exc.value.code == code


def test_attestation_matches_git_tree_sort_and_canonical_sha256(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    _write_sort_fixture(root)

    result = attest_source_tree(root, expected_git_tree_oid=FIXTURE_GIT_TREE_OID)

    assert result.algorithm == SOURCE_TREE_ALGORITHM
    assert result.tree_sha256 == FIXTURE_TREE_SHA256
    assert result.reconstructed_git_tree_oid == FIXTURE_GIT_TREE_OID
    assert result.expected_git_tree_oid == FIXTURE_GIT_TREE_OID
    assert result.member_count == 4
    assert result.file_count == 3
    assert result.directory_count == 1
    assert result.total_bytes == 31
    assert result.executable_count == 1
    assert result.git_metadata_absent is True


def test_empty_tree_reconstructs_git_empty_tree(tmp_path: Path) -> None:
    root = tmp_path / "empty"
    root.mkdir()

    result = attest_source_tree(root, expected_git_tree_oid=EMPTY_GIT_TREE_OID)

    assert result.reconstructed_git_tree_oid == EMPTY_GIT_TREE_OID
    assert result.member_count == result.file_count == result.directory_count == 0
    assert result.total_bytes == result.executable_count == 0


def test_digest_is_independent_of_permissions_mtime_creation_order_and_root(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o755)
    _write_sort_fixture(first, permissive_modes=False)

    (second / "run.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
    (second / "foo.bar").write_bytes(b"sibling\n")
    (second / "foo").mkdir()
    (second / "foo" / "inside.txt").write_bytes(b"child\n")
    (second / "run.sh").chmod(0o755)
    (second / "foo.bar").chmod(0o644)
    (second / "foo" / "inside.txt").chmod(0o644)
    (second / "foo").chmod(0o755)
    for path in (second, second / "foo", second / "foo.bar", second / "run.sh"):
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))

    first_result = attest_source_tree(first)
    second_result = attest_source_tree(second)

    assert first_result.tree_sha256 == second_result.tree_sha256 == FIXTURE_TREE_SHA256
    assert first_result.reconstructed_git_tree_oid == second_result.reconstructed_git_tree_oid


def test_content_and_executable_tampering_changes_both_identities(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    _write_sort_fixture(root)
    original = attest_source_tree(root)

    (root / "foo.bar").write_bytes(b"tampered\n")
    content_changed = attest_source_tree(root)
    assert content_changed.tree_sha256 != original.tree_sha256
    assert content_changed.reconstructed_git_tree_oid != original.reconstructed_git_tree_oid

    (root / "foo.bar").write_bytes(b"sibling\n")
    (root / "foo.bar").chmod(0o700)
    mode_changed = attest_source_tree(root)
    assert mode_changed.tree_sha256 != original.tree_sha256
    assert mode_changed.reconstructed_git_tree_oid != original.reconstructed_git_tree_oid


def test_expected_git_tree_mismatch_and_noncanonical_oid_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    _write_sort_fixture(root)

    _assert_rejected(
        root,
        "source_git_tree_mismatch",
        expected_git_tree_oid="0" * 40,
    )
    _assert_rejected(
        root,
        "invalid_git_tree_oid",
        expected_git_tree_oid=FIXTURE_GIT_TREE_OID.upper(),
    )


@pytest.mark.parametrize(
    "component",
    [
        ".git",
        ".GIT",
        ".git. ",
        "\uff0egit",
        "\uff0e\uff27\uff29\uff34... ",
    ],
)
@pytest.mark.parametrize("as_directory", [False, True])
def test_rejects_canonical_git_metadata_aliases(
    tmp_path: Path, component: str, as_directory: bool
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    target = root / component
    if as_directory:
        target.mkdir()
        (target / "config").write_text("host metadata")
    else:
        target.write_text("gitdir: elsewhere")

    _assert_rejected(root, "source_git_metadata")


def test_rejects_root_that_canonicalizes_to_git_metadata(tmp_path: Path) -> None:
    root = tmp_path / ".GIT. "
    root.mkdir()

    _assert_rejected(root, "source_git_metadata")


def test_rejects_root_and_nested_symlinks_without_following(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("must not be read")

    root_link = tmp_path / "root-link"
    root_link.symlink_to(outside, target_is_directory=True)
    _assert_rejected(root_link, "source_unsafe_root")

    root = tmp_path / "source"
    root.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=True)
    _assert_rejected(root, "source_symlink")


def test_rejects_fifo_socket_and_hardlink(tmp_path: Path) -> None:
    fifo_root = tmp_path / "fifo-source"
    fifo_root.mkdir()
    os.mkfifo(fifo_root / "pipe")
    _assert_rejected(fifo_root, "source_special_file")

    with tempfile.TemporaryDirectory(prefix="ra-socket-", dir="/tmp") as temporary:
        socket_root = Path(temporary)
        unix_socket = socket.socket(socket.AF_UNIX)
        try:
            unix_socket.bind(str(socket_root / "service.sock"))
            _assert_rejected(socket_root, "source_special_file")
        finally:
            unix_socket.close()

    hardlink_root = tmp_path / "hardlink-source"
    hardlink_root.mkdir()
    original = hardlink_root / "one"
    original.write_text("same inode")
    os.link(original, hardlink_root / "two")
    _assert_rejected(hardlink_root, "source_hardlink")


@pytest.mark.parametrize(
    ("fixture", "limits", "code"),
    [
        (
            "two_files",
            SourceAttestationLimits(max_members=1),
            "source_member_limit",
        ),
        (
            "two_files",
            SourceAttestationLimits(max_files=1),
            "source_file_limit",
        ),
        (
            "two_directories",
            SourceAttestationLimits(max_directories=1),
            "source_directory_limit",
        ),
        (
            "two_bytes",
            SourceAttestationLimits(max_file_bytes=1),
            "source_file_too_large",
        ),
        (
            "two_files",
            SourceAttestationLimits(max_total_bytes=1),
            "source_total_bytes",
        ),
        (
            "long_name",
            SourceAttestationLimits(max_path_bytes=2),
            "source_path_too_long",
        ),
        (
            "long_name",
            SourceAttestationLimits(max_component_bytes=2),
            "source_component_too_long",
        ),
    ],
)
def test_enforces_independent_limits(
    tmp_path: Path,
    fixture: str,
    limits: SourceAttestationLimits,
    code: str,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    if fixture == "two_files":
        (root / "a").write_bytes(b"a")
        (root / "b").write_bytes(b"b")
    elif fixture == "two_directories":
        (root / "a").mkdir()
        (root / "b").mkdir()
    elif fixture == "two_bytes":
        (root / "a").write_bytes(b"ab")
    else:
        (root / "abc").write_bytes(b"a")

    _assert_rejected(root, code, limits=limits)


@pytest.mark.parametrize("name", ["back\\slash", "control\x1bname", "format\u202ename"])
def test_rejects_unsafe_path_components(tmp_path: Path, name: str) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / name).write_bytes(b"payload")

    _assert_rejected(root, "source_unsafe_path")


@pytest.mark.parametrize(
    ("first", "second"),
    [("A.py", "a.py"), ("\u00e9.py", "e\u0301.py")],
)
def test_rejects_case_and_unicode_normalization_collisions(
    tmp_path: Path, first: str, second: str
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / first).write_bytes(b"first")
    try:
        (root / second).write_bytes(b"second")
    except OSError:
        pytest.skip("filesystem collapses the adversarial names")
    if set(os.listdir(root)) != {first, second}:
        pytest.skip("filesystem collapses the adversarial names")

    _assert_rejected(root, "source_path_collision")


def test_rejects_invalid_utf8_filename(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    root_bytes = os.fsencode(root)
    try:
        descriptor = os.open(root_bytes + b"/bad-\xff", os.O_WRONLY | os.O_CREAT, 0o600)
    except OSError:
        pytest.skip("filesystem rejects non-UTF-8 names")
    os.close(descriptor)

    _assert_rejected(root, "source_unsafe_path")


def test_detects_same_size_mutation_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    target = root / "large.bin"
    target.write_bytes(b"a" * (source_attestation._READ_CHUNK_SIZE + 1))
    original_read = source_attestation.os.read
    mutated = False

    def mutating_read(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        if not mutated:
            mutated = True
            target.write_bytes(b"b" * (source_attestation._READ_CHUNK_SIZE + 1))
        return original_read(descriptor, size)

    monkeypatch.setattr(source_attestation.os, "read", mutating_read)

    _assert_rejected(root, "source_tree_changed")


def test_detects_mode_change_between_lstat_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    target = root / "module.py"
    target.write_bytes(b"VALUE = 1\n")
    target.chmod(0o600)
    original_open = source_attestation.os.open
    mutated = False

    def mutating_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal mutated
        if path == "module.py" and not mutated:
            mutated = True
            target.chmod(0o700)
        return original_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(source_attestation.os, "open", mutating_open)

    _assert_rejected(root, "source_tree_changed")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_members": 0},
        {"max_files": True},
        {"max_directories": -1},
        {"max_file_bytes": 2**63},
        {"max_total_bytes": 0},
        {"max_path_bytes": 0},
        {"max_component_bytes": 0},
    ],
)
def test_limits_require_bounded_positive_integers(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        SourceAttestationLimits(**kwargs)  # type: ignore[arg-type]
