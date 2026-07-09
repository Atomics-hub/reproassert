from __future__ import annotations

import hashlib
import stat
from pathlib import Path

import pytest

from reproassert.errors import PolicyRejection
from reproassert.safeio import (
    create_private_run_dir,
    sanitize_log,
    sha256_bytes,
    sha256_file,
    sha256_text,
    write_bytes_exclusive,
    write_text_exclusive,
)


def test_create_private_run_dir_is_unique_and_private(tmp_path: Path) -> None:
    first = create_private_run_dir(tmp_path)
    second = create_private_run_dir(tmp_path)

    assert first != second
    assert stat.S_IMODE(first.stat().st_mode) == 0o700
    assert stat.S_IMODE(second.stat().st_mode) == 0o700


def test_create_private_run_dir_refuses_symlinked_base(tmp_path: Path) -> None:
    real_base = tmp_path / "real-base"
    real_base.mkdir()
    linked_base = tmp_path / "linked-base"
    linked_base.symlink_to(real_base, target_is_directory=True)

    with pytest.raises(PolicyRejection) as exc:
        create_private_run_dir(linked_base)

    assert exc.value.code == "unsafe_run_base"
    assert list(real_base.iterdir()) == []


def test_create_private_run_dir_canonicalizes_a_system_style_symlink_ancestor(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "private-var"
    real_parent.mkdir()
    linked_parent = tmp_path / "var"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    run_dir = create_private_run_dir(linked_parent / "folders" / "temporary")

    assert run_dir.parent == real_parent / "folders" / "temporary"
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700


def test_exclusive_writes_are_mode_0600_and_never_overwrite(tmp_path: Path) -> None:
    run_dir = create_private_run_dir(tmp_path)
    output = run_dir / "report.json"

    write_text_exclusive(output, "first")

    assert output.read_text() == "first"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    with pytest.raises(PolicyRejection) as exc:
        write_text_exclusive(output, "second")
    assert exc.value.code == "output_exists"
    assert output.read_text() == "first"


def test_exclusive_write_refuses_a_symlink_output(tmp_path: Path) -> None:
    run_dir = create_private_run_dir(tmp_path)
    sensitive = tmp_path / "sensitive"
    sensitive.write_bytes(b"unchanged")
    output = run_dir / "report.json"
    output.symlink_to(sensitive)

    with pytest.raises(PolicyRejection) as exc:
        write_bytes_exclusive(output, b"overwritten")

    assert exc.value.code == "output_exists"
    assert sensitive.read_bytes() == b"unchanged"


def test_exclusive_write_refuses_a_symlinked_parent(tmp_path: Path) -> None:
    run_dir = create_private_run_dir(tmp_path)
    real_parent = run_dir / "real"
    real_parent.mkdir(mode=0o700)
    linked_parent = run_dir / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(PolicyRejection) as exc:
        write_bytes_exclusive(linked_parent / "artifact", b"payload")

    assert exc.value.code == "unsafe_output_path"
    assert not (real_parent / "artifact").exists()


def test_sha256_helpers_and_nofollow_file_hashing(tmp_path: Path) -> None:
    payload = b"reproassert"
    source = tmp_path / "source"
    source.write_bytes(payload)
    link = tmp_path / "source-link"
    link.symlink_to(source)
    expected = hashlib.sha256(payload).hexdigest()

    assert sha256_bytes(payload) == expected
    assert sha256_text(payload.decode()) == expected
    assert sha256_file(source) == expected
    with pytest.raises(PolicyRejection) as exc:
        sha256_file(link)
    assert exc.value.code == "unsafe_input_path"


def test_sanitize_log_removes_terminal_and_unicode_controls() -> None:
    hostile = (
        "start\x1b[31mred\x1b[0m\rreplace"
        "\x1b]8;;https://evil.example\x1b\\link\x1b]8;;\x1b\\"
        "\x08\u202eend\n\tok"
    )

    assert sanitize_log(hostile) == "startred\nreplacelinkend\n\tok"


def test_sanitize_log_drops_unterminated_osc_and_bounds_output() -> None:
    assert sanitize_log("visible\x1b]52;c;secret") == "visible"
    bounded = sanitize_log("a" * 100, max_chars=32)
    assert len(bounded) == 32
    assert "output truncated" in bounded


@pytest.mark.parametrize("max_chars", [0, -1])
def test_sanitize_log_rejects_invalid_limit(max_chars: int) -> None:
    with pytest.raises(ValueError):
        sanitize_log("log", max_chars=max_chars)
