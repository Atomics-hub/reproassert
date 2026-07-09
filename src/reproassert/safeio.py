from __future__ import annotations

import errno
import hashlib
import os
import secrets
import stat
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from .errors import PolicyRejection

_READ_CHUNK_SIZE = 64 * 1024


def create_private_run_dir(base_dir: Path, *, prefix: str = "run-") -> Path:
    """Create an unguessable controller-owned directory with mode 0700."""

    _validate_prefix(prefix)
    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)
    try:
        base_stat = base.lstat()
    except FileNotFoundError as exc:
        raise PolicyRejection("unsafe_run_base", f"Run base does not exist: {base}") from exc
    if not stat.S_ISDIR(base_stat.st_mode):
        raise PolicyRejection("unsafe_run_base", f"Run base is not a real directory: {base}")
    canonical_base = base.resolve(strict=True)
    try:
        base_fd = _open_directory_nofollow(canonical_base)
    except (OSError, PolicyRejection) as exc:
        raise PolicyRejection("unsafe_run_base", f"Run base is unsafe: {base}") from exc

    try:
        for _ in range(32):
            name = f"{prefix}{secrets.token_hex(16)}"
            try:
                os.mkdir(name, mode=0o700, dir_fd=base_fd)
            except FileExistsError:
                continue

            run_fd = -1
            try:
                flags = os.O_RDONLY
                flags |= getattr(os, "O_DIRECTORY", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                flags |= getattr(os, "O_CLOEXEC", 0)
                run_fd = os.open(name, flags, dir_fd=base_fd)
                os.fchmod(run_fd, 0o700)
                _require_private_directory_stat(os.fstat(run_fd), canonical_base / name)
            except BaseException:
                if run_fd >= 0:
                    os.close(run_fd)
                os.rmdir(name, dir_fd=base_fd)
                raise
            os.close(run_fd)
            return canonical_base / name
    finally:
        os.close(base_fd)
    raise ReproAssertRuntimeError("Unable to allocate a unique private run directory")


@contextmanager
def open_exclusive_file(path: Path) -> Iterator[BinaryIO]:
    """Open a new regular file without following the file or parent symlinks."""

    target = Path(path)
    if target.name in {"", ".", ".."}:
        raise PolicyRejection("unsafe_output_path", f"Unsafe output path: {target}")

    parent_fd = _open_directory_nofollow(target.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            fd = os.open(target.name, flags, 0o600, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise PolicyRejection(
                "output_exists", f"Refusing to overwrite existing output: {target}"
            ) from exc
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise PolicyRejection(
                    "unsafe_output_path", f"Refusing unsafe output path: {target}"
                ) from exc
            raise
    finally:
        os.close(parent_fd)

    try:
        os.fchmod(fd, 0o600)
        descriptor_stat = os.fstat(fd)
        if not stat.S_ISREG(descriptor_stat.st_mode):
            raise PolicyRejection("unsafe_output_path", f"Output is not a regular file: {target}")
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            yield stream
    finally:
        if fd >= 0:
            os.close(fd)


def write_bytes_exclusive(path: Path, content: bytes) -> None:
    with open_exclusive_file(path) as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def write_text_exclusive(path: Path, content: str) -> None:
    write_bytes_exclusive(path, content.encode("utf-8"))


@contextmanager
def open_regular_file(path: Path) -> Iterator[BinaryIO]:
    """Open an existing regular file without following its path components."""

    target = Path(path)
    if target.name in {"", ".", ".."}:
        raise PolicyRejection("unsafe_input_path", f"Unsafe input path: {target}")
    try:
        parent_fd = _open_directory_nofollow(target.parent)
    except (OSError, PolicyRejection) as exc:
        raise PolicyRejection("unsafe_input_path", f"Refusing unsafe input path: {target}") from exc

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            fd = os.open(target.name, flags, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise PolicyRejection(
                    "unsafe_input_path", f"Refusing unsafe input path: {target}"
                ) from exc
            raise
    finally:
        os.close(parent_fd)

    try:
        descriptor_stat = os.fstat(fd)
        if not stat.S_ISREG(descriptor_stat.st_mode):
            raise PolicyRejection("unsafe_input_path", f"Input is not a regular file: {target}")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            yield stream
    finally:
        if fd >= 0:
            os.close(fd)


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_text(content: str) -> str:
    return sha256_bytes(content.encode("utf-8"))


def sha256_file(path: Path) -> str:
    """Hash a regular file without following a final symlink."""

    with open_regular_file(path) as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(_READ_CHUNK_SIZE), b""):
            digest.update(chunk)
        return digest.hexdigest()


def sanitize_log(text: str, *, max_chars: int | None = None) -> str:
    """Remove terminal control sequences and optionally bound rendered output."""

    if max_chars is not None and max_chars < 1:
        raise ValueError("max_chars must be positive")

    without_sequences = _strip_terminal_sequences(text)
    sanitized: list[str] = []
    for character in without_sequences:
        if character == "\r":
            sanitized.append("\n")
            continue
        if character in {"\n", "\t"}:
            sanitized.append(character)
            continue
        if unicodedata.category(character) in {"Cc", "Cf"}:
            continue
        sanitized.append(character)

    result = "".join(sanitized)
    if max_chars is not None and len(result) > max_chars:
        marker = "\n[output truncated]"
        keep = max(0, max_chars - len(marker))
        return result[:keep] + marker[: max_chars - keep]
    return result


def _strip_terminal_sequences(text: str) -> str:
    output: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        character = text[index]
        codepoint = ord(character)

        if character == "\x1b":
            index = _consume_escape_sequence(text, index)
            continue
        if codepoint == 0x9B:  # C1 CSI
            index = _consume_csi(text, index + 1)
            continue
        if codepoint == 0x9D:  # C1 OSC
            index = _consume_control_string(text, index + 1, bell_terminated=True)
            continue
        if codepoint in {0x90, 0x98, 0x9E, 0x9F}:  # DCS, SOS, PM, APC
            index = _consume_control_string(text, index + 1, bell_terminated=False)
            continue

        output.append(character)
        index += 1
    return "".join(output)


def _consume_escape_sequence(text: str, index: int) -> int:
    if index + 1 >= len(text):
        return len(text)
    introducer = text[index + 1]
    if introducer == "[":
        return _consume_csi(text, index + 2)
    if introducer == "]":
        return _consume_control_string(text, index + 2, bell_terminated=True)
    if introducer in {"P", "X", "^", "_"}:
        return _consume_control_string(text, index + 2, bell_terminated=False)

    cursor = index + 1
    while cursor < len(text) and " " <= text[cursor] <= "/":
        cursor += 1
    if cursor < len(text) and "0" <= text[cursor] <= "~":
        return cursor + 1
    return min(len(text), index + 2)


def _consume_csi(text: str, index: int) -> int:
    cursor = index
    while cursor < len(text):
        if "@" <= text[cursor] <= "~":
            return cursor + 1
        cursor += 1
    return len(text)


def _consume_control_string(text: str, index: int, *, bell_terminated: bool) -> int:
    cursor = index
    while cursor < len(text):
        if bell_terminated and text[cursor] == "\x07":
            return cursor + 1
        if ord(text[cursor]) == 0x9C:  # C1 string terminator
            return cursor + 1
        if text[cursor] == "\x1b" and cursor + 1 < len(text) and text[cursor + 1] == "\\":
            return cursor + 2
        cursor += 1
    return len(text)


def _validate_prefix(prefix: str) -> None:
    if not prefix or any(
        not (character.isalnum() or character in {"-", "_"}) for character in prefix
    ):
        raise ValueError("prefix must contain only ASCII letters, digits, '-' or '_'")
    if not prefix.isascii():
        raise ValueError("prefix must be ASCII")


def _require_private_directory(path: Path) -> None:
    try:
        directory_fd = _open_directory_nofollow(path)
    except FileNotFoundError as exc:
        raise PolicyRejection(
            "unsafe_run_directory", f"Run directory does not exist: {path}"
        ) from exc
    except (OSError, PolicyRejection) as exc:
        raise PolicyRejection("unsafe_run_directory", f"Run directory is unsafe: {path}") from exc
    try:
        _require_private_directory_stat(os.fstat(directory_fd), path)
    finally:
        os.close(directory_fd)


def _require_private_directory_stat(directory_stat: os.stat_result, path: Path) -> None:
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise PolicyRejection("unsafe_run_directory", f"Run path is not a directory: {path}")
    if stat.S_IMODE(directory_stat.st_mode) != 0o700:
        raise PolicyRejection("unsafe_run_directory", f"Run directory must have mode 0700: {path}")
    if hasattr(os, "getuid") and directory_stat.st_uid != os.getuid():
        raise PolicyRejection("unsafe_run_directory", f"Run directory has the wrong owner: {path}")


def require_private_directory(path: Path) -> None:
    """Validate a controller-created run directory before using it as a trust boundary."""

    _require_private_directory(Path(path))


def _open_directory_nofollow(path: Path) -> int:
    target = Path(path)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    flags = os.O_RDONLY | directory_flag | nofollow_flag | close_on_exec

    if target.is_absolute():
        current_fd = os.open(os.path.sep, flags)
        parts = target.parts[1:]
    else:
        current_fd = os.open(".", flags)
        parts = target.parts

    try:
        for part in parts:
            if part in {"", ".", ".."}:
                raise PolicyRejection("unsafe_output_path", f"Unsafe parent directory: {target}")
            try:
                next_fd = os.open(part, flags, dir_fd=current_fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise PolicyRejection(
                        "unsafe_output_path", f"Refusing symlinked parent directory: {target}"
                    ) from exc
                raise
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


class ReproAssertRuntimeError(RuntimeError):
    """An unexpected local runtime failure rather than an input-policy rejection."""
