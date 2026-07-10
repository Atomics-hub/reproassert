from __future__ import annotations

import hashlib
import io
import stat
import tarfile
import urllib.request
from pathlib import Path
from typing import Any

import pytest

import reproassert.intake as intake
from reproassert.errors import PolicyRejection
from reproassert.intake import (
    ExtractionLimits,
    download_source_archive,
    extract_source_archive,
    fetch_commit_tree_metadata,
    fetch_issue,
    parse_issue_url,
    resolve_commit_sha,
)
from reproassert.safeio import create_private_run_dir


class FakeResponse:
    def __init__(self, url: str, body: bytes, *, content_length: str | None = None) -> None:
        self._url = url
        self._stream = io.BytesIO(body)
        self.headers: dict[str, str] = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def geturl(self) -> str:
        return self._url

    def close(self) -> None:
        self._stream.close()

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _write_tar(
    path: Path,
    entries: list[tuple[str, bytes | None, bytes | None]],
) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, content, member_type in entries:
            member = tarfile.TarInfo(name)
            if member_type == tarfile.DIRTYPE:
                member.type = tarfile.DIRTYPE
                member.mode = 0o755
                archive.addfile(member)
                continue
            if member_type is not None:
                member.type = member_type
                member.linkname = "repo/target"
                archive.addfile(member)
                continue
            payload = content or b""
            member.size = len(payload)
            member.mode = 0o755 if name.endswith("tool.sh") else 0o644
            archive.addfile(member, io.BytesIO(payload))


def test_parse_canonical_public_github_issue_url() -> None:
    location = parse_issue_url("https://github.com/Atomics-hub/reprokit/issues/42")

    assert location.owner == "Atomics-hub"
    assert location.repo == "reprokit"
    assert location.number == 42
    assert location.repository_url == "https://github.com/Atomics-hub/reprokit"


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/owner/repo/issues/1",
        "https://github.com.evil.example/owner/repo/issues/1",
        "https://github.com@evil.example/owner/repo/issues/1",
        "https://github.com:443/owner/repo/issues/1",
        "https://127.0.0.1/owner/repo/issues/1",
        "https://github.com/owner/repo/issues/1?next=https://127.0.0.1",
        "https://github.com/owner/repo/issues/1#fragment",
        "https://github.com/owner/repo/issues/1/",
        "https://github.com/owner/repo/issues/01",
        "https://github.com/owner/repo/pull/1",
        "https://github.com/%2e%2e/repo/issues/1",
        "https://github.com/owner/repo/issues/1 ",
        "https://github.com\\@evil.example/owner/repo/issues/1",
    ],
)
def test_rejects_ssrf_shaped_or_noncanonical_issue_urls(url: str) -> None:
    with pytest.raises(PolicyRejection) as exc:
        parse_issue_url(url)
    assert exc.value.code == "invalid_issue_url"


def test_fetch_issue_builds_bounded_issue_ref(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_fetch_json(url: str, **kwargs: Any) -> dict[str, Any]:
        captured["url"] = url
        captured.update(kwargs)
        return {"number": 7, "title": "Broken slug", "body": "Expected one separator."}

    monkeypatch.setattr(intake, "_fetch_json", fake_fetch_json)
    document = fetch_issue("https://github.com/owner/repo/issues/7")

    assert captured["url"] == "https://api.github.com/repos/owner/repo/issues/7"
    assert captured["expected_host"] == "api.github.com"
    assert document.ref.body_sha256 == hashlib.sha256(document.body.encode()).hexdigest()
    assert document.ref.title == "Broken slug"


def test_fetch_issue_rejects_oversized_body(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        intake,
        "_fetch_json",
        lambda *_args, **_kwargs: {
            "number": 7,
            "title": "Large",
            "body": "x" * (intake.MAX_ISSUE_BODY_BYTES + 1),
        },
    )

    with pytest.raises(PolicyRejection) as exc:
        fetch_issue("https://github.com/owner/repo/issues/7")
    assert exc.value.code == "issue_body_too_large"


def test_resolve_commit_uses_fixed_api_and_requires_full_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_fetch_json(url: str, **kwargs: Any) -> dict[str, Any]:
        captured["url"] = url
        captured.update(kwargs)
        return {"sha": "A" * 40}

    monkeypatch.setattr(intake, "_fetch_json", fake_fetch_json)

    assert resolve_commit_sha("owner", "repo", "feature/fix") == "a" * 40
    assert captured["url"] == "https://api.github.com/repos/owner/repo/commits/feature%2Ffix"
    assert captured["expected_host"] == "api.github.com"

    monkeypatch.setattr(intake, "_fetch_json", lambda *_args, **_kwargs: {"sha": "abc123"})
    with pytest.raises(PolicyRejection) as exc:
        resolve_commit_sha("owner", "repo", "HEAD")
    assert exc.value.code == "invalid_commit_sha"


def test_resolve_commit_normalizes_full_sha_without_fetching_large_commit_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_fetch(*_args: object, **_kwargs: object) -> dict[str, Any]:
        raise AssertionError("a supplied full SHA must not fetch commit metadata")

    monkeypatch.setattr(intake, "_fetch_json", unexpected_fetch)

    assert resolve_commit_sha("owner", "repo", "A" * 40) == "a" * 40


def test_fetch_commit_tree_metadata_uses_git_database_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_fetch_json(url: str, **kwargs: Any) -> dict[str, Any]:
        captured["url"] = url
        captured.update(kwargs)
        return {"sha": "A" * 40, "tree": {"sha": "B" * 40}}

    monkeypatch.setattr(intake, "_fetch_json", fake_fetch_json)

    result = fetch_commit_tree_metadata("owner", "repo", "A" * 40)

    assert result.commit_sha == "a" * 40
    assert result.tree_sha == "b" * 40
    assert captured["url"] == f"https://api.github.com/repos/owner/repo/git/commits/{'a' * 40}"
    assert captured["expected_host"] == "api.github.com"
    assert captured["max_bytes"] == intake.MAX_COMMIT_JSON_BYTES


@pytest.mark.parametrize(
    "payload",
    [
        {"sha": "c" * 40, "tree": {"sha": "b" * 40}},
        {"sha": "a" * 40, "tree": {}},
        {"sha": "a" * 40, "tree": {"sha": "short"}},
        {"sha": "a" * 40, "tree": "not-an-object"},
    ],
)
def test_fetch_commit_tree_metadata_rejects_mismatched_or_invalid_response(
    monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]
) -> None:
    monkeypatch.setattr(intake, "_fetch_json", lambda *_args, **_kwargs: payload)

    with pytest.raises(PolicyRejection):
        fetch_commit_tree_metadata("owner", "repo", "a" * 40)


def test_http_opener_ignores_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    monkeypatch.setenv("SSLKEYLOGFILE", str(monkeypatch))
    monkeypatch.setenv("SSL_CERT_FILE", "/attacker-controlled/ca.pem")
    monkeypatch.setenv("SSL_CERT_DIR", "/attacker-controlled/certs")
    opener = intake._build_opener()
    proxy_handlers = [
        handler for handler in opener.handlers if isinstance(handler, urllib.request.ProxyHandler)
    ]

    assert all(handler.proxies == {} for handler in proxy_handlers)
    assert not any(
        isinstance(handler, urllib.request.ProxyBasicAuthHandler) for handler in opener.handlers
    )
    assert not any(
        isinstance(handler, urllib.request.HTTPBasicAuthHandler) for handler in opener.handlers
    )
    https_handlers = [
        handler for handler in opener.handlers if isinstance(handler, urllib.request.HTTPSHandler)
    ]
    assert https_handlers[0]._context.keylog_filename is None


def test_fixed_https_request_does_not_add_auth_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://api.github.com/repos/owner/repo/issues/1"
    captured: dict[str, Any] = {}

    class CapturingOpener:
        def open(self, request: urllib.request.Request, *, timeout: float) -> FakeResponse:
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeResponse(url, b"{}")

    monkeypatch.setattr(intake, "_build_opener", CapturingOpener)
    response = intake._open_https(url, expected_host="api.github.com", timeout_seconds=3)
    response.close()

    request = captured["request"]
    header_names = {name.lower() for name, _value in request.header_items()}
    assert "authorization" not in header_names
    assert "proxy-authorization" not in header_names


def test_json_fetch_is_stream_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://api.github.com/repos/owner/repo/issues/1"
    monkeypatch.setattr(
        intake,
        "_open_https",
        lambda *_args, **_kwargs: FakeResponse(url, b'{"value":"too large"}'),
    )

    with pytest.raises(PolicyRejection) as exc:
        intake._fetch_json(
            url,
            expected_host="api.github.com",
            max_bytes=4,
            timeout_seconds=3,
        )
    assert exc.value.code == "github_json_too_large"


def test_json_fetch_rejects_excessive_nesting_as_policy_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = "https://api.github.com/repos/owner/repo/issues/1"
    payload = ("[" * 2_000 + "0" + "]" * 2_000).encode()
    monkeypatch.setattr(
        intake,
        "_open_https",
        lambda *_args, **_kwargs: FakeResponse(url, payload),
    )

    with pytest.raises(PolicyRejection) as exc:
        intake._fetch_json(
            url,
            expected_host="api.github.com",
            max_bytes=len(payload),
            timeout_seconds=3,
        )
    assert exc.value.code == "invalid_github_response"


def test_download_streams_from_fixed_codeload_and_hashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = create_private_run_dir(tmp_path)
    sha = "a" * 40
    payload = b"\x1f\x8barchive-bytes"
    captured: dict[str, Any] = {}

    def fake_open(url: str, **kwargs: Any) -> FakeResponse:
        captured["url"] = url
        captured.update(kwargs)
        return FakeResponse(url, payload, content_length=str(len(payload)))

    monkeypatch.setattr(intake, "_open_https", fake_open)
    downloaded = download_source_archive("owner", "repo", sha, run_dir)

    assert captured["url"] == f"https://codeload.github.com/owner/repo/tar.gz/{sha}"
    assert captured["expected_host"] == "codeload.github.com"
    assert downloaded.path.read_bytes() == payload
    assert downloaded.sha256 == hashlib.sha256(payload).hexdigest()
    assert stat.S_IMODE(downloaded.path.stat().st_mode) == 0o600


def test_download_enforces_stream_limit_and_removes_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = create_private_run_dir(tmp_path)
    url = f"https://codeload.github.com/owner/repo/tar.gz/{'b' * 40}"
    monkeypatch.setattr(
        intake,
        "_open_https",
        lambda *_args, **_kwargs: FakeResponse(url, b"\x1f\x8b123456"),
    )

    with pytest.raises(PolicyRejection) as exc:
        download_source_archive("owner", "repo", "b" * 40, run_dir, max_bytes=4)
    assert exc.value.code == "archive_too_large"
    assert not (run_dir / "source.tar.gz").exists()


def test_extracts_only_regular_files_without_executing_them(tmp_path: Path) -> None:
    run_dir = create_private_run_dir(tmp_path)
    archive = run_dir / "fixture.tar.gz"
    marker = run_dir / "should-not-exist"
    _write_tar(
        archive,
        [
            ("repo-sha", None, tarfile.DIRTYPE),
            ("repo-sha/module.py", b"VALUE = 1\n", None),
            ("repo-sha/tool.sh", f"touch {marker}\n".encode(), None),
        ],
    )

    result = extract_source_archive(archive, run_dir)

    assert result.source_root == run_dir / "source" / "repo-sha"
    assert result.member_count == 3
    assert result.file_count == 2
    assert result.unpacked_bytes == len(b"VALUE = 1\n") + len(f"touch {marker}\n".encode())
    assert (result.source_root / "module.py").read_text() == "VALUE = 1\n"
    assert stat.S_IMODE((result.source_root / "module.py").stat().st_mode) == 0o600
    assert stat.S_IMODE((result.source_root / "tool.sh").stat().st_mode) == 0o700
    assert not marker.exists()


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/absolute",
        "repo/../../escape",
        "repo//file",
        "repo/./file",
        "C:/escape",
        "repo/\x1b[31m.py",
    ],
)
def test_rejects_archive_path_traversal(tmp_path: Path, name: str) -> None:
    run_dir = create_private_run_dir(tmp_path)
    archive = run_dir / "unsafe.tar.gz"
    _write_tar(archive, [(name, b"payload", None)])

    with pytest.raises(PolicyRejection) as exc:
        extract_source_archive(archive, run_dir)

    assert exc.value.code == "archive_unsafe_path"
    assert not (run_dir / "source").exists()
    assert not (run_dir / "escape").exists()


@pytest.mark.parametrize("git_name", [".git", ".GIT", "\uff0egit", ".git.", ".git "])
def test_rejects_git_metadata_components(tmp_path: Path, git_name: str) -> None:
    run_dir = create_private_run_dir(tmp_path)
    archive = run_dir / "git-metadata.tar.gz"
    _write_tar(archive, [(f"repo/{git_name}/config", b"[remote]\nurl=private\n", None)])

    with pytest.raises(PolicyRejection) as exc:
        extract_source_archive(archive, run_dir)

    assert exc.value.code == "archive_git_metadata"
    assert not (run_dir / "source").exists()


@pytest.mark.parametrize(
    "member_type",
    [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE],
)
def test_rejects_links_devices_and_fifos(tmp_path: Path, member_type: bytes) -> None:
    run_dir = create_private_run_dir(tmp_path)
    archive = run_dir / "special.tar.gz"
    _write_tar(archive, [("repo/special", None, member_type)])

    with pytest.raises(PolicyRejection) as exc:
        extract_source_archive(archive, run_dir)

    assert exc.value.code == "archive_special_file"
    assert not (run_dir / "source").exists()


@pytest.mark.parametrize(
    ("first", "second"),
    [("repo/A.py", "repo/a.py"), ("repo/\u00e9.py", "repo/e\u0301.py")],
)
def test_rejects_case_and_unicode_normalization_collisions(
    tmp_path: Path, first: str, second: str
) -> None:
    run_dir = create_private_run_dir(tmp_path)
    archive = run_dir / "collision.tar.gz"
    _write_tar(archive, [(first, b"one", None), (second, b"two", None)])

    with pytest.raises(PolicyRejection) as exc:
        extract_source_archive(archive, run_dir)

    assert exc.value.code == "archive_case_collision"
    assert not (run_dir / "source").exists()


def test_rejects_archive_file_count_and_unpacked_byte_bombs(tmp_path: Path) -> None:
    byte_run = create_private_run_dir(tmp_path)
    byte_archive = byte_run / "bytes.tar.gz"
    _write_tar(byte_archive, [("repo/file", b"12345", None)])
    with pytest.raises(PolicyRejection) as byte_exc:
        extract_source_archive(
            byte_archive,
            byte_run,
            limits=ExtractionLimits(max_files=2, max_unpacked_bytes=4),
        )
    assert byte_exc.value.code == "archive_too_large"

    count_run = create_private_run_dir(tmp_path)
    count_archive = count_run / "count.tar.gz"
    _write_tar(
        count_archive,
        [("repo/one", b"1", None), ("repo/two", b"2", None)],
    )
    with pytest.raises(PolicyRejection) as count_exc:
        extract_source_archive(
            count_archive,
            count_run,
            limits=ExtractionLimits(max_files=1, max_unpacked_bytes=10),
        )
    assert count_exc.value.code == "archive_too_many_files"


def test_rejects_member_directory_and_per_file_limits(tmp_path: Path) -> None:
    member_run = create_private_run_dir(tmp_path)
    member_archive = member_run / "members.tar.gz"
    _write_tar(member_archive, [("repo", None, tarfile.DIRTYPE), ("repo/file", b"1", None)])
    with pytest.raises(PolicyRejection) as member_exc:
        extract_source_archive(
            member_archive,
            member_run,
            limits=ExtractionLimits(max_members=1),
        )
    assert member_exc.value.code == "archive_too_many_members"

    directory_run = create_private_run_dir(tmp_path)
    directory_archive = directory_run / "directories.tar.gz"
    _write_tar(
        directory_archive,
        [("repo", None, tarfile.DIRTYPE), ("repo/nested", None, tarfile.DIRTYPE)],
    )
    with pytest.raises(PolicyRejection) as directory_exc:
        extract_source_archive(
            directory_archive,
            directory_run,
            limits=ExtractionLimits(max_directories=1),
        )
    assert directory_exc.value.code == "archive_too_many_directories"

    file_run = create_private_run_dir(tmp_path)
    file_archive = file_run / "large-file.tar.gz"
    _write_tar(file_archive, [("repo/file", b"12", None)])
    with pytest.raises(PolicyRejection) as file_exc:
        extract_source_archive(
            file_archive,
            file_run,
            limits=ExtractionLimits(max_file_bytes=1),
        )
    assert file_exc.value.code == "archive_file_too_large"


def test_rejects_excessive_archive_path_and_compressed_size(tmp_path: Path) -> None:
    path_run = create_private_run_dir(tmp_path)
    path_archive = path_run / "path.tar.gz"
    _write_tar(path_archive, [("repo/toolong", b"payload", None)])
    with pytest.raises(PolicyRejection) as path_exc:
        extract_source_archive(
            path_archive,
            path_run,
            limits=ExtractionLimits(max_component_bytes=5),
        )
    assert path_exc.value.code == "archive_path_too_long"

    compressed_run = create_private_run_dir(tmp_path)
    compressed_archive = compressed_run / "compressed.tar.gz"
    _write_tar(compressed_archive, [("repo/file", b"payload", None)])
    with pytest.raises(PolicyRejection) as compressed_exc:
        extract_source_archive(
            compressed_archive,
            compressed_run,
            limits=ExtractionLimits(max_archive_bytes=1),
        )
    assert compressed_exc.value.code == "archive_too_large"


def test_rejects_symlink_archive_input(tmp_path: Path) -> None:
    run_dir = create_private_run_dir(tmp_path)
    archive = run_dir / "real.tar.gz"
    _write_tar(archive, [("repo/file", b"payload", None)])
    link = run_dir / "link.tar.gz"
    link.symlink_to(archive)

    with pytest.raises(PolicyRejection) as exc:
        extract_source_archive(link, run_dir)

    assert exc.value.code == "unsafe_input_path"
    assert not (run_dir / "source").exists()
