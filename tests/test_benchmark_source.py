from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import tarfile
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import reproassert.benchmark_source as benchmark_source
from reproassert.errors import PolicyRejection
from reproassert.intake import ArchiveDownload, CommitTreeMetadata, ExtractionLimits
from reproassert.source_attestation import attest_source_tree

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPOSITORY_ROOT / "benchmarks" / "v0.1" / "manifest.json"
ROOT_SCHEMA = REPOSITORY_ROOT / "schemas" / "benchmark-source-receipt.schema.json"
BUNDLED_SCHEMA = (
    REPOSITORY_ROOT / "src" / "reproassert" / "schemas" / "benchmark-source-receipt.schema.json"
)
ROOT_INDEX_SCHEMA = REPOSITORY_ROOT / "schemas" / "benchmark-source-index.schema.json"
BUNDLED_INDEX_SCHEMA = (
    REPOSITORY_ROOT / "src" / "reproassert" / "schemas" / "benchmark-source-index.schema.json"
)
TOOL_GIT_SHA = "a" * 40


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _write_canonical_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def _write_source_archive(
    tmp_path: Path,
    *,
    special: bool = False,
    module_payload: bytes = b"VALUE = 1\n",
) -> tuple[Path, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    fixture = tmp_path / "fixture-tree"
    fixture.mkdir()
    (fixture / "package").mkdir()
    (fixture / "package" / "module.py").write_bytes(module_payload)
    (fixture / "tool.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
    (fixture / "tool.sh").chmod(0o700)
    tree_oid = attest_source_tree(fixture).reconstructed_git_tree_oid

    archive_path = tmp_path / ("special.tar.gz" if special else "fixture.tar.gz")
    with (
        archive_path.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w") as archive,
    ):
        entries = [
            ("repo-sha", None, tarfile.DIRTYPE, 0o755),
            ("repo-sha/package", None, tarfile.DIRTYPE, 0o755),
            ("repo-sha/package/module.py", module_payload, None, 0o644),
            ("repo-sha/tool.sh", b"#!/bin/sh\nexit 0\n", None, 0o755),
        ]
        for name, content, member_type, mode in entries:
            member = tarfile.TarInfo(name)
            member.mtime = 0
            member.mode = mode
            if member_type is not None:
                member.type = member_type
                archive.addfile(member)
            else:
                payload = content or b""
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        if special:
            member = tarfile.TarInfo("repo-sha/linked")
            member.mtime = 0
            member.type = tarfile.SYMTYPE
            member.linkname = "package"
            archive.addfile(member)
    return archive_path, tree_oid


def _install_fake_acquisition(
    monkeypatch: pytest.MonkeyPatch,
    archive_path: Path,
    tree_oid: str,
) -> None:
    def fake_commit(
        _owner: str,
        _repo: str,
        sha: str,
        *,
        timeout_seconds: float,
    ) -> CommitTreeMetadata:
        assert timeout_seconds > 0
        return CommitTreeMetadata(commit_sha=sha, tree_sha=tree_oid)

    def fake_download(
        _owner: str,
        _repo: str,
        _sha: str,
        run_dir: Path,
        *,
        timeout_seconds: float,
    ) -> ArchiveDownload:
        assert timeout_seconds > 0
        destination = run_dir / benchmark_source.SOURCE_ARCHIVE_FILENAME
        shutil.copyfile(archive_path, destination)
        destination.chmod(0o600)
        payload = destination.read_bytes()
        return ArchiveDownload(
            path=destination,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
        )

    monkeypatch.setattr(benchmark_source, "fetch_commit_tree_metadata", fake_commit)
    monkeypatch.setattr(benchmark_source, "download_source_archive", fake_download)


def _prepare_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    case_id: str = "rk-v0.1-018",
) -> tuple[Path, Path]:
    archive, tree_oid = _write_source_archive(tmp_path)
    _install_fake_acquisition(monkeypatch, archive, tree_oid)
    output_root = _private_directory(tmp_path / "prepared")
    receipt_path = benchmark_source.prepare_source_case(
        MANIFEST_PATH,
        case_id,
        output_root,
        tool_git_sha=TOOL_GIT_SHA,
    )
    return receipt_path, output_root


def test_manifest_loader_is_bounded_strict_and_case_bound(tmp_path: Path) -> None:
    manifest = benchmark_source.load_frozen_manifest(MANIFEST_PATH)

    assert manifest.benchmark_version == "0.1.0"
    assert len(manifest.cases) == 20
    assert manifest.cases[17].id == "rk-v0.1-018"
    assert manifest.cases[17].repository == "pallets/flask"
    assert manifest.cases[17].issue_number == 5010
    assert manifest.raw_sha256 == hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()

    duplicate = tmp_path / "duplicate.json"
    raw = MANIFEST_PATH.read_text()
    duplicate.write_text(
        raw.replace(
            '{\n  "benchmark_version"',
            '{\n  "benchmark_version": "0.1.0",\n  "benchmark_version"',
            1,
        )
    )
    with pytest.raises(PolicyRejection, match="strict UTF-8 JSON"):
        benchmark_source.load_frozen_manifest(duplicate)

    wrong_repo = tmp_path / "wrong-repo.json"
    decoded = json.loads(raw)
    decoded["cases"][0]["repo"] = "wrong/repository"
    wrong_repo.write_text(json.dumps(decoded))
    with pytest.raises(PolicyRejection, match="issue repository"):
        benchmark_source.load_frozen_manifest(wrong_repo)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (benchmark_source.MAX_MANIFEST_BYTES + 1))
    with pytest.raises(PolicyRejection, match="byte limit"):
        benchmark_source.load_frozen_manifest(oversized)

    depth_bomb = tmp_path / "depth-bomb.json"
    depth_bomb.write_bytes(b"[" * 5000 + b"0" + b"]" * 5000)
    with pytest.raises(PolicyRejection, match="strict UTF-8 JSON"):
        benchmark_source.load_frozen_manifest(depth_bomb)

    altered_base = tmp_path / "altered-base.json"
    coherent = json.loads(raw)
    coherent["cases"][0]["base_sha"] = "0" * 40
    altered_base.write_text(json.dumps(coherent))
    with pytest.raises(PolicyRejection, match=r"frozen v0\.1 preregistration"):
        benchmark_source.load_frozen_manifest(altered_base)


def test_prepare_is_deterministic_preserves_archive_writes_receipt_last_and_verifies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive, tree_oid = _write_source_archive(tmp_path)
    _install_fake_acquisition(monkeypatch, archive, tree_oid)
    first_root = _private_directory(tmp_path / "first")
    second_root = _private_directory(tmp_path / "second")

    first = benchmark_source.prepare_source_case(
        MANIFEST_PATH,
        "rk-v0.1-018",
        first_root,
        tool_git_sha=TOOL_GIT_SHA,
    )
    second = benchmark_source.prepare_source_case(
        MANIFEST_PATH,
        "rk-v0.1-018",
        second_root,
        tool_git_sha=TOOL_GIT_SHA,
    )

    assert first.read_bytes() == second.read_bytes()
    assert set(path.name for path in first.parent.iterdir()) == {
        benchmark_source.SOURCE_ARCHIVE_FILENAME,
        benchmark_source.SOURCE_RECEIPT_FILENAME,
    }
    assert not (first.parent / "source").exists()
    receipt_sha256 = hashlib.sha256(first.read_bytes()).hexdigest()
    scratch_root = _private_directory(tmp_path / "verify-scratch")
    receipt = benchmark_source.verify_source_receipt(
        first,
        manifest_path=MANIFEST_PATH,
        expected_case_id="rk-v0.1-018",
        expected_receipt_sha256=receipt_sha256,
        scratch_root=scratch_root,
    )
    assert list(scratch_root.iterdir()) == []
    assert receipt["case"] == {
        "id": "rk-v0.1-018",
        "repository": "pallets/flask",
        "issue_url": "https://github.com/pallets/flask/issues/5010",
        "issue_number": 5010,
        "base_sha": "7ee9ceb71e868944a46e1ff00b506772a53a4f1d",
    }
    source = receipt["source"]
    assert isinstance(source, dict)
    assert source["github_root_tree_oid"] == tree_oid
    attestation = source["attestation"]
    archive_record = source["archive"]
    assert isinstance(attestation, dict)
    assert isinstance(archive_record, dict)
    assert attestation["reconstructed_git_tree_oid"] == tree_oid
    assert attestation["expected_git_tree_oid"] == tree_oid
    assert attestation["file_count"] == archive_record["extracted_file_count"] == 2
    assert attestation["total_bytes"] == archive_record["extracted_bytes"] == 27
    assert attestation["executable_count"] == 1
    assert attestation["git_metadata_absent"] is True
    assert not any(
        field in json.dumps(receipt).lower()
        for field in ("created_at", "captured_at", "prepared_at", "timestamp")
    )


def test_receipt_schema_is_byte_identical_valid_and_packaged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt_path, _ = _prepare_one(tmp_path, monkeypatch)
    root_bytes = ROOT_SCHEMA.read_bytes()

    assert root_bytes == BUNDLED_SCHEMA.read_bytes()
    schema = json.loads(root_bytes)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(json.loads(receipt_path.read_text()))


def test_prepare_never_overwrites_and_cleans_every_partial_on_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt_path, output_root = _prepare_one(tmp_path, monkeypatch)
    original = receipt_path.read_bytes()

    with pytest.raises(PolicyRejection) as exc:
        benchmark_source.prepare_source_case(
            MANIFEST_PATH,
            "rk-v0.1-018",
            output_root,
            tool_git_sha=TOOL_GIT_SHA,
        )
    assert exc.value.code == "output_exists"
    assert receipt_path.read_bytes() == original

    special_archive, tree_oid = _write_source_archive(tmp_path / "other", special=True)
    _install_fake_acquisition(monkeypatch, special_archive, tree_oid)
    rejected_root = _private_directory(tmp_path / "rejected")
    with pytest.raises(PolicyRejection) as rejected:
        benchmark_source.prepare_source_case(
            MANIFEST_PATH,
            "rk-v0.1-017",
            rejected_root,
            tool_git_sha=TOOL_GIT_SHA,
        )
    assert rejected.value.code == "archive_special_file"
    assert list(rejected_root.iterdir()) == []


def test_verifier_rejects_wrong_case_duplicate_partial_symlink_and_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt_path, _ = _prepare_one(tmp_path, monkeypatch)

    with pytest.raises(PolicyRejection, match="requested manifest case"):
        benchmark_source.verify_source_receipt(
            receipt_path,
            manifest_path=MANIFEST_PATH,
            expected_case_id="rk-v0.1-017",
        )

    original_receipt = receipt_path.read_bytes()
    noncanonical = receipt_path.parent / "noncanonical.json"
    noncanonical.write_text(json.dumps(json.loads(original_receipt), indent=2))
    with pytest.raises(PolicyRejection, match="not canonical JSON"):
        benchmark_source.verify_source_receipt(
            noncanonical,
            manifest_path=MANIFEST_PATH,
            expected_case_id="rk-v0.1-018",
        )
    duplicate_receipt = receipt_path.parent / "duplicate.json"
    duplicate_receipt.write_bytes(
        original_receipt.replace(
            b'{"acquisition"',
            b'{"schema_version":"1.0.0","acquisition"',
            1,
        )
    )
    with pytest.raises(PolicyRejection, match="strict UTF-8 JSON"):
        benchmark_source.verify_source_receipt(
            duplicate_receipt,
            manifest_path=MANIFEST_PATH,
            expected_case_id="rk-v0.1-018",
        )

    missing = receipt_path.parent / "missing.json"
    with pytest.raises(PolicyRejection, match="regular file"):
        benchmark_source.verify_source_receipt(
            missing,
            manifest_path=MANIFEST_PATH,
            expected_case_id="rk-v0.1-018",
        )

    symlink = receipt_path.parent / "receipt-link.json"
    symlink.symlink_to(receipt_path)
    with pytest.raises(PolicyRejection, match="regular file"):
        benchmark_source.verify_source_receipt(
            symlink,
            manifest_path=MANIFEST_PATH,
            expected_case_id="rk-v0.1-018",
        )

    fifo = receipt_path.parent / "receipt.fifo"
    os.mkfifo(fifo)
    with pytest.raises(PolicyRejection, match="regular file"):
        benchmark_source.verify_source_receipt(
            fifo,
            manifest_path=MANIFEST_PATH,
            expected_case_id="rk-v0.1-018",
        )

    decoded = json.loads(original_receipt)
    decoded["source"]["archive"]["bytes"] += 1
    _write_canonical_json(receipt_path, decoded)
    with pytest.raises(PolicyRejection, match="independently derived"):
        benchmark_source.verify_source_receipt(
            receipt_path,
            manifest_path=MANIFEST_PATH,
            expected_case_id="rk-v0.1-018",
        )


def test_verifier_rejects_archive_tampering_missing_archive_and_hash_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt_path, _ = _prepare_one(tmp_path, monkeypatch)
    expected_hash = hashlib.sha256(receipt_path.read_bytes()).hexdigest()

    with pytest.raises(PolicyRejection, match="receipt SHA-256"):
        benchmark_source.verify_source_receipt(
            receipt_path,
            manifest_path=MANIFEST_PATH,
            expected_case_id="rk-v0.1-018",
            expected_receipt_sha256="0" * 64,
        )

    archive_path = receipt_path.parent / benchmark_source.SOURCE_ARCHIVE_FILENAME
    archive_bytes = archive_path.read_bytes()
    archive_path.unlink()
    with pytest.raises(PolicyRejection, match="regular file"):
        benchmark_source.verify_source_receipt(
            receipt_path,
            manifest_path=MANIFEST_PATH,
            expected_case_id="rk-v0.1-018",
            expected_receipt_sha256=expected_hash,
        )

    outside_archive = tmp_path / "outside-source.tar.gz"
    outside_archive.write_bytes(archive_bytes)
    archive_path.symlink_to(outside_archive)
    with pytest.raises(PolicyRejection, match="regular file"):
        benchmark_source.verify_source_receipt(
            receipt_path,
            manifest_path=MANIFEST_PATH,
            expected_case_id="rk-v0.1-018",
        )
    archive_path.unlink()
    archive_path.write_bytes(archive_bytes + b"tampered")
    archive_path.chmod(0o600)
    with pytest.raises(PolicyRejection):
        benchmark_source.verify_source_receipt(
            receipt_path,
            manifest_path=MANIFEST_PATH,
            expected_case_id="rk-v0.1-018",
        )


def test_verifier_uses_fresh_external_tree_preserves_producer_and_checks_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_archive, original_tree = _write_source_archive(tmp_path / "original")
    replacement_archive, replacement_tree = _write_source_archive(
        tmp_path / "replacement",
        module_payload=b"VALUE = 2\n",
    )
    assert replacement_tree != original_tree
    _install_fake_acquisition(monkeypatch, replacement_archive, replacement_tree)
    replacement_root = _private_directory(tmp_path / "replacement-output")
    replacement_receipt = benchmark_source.prepare_source_case(
        MANIFEST_PATH,
        "rk-v0.1-018",
        replacement_root,
        tool_git_sha=TOOL_GIT_SHA,
    )

    # A coordinated archive+receipt replacement still fails against the fresh
    # fixed-host base-SHA -> tree lookup.
    _install_fake_acquisition(monkeypatch, original_archive, original_tree)
    with pytest.raises(PolicyRejection, match="fresh GitHub commit metadata"):
        benchmark_source.verify_source_receipt(
            replacement_receipt,
            manifest_path=MANIFEST_PATH,
            expected_case_id="rk-v0.1-018",
        )

    original_root = _private_directory(tmp_path / "original-output")
    original_receipt = benchmark_source.prepare_source_case(
        MANIFEST_PATH,
        "rk-v0.1-018",
        original_root,
        tool_git_sha=TOOL_GIT_SHA,
    )
    producer = json.loads(original_receipt.read_text())
    producer["tool"]["version"] = "0.0.9"
    _write_canonical_json(original_receipt, producer)
    verified = benchmark_source.verify_source_receipt(
        original_receipt,
        manifest_path=MANIFEST_PATH,
        expected_case_id="rk-v0.1-018",
    )
    assert verified["tool"]["version"] == "0.0.9"

    scratch_root = _private_directory(tmp_path / "cleanup-scratch")
    real_rmtree = shutil.rmtree

    def leave_success_scratch(path: str | Path, *args: object, **kwargs: object) -> None:
        candidate = Path(path)
        if candidate.parent == scratch_root and not kwargs.get("ignore_errors"):
            return
        real_rmtree(path, *args, **kwargs)

    with monkeypatch.context() as cleanup_patch:
        cleanup_patch.setattr(benchmark_source.shutil, "rmtree", leave_success_scratch)
        with pytest.raises(PolicyRejection, match="verification scratch"):
            benchmark_source.verify_source_receipt(
                original_receipt,
                manifest_path=MANIFEST_PATH,
                expected_case_id="rk-v0.1-018",
                scratch_root=scratch_root,
            )
    for child in scratch_root.iterdir():
        real_rmtree(child)


def test_policy_hash_commits_to_concrete_safety_limits() -> None:
    changed = ExtractionLimits(
        max_members=benchmark_source.DEFAULT_EXTRACTION_LIMITS.max_members - 1
    )
    changed_policy = benchmark_source.source_acquisition_policy(extraction_limits=changed)
    changed_hash = hashlib.sha256(
        json.dumps(
            changed_policy,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    assert changed_hash != benchmark_source.SOURCE_ACQUISITION_POLICY_SHA256
    policy = benchmark_source.source_acquisition_policy()
    assert policy["network"] == {
        "scheme": "https",
        "commit_metadata_host": "api.github.com",
        "archive_host": "codeload.github.com",
        "authentication": "none",
        "proxy_environment": "disabled",
        "redirects": "rejected",
        "tls_minimum": "1.2",
        "commit_metadata_max_bytes": 524288,
    }


def test_source_index_requires_and_reverifies_exactly_20_relative_unique_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive, tree_oid = _write_source_archive(tmp_path)
    _install_fake_acquisition(monkeypatch, archive, tree_oid)
    receipts_root = _private_directory(tmp_path / "all-receipts")
    manifest = benchmark_source.load_frozen_manifest(MANIFEST_PATH)
    relative_paths: list[Path] = []
    for case in manifest.cases:
        receipt = benchmark_source.prepare_source_case(
            MANIFEST_PATH,
            case.id,
            receipts_root,
            tool_git_sha=TOOL_GIT_SHA,
        )
        relative_paths.append(receipt.relative_to(receipts_root))

    first_index = receipts_root / "index-one.json"
    second_index = receipts_root / "index-two.json"
    benchmark_source.build_source_index(
        MANIFEST_PATH,
        receipts_root,
        relative_paths,
        first_index,
        tool_git_sha=TOOL_GIT_SHA,
    )
    benchmark_source.build_source_index(
        MANIFEST_PATH,
        receipts_root,
        list(reversed(relative_paths)),
        second_index,
        tool_git_sha=TOOL_GIT_SHA,
    )

    assert first_index.read_bytes() == second_index.read_bytes()
    index = json.loads(first_index.read_text())
    assert ROOT_INDEX_SCHEMA.read_bytes() == BUNDLED_INDEX_SCHEMA.read_bytes()
    index_schema = json.loads(ROOT_INDEX_SCHEMA.read_text())
    Draft202012Validator.check_schema(index_schema)
    index_validator = Draft202012Validator(index_schema)
    index_validator.validate(index)
    missing_hash = json.loads(json.dumps(index))
    missing_hash["receipts"][0].pop("sha256")
    assert not index_validator.is_valid(missing_hash)
    extra_field = json.loads(json.dumps(index))
    extra_field["receipts"][0]["ready"] = True
    assert not index_validator.is_valid(extra_field)
    wrong_hash = json.loads(json.dumps(index))
    wrong_hash["receipts"][0]["sha256"] = "not-a-hash"
    assert not index_validator.is_valid(wrong_hash)
    assert index["receipt_count"] == 20
    assert [entry["case_id"] for entry in index["receipts"]] == [case.id for case in manifest.cases]
    assert "ready" not in json.dumps(index).lower()
    assert "campaign" not in json.dumps(index).lower()

    with pytest.raises(PolicyRejection, match="exactly the manifest"):
        benchmark_source.build_source_index(
            MANIFEST_PATH,
            receipts_root,
            relative_paths[:-1],
            receipts_root / "missing-index.json",
            tool_git_sha=TOOL_GIT_SHA,
        )
    duplicate = [*relative_paths[:-1], relative_paths[0]]
    with pytest.raises(PolicyRejection, match="duplicate"):
        benchmark_source.build_source_index(
            MANIFEST_PATH,
            receipts_root,
            duplicate,
            receipts_root / "duplicate-index.json",
            tool_git_sha=TOOL_GIT_SHA,
        )
    absolute = [*relative_paths]
    absolute[0] = receipts_root / relative_paths[0]
    with pytest.raises(PolicyRejection, match="relative"):
        benchmark_source.build_source_index(
            MANIFEST_PATH,
            receipts_root,
            absolute,
            receipts_root / "absolute-index.json",
            tool_git_sha=TOOL_GIT_SHA,
        )


def test_source_index_rejects_wrong_case_mixed_policy_symlink_and_partial_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive, tree_oid = _write_source_archive(tmp_path)
    _install_fake_acquisition(monkeypatch, archive, tree_oid)
    receipts_root = _private_directory(tmp_path / "all-receipts")
    manifest = benchmark_source.load_frozen_manifest(MANIFEST_PATH)
    relative_paths = []
    for case in manifest.cases:
        relative_paths.append(
            benchmark_source.prepare_source_case(
                MANIFEST_PATH,
                case.id,
                receipts_root,
                tool_git_sha=TOOL_GIT_SHA,
            ).relative_to(receipts_root)
        )

    wrong_case_path = receipts_root / relative_paths[0]
    wrong_case = json.loads(wrong_case_path.read_text())
    wrong_case["case"]["id"] = "rk-v0.1-002"
    _write_canonical_json(wrong_case_path, wrong_case)
    with pytest.raises(PolicyRejection):
        benchmark_source.build_source_index(
            MANIFEST_PATH,
            receipts_root,
            relative_paths,
            receipts_root / "wrong-case-index.json",
            tool_git_sha=TOOL_GIT_SHA,
        )

    # Restore case one, then create a policy mismatch in case two.
    wrong_case_path.unlink()
    case_one_dir = wrong_case_path.parent
    shutil.rmtree(case_one_dir)
    benchmark_source.prepare_source_case(
        MANIFEST_PATH,
        manifest.cases[0].id,
        receipts_root,
        tool_git_sha=TOOL_GIT_SHA,
    )
    mixed_path = receipts_root / relative_paths[1]
    mixed = json.loads(mixed_path.read_text())
    mixed["acquisition"]["policy"]["extraction"]["links"] = "allow"
    _write_canonical_json(mixed_path, mixed)
    with pytest.raises(PolicyRejection, match="acquisition policy"):
        benchmark_source.build_source_index(
            MANIFEST_PATH,
            receipts_root,
            relative_paths,
            receipts_root / "mixed-index.json",
            tool_git_sha=TOOL_GIT_SHA,
        )

    # A receipt symlink is rejected before its content can be trusted.
    shutil.rmtree(mixed_path.parent)
    benchmark_source.prepare_source_case(
        MANIFEST_PATH,
        manifest.cases[1].id,
        receipts_root,
        tool_git_sha=TOOL_GIT_SHA,
    )
    original = receipts_root / relative_paths[2]
    saved = original.parent / "saved-receipt.json"
    original.rename(saved)
    original.symlink_to(saved.name)
    with pytest.raises(PolicyRejection, match="regular file"):
        benchmark_source.build_source_index(
            MANIFEST_PATH,
            receipts_root,
            relative_paths,
            receipts_root / "symlink-index.json",
            tool_git_sha=TOOL_GIT_SHA,
        )

    original.unlink()
    saved.rename(original)
    (receipts_root / relative_paths[3]).unlink()
    with pytest.raises(PolicyRejection, match="regular file"):
        benchmark_source.build_source_index(
            MANIFEST_PATH,
            receipts_root,
            relative_paths,
            receipts_root / "partial-index.json",
            tool_git_sha=TOOL_GIT_SHA,
        )


def test_module_has_no_generation_campaign_or_ledger_dependencies() -> None:
    source = (REPOSITORY_ROOT / "src" / "reproassert" / "benchmark_source.py").read_text()

    assert "reproassert.generator" not in source
    assert "reproassert.benchmark" not in source
    assert "from reproassert.benchmark import" not in source
    assert "from reproassert.workflow import" not in source
    assert "fix_patch" not in source
    assert "model_provider" not in source
