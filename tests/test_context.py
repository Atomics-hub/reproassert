from __future__ import annotations

from pathlib import Path

from reproassert.context import build_source_context


def test_context_is_bounded_ranked_and_skips_secrets(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='fixture'\n")
    (tmp_path / "parser.py").write_text("def parse_widget():\n    return None\n")
    (tmp_path / ".env.secret").write_text("TOKEN=do-not-read\n")
    (tmp_path / "binary.py").write_bytes(b"\xff\xfe")

    context = build_source_context(
        tmp_path, issue_title="parser widget fails", issue_body="parse_widget returns None"
    )

    assert ".env.secret" in context.manifest
    assert all(item.path != ".env.secret" for item in context.files)
    assert context.files[0].path in {"parser.py", "pyproject.toml"}
    assert context.context_bytes <= 96 * 1024


def test_context_does_not_follow_directory_symlinks(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-context"
    outside.mkdir(exist_ok=True)
    (outside / "secret.py").write_text("SECRET = 'outside'\n")
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)

    context = build_source_context(tmp_path, issue_title="x", issue_body="y")

    assert all(not path.startswith("linked/") for path in context.manifest)


def test_context_excludes_sensitive_components_at_any_path_depth(tmp_path: Path) -> None:
    sensitive_files = {
        "nested/.env": "NESTED_ENV_SENTINEL=do-not-read\n",
        "config/secret.txt": "SECRET_FILE_SENTINEL\n",
        "keys/id_rsa": "PRIVATE_KEY_SENTINEL\n",
        "src/private_key.py": "PRIVATE_MODULE_SENTINEL = True\n",
        "credentials/settings.py": "CREDENTIAL_DIRECTORY_SENTINEL = True\n",
    }
    safe_files = {
        "src/tokenizer.py": "def tokenize():\n    return []\n",
        "docs/privateer.txt": "A harmless word with no sensitive-name boundary.\n",
    }
    for relative, content in sensitive_files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    for relative, content in safe_files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    context = build_source_context(
        tmp_path,
        issue_title="tokenizer privateer",
        issue_body="Inspect the safe tokenizer module and privateer notes.",
    )

    selected = {item.path: item.content for item in context.files}
    assert set(sensitive_files) <= set(context.manifest)
    assert set(sensitive_files).isdisjoint(selected)
    assert set(safe_files) <= set(selected)
    selected_content = "\n".join(selected.values())
    assert all(sentinel.strip() not in selected_content for sentinel in sensitive_files.values())
