from __future__ import annotations

from importlib import resources

SCHEMA_FILENAMES = {
    "report": "reproassert-report.schema.json",
    "benchmark-snapshot-receipt": "benchmark-snapshot-receipt.schema.json",
    "benchmark-source-receipt": "benchmark-source-receipt.schema.json",
    "benchmark-source-index": "benchmark-source-index.schema.json",
    "benchmark-object-source-receipt": "benchmark-object-source-receipt.schema.json",
}


def report_schema_text() -> str:
    """Return the exact report schema shipped inside the installed wheel."""

    return schema_text("report")


def schema_text(name: str) -> str:
    """Return one named public schema shipped inside the installed wheel."""

    try:
        filename = SCHEMA_FILENAMES[name]
    except KeyError as exc:
        raise ValueError(f"Unknown bundled schema: {name}") from exc
    return (
        resources.files("reproassert")
        .joinpath("schemas")
        .joinpath(filename)
        .read_text(encoding="utf-8")
    )
