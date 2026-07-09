from __future__ import annotations

from importlib import resources


def report_schema_text() -> str:
    """Return the exact report schema shipped inside the installed wheel."""

    return (
        resources.files("reproassert")
        .joinpath("schemas")
        .joinpath("reproassert-report.schema.json")
        .read_text(encoding="utf-8")
    )
