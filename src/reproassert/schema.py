from __future__ import annotations

from importlib import resources

SCHEMA_FILENAMES = {
    "report": "reproassert-report.schema.json",
    "benchmark-snapshot-receipt": "benchmark-snapshot-receipt.schema.json",
    "benchmark-source-receipt": "benchmark-source-receipt.schema.json",
    "benchmark-source-index": "benchmark-source-index.schema.json",
    "benchmark-object-source-receipt": "benchmark-object-source-receipt.schema.json",
    "benchmark-v02-fix-mapping": "benchmark-v02-fix-mapping.schema.json",
    "benchmark-v02-case-package": "benchmark-v02-case-package.schema.json",
    "benchmark-v02-preregistration": "benchmark-v02-preregistration.schema.json",
    "benchmark-v02-semantic-verification": ("benchmark-v02-semantic-verification.schema.json"),
    "benchmark-v02-private-event": "benchmark-v02-private-event.schema.json",
    "benchmark-v02-private-result": "benchmark-v02-private-result.schema.json",
    "benchmark-v02-embargoed-result": "benchmark-v02-embargoed-result.schema.json",
    "benchmark-v02-campaign-freeze": "benchmark-v02-campaign-freeze.schema.json",
    "benchmark-v02-causal-control-set": "benchmark-v02-causal-control-set.schema.json",
    "benchmark-v02-semantic-review-set": "benchmark-v02-semantic-review-set.schema.json",
    "benchmark-v02-campaign-finalization": ("benchmark-v02-campaign-finalization.schema.json"),
    "benchmark-v02-public-aggregate": "benchmark-v02-public-aggregate.schema.json",
    "benchmark-v02-execution-authorization": ("benchmark-v02-execution-authorization.schema.json"),
    "benchmark-v02-execution-request-bindings": (
        "benchmark-v02-execution-request-bindings.schema.json"
    ),
    "benchmark-v02-leak-audited-cohort-plan": (
        "benchmark-v02-leak-audited-cohort-plan.schema.json"
    ),
    "benchmark-v02-dataset-container-attestation": (
        "benchmark-v02-dataset-container-attestation.schema.json"
    ),
    "benchmark-v02-selection-freeze": "benchmark-v02-selection-freeze.schema.json",
    "dependency-execution-receipt": "dependency-execution-receipt.schema.json",
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
