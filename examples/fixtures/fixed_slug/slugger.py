import re


def slugify(value: str) -> str:
    """Reference fix used only by the evaluator fixture."""

    return re.sub(r"\s+", "-", value.strip().lower())
