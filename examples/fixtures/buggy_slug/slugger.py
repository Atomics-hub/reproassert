def slugify(value: str) -> str:
    """Buggy behavior: every space becomes a separator independently."""

    return value.strip().lower().replace(" ", "-")
