class crash(Exception):
    pass


def reproduce() -> int:
    print("E   AssertionError: duplicate separators remain")
    raise crash
