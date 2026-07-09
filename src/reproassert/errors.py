from __future__ import annotations


class ReproAssertError(Exception):
    """A bounded, user-displayable workflow failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class PolicyRejection(ReproAssertError):
    """Input was understood but rejected by a trust policy."""
