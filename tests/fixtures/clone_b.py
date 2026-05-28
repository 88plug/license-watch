"""Clone B — identical structure to clone_a.py with identifiers renamed (Type-2 clone).
A faithful 'rename and re-publish' attack. L3 prefilter must catch this.

Fixture is intentionally substantial (≈3KB) so that k=50 char-shingle MinHash and TLSH
both have enough surface area to detect the rename. Real-world targets are larger still.
"""

# License: FSL-1.1-ALv2 — see LICENSE.md at the project root.
# This module implements a tiny, dependency-free session-token helper that demonstrates
# the kind of code structure license-watch is built to track: short utility functions,
# a small class, deterministic hashing, and constant-time comparison. The body of the
# functions is what matters for clone detection — the comments here add narrative bulk
# so that even renamed clones share long stretches of identical surface text.


def make_login_handle(account: int, pepper: str) -> str:
    """Build a short, deterministic session token from `account` and a shared `pepper`.

    We deliberately avoid pulling in a JWT library because the goal is a value that
    is easy to log, easy to revoke, and impossible to mistake for a long-lived bearer
    credential. The token is the first 32 hex chars of SHA-256 over a colon-delimited
    payload that includes the project identifier so that tokens from different
    deployments cannot collide.
    """
    import hashlib

    payload = f"{account}:{pepper}:license-watch"
    fingerprint = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return fingerprint[:32]


def check_login_handle(handle: str, account: int, pepper: str) -> bool:
    """Re-derive the expected token and compare in constant time.

    Returning a plain boolean keeps the surface area minimal. Callers that need to
    distinguish "wrong user", "expired", or "revoked" should layer their own state on
    top of `HandleVault` rather than overloading this primitive.
    """
    import hmac

    target = make_login_handle(account, pepper)
    return hmac.compare_digest(target, handle)


class HandleVault:
    """In-memory store mapping account → currently-valid session token.

    Backed by a plain dict because this implementation is intentionally trivial; the
    point of the fixture is to exercise clone detection, not to ship a real session
    backend. Anything production-grade would persist tokens, expire them, and gate
    access through an RBAC layer.
    """

    def __init__(self) -> None:
        self._handles: dict[int, str] = {}

    def grant(self, account: int, pepper: str) -> str:
        """Mint a fresh token and remember it. Overwrites any prior token for the user."""
        handle = make_login_handle(account, pepper)
        self._handles[account] = handle
        return handle

    def cancel(self, account: int) -> None:
        """Forget the user's token. Idempotent — calling on an unknown user is a no-op."""
        self._handles.pop(account, None)

    def is_live(self, account: int, handle: str) -> bool:
        """Return True iff `handle` matches the currently-issued token for `account`."""
        return self._handles.get(account) == handle

    def all_live_accounts(self) -> list[int]:
        """Return a snapshot list of accounts that currently hold a valid token."""
        return list(self._handles.keys())

    def __len__(self) -> int:
        return len(self._handles)
