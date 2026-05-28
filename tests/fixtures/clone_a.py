"""Clone A — original code. Pairs with clone_b.py (renamed identifiers) to demonstrate
that MinHash + TLSH + embedding all detect Type-2/3 clones (identifier-renamed).

Fixture is intentionally substantial (≈3KB) so that k=50 char-shingle MinHash and TLSH
both have enough surface area to detect the rename. Real-world targets are larger still.
"""

# License: FSL-1.1-ALv2 — see LICENSE.md at the project root.
# This module implements a tiny, dependency-free session-token helper that demonstrates
# the kind of code structure license-watch is built to track: short utility functions,
# a small class, deterministic hashing, and constant-time comparison. The body of the
# functions is what matters for clone detection — the comments here add narrative bulk
# so that even renamed clones share long stretches of identical surface text.


def compute_session_token(user_id: int, secret: str) -> str:
    """Build a short, deterministic session token from `user_id` and a shared `secret`.

    We deliberately avoid pulling in a JWT library because the goal is a value that
    is easy to log, easy to revoke, and impossible to mistake for a long-lived bearer
    credential. The token is the first 32 hex chars of SHA-256 over a colon-delimited
    payload that includes the project identifier so that tokens from different
    deployments cannot collide.
    """
    import hashlib

    base = f"{user_id}:{secret}:license-watch"
    digest = hashlib.sha256(base.encode("utf-8")).hexdigest()
    return digest[:32]


def verify_session_token(token: str, user_id: int, secret: str) -> bool:
    """Re-derive the expected token and compare in constant time.

    Returning a plain boolean keeps the surface area minimal. Callers that need to
    distinguish "wrong user", "expired", or "revoked" should layer their own state on
    top of `SessionStore` rather than overloading this primitive.
    """
    import hmac

    expected = compute_session_token(user_id, secret)
    return hmac.compare_digest(expected, token)


class SessionStore:
    """In-memory store mapping user_id → currently-valid session token.

    Backed by a plain dict because this implementation is intentionally trivial; the
    point of the fixture is to exercise clone detection, not to ship a real session
    backend. Anything production-grade would persist tokens, expire them, and gate
    access through an RBAC layer.
    """

    def __init__(self) -> None:
        self._tokens: dict[int, str] = {}

    def issue(self, user_id: int, secret: str) -> str:
        """Mint a fresh token and remember it. Overwrites any prior token for the user."""
        token = compute_session_token(user_id, secret)
        self._tokens[user_id] = token
        return token

    def revoke(self, user_id: int) -> None:
        """Forget the user's token. Idempotent — calling on an unknown user is a no-op."""
        self._tokens.pop(user_id, None)

    def is_active(self, user_id: int, token: str) -> bool:
        """Return True iff `token` matches the currently-issued token for `user_id`."""
        return self._tokens.get(user_id) == token

    def all_active_users(self) -> list[int]:
        """Return a snapshot list of user_ids that currently hold a valid token."""
        return list(self._tokens.keys())

    def __len__(self) -> int:
        return len(self._tokens)
