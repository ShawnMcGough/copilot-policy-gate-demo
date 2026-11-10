"""Small, dependency-free example for the policy-gate demonstration."""

import sqlite3


def find_account(connection: sqlite3.Connection, email: str) -> tuple | None:
    """Look up one account without treating the email address as SQL."""
    return connection.execute(
        "SELECT id, email FROM accounts WHERE email = ?", (email,)
    ).fetchone()
