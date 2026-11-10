"""Small, dependency-free example reviewed by the policy gate."""

import sqlite3


def find_account(connection: sqlite3.Connection, email: str) -> tuple | None:
    """Treat the caller's email as a database value, not query syntax."""
    return connection.execute(
        "SELECT id, email FROM accounts WHERE email = ?", (email,)
    ).fetchone()


def account_exists(connection: sqlite3.Connection, email: str) -> bool:
    """The corrected demo retains a useful change without interpolating input."""
    return find_account(connection, email) is not None
