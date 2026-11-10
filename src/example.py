"""Deliberately unsafe, non-deployed policy-gate demonstration."""

import sqlite3


def find_account(connection: sqlite3.Connection, email: str) -> tuple | None:
    """This executable interpolation must fail the trusted SEC-001 policy."""
    return connection.execute(
        f"SELECT id, email FROM accounts WHERE email = '{email}'"
    ).fetchone()
