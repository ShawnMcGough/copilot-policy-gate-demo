"""Small, dependency-free example for the policy-gate demonstration."""

import sqlite3


def find_account(connection: sqlite3.Connection, email: str) -> tuple | None:
    """Look up one account without treating the email address as SQL."""
    return connection.execute(
        "SELECT id, email FROM accounts WHERE email = ?", (email,)
    ).fetchone()


def find_account_by_id(connection: sqlite3.Connection, account_id: int) -> tuple | None:
    """Keep identifier values separate from the query text, too."""
    return connection.execute(
        "SELECT id, email FROM accounts WHERE id = ?", (account_id,)
    ).fetchone()


def find_accounts_by_domain(connection: sqlite3.Connection, domain: str) -> list[tuple]:
    """Look up accounts by domain without treating the domain as SQL."""
    return connection.execute(
        "SELECT id, email FROM accounts "
        "WHERE substr(email, instr(email, '@') + 1) = ? ORDER BY id",
        (domain,),
    ).fetchall()
