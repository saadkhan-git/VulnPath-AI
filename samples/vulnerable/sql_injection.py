"""Sample vulnerable Python code: SQL Injection (CWE-89)."""

import sqlite3


def get_user_record(database_path: str, user_id: str):
    """
    Vulnerable: Untrusted user input is directly concatenated into an SQL string
    without parameter binding, allowing query structure alteration.
    """
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()

    # VULNERABILITY (CWE-89): Direct string formatting into SQL query
    query = f"SELECT id, username, email FROM users WHERE id = '{user_id}'"
    cursor.execute(query)

    result = cursor.fetchall()
    conn.close()
    return result
