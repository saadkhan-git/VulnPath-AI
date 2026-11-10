"""Sample safe Python code: Parameterized SQL Query (Mitigates CWE-89)."""

import sqlite3


def get_user_record_safe(database_path: str, user_id: str):
    """
    Safe: Input parameters are supplied as query parameters, preventing
    SQL injection regardless of input characters.
    """
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()

    # SAFE: Parameterized placeholder
    query = "SELECT id, username, email FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    result = cursor.fetchall()
    conn.close()
    return result
