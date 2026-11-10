"""Sample vulnerable Python code: Path Traversal (CWE-22)."""

import os


def read_user_document_vulnerable(base_directory: str, filename: str) -> str:
    """
    Vulnerable: User-supplied filename is concatenated without resolving or
    validating against the intended base directory.
    Attacker can supply '../../etc/passwd' to read arbitrary files.
    """
    # VULNERABILITY (CWE-22): Unrestricted path join
    target_path = os.path.join(base_directory, filename)
    with open(target_path, "r", encoding="utf-8") as f:
        return f.read()
