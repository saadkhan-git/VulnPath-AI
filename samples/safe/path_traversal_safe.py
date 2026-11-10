"""Sample safe Python code: Secure Path Resolution (Mitigates CWE-22)."""

from pathlib import Path


def read_user_document_safe(base_directory: str, filename: str) -> str:
    """
    Safe: Path is resolved and verified to strictly reside inside the base directory.
    """
    base_path = Path(base_directory).resolve()
    target_path = (base_path / filename).resolve()

    # SAFE: Path traversal boundary verification
    try:
        target_path.relative_to(base_path)
    except ValueError:
        raise PermissionError("Access denied: Path escapes base directory")

    with open(target_path, "r", encoding="utf-8") as f:
        return f.read()
