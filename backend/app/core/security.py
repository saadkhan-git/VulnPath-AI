"""Security utilities and input boundary validators for VulnPath AI."""

import os
from pathlib import Path
from typing import List, Optional


class SecurityViolationError(ValueError):
    """Raised when an untrusted input breaches safety constraints."""
    pass


def is_safe_relative_path(path_str: str) -> bool:
    """
    Ensure a path string is strictly relative and does not traverse upwards.
    Mitigates Zip Slip and path traversal vulnerabilities (CWE-22).
    """
    if not path_str or path_str.strip() == "":
        return False

    # Normalize slashes
    clean_path = path_str.replace("\\", "/")

    # Reject absolute Windows drive paths or POSIX root paths
    if clean_path.startswith("/") or ":" in clean_path:
        return False

    # Check for path traversal components
    parts = clean_path.split("/")
    depth = 0
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                return False
        else:
            depth += 1

    return True


def validate_path_within_root(target_path: Path, allowed_root: Path) -> Path:
    """
    Verify that target_path resolves strictly within allowed_root.
    Raises SecurityViolationError if the path escapes the root.
    """
    resolved_root = allowed_root.resolve()
    resolved_target = target_path.resolve()

    try:
        resolved_target.relative_to(resolved_root)
    except ValueError:
        raise SecurityViolationError(
            f"Path traversal detected: {resolved_target} escapes allowed root {resolved_root}"
        )

    return resolved_target


def is_path_in_allowed_roots(path_to_check: Path, allowed_roots: List[str]) -> bool:
    """
    Check if a path falls within any of the user-configured allowed roots.
    If no roots are configured, returns False by default to enforce safe boundary restrictions.
    """
    if not allowed_roots:
        return False

    resolved_check = path_to_check.resolve()
    for root_str in allowed_roots:
        root_path = Path(root_str).resolve()
        try:
            resolved_check.relative_to(root_path)
            return True
        except ValueError:
            continue

    return False
