"""System constants and security bounds for VulnPath AI."""

from enum import Enum
from typing import Dict, Set

# Identity and branding
PRODUCT_NAME = "VulnPath AI"
PRODUCT_TAGLINE = "Trace the path. Fix the flaw."
AUTHOR_NAME = "Mohammad Saad Khan"
AUTHOR_GITHUB = "https://github.com/saadkhan-git"
PRODUCT_VERSION = "0.1.0"
CLEAN_ROOM_COMPLIANT = True

# Operational Security Limits
DEFAULT_MAX_ARCHIVE_SIZE_BYTES = 50 * 1024 * 1024       # 50 MB
DEFAULT_MAX_SINGLE_FILE_SIZE_BYTES = 5 * 1024 * 1024    # 5 MB
DEFAULT_MAX_TOTAL_EXTRACTED_BYTES = 100 * 1024 * 1024   # 100 MB
DEFAULT_MAX_FILE_COUNT = 500                            # Maximum files in a single scan
DEFAULT_MAX_DIRECTORY_DEPTH = 10                        # Maximum traversal depth
DEFAULT_SCAN_TIMEOUT_SECONDS = 300                      # 5 minutes

# Supported File Extensions
SUPPORTED_PYTHON_EXTENSIONS: Set[str] = {".py", ".pyw"}
PLANNED_MULTI_LANG_EXTENSIONS: Set[str] = {
    ".js", ".jsx", ".ts", ".tsx",  # JavaScript / TypeScript
    ".java",                        # Java
    ".c", ".cpp", ".cc", ".h",      # C / C++
    ".go",                          # Go
    ".php",                         # PHP
    ".rb",                          # Ruby
}


class SeverityLevel(str, Enum):
    """Normalized vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConfidenceLevel(str, Enum):
    """Heuristic / model confidence level in finding."""
    CONFIRMED = "confirmed"  # Verified by taint source-to-sink reachability
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanStatus(str, Enum):
    """Lifecycle states of an analysis scan."""
    PENDING = "pending"
    EXTRACTING = "extracting"
    PARSING = "parsing"
    ANALYZING = "analyzing"
    FUSING = "fusing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# Standard CWE Definitions for the initial AST and static engine
CWE_REGISTRY: Dict[str, Dict[str, str]] = {
    "CWE-89": {
        "name": "SQL Injection",
        "description": "Improper neutralization of special elements used in an SQL Command.",
        "owasp": "A03:2021-Injection",
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "description": "Improper neutralization of special elements used in an OS Command.",
        "owasp": "A03:2021-Injection",
    },
    "CWE-22": {
        "name": "Path Traversal",
        "description": "Improper limitation of a pathname to a restricted directory ('Path Traversal').",
        "owasp": "A01:2021-Broken Access Control",
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "description": "Improper neutralization of input during web page generation.",
        "owasp": "A03:2021-Injection",
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "description": "Deserialization of untrusted data without verification.",
        "owasp": "A08:2021-Software and Data Integrity Failures",
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "description": "Hard-coding sensitive credentials directly in code or configuration.",
        "owasp": "A07:2021-Identification and Authentication Failures",
    },
    "CWE-327": {
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "description": "Use of outdated or weak hashing or encryption algorithms.",
        "owasp": "A02:2021-Cryptographic Failures",
    },
}
