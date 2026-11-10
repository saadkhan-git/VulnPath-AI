"""Base abstract class for all AST-based static vulnerability detectors."""

from abc import ABC, abstractmethod
import ast
from typing import List, Optional

from backend.app.core.constants import SeverityLevel
from backend.app.parsing.ast_parser import ParsedFile, PythonAstParser
from backend.app.schemas.finding import CodePathNode, FindingCreate


class BaseDetector(ABC):
    """Abstract base class that all vulnerability detectors implement."""

    name: str = "BaseDetector"
    cwe_id: str = "CWE-000"
    title: str = "Generic Weakness"
    severity: SeverityLevel = SeverityLevel.MEDIUM
    default_confidence: float = 0.85

    @abstractmethod
    def run(self, parsed_file: ParsedFile, scan_id: str) -> List[FindingCreate]:
        """
        Executes AST inspection on parsed_file and returns a list of detected findings.
        Must handle cases where parsed_file.ast_tree is None gracefully.
        """
        pass

    def extract_context(self, parsed_file: ParsedFile, line_number: int, context_lines: int = 3) -> str:
        """Helper to extract formatted surrounding code lines."""
        return PythonAstParser.extract_code_context(parsed_file, line_number, context_lines)

    @staticmethod
    def get_enclosing_function_name(tree: ast.AST, target_lineno: int) -> Optional[str]:
        """Finds the name of the function or method enclosing target_lineno, if any."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end_lineno = getattr(node, "end_lineno", node.lineno)
                if node.lineno <= target_lineno <= end_lineno:
                    return node.name
        return None

    @staticmethod
    def is_constant_value(node: ast.AST) -> bool:
        """Checks if an AST node evaluates to an immutable constant literal."""
        if isinstance(node, ast.Constant):
            return True
        # For Python versions where ast.Str or ast.Num might be used
        if hasattr(ast, "Str") and isinstance(node, ast.Str):
            return True
        if hasattr(ast, "Num") and isinstance(node, ast.Num):
            return True
        return False
