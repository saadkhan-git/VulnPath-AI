# VulnPath AI — Regression Test Samples

This directory contains clean-room test sample suites used to benchmark detection accuracy, false-positive resistance, and localization fidelity across development phases.

## Directory Layout

- `vulnerable/`: Deliberately flawed code snippets covering CWE-89 (SQLi), CWE-78 (Command Injection), CWE-22 (Path Traversal), CWE-798 (Hardcoded Secrets).
- `safe/`: Idiomatic, remediated counterparts testing false-positive rejection.
