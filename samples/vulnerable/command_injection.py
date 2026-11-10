"""Sample vulnerable Python code: OS Command Injection (CWE-78)."""

import os
import subprocess


def ping_host_vulnerable(host_address: str):
    """
    Vulnerable: User input is passed directly to a shell command string.
    An attacker can supply malicious delimiters like ';', '&&', or '|' to execute arbitrary commands.
    """
    # VULNERABILITY (CWE-78): Shell execution with unescaped input string
    command = f"ping -c 1 {host_address}"
    return subprocess.run(command, shell=True, capture_output=True, text=True)
