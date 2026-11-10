"""Sample safe Python code: OS Command Execution (Mitigates CWE-78)."""

import subprocess


def ping_host_safe(host_address: str):
    """
    Safe: Command arguments are passed as an immutable list with shell=False,
    preventing shell interpretation of special control operators.
    """
    # SAFE: Argument vector with shell disabled
    cmd_args = ["ping", "-c", "1", host_address]
    return subprocess.run(cmd_args, shell=False, capture_output=True, text=True)
