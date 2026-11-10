"""Sample vulnerable Python code: Hardcoded Secret (CWE-798)."""


def initialize_api_client():
    """
    Vulnerable: Sensitive private API token is committed directly in source code.
    """
    # VULNERABILITY (CWE-798): Hardcoded API key
    aws_secret_key = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY_HERE_12345"
    jwt_secret = "super_secret_signing_key_never_share"
    return {"aws": aws_secret_key, "jwt": jwt_secret}
