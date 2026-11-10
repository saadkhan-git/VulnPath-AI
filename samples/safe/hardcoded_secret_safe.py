"""Sample safe Python code: Environment-based Credentials (Mitigates CWE-798)."""

import os


def initialize_api_client_safe():
    """
    Safe: Credentials are retrieved dynamically at runtime from environment variables.
    """
    aws_secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    jwt_secret = os.environ.get("JWT_SIGNING_KEY")

    if not aws_secret_key or not jwt_secret:
        raise ValueError("Missing required security credentials in environment.")

    return {"aws": aws_secret_key, "jwt": jwt_secret}
