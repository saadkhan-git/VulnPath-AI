"""Health check and system information endpoint."""

import sys
from typing import Any, Dict
from fastapi import APIRouter

from backend.app.core.config import settings
from backend.app.core.constants import (
    AUTHOR_GITHUB,
    AUTHOR_NAME,
    CLEAN_ROOM_COMPLIANT,
    PRODUCT_NAME,
    PRODUCT_TAGLINE,
    PRODUCT_VERSION,
    SUPPORTED_PYTHON_EXTENSIONS,
)

router = APIRouter(tags=["System & Health"])


@router.get("/health", summary="Service health and capability metadata")
async def get_health_status() -> Dict[str, Any]:
    """
    Returns the real-time operational status, product identity,
    clean-room compliance, and supported scanner extensions.
    """
    return {
        "status": "healthy",
        "product": {
            "name": PRODUCT_NAME,
            "tagline": PRODUCT_TAGLINE,
            "version": PRODUCT_VERSION,
            "creator": AUTHOR_NAME,
            "github": AUTHOR_GITHUB,
        },
        "governance": {
            "clean_room_verified": CLEAN_ROOM_COMPLIANT,
            "license": "Draft Proprietary - Mohammad Saad Khan (All Rights Reserved)",
        },
        "runtime": {
            "python_version": sys.version.split()[0],
            "platform": sys.platform,
        },
        "capabilities": {
            "supported_extensions": sorted(list(SUPPORTED_PYTHON_EXTENSIONS)),
            "max_file_count": settings.max_file_count,
            "max_archive_size_mb": settings.max_archive_size_bytes // (1024 * 1024),
            "max_single_file_mb": settings.max_single_file_size_bytes // (1024 * 1024),
        },
    }
