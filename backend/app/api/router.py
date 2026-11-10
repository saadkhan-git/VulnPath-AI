"""Master API router aggregating all versioned endpoints."""

from fastapi import APIRouter
from backend.app.api import health
from backend.app.api import scans

api_router = APIRouter(prefix="/api")

# Mount foundational endpoints
api_router.include_router(health.router)
api_router.include_router(scans.router)
