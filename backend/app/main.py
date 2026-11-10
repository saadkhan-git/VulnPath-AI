"""VulnPath AI main application entrypoint."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from backend.app.api.router import api_router
from backend.app.core.config import settings
from backend.app.core.constants import PRODUCT_NAME, PRODUCT_TAGLINE, PRODUCT_VERSION
from backend.app.database.db import db_manager


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforce strict local security headers."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Server"] = "VulnPath-AI-Local"
        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle management."""
    # Ensure local storage and initialize database schema
    settings.ensure_data_dir()
    await db_manager.init_db()
    yield


app = FastAPI(
    title=PRODUCT_NAME,
    description=f"{PRODUCT_TAGLINE} — Research-grade SAST and vulnerability intelligence platform.",
    version=PRODUCT_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Apply Security Headers
app.add_middleware(SecurityHeadersMiddleware)

# Apply Loopback CORS Controls
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Mount API Endpoints
app.include_router(api_router)


@app.get("/", tags=["Root"])
async def root_status():
    """Root metadata response."""
    return {
        "product": PRODUCT_NAME,
        "tagline": PRODUCT_TAGLINE,
        "version": PRODUCT_VERSION,
        "documentation": "/docs",
        "api_health": "/api/health",
    }
