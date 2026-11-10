"""Global pytest configuration and fixtures for VulnPath AI."""

from pathlib import Path
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from backend.app.database.db import DatabaseManager, db_manager
from backend.app.main import app


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def temp_db(tmp_path: Path):
    """Provide an isolated temporary SQLite database for testing."""
    test_db_path = tmp_path / "test_vulnpath.db"
    manager = DatabaseManager(db_path=test_db_path)
    await manager.init_db()
    return manager


@pytest_asyncio.fixture
async def client(tmp_path: Path):
    """Async HTTP client bound to the FastAPI application with isolated test database."""
    test_db_path = tmp_path / "test_api.db"

    # Redirect the global db_manager to the temp path
    original_path = db_manager.db_path
    db_manager.db_path = test_db_path
    await db_manager.init_db()

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac
    finally:
        db_manager.db_path = original_path
