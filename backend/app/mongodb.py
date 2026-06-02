"""MongoDB connection and Beanie initialization."""
import logging
import os

from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

from backend.app.config import get_settings
from backend.app.models.documents import ALL_DOCUMENTS

logger = logging.getLogger("sentinel")
_client: AsyncIOMotorClient | None = None
_using_mock = False


async def connect_mongodb() -> None:
    global _client, _using_mock
    settings = get_settings()
    use_mock = os.getenv("MONGODB_USE_MOCK", "").lower() in ("1", "true", "yes")

    if use_mock:
        await _connect_mock(settings.mongodb_db)
        return

    try:
        _client = AsyncIOMotorClient(settings.mongodb_url, serverSelectionTimeoutMS=5000)
        await _client.admin.command("ping")
        db = _client[settings.mongodb_db]
        await init_beanie(database=db, document_models=ALL_DOCUMENTS)
        logger.info("MongoDB connected: %s / %s", settings.mongodb_url, settings.mongodb_db)
    except Exception as exc:
        if settings.app_env == "development":
            logger.warning("MongoDB unavailable (%s) — using in-memory mock for development", exc)
            await _connect_mock(settings.mongodb_db)
        else:
            raise


async def _connect_mock(db_name: str) -> None:
    global _client, _using_mock
    try:
        from mongomock_motor import AsyncMongoMockClient
    except ImportError:
        raise RuntimeError(
            "MongoDB is not running. Start MongoDB on port 27017, or install mock support:\n"
            "  pip install mongomock-motor\n"
            "  set MONGODB_USE_MOCK=1\n"
            "Or run: docker run -d -p 27017:27017 mongo:7-jammy"
        ) from None
    _client = AsyncMongoMockClient()
    _using_mock = True
    db = _client[db_name]
    await init_beanie(database=db, document_models=ALL_DOCUMENTS)
    logger.info("MongoDB mock (in-memory) — development only")


async def close_mongodb() -> None:
    global _client, _using_mock
    if _client and not _using_mock:
        _client.close()
    _client = None
    _using_mock = False


async def ping_mongodb() -> bool:
    if not _client:
        return False
    try:
        await _client.admin.command("ping")
        return True
    except Exception:
        return _using_mock
