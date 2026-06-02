"""Sentinel-AI XDR - FastAPI Application Entry Point."""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from backend.app.api.routes import alerts, audit, auth, compliance, dashboard_data, ips, network, pentest, threat_intel, websocket
from backend.app.config import get_settings
from backend.app.core.security import hash_password
from backend.app.models.documents import User
from backend.app.models.enums import UserRole
from backend.app.mongodb import close_mongodb, connect_mongodb, ping_mongodb

settings = get_settings()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel")

_collector_task: asyncio.Task | None = None


def _try_start_packet_capture():
    try:
        from backend.app.collectors.packet_capture import SCAPY_AVAILABLE, is_capturing, start_capture

        if SCAPY_AVAILABLE and not is_capturing() and start_capture():
            logger.info("Live packet capture started")
        elif SCAPY_AVAILABLE:
            logger.info("Packet capture skipped or unavailable (run API as admin / install Npcap on Windows)")
    except Exception as exc:
        logger.warning("Packet capture: %s", exc)


async def _background_collector():
    await asyncio.sleep(3)
    _try_start_packet_capture()
    await asyncio.sleep(5)
    while True:
        try:
            from backend.app.services.event_pipeline import process_realtime_cycle

            await process_realtime_cycle()
        except Exception as exc:
            logger.warning("Background collection: %s", exc)
        await asyncio.sleep(30)


async def _ensure_super_admin():
    admin = await User.find_one(User.role == UserRole.SUPER_ADMIN)
    if not admin:
        user = User(
            email="admin@sentinel-xdr.com",
            username="admin",
            hashed_password=hash_password("Sentinel@Admin2024!"),
            full_name="System Administrator",
            role=UserRole.SUPER_ADMIN,
            is_verified=True,
        )
        await user.insert()
        logger.info("Default super admin: admin@sentinel-xdr.com / Sentinel@Admin2024!")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _collector_task
    await connect_mongodb()
    await _ensure_super_admin()
    _collector_task = asyncio.create_task(_background_collector())
    logger.info("Sentinel-AI XDR API started [MongoDB]")
    yield
    if _collector_task:
        _collector_task.cancel()
    await close_mongodb()
    logger.info("Sentinel-AI XDR API stopped")


limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title=settings.app_name,
    description="Enterprise XDR + SIEM + UEBA + IDS/IPS Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/v1")
app.include_router(alerts.router, prefix="/api/v1")
app.include_router(network.router, prefix="/api/v1")
app.include_router(pentest.router, prefix="/api/v1")
app.include_router(dashboard_data.router, prefix="/api/v1")
app.include_router(threat_intel.router, prefix="/api/v1")
app.include_router(audit.router, prefix="/api/v1")
app.include_router(ips.router, prefix="/api/v1")
app.include_router(compliance.router, prefix="/api/v1")
app.include_router(websocket.router, prefix="/api/v1")


@app.get("/health")
async def health():
    from backend.app.mongodb import _using_mock
    mongo_ok = await ping_mongodb()
    return {
        "status": "healthy" if mongo_ok else "degraded",
        "service": settings.app_name,
        "version": "1.0.0",
        "database": "mongodb-mock" if _using_mock else "mongodb",
        "mongodb_connected": mongo_ok,
    }


@app.get("/")
async def root():
    return {
        "platform": "Sentinel-AI XDR",
        "docs": "/api/docs",
        "dashboard": "http://localhost:8501",
    }
