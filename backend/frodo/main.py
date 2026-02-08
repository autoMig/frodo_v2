"""Frodo FastAPI application."""
import asyncio
import logging
import os

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from frodo.config import setup_logging
from frodo.illumio_client.client import IllumioClient
from frodo.services.application_service import ApplicationService
from frodo.unicorn.client import UnicornClient

setup_logging()
logger = logging.getLogger("frodo")

app = FastAPI(
    title="Frodo",
    description="Firewall Operations & Definition Orchestration",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Singleton clients shared by endpoints and background refresh
_unicorn_client: UnicornClient | None = None
_illumio_client: IllumioClient | None = None


def _get_unicorn_client() -> UnicornClient:
    global _unicorn_client
    if _unicorn_client is None:
        base_url = os.environ.get("UNICORN_BASE_URL", "http://localhost:8001")
        api_user = os.environ.get("UNICORN_API_USER", "")
        api_key = os.environ.get("UNICORN_API_KEY", "")
        lifecycle_states_str = os.environ.get("UNICORN_LIFECYCLE_STATES", "Registered,Live,Configure")
        lifecycle_states = [s.strip() for s in lifecycle_states_str.split(",") if s.strip()]
        verify_ssl = os.environ.get("VERIFY_SSL", "true").strip().lower() not in ("false", "0", "no")
        _unicorn_client = UnicornClient(
            base_url=base_url,
            api_user=api_user,
            api_key=api_key,
            lifecycle_states=lifecycle_states,
            verify_ssl=verify_ssl,
        )
    return _unicorn_client


def _get_illumio_client() -> IllumioClient | None:
    global _illumio_client
    if _illumio_client is None:
        host = os.environ.get("ILLUMIO_PCE_HOST", "")
        api_key = os.environ.get("ILLUMIO_API_KEY", "")
        if not host or not api_key:
            return None
        verify_ssl = os.environ.get("VERIFY_SSL", "true").strip().lower() not in ("false", "0", "no")
        _illumio_client = IllumioClient(
            pce_host=host,
            org_id=os.environ.get("ILLUMIO_ORG_ID", "1"),
            api_key=api_key,
            api_secret=os.environ.get("ILLUMIO_API_SECRET", ""),
            port=int(os.environ.get("ILLUMIO_PCE_PORT", "443")),
            verify_ssl=verify_ssl,
        )
    return _illumio_client


def _get_application_service() -> ApplicationService:
    return ApplicationService(
        unicorn_client=_get_unicorn_client(),
        illumio_client=_get_illumio_client(),
    )


async def _run_cache_refresh() -> None:
    """Refresh Unicorn and Illumio caches. Called by background scheduler."""
    unicorn = _get_unicorn_client()
    illumio = _get_illumio_client()

    logger.info("Cache refresh: starting Unicorn fetch")
    await unicorn.refresh_servers_cache()
    if illumio:
        logger.info("Cache refresh: starting Illumio fetch")
        await asyncio.to_thread(illumio.refresh_workloads_cache)
    logger.info("Cache refresh: complete")


async def _cache_refresh_loop() -> None:
    """Background task: refresh caches on startup (after delay) and every hour."""
    interval = int(os.environ.get("CACHE_REFRESH_INTERVAL_SECONDS", "3600"))
    startup_delay = int(os.environ.get("CACHE_REFRESH_STARTUP_DELAY_SECONDS", "5"))

    await asyncio.sleep(startup_delay)
    logger.info("Starting cache refresh background task (interval=%ds)", interval)

    while True:
        try:
            await _run_cache_refresh()
        except Exception as e:
            logger.exception("Cache refresh failed: %s", e)
        await asyncio.sleep(interval)


@app.on_event("startup")
async def startup_cache_refresh():
    """Start background cache refresh task."""
    asyncio.create_task(_cache_refresh_loop())


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/api/applications")
async def get_applications(
    x_ad_groups: str | None = Header(default=None, alias="X-AD-Groups"),
):
    """
    Get application summaries for the current user.
    X-AD-Groups: comma-separated AD group names (for dev; ADFS will provide in production).
    """
    ad_groups = []
    if x_ad_groups:
        ad_groups = [g.strip() for g in x_ad_groups.split(",") if g.strip()]

    service = _get_application_service()
    try:
        applications = await service.get_applications_for_user(ad_groups=ad_groups)
        return {"applications": [a.model_dump() for a in applications]}
    except Exception as e:
        logger.exception("Failed to fetch applications")
        raise HTTPException(status_code=500, detail=str(e))
