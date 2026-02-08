"""Frodo FastAPI application."""
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


def _get_unicorn_client() -> UnicornClient:
    base_url = os.environ.get("UNICORN_BASE_URL", "http://localhost:8001")
    api_user = os.environ.get("UNICORN_API_USER", "")
    api_key = os.environ.get("UNICORN_API_KEY", "")
    lifecycle_states_str = os.environ.get("UNICORN_LIFECYCLE_STATES", "Registered,Live,Configure")
    lifecycle_states = [s.strip() for s in lifecycle_states_str.split(",") if s.strip()]
    return UnicornClient(
        base_url=base_url,
        api_user=api_user,
        api_key=api_key,
        lifecycle_states=lifecycle_states,
    )


def _get_illumio_client() -> IllumioClient | None:
    host = os.environ.get("ILLUMIO_PCE_HOST", "")
    api_key = os.environ.get("ILLUMIO_API_KEY", "")
    if not host or not api_key:
        return None
    return IllumioClient(
        pce_host=host,
        org_id=os.environ.get("ILLUMIO_ORG_ID", "1"),
        api_key=api_key,
        api_secret=os.environ.get("ILLUMIO_API_SECRET", ""),
        port=int(os.environ.get("ILLUMIO_PCE_PORT", "443")),
    )


def _get_application_service() -> ApplicationService:
    return ApplicationService(
        unicorn_client=_get_unicorn_client(),
        illumio_client=_get_illumio_client(),
    )


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
