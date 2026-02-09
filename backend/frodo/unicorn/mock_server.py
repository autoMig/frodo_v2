"""Mock Unicorn API server for development."""
import json
import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse

logger = logging.getLogger("frodo.unicorn.mock")

app = FastAPI(title="Mock Unicorn API")

# Sample servers for development
SAMPLE_SERVERS = [
    {
        "hostname": "appx-web-01",
        "environment": {"name": "production", "code": "production", "id": "1"},
        "osVersion": {"operatingSystem": {"name": "Windows"}},
        "networkIdentifier": {"code": "internal"},
        "networkSubzone": "HIGH-RISK",
        "hostingPlatform": {"name": "ICP-2-Prod"},
        "services": [{"service": {"name": "APP-X"}}],
    },
    {
        "hostname": "appx-web-02",
        "environment": {"name": "production", "code": "production", "id": "1"},
        "osVersion": {"operatingSystem": {"name": "Windows"}},
        "networkIdentifier": {"code": "internal"},
        "networkSubzone": "HIGH-RISK",
        "hostingPlatform": {"name": "ICP-2-Prod"},
        "services": [{"service": {"name": "APP-X"}}],
    },
    {
        "hostname": "appx-db-01",
        "environment": {"name": "production", "code": "production", "id": "1"},
        "osVersion": {"operatingSystem": {"name": "Linux"}},
        "networkIdentifier": {"code": "internal"},
        "networkSubzone": "",
        "hostingPlatform": {"name": "ICP-2-Prod"},
        "services": [{"service": {"name": "APP-X"}}],
    },
    {
        "hostname": "appy-web-01",
        "environment": {"name": "uat", "code": "uat", "id": "2"},
        "osVersion": {"operatingSystem": {"name": "Windows"}},
        "networkIdentifier": {"code": "IDMZ"},
        "networkSubzone": "",
        "hostingPlatform": {"name": "Legacy-VM"},
        "services": [{"service": {"name": "APP-Y-UAT"}}],
    },
    {
        "hostname": "appz-api-01",
        "environment": {"name": "production", "code": "production", "id": "1"},
        "osVersion": {"operatingSystem": {"name": "Linux"}},
        "networkIdentifier": {"code": "internal"},
        "networkSubzone": "LOW-RISK",
        "hostingPlatform": {"name": "AWS-Prod"},
        "services": [{"service": {"name": "APP-Z"}}],
    },
]


@app.get("/servers")
async def get_servers():
    """Return mock server list."""
    return SAMPLE_SERVERS


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
