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
        "environment": {"code": "production", "id": "1"},
        "osVersion": {"operatingSystem": {"name": "Windows"}},
        "networkIdentifier": {"code": "internal"},
        "networkSubzone": "HIGH-RISK",
        "hostingPlatform": {"name": "ICP-2-Prod"},
        "services": [
            {"businessApplicationName": "APP-X", "businessApplicationNumber": "BA1234"},
        ],
    },
    {
        "hostname": "appx-web-02",
        "environment": {"code": "production", "id": "1"},
        "osVersion": {"operatingSystem": {"name": "Windows"}},
        "networkIdentifier": {"code": "internal"},
        "networkSubzone": "HIGH-RISK",
        "hostingPlatform": {"name": "ICP-2-Prod"},
        "services": [
            {"businessApplicationName": "APP-X", "businessApplicationNumber": "BA1234"},
        ],
    },
    {
        "hostname": "appx-db-01",
        "environment": {"code": "production", "id": "1"},
        "osVersion": {"operatingSystem": {"name": "Linux"}},
        "networkIdentifier": {"code": "internal"},
        "networkSubzone": "",
        "hostingPlatform": {"name": "ICP-2-Prod"},
        "services": [
            {"businessApplicationName": "APP-X", "businessApplicationNumber": "BA1234"},
        ],
    },
    {
        "hostname": "appy-web-01",
        "environment": {"code": "uat", "id": "2"},
        "osVersion": {"operatingSystem": {"name": "Windows"}},
        "networkIdentifier": {"code": "IDMZ"},
        "networkSubzone": "",
        "hostingPlatform": {"name": "Legacy-VM"},
        "services": [
            {"businessApplicationName": "APP-Y-UAT", "businessApplicationNumber": "BA5678"},
        ],
    },
    {
        "hostname": "appz-api-01",
        "environment": {"code": "production", "id": "1"},
        "osVersion": {"operatingSystem": {"name": "Linux"}},
        "networkIdentifier": {"code": "internal"},
        "networkSubzone": "LOW-RISK",
        "hostingPlatform": {"name": "AWS-Prod"},
        "services": [
            {"businessApplicationName": "APP-Z", "businessApplicationNumber": "BA9999"},
        ],
    },
]


@app.get("/servers")
async def get_servers():
    """Return mock server list."""
    return SAMPLE_SERVERS


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
