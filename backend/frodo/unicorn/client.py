"""Unicorn API client for server inventory."""
import logging
from typing import Any

import httpx

from frodo.models import FirewallPlatform

logger = logging.getLogger("frodo.unicorn")

# Module-level cache: populated by background refresh only. Never fetch on read.
_servers_cache: list[dict[str, Any]] | None = None

# Suffixes to strip from business application names
APP_NAME_SUFFIXES = ("-DEV", "-UAT", "-CONT", "-OAT")

# Network zones that indicate External Checkpoint
EXTERNAL_CHECKPOINT_ZONES = {"IDMZ", "EMDZ", "EXTRANET"}


def strip_app_name_suffix(name: str) -> str:
    """Strip environment suffixes from business application name."""
    name_upper = name.upper()
    for suffix in APP_NAME_SUFFIXES:
        if name_upper.endswith(suffix):
            return name[:-len(suffix)].strip()
    return name.strip()


def get_firewall_applicability(server: dict[str, Any]) -> list[FirewallPlatform]:
    """Determine which firewall platforms apply to a server based on Unicorn data."""
    firewalls: list[FirewallPlatform] = []

    os_name = ""
    if server.get("osVersion") and isinstance(server["osVersion"], dict):
        os_obj = server["osVersion"].get("operatingSystem") or {}
        os_name = (os_obj.get("name") or "").upper()

    if os_name in ("WINDOWS", "LINUX"):
        firewalls.append(FirewallPlatform.ILLUMIO)

    network_code = ""
    if server.get("networkIdentifier") and isinstance(server["networkIdentifier"], dict):
        network_code = (server["networkIdentifier"].get("code") or "").upper()

    if network_code in EXTERNAL_CHECKPOINT_ZONES:
        firewalls.append(FirewallPlatform.EXTERNAL_CHECKPOINT)

    network_subzone = (server.get("networkSubzone") or "").strip()
    if network_subzone and network_subzone.upper() != "HERITAGE":
        firewalls.append(FirewallPlatform.INTERNAL_CHECKPOINT)

    hosting_name = ""
    if server.get("hostingPlatform") and isinstance(server["hostingPlatform"], dict):
        hosting_name = server["hostingPlatform"].get("name") or ""

    if hosting_name.upper().startswith("ICP-2"):
        firewalls.append(FirewallPlatform.NSX)

    return firewalls


class UnicornClient:
    """Client for Unicorn API."""

    def __init__(
        self,
        base_url: str,
        api_user: str,
        api_key: str,
        lifecycle_states: list[str] | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_user = api_user
        self.api_key = api_key
        self.lifecycle_states = lifecycle_states or []

    def _headers(self) -> dict[str, str]:
        return {
            "X-API-User": self.api_user,
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    PAGE_SIZE = 10000

    async def get_servers(self) -> list[dict[str, Any]]:
        """
        Return servers from cache. Never fetches from API.
        Uses mock data when api_user is empty (development mode).
        Cache miss returns empty list; data is populated by background refresh only.
        """
        if not self.api_user or not self.api_key:
            logger.info("Unicorn credentials not configured, using mock data")
            return self._get_mock_servers()

        global _servers_cache
        if _servers_cache is not None:
            return _servers_cache
        return []

    async def refresh_servers_cache(self) -> None:
        """
        Fetch servers from Unicorn API and update cache.
        Called by background scheduler only. Skips when credentials not configured.
        On success, updates cache. On failure, keeps previous cache (or leaves empty).
        """
        if not self.api_user or not self.api_key:
            return

        global _servers_cache
        try:
            servers = await self._fetch_servers_from_api()
            _servers_cache = servers
            logger.info("Unicorn cache refreshed: %d servers", len(servers))
        except Exception as e:
            logger.warning("Unicorn cache refresh failed, keeping previous: %s", e)

    async def _fetch_servers_from_api(self) -> list[dict[str, Any]]:
        """Fetch all servers from Unicorn API (used by refresh only)."""
        all_servers: list[dict[str, Any]] = []
        page_index = 0

        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                params: list[tuple[str, str | int]] = [
                    ("pageIndex", page_index),
                    ("pageSize", self.PAGE_SIZE),
                ]
                for state in self.lifecycle_states:
                    params.append(("LifecycleState", state.strip()))
                url = f"{self.base_url}/servers"
                resp = await client.get(url, headers=self._headers(), params=params)
                resp.raise_for_status()
                data = resp.json()

                results = self._extract_results(data)
                all_servers.extend(results)

                if len(results) < self.PAGE_SIZE:
                    break
                page_index += 1

        return all_servers

    def _extract_results(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract server list from API response."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "results" in data:
            return data["results"]
        if isinstance(data, dict) and "servers" in data:
            return data["servers"]
        return []

    def _get_mock_servers(self) -> list[dict[str, Any]]:
        """Return mock server data for development."""
        return [
            {
                "hostname": "appx-web-01",
                "environment": {"code": "production", "id": "1"},
                "osVersion": {"operatingSystem": {"name": "Windows"}},
                "networkIdentifier": {"code": "internal"},
                "networkSubzone": "HIGH-RISK",
                "hostingPlatform": {"name": "ICP-2-Prod"},
                "services": [{"businessApplicationName": "APP-X", "businessApplicationNumber": "BA1234"}],
            },
            {
                "hostname": "appx-web-02",
                "environment": {"code": "production", "id": "1"},
                "osVersion": {"operatingSystem": {"name": "Windows"}},
                "networkIdentifier": {"code": "internal"},
                "networkSubzone": "HIGH-RISK",
                "hostingPlatform": {"name": "ICP-2-Prod"},
                "services": [{"businessApplicationName": "APP-X", "businessApplicationNumber": "BA1234"}],
            },
            {
                "hostname": "appx-db-01",
                "environment": {"code": "production", "id": "1"},
                "osVersion": {"operatingSystem": {"name": "Linux"}},
                "networkIdentifier": {"code": "internal"},
                "networkSubzone": "",
                "hostingPlatform": {"name": "ICP-2-Prod"},
                "services": [{"businessApplicationName": "APP-X", "businessApplicationNumber": "BA1234"}],
            },
            {
                "hostname": "appy-web-01",
                "environment": {"code": "uat", "id": "2"},
                "osVersion": {"operatingSystem": {"name": "Windows"}},
                "networkIdentifier": {"code": "IDMZ"},
                "networkSubzone": "",
                "hostingPlatform": {"name": "Legacy-VM"},
                "services": [{"businessApplicationName": "APP-Y-UAT", "businessApplicationNumber": "BA5678"}],
            },
            {
                "hostname": "appz-api-01",
                "environment": {"code": "production", "id": "1"},
                "osVersion": {"operatingSystem": {"name": "Linux"}},
                "networkIdentifier": {"code": "internal"},
                "networkSubzone": "LOW-RISK",
                "hostingPlatform": {"name": "AWS-Prod"},
                "services": [{"businessApplicationName": "APP-Z", "businessApplicationNumber": "BA9999"}],
            },
        ]
