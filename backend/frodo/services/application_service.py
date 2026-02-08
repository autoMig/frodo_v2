"""Application aggregation service - combines Unicorn and Illumio data."""
import logging
from collections import defaultdict

from frodo.illumio_client.client import (
    get_enforcement_status,
    IllumioClient,
)
from frodo.models import ApplicationSummary, FirewallPlatform, IllumioEnforcementStatus
from frodo.unicorn.client import (
    get_firewall_applicability,
    strip_app_name_suffix,
    UnicornClient,
)

logger = logging.getLogger("frodo.services")


def _normalize_env(code: str) -> str:
    """Normalize environment code for grouping."""
    return (code or "").strip().lower() or "unknown"


def _illumio_app_env_normalizer(app: str, env: str) -> tuple[str, str]:
    """Normalize Illumio label values to match Unicorn app/env."""
    return strip_app_name_suffix(app), _normalize_env(env)


class ApplicationService:
    """Aggregates Unicorn and Illumio data to produce application summaries."""

    def __init__(self, unicorn_client: UnicornClient, illumio_client: IllumioClient | None):
        self.unicorn = unicorn_client
        self.illumio = illumio_client

    async def get_applications_for_user(
        self,
        ad_groups: list[str],
    ) -> list[ApplicationSummary]:
        """
        Get application summaries for applications the user can manage.
        ad_groups: list of AD group names the user belongs to.
        Uses naming convention to map groups to (app, env).
        """
        servers = await self.unicorn.get_servers()
        app_env_to_servers: dict[tuple[str, str], list[dict]] = defaultdict(list)

        for server in servers:
            env_obj = server.get("environment") or {}
            env_code = _normalize_env(env_obj.get("code") or "")
            services = server.get("services") or []

            for svc in services:
                if not isinstance(svc, dict):
                    continue
                app_name_raw = (svc.get("businessApplicationName") or "").strip()
                if not app_name_raw:
                    continue
                app_name = strip_app_name_suffix(app_name_raw)
                key = (app_name, env_code)
                app_env_to_servers[key].append(server)

        # Filter by AD group membership
        allowed_app_envs = _expand_allowed_app_envs(ad_groups)
        if allowed_app_envs:
            app_env_to_servers = {
                k: v for k, v in app_env_to_servers.items()
                if k in allowed_app_envs
            }

        # Get Illumio enforcement status for apps that have Illumio
        illumio_status: dict[tuple[str, str], IllumioEnforcementStatus] = {}
        if self.illumio:
            workloads_by_app_env = self.illumio.get_workloads_grouped_by_app_env(
                app_env_normalizer=_illumio_app_env_normalizer,
            )
            app_env_to_hostnames: dict[tuple[str, str], set[str]] = {}
            for (app, env), servers_list in app_env_to_servers.items():
                hostnames = set()
                for s in servers_list:
                    hn = (s.get("hostname") or "").strip()
                    if hn:
                        hostnames.add(hn.lower())
                app_env_to_hostnames[(app, env)] = hostnames
            illumio_status = get_enforcement_status(app_env_to_hostnames, workloads_by_app_env)

        summaries: list[ApplicationSummary] = []
        for (app_name, env_code), server_list in app_env_to_servers.items():
            all_firewalls: set[FirewallPlatform] = set()
            for s in server_list:
                all_firewalls.update(get_firewall_applicability(s))

            illumio_status_val = None
            if FirewallPlatform.ILLUMIO in all_firewalls:
                illumio_status_val = illumio_status.get(
                    (app_name, env_code),
                    IllumioEnforcementStatus.NOT_ENFORCED,
                )

            summaries.append(
                ApplicationSummary(
                    business_application_name=app_name,
                    environment=env_code,
                    server_count=len(server_list),
                    firewalls=sorted(all_firewalls, key=lambda f: f.value),
                    illumio_enforcement_status=illumio_status_val,
                )
            )

        return sorted(summaries, key=lambda a: (a.business_application_name, a.environment))


def _expand_allowed_app_envs(ad_groups: list[str]) -> set[tuple[str, str]] | None:
    """
    Map AD group names to (app, env) using naming convention.
    Convention: {AppName}-{Env}-Owners or similar.
    Returns None to allow all (when no groups = dev mode).
    """
    if not ad_groups:
        return None  # No filter - allow all in dev

    allowed = set()
    for group in ad_groups:
        # Try patterns like APP-X-Prod-Owners, APP-X-Production-Owners
        parts = group.replace("_", "-").split("-")
        if len(parts) < 2:
            continue
        # Last part often "Owners" or similar
        if parts[-1].upper() in ("OWNERS", "OWNER", "ADMINS", "ADMIN"):
            parts = parts[:-1]
        if len(parts) < 2:
            continue
        env_part = parts[-1].upper()
        app_part = "-".join(parts[:-1]).upper()
        env_map = {
            "PROD": "production",
            "PRODUCTION": "production",
            "UAT": "uat",
            "DEV": "dev",
            "DEVELOPMENT": "dev",
            "CONT": "cont",
            "OAT": "oat",
        }
        env = env_map.get(env_part, env_part.lower())
        allowed.add((app_part, env))

    return allowed if allowed else None
