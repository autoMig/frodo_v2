"""Application aggregation service - combines Unicorn and Illumio data."""
import logging
from collections import defaultdict

from frodo.illumio_client.client import (
    get_enforcement_status,
    IllumioClient,
)
from frodo.models import (
    ApplicationDetails,
    ApplicationSummary,
    FirewallPlatform,
    IllumioEnforcementStatus,
)
from frodo.unicorn.client import (
    get_firewall_applicability,
    strip_app_name_suffix,
    UnicornClient,
)

logger = logging.getLogger("frodo.services")


def _normalize_env(code: str) -> str:
    """Normalize environment code for grouping. Maps Contingency -> production."""
    raw = (code or "").strip().lower() or "unknown"
    if raw == "contingency":
        return "production"
    return raw


def _get_env_name(server: dict) -> str:
    """Extract environment from server.environment.name."""
    env = server.get("environment") or {}
    return _normalize_env((env.get("name") or "").strip())


def _get_app_names_from_services(server: dict) -> list[str]:
    """Extract business application names from server.services[].service.name."""
    services = server.get("services") or []
    names = []
    for svc in services:
        if not isinstance(svc, dict):
            continue
        service_obj = svc.get("service")
        if isinstance(service_obj, dict):
            name = (service_obj.get("name") or "").strip()
            if name:
                names.append(name)
    return names


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
        *,
        search: str | None = None,
        environment: str | None = None,
        firewall: str | None = None,
        illumio_status: str | None = None,
        page: int = 1,
        limit: int = 50,
    ) -> tuple[list[ApplicationSummary], int]:
        """
        Get application summaries for applications the user can manage.
        ad_groups: list of AD group names the user belongs to.
        Uses naming convention to map groups to (app, env).
        Optional filters: search (partial match on app name), environment, firewall, illumio_status.
        Pagination: page (1-based), limit (default 50, max 200).
        Returns (applications_for_page, total_count).
        """
        servers = await self.unicorn.get_servers()

        if not servers:
            logger.warning(
                "No servers in cache - ensure cache refresh has completed (runs ~5s after startup)"
            )
            return []

        app_env_to_servers: dict[tuple[str, str], list[dict]] = defaultdict(list)

        for server in servers:
            env_code = _get_env_name(server)
            for app_name_raw in set(_get_app_names_from_services(server)):
                app_name = strip_app_name_suffix(app_name_raw)
                key = (app_name, env_code)
                app_env_to_servers[key].append(server)

        if not app_env_to_servers:
            logger.warning(
                "Servers received but no app+env extracted - Unicorn data structure may differ. "
                "Expected: server.environment.name, server.services[].service.name. "
                "Sample server keys: %s. First service: %s",
                list(servers[0].keys()) if servers else [],
                servers[0].get("services", [])[:1] if servers else [],
            )
            return []

        # Filter by AD group membership
        allowed_app_envs = _expand_allowed_app_envs(ad_groups)
        if allowed_app_envs:
            app_env_to_servers = {
                k: v for k, v in app_env_to_servers.items()
                if k in allowed_app_envs
            }
            if not app_env_to_servers:
                logger.info(
                    "AD group filter excluded all apps (groups=%s, allowed=%s)",
                    ad_groups,
                    allowed_app_envs,
                )

        # Get Illumio enforcement status for apps that have Illumio
        illumio_status_by_app_env: dict[tuple[str, str], IllumioEnforcementStatus] = {}
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
            illumio_status_by_app_env = get_enforcement_status(app_env_to_hostnames, workloads_by_app_env)

        summaries: list[ApplicationSummary] = []
        for (app_name, env_code), server_list in app_env_to_servers.items():
            all_firewalls: set[FirewallPlatform] = set()
            for s in server_list:
                all_firewalls.update(get_firewall_applicability(s))

            illumio_status_val = None
            if FirewallPlatform.ILLUMIO in all_firewalls:
                illumio_status_val = illumio_status_by_app_env.get(
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

        sorted_summaries = sorted(summaries, key=lambda a: (a.business_application_name, a.environment))

        # Apply filters
        filtered = sorted_summaries
        if search and search.strip():
            search_lower = search.strip().lower()
            filtered = [a for a in filtered if search_lower in a.business_application_name.lower()]
        if environment and environment.strip():
            env_lower = environment.strip().lower()
            filtered = [a for a in filtered if a.environment.lower() == env_lower]
        if firewall and firewall.strip():
            try:
                fw_platform = FirewallPlatform(firewall.strip().lower())
                filtered = [a for a in filtered if fw_platform in a.firewalls]
            except ValueError:
                pass  # Invalid firewall platform, ignore filter
        if illumio_status and illumio_status.strip():
            try:
                status = IllumioEnforcementStatus(illumio_status.strip().lower())
                filtered = [a for a in filtered if a.illumio_enforcement_status == status]
            except ValueError:
                pass  # Invalid status, ignore filter

        total_count = len(filtered)

        # Pagination
        limit = min(max(1, limit), 200)
        page = max(1, page)
        start = (page - 1) * limit
        end = start + limit
        paginated = filtered[start:end]

        return (paginated, total_count)

    async def get_application_details(
        self,
        app_name: str,
        env: str,
        ad_groups: list[str],
    ) -> ApplicationDetails | None:
        """
        Get application details from cache (hosts, firewalls).
        Returns None if app not found or not authorized.
        """
        servers = await self.unicorn.get_servers()
        if not servers:
            return None

        app_env_to_servers: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for server in servers:
            env_code = _get_env_name(server)
            for app_name_raw in set(_get_app_names_from_services(server)):
                app_norm = strip_app_name_suffix(app_name_raw)
                key = (app_norm, env_code)
                app_env_to_servers[key].append(server)

        app_norm = strip_app_name_suffix((app_name or "").strip())
        env_norm = _normalize_env((env or "").strip())
        key = (app_norm.upper(), env_norm)

        # Match key - keys use normalized env but app may be mixed case in Unicorn
        matching_key = None
        for (a, e), _ in app_env_to_servers.items():
            if a.upper() == app_norm.upper() and e == env_norm:
                matching_key = (a, e)
                break
        if not matching_key:
            return None

        # AD group filter (case-insensitive app match)
        allowed_app_envs = _expand_allowed_app_envs(ad_groups)
        if allowed_app_envs:
            key_for_auth = (matching_key[0].upper(), matching_key[1])
            if key_for_auth not in allowed_app_envs:
                return None

        server_list = app_env_to_servers[matching_key]
        all_firewalls: set[FirewallPlatform] = set()
        for s in server_list:
            all_firewalls.update(get_firewall_applicability(s))

        hosts = sorted(
            (s.get("hostname") or "").strip()
            for s in server_list
            if (s.get("hostname") or "").strip()
        )

        # Illumio status if applicable
        illumio_status_val = None
        if FirewallPlatform.ILLUMIO in all_firewalls and self.illumio:
            workloads_by_app_env = self.illumio.get_workloads_grouped_by_app_env(
                app_env_normalizer=_illumio_app_env_normalizer,
            )
            hostnames = set(h.lower() for h in hosts)
            app_env_to_hostnames = {matching_key: hostnames}
            illumio_status_by_app_env = get_enforcement_status(
                app_env_to_hostnames, workloads_by_app_env
            )
            illumio_status_val = illumio_status_by_app_env.get(
                matching_key, IllumioEnforcementStatus.NOT_ENFORCED
            )

        return ApplicationDetails(
            business_application_name=matching_key[0],
            environment=matching_key[1],
            hosts=hosts,
            firewalls=sorted(all_firewalls, key=lambda f: f.value),
            illumio_enforcement_status=illumio_status_val,
        )


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
