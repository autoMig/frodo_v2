"""Illumio API client for workload and enforcement status."""
import logging
from typing import Any

from frodo.models import IllumioEnforcementStatus

logger = logging.getLogger("frodo.illumio")

# Illumio label keys for app and env (configurable via config in future)
ILLUMIO_APP_LABEL_KEY = "app"
ILLUMIO_ENV_LABEL_KEY = "env"

# Illumio enforcement mode values
ILLUMIO_ENFORCED = "full"
ILLUMIO_VISIBILITY = "visibility_only"


def get_enforcement_status(
    app_env_to_hostnames: dict[tuple[str, str], set[str]],
    workloads_by_app_env: dict[tuple[str, str], list[dict[str, Any]]],
) -> dict[tuple[str, str], IllumioEnforcementStatus]:
    """
    Compute Illumio enforcement status per (app, env) based on workload data.
    Matches workloads to hostnames from Unicorn for each app+env; aggregates enforcement.
    """
    result: dict[tuple[str, str], IllumioEnforcementStatus] = {}

    for (app, env), workloads in workloads_by_app_env.items():
        hostnames = app_env_to_hostnames.get((app, env), set())
        matching = [w for w in workloads if (w.get("hostname") or "").lower() in hostnames]
        if not matching:
            result[(app, env)] = IllumioEnforcementStatus.NOT_ENFORCED
            continue

        enforced_count = sum(
            1 for w in matching
            if (w.get("enforcement_mode") or "").lower() == ILLUMIO_ENFORCED
        )
        total = len(matching)

        if enforced_count == total:
            result[(app, env)] = IllumioEnforcementStatus.FULLY_ENFORCED
        elif enforced_count == 0:
            result[(app, env)] = IllumioEnforcementStatus.NOT_ENFORCED
        else:
            result[(app, env)] = IllumioEnforcementStatus.PARTIALLY_ENFORCED

    return result


class IllumioClient:
    """Client for Illumio PCE API using the illumio Python library."""

    def __init__(
        self,
        pce_host: str,
        org_id: str,
        api_key: str,
        api_secret: str,
        port: int | str = 443,
    ):
        self.pce_host = pce_host
        self.org_id = str(org_id)
        self.api_key = api_key
        self.api_secret = api_secret
        self.port = str(port)

    def _get_pce(self):
        """Lazy import to avoid failure when illumio not configured."""
        from illumio import PolicyComputeEngine
        pce = PolicyComputeEngine(self.pce_host, port=self.port, org_id=self.org_id)
        pce.set_credentials(self.api_key, self.api_secret)
        return pce

    def get_workloads_by_hostname(self) -> dict[str, dict[str, Any]]:
        """
        Fetch workloads from Illumio and index by hostname.
        Returns dict mapping hostname (lowercase) -> workload data including
        enforcement_mode and labels for app/env.
        """
        if not self.pce_host or not self.api_key:
            logger.debug("Illumio not configured, skipping workloads fetch")
            return {}

        try:
            pce = self._get_pce()
            workloads = pce.workloads.get(params={"managed": True})
        except Exception as e:
            logger.warning("Illumio workloads fetch failed: %s", e)
            return {}

        result: dict[str, dict[str, Any]] = {}
        for w in workloads or []:
            hostname = getattr(w, "hostname", None) or ""
            if not hostname:
                continue
            key = hostname.lower()

            # Extract enforcement_mode from workload
            enforcement = getattr(w, "enforcement_mode", None) or ""
            if hasattr(enforcement, "value"):
                enforcement = enforcement.value

            # Extract app and env from labels
            labels = getattr(w, "labels", []) or []
            app_val = ""
            env_val = ""
            for lbl in labels:
                lb_key = getattr(lbl, "key", "") or ""
                lb_val = getattr(lbl, "value", "") or ""
                if lb_key.lower() == ILLUMIO_APP_LABEL_KEY:
                    app_val = lb_val
                elif lb_key.lower() == ILLUMIO_ENV_LABEL_KEY:
                    env_val = lb_val

            result[key] = {
                "hostname": hostname,
                "enforcement_mode": enforcement,
                "app_label": app_val,
                "env_label": env_val,
            }

        return result

    def get_workloads_grouped_by_app_env(
        self,
        app_env_normalizer: callable = None,
    ) -> dict[tuple[str, str], list[dict[str, Any]]]:
        """
        Fetch workloads and group by (app, env) using label values.
        app_env_normalizer: optional callable (app_label, env_label) -> (app, env)
        to normalize label values to match Unicorn app/env (e.g. strip suffixes).
        """
        if not self.pce_host or not self.api_key:
            return {}

        by_host = self.get_workloads_by_hostname()
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}

        for w in by_host.values():
            app = (w.get("app_label") or "").strip()
            env = (w.get("env_label") or "").strip()
            if app_env_normalizer:
                app, env = app_env_normalizer(app, env)
            key = (app, env)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(w)

        return grouped
