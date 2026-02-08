"""Illumio API client for workload and enforcement status."""
import logging
import os
import time
from typing import Any

from frodo.models import IllumioEnforcementStatus

logger = logging.getLogger("frodo.illumio")


def _verify_ssl_default() -> bool:
    """Default True unless VERIFY_SSL is false/0/no (for testing with self-signed certs)."""
    v = os.environ.get("VERIFY_SSL", "true").strip().lower()
    return v not in ("false", "0", "no")

# Module-level cache: populated by background refresh only. Never fetch on read.
_workloads_cache: dict[str, dict[str, Any]] | None = None

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
        verify_ssl: bool | None = None,
    ):
        self.pce_host = pce_host
        self.org_id = str(org_id)
        self.api_key = api_key
        self.api_secret = api_secret
        self.port = str(port)
        self.verify_ssl = verify_ssl if verify_ssl is not None else _verify_ssl_default()
        if not self.verify_ssl:
            logger.warning("Illumio: SSL verification disabled (VERIFY_SSL=false) - for testing only")

    def _get_pce(self):
        """Lazy import to avoid failure when illumio not configured."""
        from illumio import PolicyComputeEngine
        pce = PolicyComputeEngine(self.pce_host, port=self.port, org_id=self.org_id)
        pce.set_credentials(self.api_key, self.api_secret)
        pce.set_tls_settings(verify=self.verify_ssl)
        return pce

    def get_workloads_by_hostname(self) -> dict[str, dict[str, Any]]:
        """
        Return workloads from cache. Never fetches from API.
        Cache miss returns empty dict; data is populated by background refresh only.
        """
        if not self.pce_host or not self.api_key:
            logger.debug("Illumio not configured, skipping workloads fetch")
            return {}

        global _workloads_cache
        if _workloads_cache is not None:
            return _workloads_cache
        return {}

    def refresh_workloads_cache(self) -> None:
        """
        Fetch workloads from Illumio PCE and update cache.
        Called by background scheduler only. Skips when not configured.
        On success, updates cache. On failure, keeps previous cache (or leaves empty).
        """
        if not self.pce_host or not self.api_key:
            return

        global _workloads_cache
        try:
            logger.info(
                "Illumio cache refresh: fetching workloads from PCE %s (may take several minutes for large environments)",
                self.pce_host,
            )
            start = time.perf_counter()
            workloads = self._fetch_workloads_from_api()
            _workloads_cache = workloads
            elapsed = time.perf_counter() - start
            logger.info("Illumio cache refreshed: %d workloads in %.1fs", len(workloads), elapsed)
        except Exception as e:
            logger.warning("Illumio cache refresh failed, keeping previous: %s", e)

    def _fetch_workloads_from_api(self) -> dict[str, dict[str, Any]]:
        """Fetch workloads from Illumio PCE (used by refresh only). Uses async API with job status logging."""
        pce = self._get_pce()
        endpoint = f"/orgs/{self.org_id}/workloads"
        params = {"managed": True}

        # Use async API to support large collections; log job progress
        headers = {"Prefer": "respond-async"}
        response = pce.get(endpoint, params=params, headers=headers, include_org=False)
        response.raise_for_status()

        if response.status_code == 202:
            # Async job - poll and log status
            location = response.headers.get("Location", "")
            retry_after = int(response.headers.get("Retry-After", "2"))
            logger.info("Illumio: async export job started, polling for completion (retry_after=%ds)", retry_after)

            poll_interval = float(retry_after)
            poll_count = 0
            while True:
                time.sleep(poll_interval)
                poll_interval = min(poll_interval * 1.5, 30)
                poll_count += 1

                poll_resp = pce.get(location)
                poll_resp.raise_for_status()
                poll_result = poll_resp.json()
                poll_status = poll_result.get("status", "unknown")

                logger.info("Illumio: job poll #%d, status=%s", poll_count, poll_status)

                if poll_status == "failed":
                    msg = poll_result.get("result", {}).get("message", str(poll_result))
                    raise RuntimeError(f"Illumio async job failed: {msg}")
                if poll_status == "done":
                    collection_href = poll_result.get("result", {}).get("href", "")
                    break
                if poll_status == "completed":
                    # Traffic flow jobs use 'completed' and result is the href directly
                    collection_href = poll_result.get("result", "")
                    break

            response = pce.get(collection_href)
            response.raise_for_status()
            raw_workloads = response.json()
        else:
            raw_workloads = response.json()

        def _get(obj: Any, key: str, default: Any = None) -> Any:
            return obj.get(key, default) if isinstance(obj, dict) else getattr(obj, key, default)

        result: dict[str, dict[str, Any]] = {}
        for w in raw_workloads or []:
            hostname = (_get(w, "hostname") or "").strip()
            if not hostname:
                continue
            key = hostname.lower()

            enforcement = _get(w, "enforcement_mode") or ""
            if hasattr(enforcement, "value"):
                enforcement = enforcement.value

            labels = _get(w, "labels") or []
            app_val = ""
            env_val = ""
            for lbl in labels:
                lb_key = lbl.get("key", "") if isinstance(lbl, dict) else getattr(lbl, "key", "") or ""
                lb_val = lbl.get("value", "") if isinstance(lbl, dict) else getattr(lbl, "value", "") or ""
                if (lb_key or "").lower() == ILLUMIO_APP_LABEL_KEY:
                    app_val = lb_val or ""
                elif (lb_key or "").lower() == ILLUMIO_ENV_LABEL_KEY:
                    env_val = lb_val or ""

            result[key] = {
                "hostname": hostname,
                "enforcement_mode": str(enforcement) if enforcement else "",
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
