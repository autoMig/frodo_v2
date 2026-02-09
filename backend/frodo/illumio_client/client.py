"""Illumio API client for workload and enforcement status."""
import asyncio
import logging
import os
import time
from typing import Any

from frodo.models import (
    IllumioEnforcementStatus,
    IllumioRuleSummary,
    IllumioRulesetSummary,
    IllumioTrafficFlow,
    TrafficQueryRequest,
)

logger = logging.getLogger("frodo.illumio")


def _get_traffic_exclude_ports() -> set[int]:
    """Parse ILLUMIO_TRAFFIC_EXCLUDE_PORTS env var."""
    raw = os.environ.get("ILLUMIO_TRAFFIC_EXCLUDE_PORTS", "53,80,443,5353").strip()
    if not raw:
        return set()
    return {int(p.strip()) for p in raw.split(",") if p.strip().isdigit()}


def _verify_ssl_default() -> bool:
    """Default True unless VERIFY_SSL is false/0/no (for testing with self-signed certs)."""
    v = os.environ.get("VERIFY_SSL", "true").strip().lower()
    return v not in ("false", "0", "no")

# Module-level cache: populated by background refresh only. Never fetch on read.
_workloads_cache: dict[str, dict[str, Any]] | None = None

# Illumio label keys for app, env, loc (configurable via config in future)
ILLUMIO_APP_LABEL_KEY = "app"
ILLUMIO_ENV_LABEL_KEY = "env"
ILLUMIO_LOC_LABEL_KEY = "loc"

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
            loc_val = ""
            for lbl in labels:
                lb_key = lbl.get("key", "") if isinstance(lbl, dict) else getattr(lbl, "key", "") or ""
                lb_val = lbl.get("value", "") if isinstance(lbl, dict) else getattr(lbl, "value", "") or ""
                if (lb_key or "").lower() == ILLUMIO_APP_LABEL_KEY:
                    app_val = lb_val or ""
                elif (lb_key or "").lower() == ILLUMIO_ENV_LABEL_KEY:
                    env_val = lb_val or ""
                elif (lb_key or "").lower() == ILLUMIO_LOC_LABEL_KEY:
                    loc_val = lb_val or ""

            result[key] = {
                "hostname": hostname,
                "enforcement_mode": str(enforcement) if enforcement else "",
                "app_label": app_val,
                "env_label": env_val,
                "loc_label": loc_val,
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

    def get_workloads_for_app_env(
        self,
        app: str,
        env: str,
        app_env_normalizer: callable = None,
    ) -> list[dict[str, Any]]:
        """Get workloads for a specific app+env from cache."""
        grouped = self.get_workloads_grouped_by_app_env(app_env_normalizer=app_env_normalizer)
        key = (app.strip(), _normalize_env_for_lookup(env))
        for (a, e), workloads in grouped.items():
            if (a or "").strip().upper() == (key[0] or "").upper() and (e or "").lower() == (key[1] or "").lower():
                return workloads
        return []

    def get_rulesets_for_app_env(
        self,
        app: str,
        env: str,
        app_env_normalizer: callable = None,
    ) -> list[IllumioRulesetSummary]:
        """Fetch rulesets that apply to app+env, with their rules."""
        if not self.pce_host or not self.api_key:
            return []

        app_norm = (app or "").strip()
        env_norm = _normalize_env_for_lookup(env)
        if app_env_normalizer:
            app_norm, env_norm = app_env_normalizer(app_norm, env_norm)

        pce = self._get_pce()
        label_map: dict[str, tuple[str, str]] = {}
        try:
            labels = pce.labels.get(params={"max_results": 2000})
            for lbl in labels or []:
                href = _get_attr(lbl, "href", "")
                if href:
                    label_map[href] = (
                        _get_attr(lbl, "key", "") or "",
                        _get_attr(lbl, "value", "") or "",
                    )
        except Exception as e:
            logger.debug("Could not fetch labels for scope matching: %s", e)

        try:
            rule_sets = pce.rule_sets.get(policy_version="active", params={"max_results": 500})
        except Exception as e:
            logger.warning("Failed to fetch rulesets: %s", e)
            return []

        result: list[IllumioRulesetSummary] = []
        for rs in rule_sets or []:
            if not _ruleset_scope_matches(rs, app_norm, env_norm, label_map):
                continue
            href = _get_attr(rs, "href", "")
            name = _get_attr(rs, "name", "")
            rules: list[IllumioRuleSummary] = []
            try:
                rules_data = pce.rules.get(parent=href, policy_version="active")
                for r in rules_data or []:
                    rules.append(
                        IllumioRuleSummary(
                            href=_get_attr(r, "href", ""),
                            description=_get_attr(r, "description"),
                        )
                    )
            except Exception as e:
                logger.debug("Failed to fetch rules for ruleset %s: %s", href, e)
            result.append(
                IllumioRulesetSummary(name=name, href=href, rules=rules)
            )
        return result

    def get_traffic_flows(
        self,
        app: str,
        env: str,
        query: TrafficQueryRequest,
        app_env_normalizer: callable = None,
    ) -> list[IllumioTrafficFlow]:
        """Run traffic query and return flows. Uses asyncio.to_thread for sync PCE call."""
        if not self.pce_host or not self.api_key:
            return []

        pce = self._get_pce()
        exclude_ports = _get_traffic_exclude_ports()

        include_services = []
        ports_to_exclude = exclude_ports - {query.port} if query.port is not None else exclude_ports
        exclude_services = [{"port": p, "proto": "tcp"} for p in ports_to_exclude]
        exclude_services += [{"port": p, "proto": "udp"} for p in ports_to_exclude]
        if query.port is not None:
            proto = 6 if (query.protocol or "").lower() == "tcp" else 17
            include_services.append({"port": query.port, "proto": proto})

        policy_decisions = [
            pd for pd in (query.policy_decisions or [])
            if pd in ("allowed", "blocked", "potentially_blocked", "unknown")
        ]
        if not policy_decisions:
            policy_decisions = ["allowed", "blocked", "potentially_blocked", "unknown"]

        include_sources = _build_traffic_filters(
            pce, query.source or f"{app}/{env}", app, env, app_env_normalizer
        )
        include_destinations = _build_traffic_filters(
            pce, query.destination or "any", app, env, app_env_normalizer
        ) if query.destination else [[]]

        try:
            from illumio.explorer import TrafficQuery

            traffic_query = TrafficQuery.build(
                start_date=query.start_date,
                end_date=query.end_date,
                include_sources=include_sources,
                exclude_sources=[],
                include_destinations=include_destinations,
                exclude_destinations=[],
                include_services=include_services if include_services else [],
                exclude_services=exclude_services,
                policy_decisions=policy_decisions,
            )
            flows = pce.get_traffic_flows_async(
                query_name=f"frodo-{app}-{env}",
                traffic_query=traffic_query,
            )
        except Exception as e:
            logger.warning("Traffic query failed: %s", e)
            return []

        return [_traffic_flow_to_model(f) for f in (flows or [])]


def _normalize_env_for_lookup(env: str) -> str:
    raw = (env or "").strip().lower() or "unknown"
    if raw == "contingency":
        return "production"
    return raw


def _get_attr(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _ruleset_scope_matches(rule_set: Any, app: str, env: str, label_map: dict[str, tuple[str, str]]) -> bool:
    """Check if ruleset scope includes app+env labels. label_map: href -> (key, value)."""
    scopes = _get_attr(rule_set, "scopes") or []
    if not scopes:
        return True
    app_upper = (app or "").upper()
    env_lower = (env or "").lower()
    for scope in scopes:
        label_refs = _get_attr(scope, "label") or _get_attr(scope, "labels") or []
        if isinstance(label_refs, dict):
            label_refs = [label_refs]
        if not label_refs:
            return True
        app_match = env_match = False
        for lbl in label_refs:
            href = _get_attr(lbl, "href", "") if isinstance(lbl, dict) else _get_attr(lbl, "href", "")
            key, value = label_map.get(href, ("", ""))
            if not key and href:
                key = _get_attr(lbl, "key", "") if isinstance(lbl, dict) else _get_attr(lbl, "key", "")
                value = _get_attr(lbl, "value", "") if isinstance(lbl, dict) else _get_attr(lbl, "value", "")
            if (key or "").lower() == ILLUMIO_APP_LABEL_KEY:
                app_match = (value or "").upper() == app_upper
            elif (key or "").lower() == ILLUMIO_ENV_LABEL_KEY:
                env_match = (value or "").lower() == env_lower
        if app_match and env_match:
            return True
    return False


def _build_traffic_filters(
    pce,
    spec: str,
    default_app: str,
    default_env: str,
    app_env_normalizer: callable = None,
) -> list:
    """Build include_sources or include_destinations from spec (app/env or IP)."""
    spec = (spec or "").strip().lower()
    if spec in ("any", ""):
        return [[]]
    if _looks_like_ip(spec):
        from illumio.explorer import TrafficQueryFilter
        return [[TrafficQueryFilter(ip_address=spec)]]
    app, env = default_app, default_env
    if "/" in spec:
        parts = spec.split("/", 1)
        app, env = (parts[0] or "").strip(), (parts[1] or "").strip()
    if app_env_normalizer:
        app, env = app_env_normalizer(app, env)
    env = _normalize_env_for_lookup(env)
    try:
        labels = pce.labels.get(params={"max_results": 1000})
        app_href = env_href = None
        for lbl in labels or []:
            k = _get_attr(lbl, "key", "").lower()
            v = _get_attr(lbl, "value", "")
            href = _get_attr(lbl, "href", "")
            if k == ILLUMIO_APP_LABEL_KEY and (v or "").upper() == (app or "").upper():
                app_href = href
            elif k == ILLUMIO_ENV_LABEL_KEY and (v or "").lower() == (env or "").lower():
                env_href = href
        refs = []
        if app_href:
            from illumio.util.jsonutils import Reference
            refs.append(Reference(href=app_href))
        if env_href:
            from illumio.util.jsonutils import Reference
            refs.append(Reference(href=env_href))
        if refs:
            from illumio.explorer import TrafficQueryFilter
            return [[TrafficQueryFilter(label=r) for r in refs]]
    except Exception as e:
        logger.debug("Could not resolve labels for traffic filter: %s", e)
    return [[]]


def _looks_like_ip(spec: str) -> bool:
    import re
    return bool(re.match(r"^[\d.]+(\/\d+)?$", (spec or "").strip()))


def _traffic_flow_to_model(flow: Any) -> IllumioTrafficFlow:
    src = dst = "?"
    port = None
    proto = None
    policy_decision = getattr(flow, "policy_decision", None) or "unknown"
    num_connections = getattr(flow, "num_connections", 0) or 0
    if hasattr(flow, "src") and flow.src:
        s = flow.src
        src = getattr(s, "ip", None) or getattr(s, "hostname", None) or str(s)
    if hasattr(flow, "dst") and flow.dst:
        d = flow.dst
        dst = getattr(d, "ip", None) or getattr(d, "hostname", None) or str(d)
    if hasattr(flow, "service") and flow.service:
        port = getattr(flow.service, "port", None)
        proto_num = getattr(flow.service, "proto", None)
        proto = "tcp" if proto_num == 6 else ("udp" if proto_num == 17 else str(proto_num))
    return IllumioTrafficFlow(
        src=str(src),
        dst=str(dst),
        port=port,
        protocol=proto,
        policy_decision=str(policy_decision) if policy_decision else "unknown",
        num_connections=int(num_connections) if num_connections else 0,
    )
