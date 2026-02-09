"""Illumio API client for workload and enforcement status."""
import json
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
from frodo.unicorn.client import strip_app_name_suffix

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
_labels_cache: list[dict[str, Any]] | None = None

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

    def refresh_labels_cache(self) -> None:
        """
        Fetch labels from Illumio PCE and update cache.
        Called by background scheduler only. Uses async API if >500 labels.
        """
        if not self.pce_host or not self.api_key:
            return

        global _labels_cache
        try:
            logger.info("Illumio cache refresh: fetching labels from PCE %s", self.pce_host)
            start = time.perf_counter()
            labels = self._fetch_labels_from_api()
            _labels_cache = labels
            elapsed = time.perf_counter() - start
            logger.info("Illumio labels cache refreshed: %d labels in %.1fs", len(labels), elapsed)
        except Exception as e:
            logger.warning("Illumio labels cache refresh failed, keeping previous: %s", e)

    def _fetch_labels_from_api(self) -> list[dict[str, Any]]:
        """Fetch all labels from Illumio PCE. Uses async API when >500 labels."""
        pce = self._get_pce()
        endpoint = f"/orgs/{self.org_id}/labels"
        params: dict[str, Any] = {}
        headers = {"Prefer": "respond-async"}
        response = pce.get(endpoint, params=params, headers=headers, include_org=False)
        response.raise_for_status()

        if response.status_code == 200:
            raw_labels = response.json()
            items = raw_labels if isinstance(raw_labels, list) else (raw_labels or {}).get("items", [])
            result: list[dict[str, Any]] = []
            for lbl in items or []:
                href = _get_attr(lbl, "href", "")
                if href:
                    result.append({
                        "href": href,
                        "key": _get_attr(lbl, "key", "") or "",
                        "value": _get_attr(lbl, "value", "") or "",
                    })
            return result

        if response.status_code == 202:
            location = response.headers.get("Location", "")
            retry_after = int(response.headers.get("Retry-After", "2"))
            logger.info("Illumio labels: async job started, polling (retry_after=%ds)", retry_after)
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
                logger.info("Illumio labels: job poll #%d, status=%s", poll_count, poll_status)
                if poll_status == "failed":
                    msg = poll_result.get("result", {}).get("message", str(poll_result))
                    raise RuntimeError(f"Illumio labels async job failed: {msg}")
                if poll_status in ("done", "completed"):
                    collection_href = (
                        poll_result.get("result", {}).get("href", "")
                        or poll_result.get("result", "")
                    )
                    break
            response = pce.get(collection_href)
            response.raise_for_status()
            raw_labels = response.json()
        else:
            raise RuntimeError(f"Unexpected labels response: {response.status_code}")

        items = raw_labels if isinstance(raw_labels, list) else (raw_labels or {}).get("items", [])
        result = []
        for lbl in items or []:
            href = _get_attr(lbl, "href", "")
            if href:
                result.append({
                    "href": href,
                    "key": _get_attr(lbl, "key", "") or "",
                    "value": _get_attr(lbl, "value", "") or "",
                })
        return result

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

        result: dict[str, dict[str, Any]] = {}
        for w in raw_workloads or []:
            parsed = _parse_workload_to_dict(w)
            if parsed:
                result[parsed["hostname"].lower()] = parsed
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

    def fetch_workloads_for_app_env_from_api(
        self,
        app: str,
        env: str,
        app_env_normalizer: callable = None,
    ) -> list[dict[str, Any]]:
        """
        Fetch workloads from Illumio API filtered by app+env labels.
        Uses cached labels for href resolution. Max 500 workloads; both managed and unmanaged.
        Returns empty list if labels not found in cache.
        """
        if not self.pce_host or not self.api_key:
            return []

        app_norm = (app or "").strip()
        env_norm = (env or "").strip()
        if app_env_normalizer:
            app_norm, env_norm = app_env_normalizer(app_norm, env_norm)
        else:
            app_norm = strip_app_name_suffix(app_norm)
            env_norm = _normalize_env_for_lookup(env_norm)

        app_label = get_label_entry(ILLUMIO_APP_LABEL_KEY, app_norm)
        env_label = get_label_entry(ILLUMIO_ENV_LABEL_KEY, env_norm)
        if not app_label or not env_label:
            return []

        labels_param = json.dumps([[app_label, env_label]])
        pce = self._get_pce()
        try:
            workloads = pce.workloads.get(params={"labels": labels_param, "max_results": 500})
        except Exception as e:
            logger.warning("Failed to fetch workloads for app=%s env=%s: %s", app, env, e)
            return []

        result: list[dict[str, Any]] = []
        for w in workloads or []:
            parsed = _parse_workload_to_dict(w)
            if parsed:
                result.append(parsed)
        return result

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

        label_map = get_label_map()
        pce = self._get_pce()
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
            query.source or f"{app}/{env}", app, env, app_env_normalizer
        )
        include_destinations = _build_traffic_filters(
            query.destination or "any", app, env, app_env_normalizer
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


def get_label_href(key: str, value: str) -> str | None:
    """Look up label href from cache. Returns None if cache empty or no match."""
    entry = get_label_entry(key, value)
    return entry.get("href") if entry else None


def get_label_entry(key: str, value: str) -> dict[str, Any] | None:
    """
    Look up full label entry from cache by key and value (exact match, case-insensitive).
    Caller must pass normalized value (strip Unicorn suffixes for app; _normalize_env for env).
    Returns dict with href, key, value or None.
    """
    global _labels_cache
    if not _labels_cache:
        return None
    key_lower = (key or "").lower()
    value_upper = (value or "").strip().upper()
    value_lower = (value or "").strip().lower()
    for lbl in _labels_cache:
        lbl_key = (lbl.get("key") or "").lower()
        lbl_val = lbl.get("value") or ""
        if lbl_key != key_lower:
            continue
        if key_lower == ILLUMIO_APP_LABEL_KEY:
            if (lbl_val or "").strip().upper() == value_upper:
                return dict(lbl)
        else:
            if (lbl_val or "").strip().lower() == value_lower:
                return dict(lbl)
    return None


def get_label_map() -> dict[str, tuple[str, str]]:
    """Build href -> (key, value) map from labels cache. Used by ruleset scope matching."""
    global _labels_cache
    if not _labels_cache:
        return {}
    result: dict[str, tuple[str, str]] = {}
    for lbl in _labels_cache:
        href = lbl.get("href")
        if href:
            result[href] = (lbl.get("key") or "", lbl.get("value") or "")
    return result


def _parse_workload_to_dict(w: Any) -> dict[str, Any] | None:
    """Parse a raw workload object/dict into our standard format. Returns None if no hostname."""
    hostname = (_get_attr(w, "hostname") or "").strip()
    if not hostname:
        return None

    enforcement = _get_attr(w, "enforcement_mode") or ""
    if hasattr(enforcement, "value"):
        enforcement = enforcement.value

    labels = _get_attr(w, "labels") or []
    app_val = env_val = loc_val = ""
    for lbl in labels:
        lb_key = (_get_attr(lbl, "key") or "").lower()
        lb_val = _get_attr(lbl, "value") or ""
        if lb_key == ILLUMIO_APP_LABEL_KEY:
            app_val = lb_val or ""
        elif lb_key == ILLUMIO_ENV_LABEL_KEY:
            env_val = lb_val or ""
        elif lb_key == ILLUMIO_LOC_LABEL_KEY:
            loc_val = lb_val or ""

    return {
        "hostname": hostname,
        "enforcement_mode": str(enforcement) if enforcement else "",
        "app_label": app_val,
        "env_label": env_val,
        "loc_label": loc_val,
    }


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
    spec: str,
    default_app: str,
    default_env: str,
    app_env_normalizer: callable = None,
) -> list:
    """Build include_sources or include_destinations from spec (app/env or IP). Uses cached labels."""
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
    else:
        app = strip_app_name_suffix(app or "")
        env = _normalize_env_for_lookup(env)
    app_href = get_label_href(ILLUMIO_APP_LABEL_KEY, app)
    env_href = get_label_href(ILLUMIO_ENV_LABEL_KEY, env)
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
