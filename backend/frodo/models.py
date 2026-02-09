"""Pydantic models for Frodo API."""
from enum import Enum

from pydantic import BaseModel, Field


class FirewallPlatform(str, Enum):
    """Firewall platforms that can apply to an application."""
    ILLUMIO = "illumio"
    NSX = "nsx"
    EXTERNAL_CHECKPOINT = "external_checkpoint"
    INTERNAL_CHECKPOINT = "internal_checkpoint"


class IllumioEnforcementStatus(str, Enum):
    """Illumio enforcement status for an application."""
    FULLY_ENFORCED = "fully_enforced"
    PARTIALLY_ENFORCED = "partially_enforced"
    NOT_ENFORCED = "not_enforced"


class ApplicationSummary(BaseModel):
    """Application summary for card display."""
    business_application_name: str = Field(..., description="Business application name (suffixes stripped)")
    environment: str = Field(..., description="Environment code (e.g. production, uat)")
    server_count: int = Field(..., description="Number of servers for this application")
    firewalls: list[FirewallPlatform] = Field(..., description="Firewall platforms applicable to this application")
    illumio_enforcement_status: IllumioEnforcementStatus | None = Field(
        default=None,
        description="Illumio enforcement status (only when Illumio applies)"
    )


class ApplicationDetails(BaseModel):
    """Application details for overview tab (from cache)."""
    business_application_name: str = Field(..., description="Business application name")
    environment: str = Field(..., description="Environment code")
    hosts: list[str] = Field(..., description="Hostnames for this application")
    firewalls: list[FirewallPlatform] = Field(..., description="Firewall platforms applicable")
    illumio_enforcement_status: IllumioEnforcementStatus | None = Field(
        default=None,
        description="Illumio enforcement status (only when Illumio applies)"
    )


class IllumioWorkload(BaseModel):
    """Illumio workload for Workloads sub-tab."""
    hostname: str = Field(..., description="Workload hostname")
    enforcement_mode: str = Field(..., description="Enforcement mode (full, visibility_only, etc.)")
    app_label: str = Field(default="", description="App label value")
    env_label: str = Field(default="", description="Env label value")
    loc_label: str = Field(default="", description="Loc (location) label value")


class IllumioRuleSummary(BaseModel):
    """Summary of a single rule within a ruleset."""
    href: str = Field(..., description="Rule HREF")
    description: str | None = Field(default=None, description="Rule description")


class IllumioRulesetSummary(BaseModel):
    """Ruleset with its rules for Ruleset sub-tab."""
    name: str = Field(..., description="Ruleset name")
    href: str = Field(..., description="Ruleset HREF")
    rules: list[IllumioRuleSummary] = Field(default_factory=list, description="Rules in this ruleset")


class IllumioTrafficFlow(BaseModel):
    """Simplified traffic flow for Traffic sub-tab."""
    src: str = Field(..., description="Source IP or hostname")
    dst: str = Field(..., description="Destination IP or hostname")
    port: int | None = Field(default=None, description="Destination port")
    protocol: str | None = Field(default=None, description="Protocol (tcp/udp)")
    policy_decision: str = Field(..., description="allowed, blocked, potentially_blocked, unknown")
    num_connections: int = Field(default=0, description="Number of connections")


class TrafficQueryRequest(BaseModel):
    """Query builder input for traffic flows."""
    source: str | None = Field(default=None, description="Source app+env or IP/CIDR (default: this app)")
    destination: str | None = Field(default=None, description="Destination app+env or IP/CIDR (default: any)")
    port: int | None = Field(default=None, description="Port to include")
    protocol: str | None = Field(default=None, description="tcp or udp")
    start_date: str = Field(..., description="Start date (ISO 8601)")
    end_date: str = Field(..., description="End date (ISO 8601)")
    policy_decisions: list[str] = Field(
        default_factory=lambda: ["allowed", "blocked", "potentially_blocked", "unknown"],
        description="Policy decision filter"
    )
