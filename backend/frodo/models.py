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
