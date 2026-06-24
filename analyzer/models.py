from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DataCategory(str, Enum):
    CARDHOLDER_PAN = "cardholder_pan"
    SENSITIVE_AUTH = "sensitive_auth_data"  # CVV, PIN — never storable post-auth
    PII = "pii"
    GENERAL = "general"


@dataclass
class DataTransfer:
    to_service: str
    to_region: str
    fields: list[str]
    safeguard: Optional[str]  # "scc", "adequacy_decision", "internal_eu", None


@dataclass
class DataStore:
    type: str
    fields: list[str]


@dataclass
class ApiEndpoint:
    path: str
    request_fields: list[str]
    response_fields: list[str]


@dataclass
class Service:
    service_id: str
    description: str
    owner: str
    region: str
    data_stores: list[DataStore]
    api_endpoints: list[ApiEndpoint]
    retention_policy: Optional[str]
    lawful_basis: Optional[str]
    data_transfers: list[DataTransfer]


@dataclass
class Violation:
    rule_id: str
    severity: Severity
    service_id: str
    title: str
    description: str
    regulatory_citation: str
    remediation: str
    fields_affected: list[str] = field(default_factory=list)
    requires_human_review: bool = False
    conflict_note: Optional[str] = None


@dataclass
class DataFlow:
    from_service: str
    to_service: str
    to_region: str
    fields: list[str]
    safeguard: Optional[str]
    crosses_border: bool
    data_categories: list[DataCategory] = field(default_factory=list)
