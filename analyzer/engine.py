from typing import Optional
from .models import Service, Violation, DataFlow, DataCategory
from .rules import ALL_RULES, ComplianceRule
from .classifier import classify_fields, is_eu_region, is_adequate_region


def run_compliance_checks(
    services: list[Service],
    extra_rules: Optional[list] = None,
) -> list[Violation]:
    rules = ALL_RULES + (extra_rules or [])
    violations: list[Violation] = []
    for service in services:
        for rule in rules:
            try:
                found = rule.check(service, services)
                violations.extend(found)
            except Exception as exc:
                # Graceful degradation: log rule failure without crashing
                violations.append(Violation(
                    rule_id=f"{rule.rule_id}-ERROR",
                    severity=__import__("analyzer.models", fromlist=["Severity"]).Severity.INFO,
                    service_id=service.service_id,
                    title=f"Rule '{rule.rule_id}' failed to evaluate",
                    description=str(exc),
                    regulatory_citation="N/A",
                    remediation="Review rule configuration.",
                    requires_human_review=True,
                ))
    return sorted(violations, key=lambda v: _severity_order(v.severity))


def build_data_flows(services: list[Service]) -> list[DataFlow]:
    flows: list[DataFlow] = []
    for svc in services:
        for transfer in svc.data_transfers:
            crosses = (
                is_eu_region(svc.region) and not is_adequate_region(transfer.to_region)
            ) or (
                svc.region.split("-")[0] != transfer.to_region.split("-")[0]
            )
            classified = classify_fields(transfer.fields)
            categories = [cat for cat in classified if classified[cat]]
            flows.append(DataFlow(
                from_service=svc.service_id,
                to_service=transfer.to_service,
                to_region=transfer.to_region,
                fields=transfer.fields,
                safeguard=transfer.safeguard,
                crosses_border=crosses,
                data_categories=categories,
            ))
    return flows


def _severity_order(severity) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return order.get(severity.value if hasattr(severity, "value") else severity, 5)
