"""
Stretch goal 6: Policy-as-Code extension.
Loads compliance rules from YAML so non-engineers can add/adjust rules.
"""

import yaml
from pathlib import Path
from .models import Service, Violation, Severity
from .rules import ComplianceRule
from .classifier import classify_fields, DataCategory


class YamlRule(ComplianceRule):
    def __init__(self, rule_def: dict):
        self.rule_id = rule_def["id"]
        self.framework = rule_def.get("framework", "CUSTOM")
        self._def = rule_def

    def check(self, service: Service, all_services: list[Service]) -> list[Violation]:
        violations = []
        rule = self._def
        conditions = rule.get("conditions", {})

        # Condition: service must be in certain regions
        if "regions" in conditions:
            if service.region not in conditions["regions"]:
                return []

        # Condition: service must NOT be in certain regions
        if "not_regions" in conditions:
            if service.region in conditions["not_regions"]:
                return []

        all_store_fields = {f for store in service.data_stores for f in store.fields}
        classified = classify_fields(list(all_store_fields))

        # Condition: must store fields of a certain data category
        if "stores_data_category" in conditions:
            cat_str = conditions["stores_data_category"]
            try:
                cat = DataCategory(cat_str)
            except ValueError:
                return []
            if cat not in classified or not classified[cat]:
                return []

        # Condition: must be missing a certain attribute
        if "missing_field" in conditions:
            attr = conditions["missing_field"]
            if getattr(service, attr, "PRESENT") is not None:
                return []

        # Condition: transfers to specific regions without safeguard (outbound)
        if "transfer_to_region_without_safeguard" in conditions:
            target_regions = conditions["transfer_to_region_without_safeguard"]
            matched_transfers = [
                t for t in service.data_transfers
                if t.to_region in target_regions and not t.safeguard
            ]
            if not matched_transfers:
                return []

        # Condition: "flag any service in US/non-EU processing EU PII without SCCs"
        # Checks if this service is in a target region AND receives EU PII without safeguard
        if "service_in_regions_receiving_eu_pii_without_scc" in conditions:
            target_regions = conditions["service_in_regions_receiving_eu_pii_without_scc"]
            if service.region not in target_regions:
                return []
            eu_regions = {"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "eu-south-1"}
            has_unsafeguarded_eu_pii = any(
                sender.region in eu_regions
                and t.to_service == service.service_id
                and not t.safeguard
                and any(
                    classify_fields([f]).get(DataCategory.PII)
                    for f in t.fields
                )
                for sender in all_services
                for t in sender.data_transfers
            )
            if not has_unsafeguarded_eu_pii:
                return []

        severity = Severity(rule.get("severity", "MEDIUM").upper())
        violations.append(Violation(
            rule_id=self.rule_id,
            severity=severity,
            service_id=service.service_id,
            title=rule["title"],
            description=rule["description"].format(service_id=service.service_id),
            regulatory_citation=rule.get("citation", "Custom policy"),
            remediation=rule.get("remediation", "Review and remediate."),
        ))
        return violations


def load_yaml_rules(path: str) -> list[ComplianceRule]:
    data = yaml.safe_load(Path(path).read_text())
    return [YamlRule(r) for r in data.get("rules", [])]
