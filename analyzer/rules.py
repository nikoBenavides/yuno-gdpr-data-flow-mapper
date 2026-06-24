"""
Compliance rules engine.

Each rule is a callable class implementing ComplianceRule.check().
Rules return zero or more Violation objects.

To add a new rule: subclass ComplianceRule, implement check(), and add to ALL_RULES.
"""

from abc import ABC, abstractmethod
from .models import Service, Violation, Severity, DataCategory
from .classifier import (
    classify_fields, is_eu_region, is_adequate_region,
    SENSITIVE_AUTH_PATTERNS, PAN_PATTERNS, is_pan_last4,
)


class ComplianceRule(ABC):
    rule_id: str
    framework: str  # "PCI-DSS", "GDPR", "BOTH"

    @abstractmethod
    def check(self, service: Service, all_services: list[Service]) -> list[Violation]:
        ...


class CVVStorageRule(ComplianceRule):
    """PCI DSS Requirement 3.2: Sensitive Authentication Data must never be stored post-auth."""
    rule_id = "PCI-3.2-SAD-STORAGE"
    framework = "PCI-DSS"

    def check(self, service: Service, all_services: list[Service]) -> list[Violation]:
        violations = []
        for store in service.data_stores:
            sad_fields = [f for f in store.fields if f.lower() in SENSITIVE_AUTH_PATTERNS]
            if sad_fields:
                violations.append(Violation(
                    rule_id=self.rule_id,
                    severity=Severity.CRITICAL,
                    service_id=service.service_id,
                    title="Sensitive Authentication Data (CVV/PIN) stored post-authorization",
                    description=(
                        f"Service '{service.service_id}' stores sensitive authentication data "
                        f"in {store.type}: {sad_fields}. PCI DSS explicitly forbids storing "
                        f"CVV/CVC, PINs, or magnetic stripe data after transaction authorization, "
                        f"even in encrypted form."
                    ),
                    regulatory_citation="PCI DSS v4.0 Requirement 3.2.1",
                    remediation=(
                        "Immediately delete CVV/PIN fields from all data stores. "
                        "Authentication data may be held in memory only during the authorization "
                        "transaction and must not be persisted. Implement a data purge job and "
                        "verify with a QSA before next PCI audit."
                    ),
                    fields_affected=sad_fields,
                ))
        return violations


class MissingRetentionPolicyRule(ComplianceRule):
    """GDPR Article 5(1)(e): Personal data must not be kept longer than necessary."""
    rule_id = "GDPR-5.1e-RETENTION"
    framework = "GDPR"

    def check(self, service: Service, all_services: list[Service]) -> list[Violation]:
        all_fields = [f for store in service.data_stores for f in store.fields]
        classified = classify_fields(all_fields)
        has_personal_data = any(
            cat in classified for cat in [DataCategory.PII, DataCategory.CARDHOLDER_PAN, DataCategory.SENSITIVE_AUTH]
        )
        if has_personal_data and not service.retention_policy:
            personal_fields = (
                classified.get(DataCategory.PII, []) +
                classified.get(DataCategory.CARDHOLDER_PAN, []) +
                classified.get(DataCategory.SENSITIVE_AUTH, [])
            )
            return [Violation(
                rule_id=self.rule_id,
                severity=Severity.HIGH,
                service_id=service.service_id,
                title="No retention policy defined for personal data",
                description=(
                    f"Service '{service.service_id}' stores personal data {personal_fields} "
                    f"but has no documented retention policy. Under GDPR Article 5(1)(e), "
                    f"personal data must be deleted when no longer necessary for its purpose."
                ),
                regulatory_citation="GDPR Article 5(1)(e), Article 30(1)(f)",
                remediation=(
                    "Define and document a retention period justified by the lawful basis "
                    "(e.g., contract duration + statutory limitation period, or regulatory "
                    "minimum). Implement automated deletion or anonymization at end of period. "
                    "Add retention_policy to your Article 30 register."
                ),
                fields_affected=personal_fields,
            )]
        return []


class MissingLawfulBasisRule(ComplianceRule):
    """GDPR Article 6: Processing requires a documented lawful basis."""
    rule_id = "GDPR-6-LAWFUL-BASIS"
    framework = "GDPR"

    VALID_BASES = {"contract", "legal_obligation", "legitimate_interest", "consent", "vital_interest", "public_task"}

    def check(self, service: Service, all_services: list[Service]) -> list[Violation]:
        all_fields = [f for store in service.data_stores for f in store.fields]
        classified = classify_fields(all_fields)
        has_personal_data = any(
            cat in classified for cat in [DataCategory.PII, DataCategory.CARDHOLDER_PAN, DataCategory.SENSITIVE_AUTH]
        )
        if not has_personal_data:
            return []
        if not service.lawful_basis or service.lawful_basis.lower() not in self.VALID_BASES:
            return [Violation(
                rule_id=self.rule_id,
                severity=Severity.HIGH,
                service_id=service.service_id,
                title="No valid lawful basis documented for personal data processing",
                description=(
                    f"Service '{service.service_id}' processes personal data but has no "
                    f"documented lawful basis (or basis '{service.lawful_basis}' is unrecognized). "
                    f"GDPR Article 6 requires every processing activity to have a valid lawful basis."
                ),
                regulatory_citation="GDPR Article 6(1)",
                remediation=(
                    "Identify the appropriate lawful basis: 'contract' (processing needed to "
                    "fulfill a contract), 'legal_obligation' (regulatory requirement), "
                    "'legitimate_interest' (with LIA documented), or 'consent' (freely given, "
                    "specific, informed). Document in your Article 30 register."
                ),
            )]
        return []


class CrossBorderTransferRule(ComplianceRule):
    """GDPR Chapter V: Cross-border transfers require safeguards."""
    rule_id = "GDPR-46-CROSS-BORDER"
    framework = "GDPR"

    def check(self, service: Service, all_services: list[Service]) -> list[Violation]:
        if not is_eu_region(service.region):
            return []
        violations = []
        for transfer in service.data_transfers:
            if is_adequate_region(transfer.to_region):
                continue
            personal_fields = [
                f for f in transfer.fields
                if classify_fields([f]).get(DataCategory.PII) or
                   classify_fields([f]).get(DataCategory.CARDHOLDER_PAN) or
                   classify_fields([f]).get(DataCategory.SENSITIVE_AUTH)
            ]
            if not personal_fields:
                continue
            safeguard = transfer.safeguard
            if safeguard in ("scc", "adequacy_decision", "binding_corporate_rules"):
                continue
            violations.append(Violation(
                rule_id=self.rule_id,
                severity=Severity.HIGH,
                service_id=service.service_id,
                title=f"Unlawful cross-border transfer: EU → {transfer.to_region} ({transfer.to_service})",
                description=(
                    f"Service '{service.service_id}' (EU: {service.region}) transfers personal data "
                    f"{personal_fields} to '{transfer.to_service}' in {transfer.to_region}, "
                    f"which is not an adequate country under GDPR. No valid transfer safeguard "
                    f"(SCC, BCR, adequacy decision) is documented."
                ),
                regulatory_citation="GDPR Article 46, Chapter V; Schrems II (C-311/18)",
                remediation=(
                    f"Implement Standard Contractual Clauses (EU SCCs, June 2021 version) with "
                    f"'{transfer.to_service}'. Conduct a Transfer Impact Assessment (TIA) for "
                    f"transfers to the US given Schrems II. Alternatively, consider migrating "
                    f"the receiving service to an EU region."
                ),
                fields_affected=personal_fields,
            ))
        return violations


class DataMinimizationRule(ComplianceRule):
    """GDPR Article 5(1)(c): Store only what is necessary for the stated purpose."""
    rule_id = "GDPR-5.1c-MINIMIZATION"
    framework = "GDPR"

    def check(self, service: Service, all_services: list[Service]) -> list[Violation]:
        violations = []
        all_store_fields = {f for store in service.data_stores for f in store.fields}
        all_api_fields = {
            f
            for ep in service.api_endpoints
            for f in ep.request_fields + ep.response_fields
        }

        # Full PAN stored but only pan_last4 exposed in APIs
        has_full_pan_stored = any(f.lower() in PAN_PATTERNS for f in all_store_fields)
        has_pan_last4_only = all(
            is_pan_last4(f) or f.lower() not in PAN_PATTERNS
            for f in all_api_fields
        )
        # Tokenization vault is the legitimate holder of encrypted PAN — not a violation
        is_tokenization_vault = "token" in all_store_fields or service.service_id == "tokenization-vault"

        if has_full_pan_stored and has_pan_last4_only and not is_tokenization_vault:
            pan_fields = [f for f in all_store_fields if f.lower() in PAN_PATTERNS]
            violations.append(Violation(
                rule_id=self.rule_id,
                severity=Severity.MEDIUM,
                service_id=service.service_id,
                title="Full PAN stored but only last-4 digits exposed — data minimization failure",
                description=(
                    f"Service '{service.service_id}' stores full PAN ({pan_fields}) but all "
                    f"API endpoints only expose pan_last4. If the service doesn't need to transmit "
                    f"or process the full PAN, it should store only the token + last4 and delegate "
                    f"detokenization to the tokenization vault."
                ),
                regulatory_citation="GDPR Article 5(1)(c); PCI DSS v4.0 Requirement 3.3",
                remediation=(
                    "Replace full PAN storage with a token from the tokenization vault. "
                    "Store only pan_last4 for display purposes. The tokenization vault already "
                    "provides secure PAN retrieval when needed for authorization."
                ),
                fields_affected=pan_fields,
            ))

        # Stored fields not referenced in any API (unused data collection)
        api_referenced = all_api_fields | {
            f for t in service.data_transfers for f in t.fields
        }
        stored_personal = {
            f for f in all_store_fields
            if classify_fields([f]).get(DataCategory.PII) or
               classify_fields([f]).get(DataCategory.CARDHOLDER_PAN)
        }
        unused_personal = stored_personal - api_referenced
        # Filter out fields that are plausibly internal (customer_id, timestamps, etc.)
        internal_fields = {"customer_id", "merchant_id", "timestamp", "created_at", "updated_at", "kyc_status"}
        unused_personal -= internal_fields
        if unused_personal:
            violations.append(Violation(
                rule_id=self.rule_id + "-UNUSED",
                severity=Severity.MEDIUM,
                service_id=service.service_id,
                title=f"Personal data stored but not referenced in any API or transfer",
                description=(
                    f"Service '{service.service_id}' stores personal fields {sorted(unused_personal)} "
                    f"that do not appear in any API endpoint or outbound data transfer. "
                    f"This suggests excessive collection with no clear purpose."
                ),
                regulatory_citation="GDPR Article 5(1)(c) — data minimization",
                remediation=(
                    "Review whether these fields serve a documented purpose. If not, remove them "
                    "from the data store schema. If they serve an undocumented purpose "
                    "(e.g., internal analytics), document the lawful basis and purpose limitation."
                ),
                fields_affected=sorted(unused_personal),
            ))

        return violations


class FullPANInLogsRule(ComplianceRule):
    """PCI DSS Requirement 3.3 / GDPR Article 5(1)(c): Full PAN must not appear in logs."""
    rule_id = "PCI-3.3-PAN-IN-LOGS"
    framework = "BOTH"

    LOG_STORE_TYPES = {"elasticsearch", "splunk", "cloudwatch", "log-aggregator", "s3"}

    def check(self, service: Service, all_services: list[Service]) -> list[Violation]:
        violations = []
        for store in service.data_stores:
            if store.type.lower() not in self.LOG_STORE_TYPES:
                continue
            pan_fields = [f for f in store.fields if f.lower() in PAN_PATTERNS | {"pan_full"}]
            if pan_fields:
                violations.append(Violation(
                    rule_id=self.rule_id,
                    severity=Severity.CRITICAL,
                    service_id=service.service_id,
                    title="Full PAN present in log/search store",
                    description=(
                        f"Service '{service.service_id}' stores full PAN ({pan_fields}) in a "
                        f"log or search store ({store.type}). PCI DSS prohibits unmasked PAN "
                        f"in logs. This expands the CDE scope unnecessarily and creates a "
                        f"high-risk data leakage surface."
                    ),
                    regulatory_citation="PCI DSS v4.0 Requirement 3.3.1; ISO 27001 A.8.12",
                    remediation=(
                        "Mask PAN in log entries (show only last 4 digits: ************1234). "
                        "Implement a log scrubbing pipeline to redact PAN from existing log entries. "
                        "Restrict access to the audit log service to security personnel only."
                    ),
                    fields_affected=pan_fields,
                    conflict_note=(
                        "PCI DSS Requirement 10 requires retaining audit logs for 1 year, "
                        "but logs must not contain full PAN. Resolution: retain logs with masked PAN."
                    ),
                ))
        return violations


class FraudEngineRetentionAmbiguityRule(ComplianceRule):
    """
    Handles the specific GDPR/PCI conflict for fraud ML logs:
    - PCI DSS Req 10.7: audit logs ≥ 1 year
    - GDPR Art 5(1)(e): only as long as necessary
    - Legitimate interest for fraud prevention may justify extended retention,
      but email/IP in ML training sets for 3 years warrants scrutiny.

    Decision: Flag as MEDIUM requiring human review, not auto-fail.
    Rationale: A documented LIA (Legitimate Interest Assessment) with purpose limitation
    could justify 3 years for behavioral features, but direct identifiers (email, IP)
    are rarely necessary for model training — pseudonymized features suffice.
    """
    rule_id = "GDPR-5.1e-FRAUD-LOG-AMBIGUITY"
    framework = "BOTH"

    DIRECT_IDENTIFIERS = {"email", "ip_address", "full_name", "phone_number"}

    def check(self, service: Service, all_services: list[Service]) -> list[Violation]:
        violations = []
        for store in service.data_stores:
            direct_ids = [f for f in store.fields if f.lower() in self.DIRECT_IDENTIFIERS]
            if not direct_ids:
                continue

            # Multi-year retention of direct identifiers in ML/analytics stores
            if service.retention_policy and "year" in service.retention_policy.lower():
                try:
                    years = int(service.retention_policy.split()[0])
                except (ValueError, IndexError):
                    years = 0
                if years > 1 and "fraud" in service.service_id or "analytics" in service.service_id or "ml" in service.service_id:
                    violations.append(Violation(
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        service_id=service.service_id,
                        title=f"Direct identifiers retained {service.retention_policy} in analytics/fraud store — GDPR/PCI conflict",
                        description=(
                            f"Service '{service.service_id}' retains direct identifiers "
                            f"{direct_ids} for {service.retention_policy} in {store.type}. "
                            f"GDPR Article 5(1)(e) requires data be kept only as long as necessary; "
                            f"PCI DSS Req 10.7 mandates 1-year minimum for audit logs. "
                            f"Retaining email and IP addresses beyond 1 year for ML training "
                            f"is rarely justified when pseudonymized features would suffice."
                        ),
                        regulatory_citation=(
                            "GDPR Article 5(1)(c)(e); PCI DSS v4.0 Requirement 10.7; "
                            "EDPB Guidelines 02/2019 on Article 6(1)(f)"
                        ),
                        remediation=(
                            "1. Pseudonymize/hash email and IP after 1 year — retain behavioral "
                            "features (transaction_amount, fraud_score, device_fingerprint) for ML. "
                            "2. Document a Legitimate Interest Assessment (LIA) if 3-year retention "
                            "of direct identifiers is deemed necessary. "
                            "3. Implement data lifecycle automation to enforce the policy."
                        ),
                        fields_affected=direct_ids,
                        requires_human_review=True,
                        conflict_note=(
                            "GDPR minimization vs. PCI audit log retention: "
                            "Resolution — retain logs but replace direct identifiers with "
                            "pseudonymous behavioral features after the PCI minimum (1 year)."
                        ),
                    ))
        return violations


class NonEUServiceCrossBorderRule(ComplianceRule):
    """
    Non-EU services receiving EU personal data must have adequate safeguards.
    Checks from the receiving side for services in non-adequate regions.
    """
    rule_id = "GDPR-46-RECEIVING-NON-EU"
    framework = "GDPR"

    def check(self, service: Service, all_services: list[Service]) -> list[Violation]:
        if is_eu_region(service.region) or is_adequate_region(service.region):
            return []
        all_fields = [f for store in service.data_stores for f in store.fields]
        classified = classify_fields(all_fields)
        personal_fields = (
            classified.get(DataCategory.PII, []) +
            classified.get(DataCategory.CARDHOLDER_PAN, []) +
            classified.get(DataCategory.SENSITIVE_AUTH, [])
        )
        if not personal_fields:
            return []
        # Check if any EU service sends data here without safeguards
        incoming_unsafeguarded = []
        for sender in all_services:
            if not is_eu_region(sender.region):
                continue
            for t in sender.data_transfers:
                if t.to_service == service.service_id and t.safeguard not in ("scc", "adequacy_decision", "binding_corporate_rules"):
                    incoming_unsafeguarded.extend(t.fields)

        if incoming_unsafeguarded:
            return [Violation(
                rule_id=self.rule_id,
                severity=Severity.HIGH,
                service_id=service.service_id,
                title=f"Non-EU service ({service.region}) holds EU personal data without documented safeguards",
                description=(
                    f"Service '{service.service_id}' is located in {service.region} (non-adequate) "
                    f"and receives EU personal data: {sorted(set(incoming_unsafeguarded))}. "
                    f"No transfer safeguard is documented for incoming EU data flows."
                ),
                regulatory_citation="GDPR Article 44-46, Chapter V",
                remediation=(
                    f"Either: (a) migrate '{service.service_id}' to an EU/adequate region, "
                    f"(b) implement SCCs with all EU senders, or (c) pseudonymize data before "
                    f"transfer so it no longer qualifies as personal data."
                ),
                fields_affected=sorted(set(incoming_unsafeguarded)),
            )]
        return []


ALL_RULES: list[ComplianceRule] = [
    CVVStorageRule(),
    FullPANInLogsRule(),
    MissingRetentionPolicyRule(),
    MissingLawfulBasisRule(),
    CrossBorderTransferRule(),
    DataMinimizationRule(),
    FraudEngineRetentionAmbiguityRule(),
    NonEUServiceCrossBorderRule(),
]
