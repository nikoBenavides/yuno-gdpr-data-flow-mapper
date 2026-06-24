"""
Generates two audit-ready reports:
1. GDPR Article 30 Data Processing Inventory (Markdown table + JSON)
2. Compliance Risk Report (prioritized violations with remediation)
"""

import json
from datetime import date
from .models import Service, Violation, DataFlow, Severity
from .classifier import classify_fields, DataCategory


SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH: "🟠 HIGH",
    Severity.MEDIUM: "🟡 MEDIUM",
    Severity.LOW: "🟢 LOW",
    Severity.INFO: "ℹ️  INFO",
}


def generate_inventory_markdown(services: list[Service]) -> str:
    lines = [
        "# GDPR Article 30 — Data Processing Inventory",
        f"*Generated: {date.today().isoformat()} | Classification: CONFIDENTIAL*",
        "",
        "> This register is maintained pursuant to GDPR Article 30 (Records of Processing Activities).",
        "> It must be made available to supervisory authorities on request.",
        "",
    ]

    for svc in services:
        all_fields = [f for store in svc.data_stores for f in store.fields]
        classified = classify_fields(all_fields)

        cardholder = classified.get(DataCategory.CARDHOLDER_PAN, [])
        sensitive_auth = classified.get(DataCategory.SENSITIVE_AUTH, [])
        pii = classified.get(DataCategory.PII, [])

        transfers_desc = "; ".join(
            f"{t.to_service} ({t.to_region}) [{t.safeguard or '⚠️ NO SAFEGUARD'}]"
            for t in svc.data_transfers
        ) or "None"

        data_categories_desc = []
        if sensitive_auth:
            data_categories_desc.append(f"Sensitive Auth Data: {sensitive_auth}")
        if cardholder:
            data_categories_desc.append(f"Cardholder Data (PAN): {cardholder}")
        if pii:
            data_categories_desc.append(f"PII: {pii}")
        if not data_categories_desc:
            data_categories_desc = ["No personal data identified"]

        lines += [
            f"## {svc.service_id}",
            "",
            f"| Attribute | Value |",
            f"|-----------|-------|",
            f"| **Description** | {svc.description} |",
            f"| **Owner** | {svc.owner} |",
            f"| **Region** | {svc.region} |",
            f"| **Lawful Basis** | {svc.lawful_basis or '⚠️ NOT DOCUMENTED'} |",
            f"| **Retention Policy** | {svc.retention_policy or '⚠️ NOT DOCUMENTED'} |",
            f"| **Cross-Border Transfers** | {transfers_desc} |",
            "",
            "**Data Categories Processed:**",
            "",
        ]
        for d in data_categories_desc:
            lines.append(f"- {d}")
        lines.append("")

    return "\n".join(lines)


def generate_inventory_json(services: list[Service]) -> dict:
    inventory = []
    for svc in services:
        all_fields = [f for store in svc.data_stores for f in store.fields]
        classified = classify_fields(all_fields)
        inventory.append({
            "service_id": svc.service_id,
            "description": svc.description,
            "owner": svc.owner,
            "region": svc.region,
            "lawful_basis": svc.lawful_basis,
            "retention_policy": svc.retention_policy,
            "data_categories": {
                cat.value: fields
                for cat, fields in classified.items()
                if fields
            },
            "cross_border_transfers": [
                {
                    "to_service": t.to_service,
                    "to_region": t.to_region,
                    "fields": t.fields,
                    "safeguard": t.safeguard,
                    "compliant": t.safeguard in ("scc", "adequacy_decision", "binding_corporate_rules", "internal_eu"),
                }
                for t in svc.data_transfers
            ],
        })
    return {"generated_at": date.today().isoformat(), "record_count": len(inventory), "records": inventory}


def generate_risk_report_markdown(violations: list[Violation], flows: list[DataFlow]) -> str:
    counts = {s: sum(1 for v in violations if v.severity == s) for s in Severity}
    total = len(violations)
    human_review = sum(1 for v in violations if v.requires_human_review)

    lines = [
        "# Compliance Risk Report",
        f"*Generated: {date.today().isoformat()} | Classification: CONFIDENTIAL — DPO + Legal Eyes Only*",
        "",
        "## Executive Summary",
        "",
        f"**Total findings:** {total}  ",
        f"**Requires immediate action (Critical + High):** {counts[Severity.CRITICAL] + counts[Severity.HIGH]}  ",
        f"**Requires human review (regulatory ambiguity):** {human_review}  ",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        lines.append(f"| {SEVERITY_EMOJI[sev]} | {counts[sev]} |")

    lines += [
        "",
        "---",
        "",
        "## Cross-Border Data Flow Summary",
        "",
    ]
    cross_border = [f for f in flows if f.crosses_border]
    if cross_border:
        lines.append("| Source | Destination | Region | Fields | Safeguard |")
        lines.append("|--------|-------------|--------|--------|-----------|")
        for f in cross_border:
            safeguard_display = f.safeguard or "⚠️ NONE"
            lines.append(
                f"| {f.from_service} | {f.to_service} | {f.to_region} "
                f"| {', '.join(f.fields[:3])}{'...' if len(f.fields) > 3 else ''} "
                f"| {safeguard_display} |"
            )
    else:
        lines.append("No cross-border transfers identified.")

    lines += ["", "---", "", "## Findings", ""]

    for i, v in enumerate(violations, 1):
        review_flag = " ⚠️ **HUMAN REVIEW REQUIRED**" if v.requires_human_review else ""
        lines += [
            f"### Finding {i}: {v.title}{review_flag}",
            "",
            f"**Severity:** {SEVERITY_EMOJI[v.severity]}  ",
            f"**Service:** `{v.service_id}`  ",
            f"**Rule ID:** `{v.rule_id}`  ",
            f"**Regulatory Citation:** {v.regulatory_citation}  ",
            "",
            f"**Description:** {v.description}",
            "",
            f"**Remediation:** {v.remediation}",
            "",
        ]
        if v.fields_affected:
            lines.append(f"**Affected Fields:** `{'`, `'.join(v.fields_affected)}`  ")
            lines.append("")
        if v.conflict_note:
            lines.append(f"> **Regulatory Conflict Note:** {v.conflict_note}")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# Fields that link a record to a specific customer (used to determine DSAR scope)
CUSTOMER_IDENTIFIER_FIELDS = {"customer_id", "email", "phone_number", "full_name"}

# Fields that are personal data a subject has the right to receive under GDPR Art. 15
PERSONAL_DATA_FIELDS = {
    "email", "full_name", "first_name", "last_name", "phone_number",
    "billing_address", "ip_address", "date_of_birth", "pan_last4",
    "notification_preferences", "transaction_history", "dispute_evidence",
    "fraud_score", "device_fingerprint",
}


def generate_dsar_response(services: list[Service], customer_id: str) -> str:
    """
    DSAR simulation (GDPR Article 15).

    Identifies every service that stores customer-linked fields, then lists:
    - Which personal data fields it holds (what the subject can request a copy of)
    - Which fields are sensitive/restricted (must be redacted in the DSAR response)
    - Retention policy and lawful basis (required disclosures under Art. 15(1))

    Limitation: this is a schema-level scan. It proves a service *can* hold data
    for this customer_id, not that it *does*. Service owners must confirm before
    responding to the actual DSAR.
    """
    lines = [
        "# GDPR Data Subject Access Request — Scoping Report",
        f"*Subject Customer ID: `{customer_id}`*",
        f"*Generated: {date.today().isoformat()} | Must respond within 30 days (GDPR Art. 15)*",
        "",
        "## Scope",
        "",
        "This report identifies every service whose schema contains customer-linked fields.",
        "**Action required:** Each service owner must confirm whether a record for",
        f"`{customer_id}` exists and provide the actual data for the DSAR response.",
        "",
        "---",
        "",
    ]

    found_any = False
    for svc in services:
        all_fields = list(dict.fromkeys(f for store in svc.data_stores for f in store.fields))
        # Only include services that store a field that could link to this customer
        if not any(f in CUSTOMER_IDENTIFIER_FIELDS for f in all_fields):
            continue

        found_any = True
        disclosable = [f for f in all_fields if f in PERSONAL_DATA_FIELDS]
        sensitive = [f for f in all_fields if any(
            kw in f.lower() for kw in ("pan_encrypted", "cvv", "pin", "token", "encrypted")
        )]
        cross_border = [
            f"{t.to_service} ({t.to_region})" for t in svc.data_transfers
            if any(f in PERSONAL_DATA_FIELDS for f in t.fields)
        ]

        lines += [
            f"## {svc.service_id}",
            "",
            f"| Attribute | Value |",
            f"|-----------|-------|",
            f"| Region | {svc.region} |",
            f"| Lawful Basis | {svc.lawful_basis or '⚠️ Not documented'} |",
            f"| Retention | {svc.retention_policy or '⚠️ Not documented'} |",
            "",
            f"**Data disclosable to subject (Art. 15):** "
            f"{', '.join(disclosable) if disclosable else 'None identified'}",
            "",
        ]
        if sensitive:
            lines.append(
                f"**Sensitive fields (redact from DSAR response):** {', '.join(sensitive)}"
            )
            lines.append("")
        if cross_border:
            lines.append(
                f"**Subject's data transferred to:** {'; '.join(cross_border)} "
                f"*(must disclose recipients under Art. 15(1)(c))*"
            )
            lines.append("")
        lines.append("---")
        lines.append("")

    if not found_any:
        lines.append(f"No services identified as processing data for customer `{customer_id}`.")

    lines += [
        "> **Legal Note:** This automated report covers schema-level scope only.",
        "> Before sending the DSAR response, each service owner must attest to the",
        "> presence/absence of a record for this customer and provide actual field values.",
        "> CVV, full PAN, and encrypted fields must never be included in DSAR responses.",
    ]
    return "\n".join(lines)
