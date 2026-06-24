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


def generate_dsar_response(services: list[Service], customer_id: str) -> str:
    """Stretch goal 5: DSAR simulation — find all data held about a customer."""
    lines = [
        f"# Data Subject Access Request Response",
        f"*Subject Customer ID: `{customer_id}`*",
        f"*Generated: {date.today().isoformat()}*",
        "",
        "The following services process data that may be associated with this customer:",
        "",
    ]
    found_any = False
    for svc in services:
        all_fields = [f for store in svc.data_stores for f in store.fields]
        if "customer_id" in all_fields or "email" in all_fields:
            found_any = True
            lines += [
                f"## {svc.service_id}",
                f"- **Region:** {svc.region}",
                f"- **Data fields potentially held:** {', '.join(all_fields)}",
                f"- **Retention policy:** {svc.retention_policy or 'Not documented'}",
                f"- **Lawful basis:** {svc.lawful_basis or 'Not documented'}",
                "",
            ]
    if not found_any:
        lines.append("No services identified as processing data for this customer.")
    lines += [
        "---",
        "> **Note:** This is an automated scan based on service metadata. "
        "A manual review by service owners is required to confirm actual data held "
        "for the specific customer ID before responding to the DSAR.",
    ]
    return "\n".join(lines)
