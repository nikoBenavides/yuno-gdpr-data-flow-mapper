# Yuno GDPR Data Flow Mapper

A Python CLI tool that ingests service metadata and automatically:
1. Discovers cardholder data (PAN, CVV) and PII flows across microservices
2. Detects GDPR/PCI DSS compliance violations with severity ratings
3. Generates audit-ready reports for GDPR Article 30 and ISO 27001 auditors

## Quick Start

```bash
# No dependencies beyond Python 3.9+ standard library + PyYAML
pip install pyyaml

# Run full compliance analysis
python3 main.py analyze --input services.json --rules rules.yaml --output-dir reports/

# Simulate a GDPR Data Subject Access Request
python3 main.py dsar --input services.json --customer-id cust_DE_87234

# Print data flow lineage
python3 main.py visualize --input services.json --format ascii
python3 main.py visualize --input services.json --format dot | dot -Tpng -o lineage.png
```

## Outputs

| File | Description |
|------|-------------|
| `reports/data_processing_inventory.md` | GDPR Article 30 register (Markdown) |
| `reports/data_processing_inventory.json` | Article 30 register (machine-readable) |
| `reports/compliance_risk_report.md` | Prioritized violations with GDPR/PCI citations |
| `reports/data_lineage.txt` | ASCII data flow graph |
| `reports/data_lineage.dot` | Graphviz DOT for visual rendering |

## Architecture

```
main.py                     CLI entry point, command dispatch
analyzer/
  loader.py                 Parses services.json → Service dataclasses
  models.py                 Dataclasses: Service, Violation, DataFlow, Severity
  classifier.py             Field-name → DataCategory classifier (PAN, SAD, PII)
  rules.py                  ComplianceRule base class + 8 built-in rules
  engine.py                 Orchestrates rule evaluation, builds flow graph
  reporter.py               Generates Markdown/JSON inventory and risk report
  visualizer.py             DOT graph + ASCII lineage for data flows
  policy_loader.py          Loads custom rules from rules.yaml (Policy-as-Code)
rules.yaml                  Configurable compliance rules (no Python required)
```

**Adding a new compliance rule**: subclass `ComplianceRule` in `analyzer/rules.py`, implement `check()`, add to `ALL_RULES`. Alternatively, add a YAML entry to `rules.yaml` for non-engineer rule authors.

## Compliance Rules Implemented

| Rule ID | Framework | Severity | Description |
|---------|-----------|----------|-------------|
| `PCI-3.2-SAD-STORAGE` | PCI DSS | CRITICAL | CVV/PIN stored post-authorization |
| `PCI-3.3-PAN-IN-LOGS` | Both | CRITICAL | Full PAN in log/search stores |
| `GDPR-5.1e-RETENTION` | GDPR | HIGH | Missing retention policy for personal data |
| `GDPR-6-LAWFUL-BASIS` | GDPR | HIGH | No documented lawful basis |
| `GDPR-46-CROSS-BORDER` | GDPR | HIGH | EU→non-adequate transfer without SCC |
| `GDPR-5.1c-MINIMIZATION` | GDPR | MEDIUM | Full PAN stored, only last-4 exposed |
| `GDPR-5.1e-FRAUD-LOG-AMBIGUITY` | Both | MEDIUM | Direct identifiers in multi-year ML logs (human review) |
| `GDPR-46-RECEIVING-NON-EU` | GDPR | HIGH | Non-EU service holds EU data without safeguard |

## Exit Codes

- `0` — no CRITICAL findings
- `1` — CRITICAL findings found (suitable for CI/CD pipeline gates)

## Test Data

`services.json` contains 10 realistic payment services with intentional compliance gaps:
- `payment-gateway-api`: stores CVV post-auth (CRITICAL)
- `3ds-auth-service`: stores CVV hash in two stores (CRITICAL ×2)
- `audit-log-service`: full PAN in Elasticsearch logs (CRITICAL)
- `fraud-engine`: EU→US transfer without SCC; 3-year retention of direct identifiers
- `merchant-dashboard`: no retention policy; full PAN stored, only last-4 exposed
- `analytics-warehouse`: no lawful basis, no retention policy, US region
- `dispute-management`: APAC region, EU PII transferred to card network without SCC
