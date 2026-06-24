# Design Decisions & Compliance Reasoning

## 1. `pan_last4`: Not Cardholder Data, But Still Personal Data

**Under PCI DSS — not sensitive.** Requirement 3.3 explicitly permits storing the last four digits of a PAN. It cannot reconstruct the full account number or initiate a transaction. The tool does not flag `pan_last4` as a PCI DSS violation.

**Under GDPR — personal data.** Combined with `customer_id`, `email`, or `full_name` (all commonly co-stored), `pan_last4` is sufficient to identify a specific payment instrument belonging to a natural person under GDPR Article 4(1). The tool therefore classifies `pan_last4` as **PII under GDPR** for cross-border transfer analysis, retention checks, and DSAR scoping.

This distinction matters: the `tokenization-vault → fraud-engine` transfer of `pan_last4` to `us-east-1` without SCCs is flagged as a **GDPR Article 46 violation**, even though it is not a PCI DSS violation. Same field, two different answers depending on the framework.

## 2. The Fraud Engine Retention Dilemma

`fraud-engine` retains `email` and `ip_address` for 3 years to train ML models. Three frameworks conflict:

- **GDPR Article 5(1)(e)**: keep only as long as necessary
- **GDPR Article 5(1)(c)**: minimize — do fraud models need direct identifiers or just behavioral features?
- **PCI DSS Requirement 10.7**: audit logs must be kept ≥ 1 year

**My judgment**: Flag as **MEDIUM with human review required** — not HIGH or CRITICAL. Reasoning:

1. PCI DSS mandates 1-year minimum, so some retention is legally required.
2. Retaining behavioral features (`transaction_amount`, `fraud_score`) for 3 years can be justified under GDPR Article 6(1)(f) legitimate interest with a documented LIA.
3. **However**, `email` and `ip_address` are direct identifiers rarely necessary for ML training — pseudonymized features suffice. Three-year retention of these specific fields goes beyond Article 5(1)(c).

Remediation: pseudonymize email and IP after 1 year; retain behavioral features for the full ML window; document the LIA. The tool does not auto-fail because a valid business justification may exist — it surfaces the conflict for human review rather than generating a false positive.

## 3. CVV Storage: No Nuance

**Decision: CRITICAL regardless of encryption or hashing.**

PCI DSS Requirement 3.2.1 is unambiguous — sensitive authentication data must not be stored post-authorization, even encrypted. I explicitly include `cvv_hash` (in `3ds-auth-service`) as a violation. Some engineers assume hashing is sufficient because it's one-way. PCI DSS disagrees: the *presence* of CVV-derived data in any store is the violation. A hash still expands CDE scope and enables correlation attacks.

## 4. Cross-Border Transfers: Adequacy vs. SCCs

The tool distinguishes three states — not all cross-border transfers are violations:

- `safeguard: "scc"` → **not flagged** (e.g., `notification-service → sendgrid` is compliant post-Schrems II if SCCs + TIA are in place)
- `safeguard: "adequacy_decision"` → **not flagged**
- `safeguard: null` to non-adequate country → **HIGH**

Severity is HIGH (not CRITICAL) because unlike CVV storage, the violation can be remediated retroactively by executing SCCs — no data needs to be deleted.

## 5. The Tokenization Vault Exception

`tokenization-vault` stores `pan_encrypted` and is explicitly **exempted** from the data minimization rule. Flagging a tokenization vault for storing PAN would be a false positive — equivalent to flagging a hospital for storing medical records. The correct audit question is CDE segmentation and access control, not whether the vault stores PAN. Context determines compliance.

## 6. KYC Document Storage

`merchant-onboarding` stores `id_document_scan`, `proof_of_address_scan`, and `bank_account_iban` which do not appear in any API endpoint. The tool exempts these from the "unused personal data" rule. They are outputs of the KYC processing workflow and are required for AML regulatory obligations (`legal_obligation` lawful basis) — not excessive collection. Flagging them would generate noise that undermines the credibility of the report.

## 7. Edge Cases and Privacy Awareness

- **Missing fields**: Loader uses `.get()` throughout — missing `retention_policy`, `lawful_basis`, or `data_transfers` produce findings, not crashes.
- **GDPR/PCI conflicts**: Where frameworks conflict (audit log retention vs. minimization), the tool emits a `conflict_note` and sets `requires_human_review: true`. Binary pass/fail is incorrect for regulatory ambiguity.
- **Tool privacy**: The analyzer operates on schema metadata, never on actual cardholder values. Reports contain field names only — no PAN values, no CVV values, no raw PII.

## 8. What I'd Add With More Time

1. **Indirect flow traversal**: Detect A → B → C cross-border chains even without a direct A→C transfer documented.
2. **Service-level risk score**: Aggregate findings per service to produce a remediation priority queue.
3. **SCC version validation**: Distinguish June 2021 SCCs (valid) from 2010 SCCs (expired December 2022).
4. **CDE segmentation analysis**: Flag services that share network space with CDE services without documented isolation controls.
