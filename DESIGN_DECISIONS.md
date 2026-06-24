# Design Decisions & Compliance Reasoning

## Overview

This document explains the interpretive choices made when translating GDPR and PCI DSS requirements into automated detection logic. These are the kinds of judgment calls that distinguish a compliance tool from a checklist executor.

---

## 1. Is `pan_last4` Cardholder Data?

**Decision: No — `pan_last4` is not flagged as cardholder data or a PCI DSS violation.**

PCI DSS v4.0 Requirement 3.3 explicitly allows storing the last four digits of a PAN as long as the full PAN is not recoverable. `pan_last4` alone cannot be used to reconstruct a card number, initiate a transaction, or identify a specific card without additional data. The standard's intent is to protect the full account number, not derived display artifacts.

However, I do include `pan_last4` fields when assessing data minimization (GDPR Article 5(1)(c)): if a service stores full encrypted PAN *and* exposes only `pan_last4` in its APIs, that is flagged as a data minimization issue — not a PCI DSS violation, but a GDPR concern. The service should hold only the token + last4 and delegate PAN retrieval to the tokenization vault.

**Contrast**: The `tokenization-vault` service stores `pan_encrypted` and is *not* flagged for data minimization, because storing and managing encrypted PANs is its explicit, documented purpose. Context matters — the same field can be compliant in one service and a violation in another.

---

## 2. The Fraud Engine Retention Dilemma

**Scenario**: `fraud-engine` retains `email` and `ip_address` for 3 years to train ML models.

This is the most genuinely ambiguous case in the dataset, sitting at the intersection of three requirements:

- **GDPR Article 5(1)(e)**: data kept no longer than necessary for the stated purpose
- **GDPR Article 5(1)(c)**: data minimization — collect only what is necessary
- **PCI DSS Requirement 10.7**: audit logs must be retained for at least 1 year

**My interpretation**: I flag this as **MEDIUM** (not HIGH or CRITICAL) and mark it `requires_human_review: true`. The reasoning:

1. A 1-year minimum for audit logs is mandated by PCI DSS — the service *must* retain some records.
2. Retaining behavioral features (`transaction_amount`, `fraud_score`, `device_fingerprint`) for 3 years for ML training can be justified under GDPR Article 6(1)(f) legitimate interest, if a proper Legitimate Interest Assessment (LIA) is documented.
3. **However**, direct identifiers — specifically `email` and `ip_address` — are rarely necessary for model training. Fraud models can be trained on pseudonymized behavioral features. Retaining these identifiers for 3 years goes beyond what is necessary under Article 5(1)(c).

**Recommendation in the tool**: Pseudonymize/hash email and IP after 1 year (satisfying PCI minimum), retain behavioral features for ML training period, and document the LIA. I do not auto-fail this because the business may have a documented legal basis — the tool surfaces it for human review rather than generating a false positive.

---

## 3. CVV Storage: No Nuance

**Decision: Any CVV/CVC/PIN field in any data store is CRITICAL, regardless of encryption.**

PCI DSS Requirement 3.2.1 is unambiguous: sensitive authentication data (SAD) must not be stored after authorization is complete, *even if encrypted*. The standard's rationale is that encryption protects data at rest but does not remove the compliance obligation — the data should not exist post-authorization at all.

I explicitly include `cvv_hash` (as seen in `3ds-auth-service`) as a violation. Some engineers assume hashing is sufficient because it's one-way. PCI DSS disagrees: the *presence* of CVV-derived data in storage is the violation, regardless of the cryptographic transformation applied. A hash can still be used for correlation attacks and represents a CDE-expanding data element.

---

## 4. Cross-Border Transfers: Adequacy vs. SCCs

**Decision: The tool distinguishes between adequacy decisions, SCCs, and no safeguard — not all cross-border transfers are violations.**

The `notification-service` transfers `email` to `sendgrid-external` in `us-east-1` with `safeguard: "scc"`. This is **not** flagged as a violation. Post-Schrems II, Standard Contractual Clauses (June 2021 version) remain a valid transfer mechanism for US transfers, provided a Transfer Impact Assessment (TIA) is completed. The tool does not flag SCC-covered transfers.

Transfers with `safeguard: null` to non-adequate countries are flagged as HIGH. The severity is HIGH rather than CRITICAL because (unlike CVV storage) the violation is potentially remediated retroactively by putting SCCs in place — whereas CVV data that was stored must be deleted and the CDE scope must be reassessed.

The `dispute-management` service in `ap-southeast-1` (Singapore) is flagged because Singapore's PDPA is not an EU adequacy decision, and card network transfers (`card-network-visa`) carry significant EU PII with no documented safeguard.

---

## 5. The Tokenization Vault Exception

**Decision: `tokenization-vault` is exempted from the full-PAN data minimization rule.**

Storing encrypted PAN is the vault's entire purpose. Flagging it for "full PAN stored" would be a false positive — equivalent to flagging a hospital for "storing patient records." The correct question is whether the vault is properly segmented (CDE isolation) and access-controlled, not whether it stores PAN. The tool applies a domain-specific exception using service identity and the presence of `token` in stored fields.

---

## 6. `analytics-warehouse`: Missing Lawful Basis

**Decision: Missing lawful basis for an analytics service is flagged as HIGH, not MEDIUM.**

The `analytics-warehouse` has no documented lawful basis (`lawful_basis: null`). This is particularly concerning because the service is in `us-east-1` (already a cross-border transfer risk), stores `email`, `full_name`, and `pan_last4`, and its purpose appears to be business intelligence — not contractual necessity. Under GDPR Article 6, every processing activity requires a valid lawful basis. The absence of one for a service with significant personal data exposure warrants HIGH severity.

---

## 7. Edge Cases and Graceful Degradation

- **Missing fields in services.json**: The loader uses `.get()` with defaults throughout. Missing optional fields (description, owner, retention_policy) produce appropriate GDPR findings rather than crashes.
- **Conflicting framework rules**: Where GDPR and PCI DSS conflict (primarily on audit log retention), the tool flags for human review with an explicit `conflict_note` in the violation output. Binary pass/fail is inappropriate here.
- **The tool itself**: The compliance analyzer does not log, print, or write any raw PAN values. Report output redacts sensitive fields to field names only, never values. The tool operates on metadata schemas, not actual cardholder data.

---

## 8. What I'd Add With More Time

1. **Graph traversal for indirect data flows**: Currently the tool checks direct `data_transfers`. A more sophisticated version would traverse the service graph to detect indirect flows (e.g., service A → service B → service C where C is non-adequate, even if A→C has no direct transfer).
2. **Risk scoring aggregation**: Aggregate violation counts per service to produce a service-level risk score, enabling prioritization when remediating 10+ findings.
3. **DSAR completeness verification**: The current DSAR simulation identifies services that *might* hold customer data based on stored field names. A production version would require service owners to attest to customer data presence and provide a record count.
4. **SCCs version checking**: The June 2021 EU SCCs replaced the older 2010 versions (which expired in December 2022). A tool that detects `safeguard: "scc"` without verifying which version is used could miss compliance gaps.
5. **PCI DSS CDE segmentation analysis**: Identify which services are in-scope for PCI DSS (the Cardholder Data Environment) and flag services that share network space without documented segmentation controls.
