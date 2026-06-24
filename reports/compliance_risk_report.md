# Compliance Risk Report
*Generated: 2026-06-23 | Classification: CONFIDENTIAL — DPO + Legal Eyes Only*

## Executive Summary

**Total findings:** 21  
**Requires immediate action (Critical + High):** 10  
**Requires human review (regulatory ambiguity):** 1  

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 4 |
| 🟠 HIGH | 6 |
| 🟡 MEDIUM | 11 |
| 🟢 LOW | 0 |
| ℹ️  INFO | 0 |

---

## Cross-Border Data Flow Summary

| Source | Destination | Region | Fields | Safeguard |
|--------|-------------|--------|--------|-----------|
| payment-gateway-api | fraud-engine | us-east-1 | email, ip_address, transaction_amount... | ⚠️ NONE |
| notification-service | sendgrid-external | us-east-1 | email, full_name | scc |
| dispute-management | card-network-visa | us-east-1 | full_name, email, billing_address... | ⚠️ NONE |

---

## Findings

### Finding 1: Sensitive Authentication Data (CVV/PIN) stored post-authorization

**Severity:** 🔴 CRITICAL  
**Service:** `payment-gateway-api`  
**Rule ID:** `PCI-3.2-SAD-STORAGE`  
**Regulatory Citation:** PCI DSS v4.0 Requirement 3.2.1  

**Description:** Service 'payment-gateway-api' stores sensitive authentication data in postgres: ['cvv_encrypted']. PCI DSS explicitly forbids storing CVV/CVC, PINs, or magnetic stripe data after transaction authorization, even in encrypted form.

**Remediation:** Immediately delete CVV/PIN fields from all data stores. Authentication data may be held in memory only during the authorization transaction and must not be persisted. Implement a data purge job and verify with a QSA before next PCI audit.

**Affected Fields:** `cvv_encrypted`  

---

### Finding 2: Sensitive Authentication Data (CVV/PIN) stored post-authorization

**Severity:** 🔴 CRITICAL  
**Service:** `3ds-auth-service`  
**Rule ID:** `PCI-3.2-SAD-STORAGE`  
**Regulatory Citation:** PCI DSS v4.0 Requirement 3.2.1  

**Description:** Service '3ds-auth-service' stores sensitive authentication data in redis: ['cvv_hash']. PCI DSS explicitly forbids storing CVV/CVC, PINs, or magnetic stripe data after transaction authorization, even in encrypted form.

**Remediation:** Immediately delete CVV/PIN fields from all data stores. Authentication data may be held in memory only during the authorization transaction and must not be persisted. Implement a data purge job and verify with a QSA before next PCI audit.

**Affected Fields:** `cvv_hash`  

---

### Finding 3: Sensitive Authentication Data (CVV/PIN) stored post-authorization

**Severity:** 🔴 CRITICAL  
**Service:** `3ds-auth-service`  
**Rule ID:** `PCI-3.2-SAD-STORAGE`  
**Regulatory Citation:** PCI DSS v4.0 Requirement 3.2.1  

**Description:** Service '3ds-auth-service' stores sensitive authentication data in postgres: ['cvv_hash']. PCI DSS explicitly forbids storing CVV/CVC, PINs, or magnetic stripe data after transaction authorization, even in encrypted form.

**Remediation:** Immediately delete CVV/PIN fields from all data stores. Authentication data may be held in memory only during the authorization transaction and must not be persisted. Implement a data purge job and verify with a QSA before next PCI audit.

**Affected Fields:** `cvv_hash`  

---

### Finding 4: Full PAN present in log/search store

**Severity:** 🔴 CRITICAL  
**Service:** `audit-log-service`  
**Rule ID:** `PCI-3.3-PAN-IN-LOGS`  
**Regulatory Citation:** PCI DSS v4.0 Requirement 3.3.1; ISO 27001 A.8.12  

**Description:** Service 'audit-log-service' stores full PAN (['pan_full']) in a log or search store (elasticsearch). PCI DSS prohibits unmasked PAN in logs. This expands the CDE scope unnecessarily and creates a high-risk data leakage surface.

**Remediation:** Mask PAN in log entries (show only last 4 digits: ************1234). Implement a log scrubbing pipeline to redact PAN from existing log entries. Restrict access to the audit log service to security personnel only.

**Affected Fields:** `pan_full`  

> **Regulatory Conflict Note:** PCI DSS Requirement 10 requires retaining audit logs for 1 year, but logs must not contain full PAN. Resolution: retain logs with masked PAN.

---

### Finding 5: Unlawful cross-border transfer: EU → us-east-1 (fraud-engine)

**Severity:** 🟠 HIGH  
**Service:** `payment-gateway-api`  
**Rule ID:** `GDPR-46-CROSS-BORDER`  
**Regulatory Citation:** GDPR Article 46, Chapter V; Schrems II (C-311/18)  

**Description:** Service 'payment-gateway-api' (EU: eu-west-1) transfers personal data ['email', 'ip_address'] to 'fraud-engine' in us-east-1, which is not an adequate country under GDPR. No valid transfer safeguard (SCC, BCR, adequacy decision) is documented.

**Remediation:** Implement Standard Contractual Clauses (EU SCCs, June 2021 version) with 'fraud-engine'. Conduct a Transfer Impact Assessment (TIA) for transfers to the US given Schrems II. Alternatively, consider migrating the receiving service to an EU region.

**Affected Fields:** `email`, `ip_address`  

---

### Finding 6: Non-EU service (us-east-1) holds EU personal data without documented safeguards

**Severity:** 🟠 HIGH  
**Service:** `fraud-engine`  
**Rule ID:** `GDPR-46-RECEIVING-NON-EU`  
**Regulatory Citation:** GDPR Article 44-46, Chapter V  

**Description:** Service 'fraud-engine' is located in us-east-1 (non-adequate) and receives EU personal data: ['email', 'ip_address', 'merchant_id', 'transaction_amount']. No transfer safeguard is documented for incoming EU data flows.

**Remediation:** Either: (a) migrate 'fraud-engine' to an EU/adequate region, (b) implement SCCs with all EU senders, or (c) pseudonymize data before transfer so it no longer qualifies as personal data.

**Affected Fields:** `email`, `ip_address`, `merchant_id`, `transaction_amount`  

---

### Finding 7: No retention policy defined for personal data

**Severity:** 🟠 HIGH  
**Service:** `merchant-dashboard`  
**Rule ID:** `GDPR-5.1e-RETENTION`  
**Regulatory Citation:** GDPR Article 5(1)(e), Article 30(1)(f)  

**Description:** Service 'merchant-dashboard' stores personal data ['customer_id', 'email', 'billing_address', 'full_name', 'pan_encrypted'] but has no documented retention policy. Under GDPR Article 5(1)(e), personal data must be deleted when no longer necessary for its purpose.

**Remediation:** Define and document a retention period justified by the lawful basis (e.g., contract duration + statutory limitation period, or regulatory minimum). Implement automated deletion or anonymization at end of period. Add retention_policy to your Article 30 register.

**Affected Fields:** `customer_id`, `email`, `billing_address`, `full_name`, `pan_encrypted`  

---

### Finding 8: Cardholder data stored without retention policy

**Severity:** 🟠 HIGH  
**Service:** `merchant-dashboard`  
**Rule ID:** `CUSTOM-MISSING-RETENTION-CARDHOLDER`  
**Regulatory Citation:** GDPR Article 5(1)(e); PCI DSS v4.0 Requirement 3.2  

**Description:** Service 'merchant-dashboard' stores cardholder PAN data without a documented retention period.

**Remediation:** Define retention aligned with contractual need (typically 7 years for payment records under EU financial regulation). Implement automated purge.

---

### Finding 9: No retention policy defined for personal data

**Severity:** 🟠 HIGH  
**Service:** `analytics-warehouse`  
**Rule ID:** `GDPR-5.1e-RETENTION`  
**Regulatory Citation:** GDPR Article 5(1)(e), Article 30(1)(f)  

**Description:** Service 'analytics-warehouse' stores personal data ['customer_id', 'email', 'ip_address', 'full_name'] but has no documented retention policy. Under GDPR Article 5(1)(e), personal data must be deleted when no longer necessary for its purpose.

**Remediation:** Define and document a retention period justified by the lawful basis (e.g., contract duration + statutory limitation period, or regulatory minimum). Implement automated deletion or anonymization at end of period. Add retention_policy to your Article 30 register.

**Affected Fields:** `customer_id`, `email`, `ip_address`, `full_name`  

---

### Finding 10: No valid lawful basis documented for personal data processing

**Severity:** 🟠 HIGH  
**Service:** `analytics-warehouse`  
**Rule ID:** `GDPR-6-LAWFUL-BASIS`  
**Regulatory Citation:** GDPR Article 6(1)  

**Description:** Service 'analytics-warehouse' processes personal data but has no documented lawful basis (or basis 'None' is unrecognized). GDPR Article 6 requires every processing activity to have a valid lawful basis.

**Remediation:** Identify the appropriate lawful basis: 'contract' (processing needed to fulfill a contract), 'legal_obligation' (regulatory requirement), 'legitimate_interest' (with LIA documented), or 'consent' (freely given, specific, informed). Document in your Article 30 register.

---

### Finding 11: Personal data stored but not referenced in any API or transfer

**Severity:** 🟡 MEDIUM  
**Service:** `payment-gateway-api`  
**Rule ID:** `GDPR-5.1c-MINIMIZATION-UNUSED`  
**Regulatory Citation:** GDPR Article 5(1)(c) — data minimization  

**Description:** Service 'payment-gateway-api' stores personal fields ['billing_address', 'pan_encrypted'] that do not appear in any API endpoint or outbound data transfer. This suggests excessive collection with no clear purpose.

**Remediation:** Review whether these fields serve a documented purpose. If not, remove them from the data store schema. If they serve an undocumented purpose (e.g., internal analytics), document the lawful basis and purpose limitation.

**Affected Fields:** `billing_address`, `pan_encrypted`  

---

### Finding 12: Personal data stored but not referenced in any API or transfer

**Severity:** 🟡 MEDIUM  
**Service:** `tokenization-vault`  
**Rule ID:** `GDPR-5.1c-MINIMIZATION-UNUSED`  
**Regulatory Citation:** GDPR Article 5(1)(c) — data minimization  

**Description:** Service 'tokenization-vault' stores personal fields ['card_expiry_encrypted'] that do not appear in any API endpoint or outbound data transfer. This suggests excessive collection with no clear purpose.

**Remediation:** Review whether these fields serve a documented purpose. If not, remove them from the data store schema. If they serve an undocumented purpose (e.g., internal analytics), document the lawful basis and purpose limitation.

**Affected Fields:** `card_expiry_encrypted`  

---

### Finding 13: Direct identifiers retained 3 years in fraud/ML store — GDPR/PCI conflict ⚠️ **HUMAN REVIEW REQUIRED**

**Severity:** 🟡 MEDIUM  
**Service:** `fraud-engine`  
**Rule ID:** `GDPR-5.1e-FRAUD-LOG-AMBIGUITY`  
**Regulatory Citation:** GDPR Article 5(1)(c)(e); PCI DSS v4.0 Requirement 10.7; EDPB Guidelines 02/2019 on Article 6(1)(f)  

**Description:** Service 'fraud-engine' retains direct identifiers ['email', 'ip_address'] for 3 years. GDPR Article 5(1)(e) requires data be kept only as long as necessary; PCI DSS Req 10.7 mandates 1-year minimum for audit logs. Retaining email and IP addresses beyond 1 year for ML training is rarely justified when pseudonymized features would suffice.

**Remediation:** 1. Pseudonymize/hash email and IP after 1 year — retain behavioral features (transaction_amount, fraud_score, device_fingerprint) for ML. 2. Document a Legitimate Interest Assessment (LIA) if 3-year retention of direct identifiers is deemed necessary. 3. Implement data lifecycle automation to enforce the policy.

**Affected Fields:** `email`, `ip_address`  

> **Regulatory Conflict Note:** GDPR minimization vs. PCI audit log retention: Resolution — retain logs but replace direct identifiers with pseudonymous behavioral features after the PCI minimum (1 year).

---

### Finding 14: Full PAN stored but only last-4 digits exposed — data minimization failure

**Severity:** 🟡 MEDIUM  
**Service:** `merchant-dashboard`  
**Rule ID:** `GDPR-5.1c-MINIMIZATION`  
**Regulatory Citation:** GDPR Article 5(1)(c); PCI DSS v4.0 Requirement 3.3  

**Description:** Service 'merchant-dashboard' stores full PAN (['pan_encrypted']) but all API endpoints only expose pan_last4. If the service doesn't need to transmit or process the full PAN, it should store only the token + last4 and delegate detokenization to the tokenization vault.

**Remediation:** Replace full PAN storage with a token from the tokenization vault. Store only pan_last4 for display purposes. The tokenization vault already provides secure PAN retrieval when needed for authorization.

**Affected Fields:** `pan_encrypted`  

---

### Finding 15: Personal data stored but not referenced in any API or transfer

**Severity:** 🟡 MEDIUM  
**Service:** `merchant-dashboard`  
**Rule ID:** `GDPR-5.1c-MINIMIZATION-UNUSED`  
**Regulatory Citation:** GDPR Article 5(1)(c) — data minimization  

**Description:** Service 'merchant-dashboard' stores personal fields ['billing_address', 'pan_encrypted'] that do not appear in any API endpoint or outbound data transfer. This suggests excessive collection with no clear purpose.

**Remediation:** Review whether these fields serve a documented purpose. If not, remove them from the data store schema. If they serve an undocumented purpose (e.g., internal analytics), document the lawful basis and purpose limitation.

**Affected Fields:** `billing_address`, `pan_encrypted`  

---

### Finding 16: Personal data stored but not referenced in any API or transfer

**Severity:** 🟡 MEDIUM  
**Service:** `analytics-warehouse`  
**Rule ID:** `GDPR-5.1c-MINIMIZATION-UNUSED`  
**Regulatory Citation:** GDPR Article 5(1)(c) — data minimization  

**Description:** Service 'analytics-warehouse' stores personal fields ['email', 'full_name', 'ip_address'] that do not appear in any API endpoint or outbound data transfer. This suggests excessive collection with no clear purpose.

**Remediation:** Review whether these fields serve a documented purpose. If not, remove them from the data store schema. If they serve an undocumented purpose (e.g., internal analytics), document the lawful basis and purpose limitation.

**Affected Fields:** `email`, `full_name`, `ip_address`  

---

### Finding 17: Personal data stored but not referenced in any API or transfer

**Severity:** 🟡 MEDIUM  
**Service:** `notification-service`  
**Rule ID:** `GDPR-5.1c-MINIMIZATION-UNUSED`  
**Regulatory Citation:** GDPR Article 5(1)(c) — data minimization  

**Description:** Service 'notification-service' stores personal fields ['billing_address', 'date_of_birth', 'ip_address', 'phone_number'] that do not appear in any API endpoint or outbound data transfer. This suggests excessive collection with no clear purpose.

**Remediation:** Review whether these fields serve a documented purpose. If not, remove them from the data store schema. If they serve an undocumented purpose (e.g., internal analytics), document the lawful basis and purpose limitation.

**Affected Fields:** `billing_address`, `date_of_birth`, `ip_address`, `phone_number`  

---

### Finding 18: Personal data stored but not referenced in any API or transfer

**Severity:** 🟡 MEDIUM  
**Service:** `merchant-onboarding`  
**Rule ID:** `GDPR-5.1c-MINIMIZATION-UNUSED`  
**Regulatory Citation:** GDPR Article 5(1)(c) — data minimization  

**Description:** Service 'merchant-onboarding' stores personal fields ['bank_account_iban', 'id_document_scan', 'proof_of_address_scan'] that do not appear in any API endpoint or outbound data transfer. This suggests excessive collection with no clear purpose.

**Remediation:** Review whether these fields serve a documented purpose. If not, remove them from the data store schema. If they serve an undocumented purpose (e.g., internal analytics), document the lawful basis and purpose limitation.

**Affected Fields:** `bank_account_iban`, `id_document_scan`, `proof_of_address_scan`  

---

### Finding 19: Personal data stored but not referenced in any API or transfer

**Severity:** 🟡 MEDIUM  
**Service:** `3ds-auth-service`  
**Rule ID:** `GDPR-5.1c-MINIMIZATION-UNUSED`  
**Regulatory Citation:** GDPR Article 5(1)(c) — data minimization  

**Description:** Service '3ds-auth-service' stores personal fields ['pan_encrypted'] that do not appear in any API endpoint or outbound data transfer. This suggests excessive collection with no clear purpose.

**Remediation:** Review whether these fields serve a documented purpose. If not, remove them from the data store schema. If they serve an undocumented purpose (e.g., internal analytics), document the lawful basis and purpose limitation.

**Affected Fields:** `pan_encrypted`  

---

### Finding 20: Full PAN stored but only last-4 digits exposed — data minimization failure

**Severity:** 🟡 MEDIUM  
**Service:** `audit-log-service`  
**Rule ID:** `GDPR-5.1c-MINIMIZATION`  
**Regulatory Citation:** GDPR Article 5(1)(c); PCI DSS v4.0 Requirement 3.3  

**Description:** Service 'audit-log-service' stores full PAN (['pan_full']) but all API endpoints only expose pan_last4. If the service doesn't need to transmit or process the full PAN, it should store only the token + last4 and delegate detokenization to the tokenization vault.

**Remediation:** Replace full PAN storage with a token from the tokenization vault. Store only pan_last4 for display purposes. The tokenization vault already provides secure PAN retrieval when needed for authorization.

**Affected Fields:** `pan_full`  

---

### Finding 21: Personal data stored but not referenced in any API or transfer

**Severity:** 🟡 MEDIUM  
**Service:** `audit-log-service`  
**Rule ID:** `GDPR-5.1c-MINIMIZATION-UNUSED`  
**Regulatory Citation:** GDPR Article 5(1)(c) — data minimization  

**Description:** Service 'audit-log-service' stores personal fields ['ip_address', 'pan_full'] that do not appear in any API endpoint or outbound data transfer. This suggests excessive collection with no clear purpose.

**Remediation:** Review whether these fields serve a documented purpose. If not, remove them from the data store schema. If they serve an undocumented purpose (e.g., internal analytics), document the lawful basis and purpose limitation.

**Affected Fields:** `ip_address`, `pan_full`  

---
