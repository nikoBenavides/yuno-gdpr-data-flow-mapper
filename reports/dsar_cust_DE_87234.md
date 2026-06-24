# GDPR Data Subject Access Request — Scoping Report
*Subject Customer ID: `cust_DE_87234`*
*Generated: 2026-06-23 | Must respond within 30 days (GDPR Art. 15)*

## Scope

This report identifies every service whose schema contains customer-linked fields.
**Action required:** Each service owner must confirm whether a record for
`cust_DE_87234` exists and provide the actual data for the DSAR response.

---

## payment-gateway-api

| Attribute | Value |
|-----------|-------|
| Region | eu-west-1 |
| Lawful Basis | contract |
| Retention | 7 years |

**Data disclosable to subject (Art. 15):** email, billing_address, ip_address

**Sensitive fields (redact from DSAR response):** pan_encrypted, cvv_encrypted

**Subject's data transferred to:** fraud-engine (us-east-1) *(must disclose recipients under Art. 15(1)(c))*

---

## fraud-engine

| Attribute | Value |
|-----------|-------|
| Region | us-east-1 |
| Lawful Basis | legitimate_interest |
| Retention | 3 years |

**Data disclosable to subject (Art. 15):** email, ip_address, pan_last4, device_fingerprint, fraud_score

**Subject's data transferred to:** analytics-warehouse (us-east-1) *(must disclose recipients under Art. 15(1)(c))*

---

## merchant-dashboard

| Attribute | Value |
|-----------|-------|
| Region | eu-west-1 |
| Lawful Basis | contract |
| Retention | ⚠️ Not documented |

**Data disclosable to subject (Art. 15):** pan_last4, email, billing_address, transaction_history, full_name

**Sensitive fields (redact from DSAR response):** pan_encrypted

---

## analytics-warehouse

| Attribute | Value |
|-----------|-------|
| Region | us-east-1 |
| Lawful Basis | ⚠️ Not documented |
| Retention | ⚠️ Not documented |

**Data disclosable to subject (Art. 15):** email, ip_address, pan_last4, full_name

---

## notification-service

| Attribute | Value |
|-----------|-------|
| Region | eu-west-1 |
| Lawful Basis | contract |
| Retention | 2 years |

**Data disclosable to subject (Art. 15):** email, phone_number, notification_preferences, date_of_birth, billing_address, full_name, ip_address

**Subject's data transferred to:** sendgrid-external (us-east-1) *(must disclose recipients under Art. 15(1)(c))*

---

## 3ds-auth-service

| Attribute | Value |
|-----------|-------|
| Region | eu-west-1 |
| Lawful Basis | contract |
| Retention | 1 year |

**Data disclosable to subject (Art. 15):** None identified

**Sensitive fields (redact from DSAR response):** pan_encrypted, cvv_hash

---

## dispute-management

| Attribute | Value |
|-----------|-------|
| Region | ap-southeast-1 |
| Lawful Basis | legal_obligation |
| Retention | 5 years |

**Data disclosable to subject (Art. 15):** pan_last4, full_name, email, billing_address, dispute_evidence

**Subject's data transferred to:** card-network-visa (us-east-1) *(must disclose recipients under Art. 15(1)(c))*

---

> **Legal Note:** This automated report covers schema-level scope only.
> Before sending the DSAR response, each service owner must attest to the
> presence/absence of a record for this customer and provide actual field values.
> CVV, full PAN, and encrypted fields must never be included in DSAR responses.