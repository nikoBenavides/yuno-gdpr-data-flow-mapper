# GDPR Article 30 — Data Processing Inventory
*Generated: 2026-06-23 | Classification: CONFIDENTIAL*

> This register is maintained pursuant to GDPR Article 30 (Records of Processing Activities).
> It must be made available to supervisory authorities on request.

## payment-gateway-api

| Attribute | Value |
|-----------|-------|
| **Description** | Primary payment processing API that handles charge requests from merchants |
| **Owner** | payments-team |
| **Region** | eu-west-1 |
| **Lawful Basis** | contract |
| **Retention Policy** | 7 years |
| **Cross-Border Transfers** | tokenization-vault (eu-west-1) [internal_eu]; fraud-engine (us-east-1) [⚠️ NO SAFEGUARD] |

**Data Categories Processed:**

- Sensitive Auth Data: ['cvv_encrypted']
- Cardholder Data (PAN): ['pan_encrypted', 'card_expiry']
- PII: ['customer_id', 'email', 'billing_address', 'ip_address']

## tokenization-vault

| Attribute | Value |
|-----------|-------|
| **Description** | Stores and manages encrypted PANs, issuing tokens for downstream services |
| **Owner** | security-team |
| **Region** | eu-west-1 |
| **Lawful Basis** | contract |
| **Retention Policy** | 10 years |
| **Cross-Border Transfers** | None |

**Data Categories Processed:**

- Cardholder Data (PAN): ['pan_encrypted', 'card_expiry_encrypted']

## fraud-engine

| Attribute | Value |
|-----------|-------|
| **Description** | ML-based fraud detection service; scores transactions in real time |
| **Owner** | risk-team |
| **Region** | us-east-1 |
| **Lawful Basis** | legitimate_interest |
| **Retention Policy** | 3 years |
| **Cross-Border Transfers** | analytics-warehouse (us-east-1) [⚠️ NO SAFEGUARD] |

**Data Categories Processed:**

- PII: ['customer_id', 'email', 'ip_address', 'device_fingerprint', 'email', 'ip_address']

## merchant-dashboard

| Attribute | Value |
|-----------|-------|
| **Description** | Web portal for merchants to view transactions, refunds, and cardholder data |
| **Owner** | merchant-team |
| **Region** | eu-west-1 |
| **Lawful Basis** | contract |
| **Retention Policy** | ⚠️ NOT DOCUMENTED |
| **Cross-Border Transfers** | None |

**Data Categories Processed:**

- Cardholder Data (PAN): ['pan_encrypted']
- PII: ['customer_id', 'email', 'billing_address', 'full_name']

## analytics-warehouse

| Attribute | Value |
|-----------|-------|
| **Description** | Business intelligence and reporting warehouse; aggregates payment data for dashboards |
| **Owner** | data-team |
| **Region** | us-east-1 |
| **Lawful Basis** | ⚠️ NOT DOCUMENTED |
| **Retention Policy** | ⚠️ NOT DOCUMENTED |
| **Cross-Border Transfers** | None |

**Data Categories Processed:**

- PII: ['customer_id', 'email', 'ip_address', 'full_name']

## notification-service

| Attribute | Value |
|-----------|-------|
| **Description** | Sends transactional emails and SMS to cardholders for payment confirmations and alerts |
| **Owner** | comms-team |
| **Region** | eu-west-1 |
| **Lawful Basis** | contract |
| **Retention Policy** | 2 years |
| **Cross-Border Transfers** | sendgrid-external (us-east-1) [scc] |

**Data Categories Processed:**

- PII: ['customer_id', 'email', 'phone_number', 'date_of_birth', 'billing_address', 'full_name', 'ip_address']

## merchant-onboarding

| Attribute | Value |
|-----------|-------|
| **Description** | KYC/AML onboarding workflow for new merchants; stores identity verification data |
| **Owner** | compliance-team |
| **Region** | eu-west-1 |
| **Lawful Basis** | legal_obligation |
| **Retention Policy** | 5 years |
| **Cross-Border Transfers** | kyc-provider-external (eu-central-1) [internal_eu] |

**Data Categories Processed:**

- PII: ['owner_full_name', 'owner_dob', 'owner_national_id', 'bank_account_iban', 'id_document_scan', 'proof_of_address_scan']

## 3ds-auth-service

| Attribute | Value |
|-----------|-------|
| **Description** | Handles 3D Secure authentication challenges for card-present and card-not-present transactions |
| **Owner** | payments-team |
| **Region** | eu-west-1 |
| **Lawful Basis** | contract |
| **Retention Policy** | 1 year |
| **Cross-Border Transfers** | None |

**Data Categories Processed:**

- Sensitive Auth Data: ['cvv_hash', 'cvv_hash']
- Cardholder Data (PAN): ['pan_encrypted', 'pan_encrypted']
- PII: ['customer_id']

## audit-log-service

| Attribute | Value |
|-----------|-------|
| **Description** | Centralized audit log for all access to cardholder data; required for PCI DSS Requirement 10 |
| **Owner** | security-team |
| **Region** | eu-west-1 |
| **Lawful Basis** | legal_obligation |
| **Retention Policy** | 1 year |
| **Cross-Border Transfers** | None |

**Data Categories Processed:**

- Cardholder Data (PAN): ['pan_full']
- PII: ['ip_address']

## dispute-management

| Attribute | Value |
|-----------|-------|
| **Description** | Manages chargeback disputes and evidence collection between merchants and card networks |
| **Owner** | operations-team |
| **Region** | ap-southeast-1 |
| **Lawful Basis** | legal_obligation |
| **Retention Policy** | 5 years |
| **Cross-Border Transfers** | card-network-visa (us-east-1) [⚠️ NO SAFEGUARD] |

**Data Categories Processed:**

- PII: ['customer_id', 'full_name', 'email', 'billing_address']
