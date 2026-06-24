# Data Subject Access Request Response
*Subject Customer ID: `cust_DE_87234`*
*Generated: 2026-06-23*

The following services process data that may be associated with this customer:

## payment-gateway-api
- **Region:** eu-west-1
- **Data fields potentially held:** customer_id, pan_encrypted, cvv_encrypted, card_expiry, email, billing_address, ip_address
- **Retention policy:** 7 years
- **Lawful basis:** contract

## fraud-engine
- **Region:** us-east-1
- **Data fields potentially held:** customer_id, email, ip_address, transaction_amount, pan_last4, device_fingerprint, merchant_id, email, ip_address, transaction_amount, pan_last4, fraud_score, model_version
- **Retention policy:** 3 years
- **Lawful basis:** legitimate_interest

## merchant-dashboard
- **Region:** eu-west-1
- **Data fields potentially held:** customer_id, pan_encrypted, pan_last4, email, billing_address, transaction_history, full_name
- **Retention policy:** Not documented
- **Lawful basis:** contract

## analytics-warehouse
- **Region:** us-east-1
- **Data fields potentially held:** customer_id, email, ip_address, transaction_amount, pan_last4, country, device_type, full_name
- **Retention policy:** Not documented
- **Lawful basis:** Not documented

## notification-service
- **Region:** eu-west-1
- **Data fields potentially held:** customer_id, email, phone_number, notification_preferences, last_notified_at
- **Retention policy:** 2 years
- **Lawful basis:** contract

## 3ds-auth-service
- **Region:** eu-west-1
- **Data fields potentially held:** session_id, pan_encrypted, cvv_hash, auth_attempt_count, customer_ip, customer_id, pan_encrypted, cvv_hash, auth_result, timestamp
- **Retention policy:** 1 year
- **Lawful basis:** contract

## dispute-management
- **Region:** ap-southeast-1
- **Data fields potentially held:** customer_id, pan_last4, full_name, email, billing_address, transaction_details, dispute_evidence
- **Retention policy:** 5 years
- **Lawful basis:** legal_obligation

---
> **Note:** This is an automated scan based on service metadata. A manual review by service owners is required to confirm actual data held for the specific customer ID before responding to the DSAR.