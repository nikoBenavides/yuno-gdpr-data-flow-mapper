from .models import DataCategory

# Field name patterns → data category
# Order matters: more specific patterns first

SENSITIVE_AUTH_PATTERNS = {
    "cvv", "cvc", "cvv2", "cvc2", "cvv_encrypted", "cvv_hash",
    "cvc_encrypted", "pin", "pin_block", "magnetic_stripe", "track1", "track2",
}

PAN_PATTERNS = {
    "pan", "pan_encrypted", "pan_full", "card_number", "card_number_encrypted",
    "primary_account_number",
}

# pan_last4 is NOT cardholder data per PCI DSS 3.3 — it cannot be used to reconstruct
# full PAN and is considered non-sensitive. We track it separately as metadata.
PAN_LAST4_PATTERNS = {"pan_last4", "last4", "card_last4"}

CARDHOLDER_DATA_PATTERNS = PAN_PATTERNS | {
    "card_expiry", "card_expiry_encrypted", "expiry_date", "cardholder_name",
}

PII_PATTERNS = {
    "email", "full_name", "first_name", "last_name", "phone_number", "phone",
    "billing_address", "address", "ip_address", "date_of_birth", "dob",
    "owner_dob", "owner_national_id", "national_id", "ssn", "passport_number",
    "bank_account_iban", "iban", "device_fingerprint", "customer_id",
    "owner_full_name", "id_document_scan", "proof_of_address_scan",
    # pan_last4 is not full PAN (PCI DSS 3.3) but IS personal data under GDPR
    # because combined with customer_id/email it uniquely identifies a card.
    "pan_last4", "last4", "card_last4",
}

EU_REGIONS = {
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "eu-south-1", "eu-south-2", "eu-central-2",
}

# Countries/regions with EU adequacy decisions (as of 2026)
ADEQUATE_REGIONS = {
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "eu-south-1", "eu-south-2", "eu-central-2",
    # UK post-Brexit adequacy (IDTA)
    "uk-south-1", "uk-west-1",
    # Switzerland
    "ch-zurich-1",
    # Japan
    "ap-northeast-1",
}


def classify_field(field_name: str) -> DataCategory:
    f = field_name.lower()
    if f in SENSITIVE_AUTH_PATTERNS:
        return DataCategory.SENSITIVE_AUTH
    if f in PAN_PATTERNS or f in CARDHOLDER_DATA_PATTERNS:
        return DataCategory.CARDHOLDER_PAN
    if f in PII_PATTERNS:
        return DataCategory.PII
    return DataCategory.GENERAL


def classify_fields(fields: list[str]) -> dict[DataCategory, list[str]]:
    result: dict[DataCategory, list[str]] = {}
    for f in fields:
        cat = classify_field(f)
        result.setdefault(cat, []).append(f)
    return result


def is_eu_region(region: str) -> bool:
    return region in EU_REGIONS


def is_adequate_region(region: str) -> bool:
    return region in ADEQUATE_REGIONS


def is_pan_last4(field_name: str) -> bool:
    return field_name.lower() in PAN_LAST4_PATTERNS
