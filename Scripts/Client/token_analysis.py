
import base64
import json
import time
from datetime import datetime, timezone

import os

from urllib.parse import urlparse

from dotenv import load_dotenv


def decode_jwt_segment(segment):
    padding = "=" * (-len(segment) % 4)
    decoded = base64.urlsafe_b64decode(segment + padding)
    return json.loads(decoded)


def analyze_access_token(access_token):
    parts = access_token.split(".")

    if len(parts) != 3:
        print("Access token is not a three-part JWT.")
        return

    try:
        header = decode_jwt_segment(parts[0])
        payload = decode_jwt_segment(parts[1])
    except (ValueError, UnicodeDecodeError) as error:
        print("Unable to decode JWT header or payload.")
        return

    print("\n=== JWT HEADER ===")
    print("Token type:", header.get("typ"))
    print("Signing algorithm:", header.get("alg"))
    print("Key ID present:", bool(header.get("kid")))

    print("\n=== ACCESS TOKEN CLAIMS ===")
    print("Audience (aud):", payload.get("aud"))
    print("Issuer present (iss):", bool(payload.get("iss")))

    print("Token version (ver):", payload.get("ver"))
    print(
    "Issuer format (iss):",
    "v2.0" if payload.get("iss", "").endswith("/v2.0")
    else "Other"
)
    print("Tenant ID present (tid):", bool(payload.get("tid")))
    print("Object ID present (oid):", bool(payload.get("oid")))
    print("Delegated scopes (scp):", payload.get("scp"))
    print("Application ID present:", bool(
        payload.get("azp") or payload.get("appid")
    ))

    expiration = payload.get("exp")

    if isinstance(expiration, (int, float)):
        expires_at = datetime.fromtimestamp(
            expiration, tz=timezone.utc
        )
        print("Expiration (UTC):", expires_at.isoformat())
    else:
        print("Expiration (exp): Missing or invalid")

    print("\nJWT decoding completed.")
    print("JWT signature has NOT been validated.")





def verify_access_token_claims(access_token):
    load_dotenv()

    tenant_id = os.getenv("TENANT_ID")
    client_id = os.getenv("CLIENT_ID")
    api_scope = os.getenv("API_SCOPE")

    if not all([tenant_id, client_id, api_scope]):
        print("Verification configuration missing.")
        return False

    # API_SCOPE is configured as:
    # api://<ServiceDesk-API-ID>/Tickets.Read
    expected_audience = api_scope.rsplit("/", 1)[0]
    expected_scope = api_scope.rsplit("/", 1)[-1]

    parts = access_token.split(".")

    if len(parts) != 3:
        print("Invalid JWT structure.")
        return False

    try:
        payload = decode_jwt_segment(parts[1])
    except (ValueError, UnicodeDecodeError):
        print("Unable to decode token payload.")
        return False

    now = int(time.time())
    clock_skew = 60

    actual_audience = payload.get("aud")
    actual_issuer = payload.get("iss")
    actual_tenant = payload.get("tid")
    actual_scopes = payload.get("scp", "")
    actual_client = payload.get("azp") or payload.get("appid")

    expected_issuers = {
        f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        f"https://sts.windows.net/{tenant_id}/",
    }

    checks = {
        "Audience matches ServiceDesk API":
            actual_audience == expected_audience,

        "Issuer matches Microsoft Entra ID tenant":
            actual_issuer in expected_issuers,

        "Tenant ID matches configuration":
            actual_tenant == tenant_id,

        "Client application ID matches":
            actual_client == client_id,

        "Tickets.Read delegated scope granted":
            expected_scope in actual_scopes.split(),

        "Token has not expired":
            isinstance(payload.get("exp"), (int, float))
            and now < payload["exp"] + clock_skew,

        "Token is valid for current time":
            isinstance(payload.get("nbf"), (int, float))
            and now + clock_skew >= payload["nbf"],

        "Token issuance time is not in future":
            isinstance(payload.get("iat"), (int, float))
            and now + clock_skew >= payload["iat"],
    }

    print("\n=== ACCESS TOKEN CLAIM VERIFICATION ===")

    for name, passed in checks.items():
        status = "PASS" if passed else "FAIL"
        print(f"{name}: {status}")

    all_passed = all(checks.values())

    print("\nOverall claim verification:",
          "PASS" if all_passed else "FAIL")

    print("JWT signature has NOT been validated.")

    return all_passed





def verify_least_privilege_scopes(access_token):
    parts = access_token.split(".")

    if len(parts) != 3:
        print("Invalid JWT structure.")
        return False

    try:
        payload = decode_jwt_segment(parts[1])
    except (ValueError, UnicodeDecodeError):
        print("Unable to decode token payload.")
        return False

    # Delegated permissions issued in the access token.
    scopes_value = payload.get("scp")

    if not isinstance(scopes_value, str):
        print("Delegated scope claim missing or invalid.")
        return False

    issued_scopes = set(scopes_value.split())

    required_scopes = {"Tickets.Read"}
    unauthorized_scopes = {"Tickets.Write", "Reports.Read"}

    required_present = required_scopes.issubset(issued_scopes)
    privileged_absent = issued_scopes.isdisjoint(unauthorized_scopes)

    # For this lab, the token should contain exactly Tickets.Read.
    exact_scope_match = issued_scopes == required_scopes

    print("\n=== DELEGATED SCOPE VERIFICATION ===")

    print(
        "Tickets.Read permission present:",
        "PASS" if required_present else "FAIL"
    )

    print(
        "Tickets.Write permission absent:",
        "PASS" if "Tickets.Write" not in issued_scopes else "FAIL"
    )

    print(
        "Reports.Read permission absent:",
        "PASS" if "Reports.Read" not in issued_scopes else "FAIL"
    )

    print(
        "Only expected delegated scopes issued:",
        "PASS" if exact_scope_match else "FAIL"
    )

    all_passed = (
        required_present
        and privileged_absent
        and exact_scope_match
    )

    print(
        "\nOverall least-privilege verification:",
        "PASS" if all_passed else "FAIL"
    )

    print("JWT signature has NOT been validated.")

    return all_passed



def analyze_token_lifetime(access_token):
    parts = access_token.split(".")

    if len(parts) != 3:
        print("Invalid JWT structure.")
        return False

    try:
        payload = decode_jwt_segment(parts[1])
    except (ValueError, UnicodeDecodeError):
        print("Unable to decode token payload.")
        return False

    issued_at = payload.get("iat")
    not_before = payload.get("nbf")
    expires_at = payload.get("exp")

    print("\n=== ACCESS TOKEN LIFETIME ANALYSIS ===")

    timestamps = [issued_at, not_before, expires_at]

    if any(
        not isinstance(value, int) or isinstance(value, bool)
        for value in timestamps
    ):
        print("Required token timestamps missing or invalid.")
        return False

    issued_datetime = datetime.fromtimestamp(
        issued_at, tz=timezone.utc
    )
    valid_from_datetime = datetime.fromtimestamp(
        not_before, tz=timezone.utc
    )
    expiration_datetime = datetime.fromtimestamp(
        expires_at, tz=timezone.utc
    )

    total_lifetime_seconds = expires_at - issued_at
    current_time = int(time.time())
    remaining_seconds = max(0, expires_at - current_time)

    print("Issued at (UTC):", issued_datetime.isoformat())
    print("Valid from (UTC):", valid_from_datetime.isoformat())
    print("Expires at (UTC):", expiration_datetime.isoformat())

    print(
        "Total token lifetime (minutes):",
        round(total_lifetime_seconds / 60, 2)
    )

    print(
        "Remaining token lifetime (minutes):",
        round(remaining_seconds / 60, 2)
    )

    issued_before_expiration = issued_at < expires_at
    valid_before_expiration = not_before < expires_at
    token_currently_valid = (
        not_before <= current_time < expires_at
    )

    print(
        "Issuance precedes expiration:",
        "PASS" if issued_before_expiration else "FAIL"
    )

    print(
        "Valid-from precedes expiration:",
        "PASS" if valid_before_expiration else "FAIL"
    )

    print(
        "Token currently within validity window:",
        "PASS" if token_currently_valid else "FAIL"
    )

    all_passed = (
        issued_before_expiration
        and valid_before_expiration
        and token_currently_valid
    )

    print(
        "\nOverall token lifetime analysis:",
        "PASS" if all_passed else "FAIL"
    )

    print("JWT signature has NOT been validated.")

    return all_passed

