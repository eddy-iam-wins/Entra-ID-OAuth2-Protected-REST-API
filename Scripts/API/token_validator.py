
import os

import jwt
from dotenv import load_dotenv
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
API_AUDIENCE = os.getenv("API_AUDIENCE")

if not TENANT_ID or not API_AUDIENCE:
    raise RuntimeError(
        "Missing TENANT_ID or API_AUDIENCE in API configuration."
    )

# This lab uses the v2.0 issuer format.
EXPECTED_ISSUER = (
    f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
)

JWKS_URL = (
    f"https://login.microsoftonline.com/{TENANT_ID}"
    "/discovery/v2.0/keys"
)

# Retrieve and cache Microsoft's public signing keys.
jwks_client = PyJWKClient(
    JWKS_URL,
    cache_jwk_set=True,
    lifespan=300
)



def validate_access_token(access_token):
    """
    Validate a Microsoft Entra ID access token.

    Returns verified claims when successful.
    Raises InvalidTokenError when validation fails.
    """

    try:
        # Check that the JWT header is well-formed.
        try:
            jwt.get_unverified_header(access_token)
        except jwt.InvalidTokenError as error:
            raise InvalidTokenError(
                "Malformed JWT header."
            ) from error

        # Retrieve the Microsoft Entra ID signing key.
        signing_key = jwks_client.get_signing_key_from_jwt(
            access_token
        )

        # Verify the signature and expected claims.
        claims = jwt.decode(
            access_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=API_AUDIENCE,
            issuer=EXPECTED_ISSUER,
            leeway=60,
            options={
                "require": [
                    "exp",
                    "iat",
                    "nbf",
                    "aud",
                    "iss",
                    "tid"
                ]
            }
        )

        if claims.get("tid") != TENANT_ID:
            raise InvalidTokenError(
                "Token tenant does not match."
            )

        print("JWT signature validation: PASS")
        print("JWT audience validation: PASS")
        print("JWT issuer validation: PASS")
        print("JWT lifetime validation: PASS")
        print("JWT tenant validation: PASS")

        return claims

  

    except jwt.ExpiredSignatureError:
        print("JWT expiration validation: FAIL - Token expired")
        raise

    except jwt.InvalidAudienceError:
        print("JWT audience validation: FAIL - Incorrect audience")
        raise

    except InvalidTokenError as error:
        print("JWT access token validation: FAIL")
        print("JWT failure type:", type(error).__name__)
        raise

