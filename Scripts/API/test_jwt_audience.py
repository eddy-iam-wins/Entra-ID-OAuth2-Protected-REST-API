
import os
import jwt

from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv
from jwt.exceptions import InvalidAudienceError

load_dotenv()

EXPECTED_AUDIENCE = os.getenv("API_AUDIENCE")

if not EXPECTED_AUDIENCE:
    raise RuntimeError("API_AUDIENCE is missing from the environment.")

# Generate a temporary RSA key pair for this isolated test.
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

now = datetime.now(timezone.utc)

def create_test_token(audience):
    claims = {
        "sub": "audience-test-user",
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(minutes=10)
    }

    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256"
    )

def validate_test_token(token):
    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=EXPECTED_AUDIENCE
    )

print("=" * 55)
print("ServiceDesk JWT Audience Validation - Isolated Test")
print("=" * 55)

# TEST 1: Correct audience
print("\nTEST 1: Correct JWT Audience")

correct_token = create_test_token(EXPECTED_AUDIENCE)

try:
    validate_test_token(correct_token)
    print("Signature validation: PASS")
    print("Audience validation: PASS")
    print("Overall Result: PASS")
except Exception as error:
    print("Overall Result: FAIL")
    print("Failure type:", type(error).__name__)

# TEST 2: Incorrect audience
print("\nTEST 2: Incorrect JWT Audience")

incorrect_token = create_test_token(
    "api://incorrect-audience-test"
)

try:
    validate_test_token(incorrect_token)
    print("Overall Result: FAIL - Incorrect audience accepted")

except InvalidAudienceError:
    print("Signature validation: PASS")
    print("Audience validation: FAIL - Incorrect audience")
    print("JWT rejected: InvalidAudienceError")
    print("Overall Result: PASS")

except Exception as error:
    print("Overall Result: FAIL")
    print("Unexpected failure type:", type(error).__name__)

print("\nTest completed.")
