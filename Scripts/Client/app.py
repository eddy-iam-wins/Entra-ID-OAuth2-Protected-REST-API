
import os
import secrets
import threading
import time
import logging
from token_analysis import (
    analyze_access_token,
    verify_access_token_claims,
    verify_least_privilege_scopes,
    analyze_token_lifetime,
)
from urllib.parse import parse_qs, urlparse

import msal
import requests
from dotenv import load_dotenv
from flask import Flask, redirect, request, session, url_for

load_dotenv()

app = Flask(__name__)

# Prevent Werkzeug from logging OAuth callback URLs
logging.getLogger("werkzeug").setLevel(logging.ERROR)

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
API_SCOPE = os.getenv("API_SCOPE")
REDIRECT_URI = os.getenv("REDIRECT_URI")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")

required_variables = {
    "TENANT_ID": TENANT_ID,
    "CLIENT_ID": CLIENT_ID,
    "CLIENT_SECRET": CLIENT_SECRET,
    "API_SCOPE": API_SCOPE,
    "REDIRECT_URI": REDIRECT_URI,
    "FLASK_SECRET_KEY": FLASK_SECRET_KEY,
}

missing = [k for k, v in required_variables.items() if not v]

if missing:
    raise RuntimeError("Missing configuration: " + ", ".join(missing))

app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"

# Local, single-process lab storage.
# Do not use this in-memory approach for production.
pending_flows = {}
completed_tokens = {}
storage_lock = threading.Lock()
graph_pending_flows = {}
graph_completed_tokens = {}

def build_msal_app():
    return msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        authority=AUTHORITY,
        client_credential=CLIENT_SECRET,
    )


@app.route("/")
def home():
    return """
    <h2>ServiceDesk Client</h2>
    <p>Microsoft Entra ID OAuth 2.0 Lab</p>
    <a href="/login">Sign in with Microsoft Entra ID</a>
    """


@app.route("/login")
def login():
    # Random identifier stored in a signed browser session.
    browser_session_id = session.get("browser_session_id")
    if not browser_session_id:
        browser_session_id = secrets.token_urlsafe(32)
        session["browser_session_id"] = browser_session_id

    # MSAL creates authorization request parameters,
    # including state, nonce, and PKCE material.
    flow = build_msal_app().initiate_auth_code_flow(
        scopes=[API_SCOPE],
        redirect_uri=REDIRECT_URI,
        response_mode="query",
    )

    if "auth_uri" not in flow:
        return "Unable to initiate authorization flow.", 500

    with storage_lock:
        pending_flows[browser_session_id] = {
            "flow": flow,
            "created_at": time.time(),
        }
        completed_tokens.pop(browser_session_id, None)

    # Confirm PKCE parameters without printing their values.
    parameters = parse_qs(urlparse(flow["auth_uri"]).query)
    pkce_enabled = (
        "code_challenge" in parameters
        and parameters.get("code_challenge_method") == ["S256"]
    )

    if not pkce_enabled:
        with storage_lock:
            pending_flows.pop(browser_session_id, None)
        return "PKCE verification failed. Authorization stopped.", 500

    print("Authorization request created.")
    print("PKCE S256 challenge present: True")
    print("OAuth state parameter present:", "state" in parameters)
    print("Requested delegated permission: Tickets.Read")

    return redirect(flow["auth_uri"])


@app.route("/getAToken", methods=["GET"])
def authorized():
    browser_session_id = session.get("browser_session_id")
    if not browser_session_id:
        return "No matching browser session.", 400

    with storage_lock:
        entry = pending_flows.pop(browser_session_id, None)

    if not entry or time.time() - entry["created_at"] > 600:
        return "Authorization flow missing or expired.", 400

    try:
        result = build_msal_app().acquire_token_by_auth_code_flow(
            entry["flow"],
            request.args.to_dict(),
        )
    except ValueError:
        return "Authorization response validation failed.", 400

    if "access_token" not in result:
        # Do not expose raw provider error details in the browser.
        print("Token acquisition unsuccessful.")
        print("Error type:", result.get("error", "unknown"))
        return "Token acquisition unsuccessful. Check server output.", 400

    with storage_lock:
        completed_tokens[browser_session_id] = {
            "access_token": result["access_token"],
            "created_at": time.time(),
        }

    print("Authorization code exchange successful.")
    print("Access token acquired: True")

    analyze_access_token(result["access_token"])

    verify_access_token_claims(result["access_token"])

    verify_least_privilege_scopes(result["access_token"])

    analyze_token_lifetime(result["access_token"])

    return redirect(url_for("success"))

@app.route("/success")
def success():
    browser_session_id = session.get("browser_session_id")

    if not browser_session_id:
        return redirect(url_for("home"))

    with storage_lock:
        token_entry = completed_tokens.get(browser_session_id)

    if not token_entry:
        return redirect(url_for("home"))

    return """
    <h2>ServiceDesk Authentication Successful</h2>
    <p>Microsoft Entra ID returned an access token.</p>
    <p>The token is stored temporarily on the local server.</p>
    <p>No token values are displayed.</p>
    <p><a href="/tickets">Access Protected ServiceDesk Tickets</a></p>
    """



@app.route("/tickets", methods=["GET"])
def view_protected_tickets():
    browser_session_id = session.get("browser_session_id")

    if not browser_session_id:
        return redirect(url_for("home"))

    with storage_lock:
        token_entry = completed_tokens.get(browser_session_id)

    if not token_entry:
        return redirect(url_for("home"))

    access_token = token_entry["access_token"]

    try:
        response = requests.get(
            "http://localhost:5001/api/tickets",
            headers={
                "Authorization": f"Bearer {access_token}"
            },
            timeout=10
        )

    except requests.RequestException:
        print("ServiceDesk API connection: FAIL")
        return "Unable to connect to ServiceDesk API.", 502

    print("ServiceDesk API HTTP status:", response.status_code)

    if response.status_code == 200:
        print("Protected ServiceDesk API request: PASS")
        return (
            "<h2>Protected ServiceDesk API Access Successful</h2>"
            "<p>HTTP 200 - OK</p>"
            "<p>The ServiceDesk API accepted the access token.</p>"
            "<p>JWT signature and claims validation succeeded.</p>"
        ), 200

    if response.status_code == 401:
        print("Protected ServiceDesk API request: FAIL - 401")
        return (
            "<h2>ServiceDesk API Authentication Failed</h2>"
            "<p>HTTP 401 - Unauthorized</p>"
        ), 401

    print("Protected ServiceDesk API request: Unexpected response")

    return (
        "<h2>ServiceDesk API Request Unsuccessful</h2>"
        f"<p>HTTP status: {response.status_code}</p>"
    ), 502




# ---------------------------------------------------------
# Step 5.5.4 - Delegated Scope Authorization Testing
# ---------------------------------------------------------

@app.route("/authorization-tests", methods=["GET"])
def test_scope_authorization():

    browser_session_id = session.get("browser_session_id")

    if not browser_session_id:
        return redirect(url_for("home"))

    with storage_lock:
        token_entry = completed_tokens.get(browser_session_id)

    if not token_entry:
        return redirect(url_for("home"))

    access_token = token_entry["access_token"]

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    test_cases = [
        {
            "name": "GET Tickets",
            "method": "GET",
            "url": "http://localhost:5001/api/tickets",
            "expected": 200
        },
        {
            "name": "POST Tickets",
            "method": "POST",
            "url": "http://localhost:5001/api/tickets",
            "expected": 403,
            "json": {
                "title": "Unauthorized ticket creation test",
                "department": "IT"
            }
        },
        {
            "name": "GET Reports",
            "method": "GET",
            "url": "http://localhost:5001/api/reports",
            "expected": 403
        }
    ]

    results = []

    for test in test_cases:
        try:
            response = requests.request(
                method=test["method"],
                url=test["url"],
                headers=headers,
                json=test.get("json"),
                timeout=10
            )

            actual_status = response.status_code
            passed = actual_status == test["expected"]

            print(
                "Authorization Test:",
                test["name"],
                "| Expected:", test["expected"],
                "| Actual:", actual_status,
                "| Result:", "PASS" if passed else "FAIL"
            )

            results.append({
                "name": test["name"],
                "expected": test["expected"],
                "actual": actual_status,
                "passed": passed
            })

        except requests.RequestException:
            print(
                "Authorization Test:",
                test["name"],
                "| Connection: FAIL"
            )

            results.append({
                "name": test["name"],
                "expected": test["expected"],
                "actual": "Connection Error",
                "passed": False
            })

    all_passed = all(result["passed"] for result in results)

    rows = ""

    for result in results:
        status = "PASS" if result["passed"] else "FAIL"

        rows += (
            "<tr>"
            f"<td>{result['name']}</td>"
            f"<td>{result['expected']}</td>"
            f"<td>{result['actual']}</td>"
            f"<td>{status}</td>"
            "</tr>"
        )

    overall = "PASS" if all_passed else "FAIL"

    html = (
        "<h2>ServiceDesk OAuth 2.0 Authorization Tests</h2>"
        f"<h3>Overall Result: {overall}</h3>"
        "<table border='1' cellpadding='8'>"
        "<tr>"
        "<th>Operation</th>"
        "<th>Expected HTTP</th>"
        "<th>Actual HTTP</th>"
        "<th>Result</th>"
        "</tr>"
        f"{rows}"
        "</table>"
    )

    return html, 200 if all_passed else 500




# ---------------------------------------------------------
# Step 5.5.6.2 - JWT Signature Tampering Test
# ---------------------------------------------------------

@app.route("/signature-tampering-test", methods=["GET"])
def test_signature_tampering():

    browser_session_id = session.get("browser_session_id")

    if not browser_session_id:
        return redirect(url_for("home"))

    with storage_lock:
        token_entry = completed_tokens.get(browser_session_id)

    if not token_entry:
        return redirect(url_for("home"))

    original_token = token_entry["access_token"]

    # A JWT must contain exactly three sections.
    parts = original_token.split(".")

    if len(parts) != 3 or not all(parts):
        return "Original access token is malformed.", 500

    header, payload, signature = parts

    # Change the first Base64URL character of the signature.
    # This changes the decoded signature bytes.
    replacement = "A" if signature[0] != "A" else "B"
    modified_signature = replacement + signature[1:]

    tampered_token = (
        f"{header}.{payload}.{modified_signature}"
    )

    # Confirm that only the signature was modified.
    structure_preserved = (
        tampered_token.split(".")[:2] == parts[:2]
        and modified_signature != signature
    )

    if not structure_preserved:
        return "Signature tampering preparation failed.", 500

    try:
        # Control test: original token should be accepted.
        original_response = requests.get(
            "http://localhost:5001/api/tickets",
            headers={
                "Authorization": f"Bearer {original_token}"
            },
            timeout=10
        )

        # Negative test: modified signature should be rejected.
        tampered_response = requests.get(
            "http://localhost:5001/api/tickets",
            headers={
                "Authorization": f"Bearer {tampered_token}"
            },
            timeout=10
        )

    except requests.RequestException:
        print("JWT signature tampering test: Connection FAIL")
        return "Unable to connect to ServiceDesk API.", 502

    original_status = original_response.status_code
    tampered_status = tampered_response.status_code

    passed = (
        original_status == 200
        and tampered_status == 401
    )

    print("JWT signature tampering test")
    print("JWT header unchanged: True")
    print("JWT payload unchanged: True")
    print("JWT signature modified: True")
    print("Original token HTTP status:", original_status)
    print("Tampered token HTTP status:", tampered_status)
    print(
        "Signature integrity enforcement:",
        "PASS" if passed else "FAIL"
    )

    result = "PASS" if passed else "FAIL"

    html = (
        "<h2>ServiceDesk JWT Signature Tampering Test</h2>"
        "<p>JWT header unchanged: True</p>"
        "<p>JWT payload unchanged: True</p>"
        "<p>JWT signature modified: True</p>"
        f"<p>Original token HTTP status: {original_status}</p>"
        f"<p>Tampered token HTTP status: {tampered_status}</p>"
        f"<h3>Overall Result: {result}</h3>"
    )

    return html, 200 if passed else 500



# ---------------------------------------------------------
# Step 5.5.6.3 - Access Token Expiration Check
# ---------------------------------------------------------

@app.route("/token-expiration-check", methods=["GET"])
def token_expiration_check():

    browser_session_id = session.get("browser_session_id")

    if not browser_session_id:
        return redirect(url_for("home"))

    with storage_lock:
        token_entry = completed_tokens.get(browser_session_id)

    if not token_entry:
        return redirect(url_for("home"))

    import base64
    import json
    from datetime import datetime, timezone

    access_token = token_entry["access_token"]

    try:
        payload_segment = access_token.split(".")[1]
        padding = "=" * (-len(payload_segment) % 4)

        claims = json.loads(
            base64.urlsafe_b64decode(
                payload_segment + padding
            )
        )

        expiration = int(claims["exp"])

    except (IndexError, ValueError, KeyError, TypeError):
        return "Unable to read token expiration.", 500

    now = int(time.time())
    remaining_seconds = expiration - now
    remaining_minutes = round(remaining_seconds / 60, 2)

    expiration_utc = datetime.fromtimestamp(
        expiration, timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")

    status = "EXPIRED" if remaining_seconds <= 0 else "VALID"

    return (
        "<h2>ServiceDesk Access Token Expiration Check</h2>"
        f"<p>Expiration: {expiration_utc}</p>"
        f"<p>Remaining minutes: {remaining_minutes}</p>"
        f"<h3>Token Status: {status}</h3>"
        "<p>Token contents are not displayed.</p>"
    )



# ---------------------------------------------------------
# Step 5.5.6.4 - Microsoft Graph Authentication
# Incorrect JWT Audience Security Testing
# ---------------------------------------------------------

@app.route("/graph-login", methods=["GET"])
def graph_login():

    browser_session_id = session.get("browser_session_id")

    if not browser_session_id:
        browser_session_id = secrets.token_urlsafe(32)
        session["browser_session_id"] = browser_session_id

    flow = build_msal_app().initiate_auth_code_flow(
        scopes=["User.Read"],
        redirect_uri="http://localhost:5000/graph-callback",
        response_mode="query",
    )

    if "auth_uri" not in flow:
        return "Unable to initiate Microsoft Graph authorization.", 500

    parameters = parse_qs(urlparse(flow["auth_uri"]).query)

    pkce_enabled = (
        "code_challenge" in parameters
        and parameters.get("code_challenge_method") == ["S256"]
    )

    if not pkce_enabled:
        return "Graph authorization PKCE verification failed.", 500

    with storage_lock:
        graph_pending_flows[browser_session_id] = {
            "flow": flow,
            "created_at": time.time(),
        }
        graph_completed_tokens.pop(browser_session_id, None)

    print("Microsoft Graph authorization request created.")
    print("Graph delegated permission requested: User.Read")
    print("Graph PKCE S256 challenge present: True")

    return redirect(flow["auth_uri"])


@app.route("/graph-callback", methods=["GET"])
def graph_callback():

    browser_session_id = session.get("browser_session_id")

    if not browser_session_id:
        return "No matching Graph browser session.", 400

    with storage_lock:
        entry = graph_pending_flows.pop(browser_session_id, None)

    if not entry or time.time() - entry["created_at"] > 600:
        return "Graph authorization flow missing or expired.", 400

    try:
        result = build_msal_app().acquire_token_by_auth_code_flow(
            entry["flow"],
            request.args.to_dict(),
        )
    except ValueError:
        return "Graph authorization response validation failed.", 400
    except requests.RequestException:
        print("Microsoft Graph authentication: Network connection failed")
        return "Unable to contact Microsoft Entra ID.", 502

    if "access_token" not in result:
        print("Microsoft Graph token acquisition: FAIL")
        print("Error type:", result.get("error", "unknown"))
        return "Microsoft Graph token acquisition unsuccessful.", 400

    with storage_lock:
        graph_completed_tokens[browser_session_id] = {
            "access_token": result["access_token"],
            "created_at": time.time(),
        }

    print("Microsoft Graph authorization code exchange: PASS")
    print("Microsoft Graph access token acquired: True")

    return (
        "<h2>Microsoft Graph Authentication Successful</h2>"
        "<p>A Microsoft Graph access token was acquired.</p>"
        "<p>The token is stored temporarily on the local server.</p>"
        "<p>No access token values are displayed.</p>"
    ), 200



# ---------------------------------------------------------
# Step 5.5.6.4 - Incorrect JWT Audience Test
# ---------------------------------------------------------

@app.route("/incorrect-audience-test", methods=["GET"])
def incorrect_audience_test():

    browser_session_id = session.get("browser_session_id")

    if not browser_session_id:
        return redirect(url_for("home"))

    with storage_lock:
        token_entry = graph_completed_tokens.get(browser_session_id)

    if not token_entry:
        return (
            "No Graph token available. "
            "Please authenticate at /graph-login."
        ), 400

    access_token = token_entry["access_token"]

    # Decode claims for inspection only.
    # The API will perform actual cryptographic validation.
    import jwt

    try:
        claims = jwt.decode(
            access_token,
            options={"verify_signature": False}
        )
    except jwt.InvalidTokenError:
        return "Unable to inspect Graph token claims.", 500

    actual_audience = claims.get("aud")

    graph_audience = (
        "00000003-0000-0000-c000-000000000000"
    )

    if actual_audience != graph_audience:
        print("Graph audience verification: FAIL")
        return "Token audience is not Microsoft Graph.", 500

    try:
        response = requests.get(
            "http://localhost:5001/api/tickets",
            headers={
                "Authorization": f"Bearer {access_token}"
            },
            timeout=10
        )
    except requests.RequestException:
        return "ServiceDesk API connection failed.", 502

    passed = response.status_code == 401

    print("Incorrect JWT Audience Test")
    print("Graph token audience confirmed: True")
    print("ServiceDesk API HTTP status:", response.status_code)
    print(
        "Incorrect audience rejection:",
        "PASS" if passed else "FAIL"
    )

    result = "PASS" if passed else "FAIL"

    html = (
        "<h2>ServiceDesk Incorrect JWT Audience Test</h2>"
        "<p>Token audience: Microsoft Graph</p>"
        "<p>Expected audience: ServiceDesk API</p>"
        f"<p>ServiceDesk API HTTP status: {response.status_code}</p>"
        f"<h3>Overall Result: {result}</h3>"
        "<p>No access token values are displayed.</p>"
    )

    return html, 200 if passed else 500



if __name__ == "__main__":
    app.run(
        host="localhost",
        port=5000,
        debug=False,
        use_reloader=False,
    )
