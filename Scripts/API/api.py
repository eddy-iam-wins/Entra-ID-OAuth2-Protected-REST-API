from functools import wraps

from flask import Flask, jsonify, request
from jwt.exceptions import InvalidTokenError, PyJWKClientError

from token_validator import validate_access_token

app = Flask(__name__)



def require_authentication(view_function):
    @wraps(view_function)
    def wrapper(*args, **kwargs):
        authorization = request.headers.get(
            "Authorization", ""
        )

        parts = authorization.split()

        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({
                "error": "Unauthorized",
                "message": "A bearer access token is required."
            }), 401

        access_token = parts[1]

        try:
            verified_claims = validate_access_token(
                access_token
            )

        except InvalidTokenError:
            return jsonify({
                "error": "Unauthorized",
                "message": "Invalid or expired access token."
            }), 401

        except PyJWKClientError:
            return jsonify({
                "error": "Unauthorized",
                "message": "Token signing key could not be verified."
            }), 401

        request.verified_claims = verified_claims

        return view_function(*args, **kwargs)

    return wrapper


def require_scope(required_scope):
    """
    Enforce a delegated OAuth 2.0 permission
    after the access token has been validated.
    """

    def decorator(view_function):
        @wraps(view_function)
        def wrapper(*args, **kwargs):

            verified_claims = getattr(
                request, "verified_claims", None
            )

            if verified_claims is None:
                return jsonify({
                    "error": "Unauthorized",
                    "message": "Token authentication is required."
                }), 401

            scopes_value = verified_claims.get("scp", "")

            if not isinstance(scopes_value, str):
                scopes_value = ""

            granted_scopes = set(scopes_value.split())

            if required_scope not in granted_scopes:
                print(
                    "OAuth scope authorization: FAIL",
                    "- Required scope:",
                    required_scope
                )

                return jsonify({
                    "error": "Forbidden",
                    "message": "Insufficient delegated permissions.",
                    "required_scope": required_scope
                }), 403

            print(
                "OAuth scope authorization: PASS",
                "- Required scope:",
                required_scope
            )

            return view_function(*args, **kwargs)

        return wrapper

    return decorator


# Simulated ServiceDesk ticket database
tickets = [
    {
        "ticket_id": 1001,
        "title": "Unable to access email",
        "status": "Open",
        "department": "IT"
    },
    {
        "ticket_id": 1002,
        "title": "Password reset request",
        "status": "In Progress",
        "department": "Help Desk"
    },
    {
        "ticket_id": 1003,
        "title": "VPN connection issue",
        "status": "Resolved",
        "department": "IT"
    }
]


# -----------------------------------------
# Health Check
# -----------------------------------------

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "service": "ServiceDesk API",
        "status": "running"
    }), 200


# -----------------------------------------
# GET /api/tickets
# Future permission: Tickets.Read
# -----------------------------------------

@app.route("/api/tickets", methods=["GET"])
@require_authentication
@require_scope("Tickets.Read")
def get_tickets():
    return jsonify({
        "message": "ServiceDesk tickets retrieved successfully",
        "tickets": tickets
    }), 200


# -----------------------------------------
# POST /api/tickets
# Future permission: Tickets.Write
# -----------------------------------------

@app.route("/api/tickets", methods=["POST"])
@require_authentication
@require_scope("Tickets.Write")
def create_ticket():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "A JSON object is required"
        }), 400

    title = data.get("title")
    department = data.get("department")

    if not isinstance(title, str) or not title.strip():
        return jsonify({
            "error": "A non-empty ticket title is required"
        }), 400

    if not isinstance(department, str) or not department.strip():
        return jsonify({
            "error": "A non-empty department is required"
        }), 400

    new_ticket = {
        "ticket_id": max(
            ticket["ticket_id"] for ticket in tickets
        ) + 1,
        "title": title.strip(),
        "status": "Open",
        "department": department.strip()
    }

    tickets.append(new_ticket)

    return jsonify({
        "message": "ServiceDesk ticket created successfully",
        "ticket": new_ticket
    }), 201


# -----------------------------------------
# GET /api/reports
# Future permission: Reports.Read
# -----------------------------------------

@app.route("/api/reports", methods=["GET"])
@require_authentication
@require_scope("Reports.Read")
def get_reports():
    return jsonify({
        "report_name": "ServiceDesk Ticket Summary",
        "total_tickets": len(tickets),
        "open_tickets": sum(
            ticket["status"] == "Open"
            for ticket in tickets
        ),
        "resolved_tickets": sum(
            ticket["status"] == "Resolved"
            for ticket in tickets
        )
    }), 200


# -----------------------------------------
# Start ServiceDesk API
# -----------------------------------------

if __name__ == "__main__":
    app.run(
        host="localhost",
        port=5001,
        debug=False,
        use_reloader=False
    )
