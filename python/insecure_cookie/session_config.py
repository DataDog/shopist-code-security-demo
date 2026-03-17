from flask import Flask, make_response, request

app = Flask(__name__)


# VULN 1: Session cookie set without Secure flag - transmitted over HTTP
@app.route("/login", methods=["POST"])
def login():
    response = make_response({"status": "ok"})
    response.set_cookie(
        "session_id",
        value="abc123",
        httponly=True,
        secure=False,  # missing Secure flag
        samesite="Lax",
    )
    return response


# VULN 2: Auth cookie set without HttpOnly flag - accessible via JavaScript (XSS risk)
@app.route("/auth/token")
def set_auth_token():
    token = generate_token()
    response = make_response({"status": "authenticated"})
    response.set_cookie(
        "auth_token",
        value=token,
        httponly=False,  # missing HttpOnly flag
        secure=True,
        samesite="Strict",
    )
    return response


# VULN 3: Remember-me cookie with no expiry controls and no SameSite
@app.route("/remember-me")
def set_remember_me_cookie():
    user_id = request.args.get("user_id")
    response = make_response({"remembered": True})
    response.set_cookie("remember_me", value=user_id)  # no Secure, HttpOnly, or SameSite
    return response


def generate_token():
    return "tok_abc123"
