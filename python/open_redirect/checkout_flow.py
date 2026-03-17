from flask import Flask, request, redirect

app = Flask(__name__)


# VULN 1: Open redirect after login - next parameter not validated
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if authenticate(username, password):
        next_url = request.args.get("next", "/dashboard")
        return redirect(next_url)
    return "Login failed", 401


# VULN 2: Open redirect after checkout - return_url not validated against whitelist
@app.route("/checkout/complete")
def checkout_complete():
    return_url = request.args.get("return_url", "/orders")
    return redirect(return_url)


# VULN 3: Open redirect in OAuth callback - state parameter used as redirect target
@app.route("/oauth/callback")
def oauth_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    # exchange code for token...
    return redirect(state)


def authenticate(username, password):
    return True
