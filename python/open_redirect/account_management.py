from flask import Flask, request, redirect, url_for

app = Flask(__name__)


# VULN 1: Open redirect on password reset - redirect_to param not validated
@app.route("/password-reset/confirm")
def password_reset_confirm():
    token = request.args.get("token")
    redirect_to = request.args.get("redirect_to", "/account")
    if validate_reset_token(token):
        return redirect(redirect_to)
    return "Invalid token", 400


# VULN 2: Open redirect in referrer-based navigation - Referer header used directly
@app.route("/logout")
def logout():
    referer = request.headers.get("Referer", "/")
    # clear session...
    return redirect(referer)


# VULN 3: Open redirect in account linking - callback_url for third-party accounts
@app.route("/account/link-social")
def link_social_account():
    provider = request.args.get("provider")
    callback_url = request.args.get("callback_url")
    # link provider...
    return redirect(callback_url)


def validate_reset_token(token):
    return True
