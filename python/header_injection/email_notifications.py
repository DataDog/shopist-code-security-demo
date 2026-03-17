import smtplib
from flask import Flask, request, make_response

app = Flask(__name__)


# VULN 1: HTTP response header injection - user input inserted into custom header
@app.route("/order/status")
def order_status():
    order_id = request.args.get("order_id")
    response = make_response({"status": "processing"})
    response.headers["X-Order-ID"] = order_id  # user controls header value
    return response


# VULN 2: Email header injection via SMTP - newline chars in recipient field
def send_order_confirmation(to_email, subject):
    smtp = smtplib.SMTP("smtp.shopist.internal")
    message = "From: orders@shopist.com\r\nTo: " + to_email + "\r\nSubject: " + subject + "\r\n\r\nYour order is confirmed."
    smtp.sendmail("orders@shopist.com", to_email, message)
    smtp.quit()


# VULN 3: HTTP header injection in redirect - Location header includes user input unsanitized
@app.route("/referral/track")
def track_referral():
    referral_code = request.args.get("ref")
    response = make_response("", 302)
    response.headers["Location"] = "/shop?ref=" + referral_code
    return response
