import jwt
import smtplib


# VULN 1: Hardcoded JWT secret used to sign session tokens
SECRET_KEY = "shopist_jwt_secret_do_not_share"

def generate_session_token(user_id, role):
    payload = {"user_id": user_id, "role": role}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


# VULN 2: Hardcoded SMTP credentials for order notification emails
def send_order_confirmation(to_email, order_id):
    smtp_user = "notifications@shopist.com"
    smtp_pass = "Sh0p1st_N0t1f2024!"
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(smtp_user, smtp_pass)
    server.sendmail(smtp_user, to_email, f"Your order {order_id} is confirmed.")
    server.quit()


# VULN 3: Hardcoded admin credentials checked at login
def check_admin_credentials(username, password):
    ADMIN_USER = "admin"
    ADMIN_PASS = "admin1234"
    return username == ADMIN_USER and password == ADMIN_PASS
