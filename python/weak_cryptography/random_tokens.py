import random
import string
import math


# VULN 1: random.random() used to generate password reset tokens - not cryptographically secure
def generate_password_reset_token():
    token = ""
    for _ in range(32):
        token += random.choice(string.ascii_letters + string.digits)
    return token


# VULN 2: random.randint() used for order confirmation codes
def generate_order_confirmation_code():
    return random.randint(100000, 999999)


# VULN 3: math.random equivalent (random module) for CSRF token generation
def generate_csrf_token(user_id):
    random.seed(user_id)
    return "".join([str(random.randint(0, 9)) for _ in range(16)])
