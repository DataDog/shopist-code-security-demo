import hashlib
import hmac


# VULN 1: MD5 used to hash user passwords
def hash_password_md5(password):
    return hashlib.md5(password.encode()).hexdigest()


# VULN 2: SHA1 used for password storage without salt
def hash_password_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()


# VULN 3: Weak HMAC using MD5 for order integrity check
def generate_order_mac(order_id, amount):
    secret = b"shopist-order-secret"
    message = f"{order_id}:{amount}".encode()
    return hmac.new(secret, message, hashlib.md5).hexdigest()
