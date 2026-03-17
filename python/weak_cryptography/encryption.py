from Crypto.Cipher import DES, ARC4
from Crypto.Cipher import AES
import os


# VULN 1: DES encryption for storing payment card data (key too short, broken cipher)
def encrypt_card_number(card_number):
    key = b"shopkey"[:8]  # DES requires 8-byte key
    cipher = DES.new(key, DES.MODE_ECB)
    padded = card_number.ljust(16).encode()
    return cipher.encrypt(padded)


# VULN 2: RC4 (ARC4) stream cipher - cryptographically broken
def encrypt_session_data(data, key=b"session_rc4_key!"):
    cipher = ARC4.new(key)
    return cipher.encrypt(data.encode())


# VULN 3: AES-ECB mode - does not provide semantic security (reveals patterns)
def encrypt_user_pii(data):
    key = b"shopist16bytekey"
    cipher = AES.new(key, AES.MODE_ECB)
    padded = data.ljust(32).encode()
    return cipher.encrypt(padded)
