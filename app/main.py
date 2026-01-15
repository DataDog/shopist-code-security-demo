# Shopist Backend - Code Security Demo
# Contains LOW, MEDIUM, and HIGH severity code quality violations

import os
import sys
import json
import pickle
import hashlib
import subprocess
import random
import sqlite3

# ============================================================
# HIGH SEVERITY VIOLATIONS
# ============================================================

# HIGH: Hardcoded credentials
DATABASE_PASSWORD = "SuperSecret123!"
API_SECRET_KEY = "sk-prod-1234567890abcdef"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# HIGH: SQL Injection vulnerability
def get_user_by_id(user_id):
    conn = sqlite3.connect('shopist.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()

# HIGH: SQL Injection in search
def search_products(search_term):
    conn = sqlite3.connect('shopist.db')
    cursor = conn.cursor()
    query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    cursor.execute(query)
    return cursor.fetchall()

# HIGH: Command Injection vulnerability
def generate_report(report_name):
    os.system("echo 'Report' > /tmp/" + report_name + ".txt")

# HIGH: Command injection with subprocess
def backup_database(filename):
    subprocess.call("pg_dump shopist > " + filename, shell=True)

# HIGH: Insecure deserialization with pickle
def load_user_session(session_data):
    return pickle.loads(session_data)

# HIGH: Insecure deserialization from file
def restore_cart(cart_file):
    with open(cart_file, 'rb') as f:
        return pickle.load(f)

# HIGH: Path traversal vulnerability
def get_product_image(image_name):
    image_path = "/var/www/images/" + image_name
    with open(image_path, 'rb') as f:
        return f.read()

# HIGH: Arbitrary file read
def read_config(config_name):
    return open("/etc/shopist/" + config_name).read()

# HIGH: SSRF vulnerability
def fetch_product_data(url):
    import urllib.request
    return urllib.request.urlopen(url).read()

# ============================================================
# MEDIUM SEVERITY VIOLATIONS
# ============================================================

# MEDIUM: Weak hashing algorithm (MD5)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# MEDIUM: Weak hashing (SHA1)
def generate_token(data):
    return hashlib.sha1(data.encode()).hexdigest()

# MEDIUM: Insecure random number generation
def generate_session_id():
    return str(random.randint(100000, 999999))

# MEDIUM: Insecure random for password reset
def generate_reset_token():
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    token = ""
    for i in range(32):
        token += chars[random.randint(0, len(chars) - 1)]
    return token

# MEDIUM: Missing input validation
def update_user_profile(user_id, data):
    conn = sqlite3.connect('shopist.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET name = ?, email = ? WHERE id = ?", 
                   (data['name'], data['email'], user_id))
    conn.commit()

# MEDIUM: Cleartext storage of sensitive data
def save_credit_card(user_id, card_number, cvv, expiry):
    conn = sqlite3.connect('shopist.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO cards VALUES (?, ?, ?, ?)", 
                   (user_id, card_number, cvv, expiry))
    conn.commit()

# MEDIUM: Insecure temp file creation
def create_temp_report():
    import tempfile
    return tempfile.mktemp()

# ============================================================
# LOW SEVERITY VIOLATIONS
# ============================================================

# LOW: Unused variables, high cyclomatic complexity, too many parameters
def process_order(order, user, discount, shipping, tax, extra1, extra2, extra3):
    x = 0
    y = 0
    temp = None
    unused_var = "never used"
    
    if order:
        if order['items']:
            if len(order['items']) > 0:
                if user:
                    if user['active']:
                        if discount > 0:
                            if shipping:
                                if tax:
                                    x = 1
                                else:
                                    x = 2
                            else:
                                x = 3
                        else:
                            x = 4
                    else:
                        x = 5
                else:
                    x = 6
            else:
                x = 7
        else:
            x = 8
    else:
        x = 9
    
    total = 0
    for i in range(len(order['items'])):
        total = total + order['items'][i]['price']
    
    return total

# LOW: Bare except clause
def get_user(id):
    try:
        data = open("/tmp/users.json").read()
        return json.loads(data)
    except:
        pass
    return None

# LOW: Code duplication
def format_price(price):
    return "$" + str(price)

def format_currency(amount):
    return "$" + str(amount)

def format_money(value):
    return "$" + str(value)

# LOW: Boolean comparison anti-pattern
def is_admin(user):
    if user.get('admin') == True:
        return True
    else:
        return False

# LOW: Inefficient string concatenation in loop
def build_query_string(params):
    result = ""
    for key in params:
        result = result + key + "=" + str(params[key]) + "&"
    return result

# LOW: Print statements instead of logging
def log_message(msg):
    print(msg)
    
def log_error(msg):
    print("ERROR: " + msg)

