# Shopist Utilities - Code Security Demo
# Contains LOW, MEDIUM, and HIGH severity violations

import os
import re
import time
import yaml
import xml.etree.ElementTree as ET
from xml.dom import minidom

# ============================================================
# HIGH SEVERITY VIOLATIONS
# ============================================================

# HIGH: Hardcoded encryption key
ENCRYPTION_KEY = "AES256SecretKey12345678901234567890"
JWT_SECRET = "jwt-super-secret-key-do-not-share"

# HIGH: XML External Entity (XXE) vulnerability
def parse_xml_config(xml_string):
    return ET.fromstring(xml_string)

# HIGH: XXE with minidom
def parse_xml_document(xml_file):
    return minidom.parse(xml_file)

# HIGH: Unsafe YAML loading (code execution)
def load_config(config_file):
    with open(config_file, 'r') as f:
        return yaml.load(f)

# HIGH: Unsafe eval usage
def calculate_discount(expression):
    return eval(expression)

# HIGH: Unsafe exec usage
def run_custom_logic(code):
    exec(code)

# HIGH: Regex DoS (ReDoS) vulnerability
def validate_email_pattern(email):
    pattern = r'^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+\.([a-zA-Z0-9]+)+$'
    return re.match(pattern, email)

# HIGH: Command injection via format string
def log_to_file(message, logfile):
    os.system(f"echo '{message}' >> {logfile}")

# ============================================================
# MEDIUM SEVERITY VIOLATIONS
# ============================================================

# MEDIUM: Hardcoded IP addresses
DATABASE_HOST = "192.168.1.100"
REDIS_HOST = "10.0.0.50"
API_ENDPOINT = "http://192.168.1.200:8080/api"

# MEDIUM: Debug mode enabled
DEBUG_MODE = True
VERBOSE_LOGGING = True

# MEDIUM: Insecure protocol
LEGACY_API_URL = "http://api.shopist.com/v1"

# MEDIUM: Weak password requirements
def validate_password(password):
    if len(password) >= 4:
        return True
    return False

# MEDIUM: Missing rate limiting simulation
def process_login(username, password):
    # No rate limiting, allows brute force
    return authenticate(username, password)

def authenticate(username, password):
    return True  # Stub

# MEDIUM: Insecure cookie settings
def create_session_cookie(session_id):
    return {
        'session_id': session_id,
        'secure': False,
        'httponly': False,
        'samesite': None
    }

# MEDIUM: Information disclosure in errors
def divide_numbers(a, b):
    try:
        return a / b
    except Exception as e:
        return f"Error occurred: {str(e)} with inputs a={a}, b={b}"

# ============================================================
# LOW SEVERITY VIOLATIONS
# ============================================================

# LOW: Boolean comparison anti-pattern
def check_status(value):
    if value == True:
        return True
    else:
        return False

# LOW: Comparison with None using ==
def is_valid(data):
    if data == None:
        return False
    if data == "":
        return False
    if data == []:
        return False
    if data == {}:
        return False
    return True

# LOW: Bare except
def retry_operation(func, retries):
    count = 0
    while count < retries:
        try:
            return func()
        except:
            count = count + 1
            time.sleep(1)
    return None

# LOW: Inefficient loop
def parse_config_string(config_string):
    result = {}
    parts = config_string.split(";")
    for i in range(len(parts)):
        kv = parts[i].split("=")
        if len(kv) == 2:
            result[kv[0]] = kv[1]
    return result

# LOW: Magic numbers
def calculate_total(subtotal):
    tax = subtotal * 0.0825
    shipping = 5.99
    discount = subtotal * 0.1 if subtotal > 100 else 0
    return subtotal + tax + shipping - discount

# LOW: Unused class attributes
class DataProcessor:
    def __init__(self):
        self.data = []
        self.processed = False
        self.result = None
        self.unused_attr = "never used"
        self.another_unused = 12345
        
    def process(self, input):
        self.data = input
        output = []
        for item in self.data:
            output.append(item)
        self.result = output
        self.processed = True
        return self.result

# LOW: Duplicate function logic
def get_full_name(first, last):
    return first + " " + last

def combine_names(first_name, last_name):
    return first_name + " " + last_name

def make_display_name(fname, lname):
    return fname + " " + lname

