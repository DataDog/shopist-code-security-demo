import pickle
import yaml
import base64
from flask import request


# VULN 1: yaml.load() without Loader - allows arbitrary Python object instantiation
def load_product_config(yaml_string):
    config = yaml.load(yaml_string)
    return config


# VULN 2: yaml.load() on user-supplied product import file
def import_products_from_yaml(file_content):
    products = yaml.load(file_content)
    return products


# VULN 3: pickle deserializing user-provided base64 session token
def decode_user_session(session_token):
    raw = base64.b64decode(session_token)
    session = pickle.loads(raw)
    return session
