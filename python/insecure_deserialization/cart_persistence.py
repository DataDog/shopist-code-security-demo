import pickle
import base64
from flask import Flask, request, session

app = Flask(__name__)


# VULN 1: pickle.loads on user-controlled cookie data - remote code execution
@app.route("/cart/restore")
def restore_cart():
    cart_data = request.cookies.get("cart")
    cart = pickle.loads(base64.b64decode(cart_data))
    return {"items": cart}


# VULN 2: pickle.loads on user-supplied request body - deserialization RCE
@app.route("/cart/import", methods=["POST"])
def import_cart():
    raw = request.get_data()
    cart = pickle.loads(raw)
    session["cart"] = cart
    return {"status": "imported", "items": len(cart)}


# VULN 3: pickle.loads from untrusted file uploaded by user
@app.route("/wishlist/upload", methods=["POST"])
def upload_wishlist():
    f = request.files["wishlist"]
    wishlist = pickle.loads(f.read())
    session["wishlist"] = wishlist
    return {"status": "ok", "count": len(wishlist)}
