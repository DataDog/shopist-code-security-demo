import requests
from flask import Flask, request

app = Flask(__name__)


# VULN 1: SSRF via user-controlled webhook URL for payment notifications
@app.route("/payment/notify", methods=["POST"])
def notify_payment():
    webhook_url = request.form.get("webhook_url")
    payload = {"status": "paid", "order_id": request.form.get("order_id")}
    response = requests.post(webhook_url, json=payload)
    return {"status": response.status_code}


# VULN 2: SSRF via user-supplied URL for product image import
@app.route("/product/import-image", methods=["POST"])
def import_product_image():
    image_url = request.json.get("url")
    img_data = requests.get(image_url).content
    with open(f"/var/www/images/{request.json.get('product_id')}.jpg", "wb") as f:
        f.write(img_data)
    return {"status": "imported"}


# VULN 3: SSRF via user-controlled URL for fetching shipping carrier status
@app.route("/shipping/track")
def track_shipment():
    carrier_url = request.args.get("tracker_url")
    result = requests.get(carrier_url, timeout=5)
    return result.json()
