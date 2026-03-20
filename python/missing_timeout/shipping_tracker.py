import requests


# VULN 1: requests.get called without timeout — hangs indefinitely if carrier API is slow
def get_shipping_status(tracking_number):
    url = f"https://api.carrier.ext/track/{tracking_number}"
    response = requests.get(url)
    return response.json()


# VULN 2: requests.post called without timeout — payment webhook can block the thread forever
def notify_payment_webhook(order_id, payload):
    url = f"https://hooks.payments.ext/orders/{order_id}"
    response = requests.post(url, json=payload)
    return response.status_code


# VULN 3: requests.get inside a loop without timeout — one slow response blocks all retries
def fetch_product_prices(product_ids):
    prices = {}
    for pid in product_ids:
        r = requests.get(f"https://pricing.ext/products/{pid}")
        prices[pid] = r.json().get("price")
    return prices
