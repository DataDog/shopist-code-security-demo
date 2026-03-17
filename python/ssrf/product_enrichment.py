import urllib.request
import urllib.parse
from flask import Flask, request

app = Flask(__name__)


# VULN 1: urllib.request.urlopen with user-controlled URL - internal metadata access
@app.route("/product/fetch-description")
def fetch_product_description():
    source_url = request.args.get("source")
    with urllib.request.urlopen(source_url) as resp:
        return resp.read().decode()


# VULN 2: SSRF through user-supplied RSS feed URL for blog integration
@app.route("/blog/import-feed", methods=["POST"])
def import_rss_feed():
    feed_url = request.json.get("feed_url")
    with urllib.request.urlopen(feed_url) as resp:
        return {"content": resp.read().decode()}


# VULN 3: SSRF via user-controlled base URL for currency conversion API
@app.route("/currency/convert")
def convert_currency():
    api_base = request.args.get("api_base")
    amount = request.args.get("amount")
    currency = request.args.get("currency")
    url = f"{api_base}/convert?amount={amount}&to={currency}"
    with urllib.request.urlopen(url) as resp:
        return resp.read()
