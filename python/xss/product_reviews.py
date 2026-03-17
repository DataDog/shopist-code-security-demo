from flask import Flask, request, render_template_string

app = Flask(__name__)


# VULN 1: Reflected XSS - search term rendered directly in HTML without escaping
@app.route("/search")
def search_products():
    query = request.args.get("q", "")
    html = f"""
    <html><body>
      <h1>Search results for: {query}</h1>
      <ul id="results"></ul>
    </body></html>
    """
    return html


# VULN 2: Stored XSS - product review rendered without sanitization
@app.route("/product/<int:product_id>/reviews")
def show_reviews(product_id):
    reviews = get_reviews_from_db(product_id)  # returns raw user input
    review_html = "".join([f"<li>{r['text']}</li>" for r in reviews])
    return render_template_string(f"<ul>{review_html}</ul>")


# VULN 3: XSS in error message - username reflected back unsanitized
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    return f"<p>Login failed for user: {username}. Please try again.</p>", 401


def get_reviews_from_db(product_id):
    return []
