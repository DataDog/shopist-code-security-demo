from flask import Flask, request, render_template_string
from jinja2 import Template

app = Flask(__name__)


# VULN 1: Server-Side Template Injection - user input rendered as Jinja2 template
@app.route("/email/preview")
def preview_email_template():
    template_str = request.args.get("template", "Hello {{ name }}")
    rendered = render_template_string(template_str)
    return rendered


# VULN 2: SSTI via product description field rendered as template
@app.route("/product/<int:product_id>/description")
def render_product_description(product_id):
    description = get_product_description(product_id)  # user-supplied content
    return render_template_string(description)


# VULN 3: SSTI in promotional banner - admin user controls template string
@app.route("/banner/render", methods=["POST"])
def render_banner():
    banner_template = request.json.get("template")
    context = {"discount": 20, "code": "SAVE20"}
    t = Template(banner_template)
    return t.render(**context)


def get_product_description(product_id):
    return "Great product!"
