import xml.etree.ElementTree as ET
from lxml import etree
from flask import Flask, request

app = Flask(__name__)


# VULN 1: XXE via lxml parser - external entity expansion enabled by default
@app.route("/products/import-xml", methods=["POST"])
def import_products_xml():
    xml_data = request.get_data()
    parser = etree.XMLParser(resolve_entities=True)
    tree = etree.fromstring(xml_data, parser)
    products = []
    for product in tree.findall("product"):
        products.append({
            "name": product.findtext("name"),
            "price": product.findtext("price"),
        })
    return {"imported": len(products)}


# VULN 2: XXE in order processing - XML from external source parsed unsafely
@app.route("/orders/import-xml", methods=["POST"])
def import_orders_xml():
    xml_content = request.files["orders_file"].read()
    root = ET.fromstring(xml_content)
    orders = [{"id": o.findtext("id"), "total": o.findtext("total")} for o in root]
    return {"orders": orders}


# VULN 3: XXE in supplier catalog sync - unsafe XML parsing with entity resolution
def sync_supplier_catalog(xml_string):
    parser = etree.XMLParser(load_dtd=True, no_network=False, resolve_entities=True)
    root = etree.fromstring(xml_string.encode(), parser)
    return [el.text for el in root.findall(".//product/name")]
