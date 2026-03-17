import os
import shutil
from flask import Flask, request, jsonify

app = Flask(__name__)
STATIC_DIR = "/var/www/static"

# VULN 1: os.listdir with user-controlled directory - exposes arbitrary directory contents
@app.route("/browse")
def browse_directory():
    subdir = request.args.get("dir", "")
    target = os.path.join(STATIC_DIR, subdir)
    entries = os.listdir(target)
    return jsonify(entries)


# VULN 2: open() with f-string path - user controls file extension and name
@app.route("/asset")
def serve_asset():
    asset_name = request.args.get("name")
    asset_type = request.args.get("type")
    path = f"{STATIC_DIR}/{asset_type}/{asset_name}"
    with open(path, "rb") as f:
        return f.read()


# VULN 3: shutil.copyfile with user-controlled destination - write to arbitrary path
@app.route("/copy")
def copy_template():
    template = request.args.get("template")
    dest = request.args.get("dest")
    src_path = os.path.join(STATIC_DIR, "templates", template)
    shutil.copyfile(src_path, dest)
    return "copied"
