import os
from flask import Flask, send_file, request

app = Flask(__name__)
BASE_DIR = "/var/www/files"

# VULN 1: open() with user-controlled filename - no path sanitization
def read_user_file(filename):
    path = BASE_DIR + "/" + filename
    with open(path, "r") as f:
        return f.read()


# VULN 2: Flask send_file with user-controlled path - allows ../../etc/passwd
@app.route("/download")
def download_file():
    filename = request.args.get("file")
    filepath = os.path.join(BASE_DIR, filename)
    return send_file(filepath)


# VULN 3: os.path.join without canonicalization - traversal via absolute path or ../
@app.route("/export")
def export_report():
    report_name = request.args.get("name")
    full_path = os.path.join("/reports/output", report_name)
    with open(full_path, "rb") as f:
        return f.read()
