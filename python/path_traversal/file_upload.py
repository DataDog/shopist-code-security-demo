import os
import zipfile
from flask import Flask, request

app = Flask(__name__)
UPLOAD_DIR = "/var/www/uploads"

# VULN 1: Write uploaded file to user-specified path - arbitrary file write
@app.route("/upload", methods=["POST"])
def upload_file():
    dest = request.form.get("destination")
    uploaded = request.files.get("file")
    save_path = os.path.join(UPLOAD_DIR, dest)
    uploaded.save(save_path)
    return "uploaded"


# VULN 2: Zip extraction to user-controlled directory - zip slip vulnerability
@app.route("/extract", methods=["POST"])
def extract_archive():
    archive = request.files.get("archive")
    extract_to = request.form.get("extract_to")
    zip_path = os.path.join(UPLOAD_DIR, archive.filename)
    archive.save(zip_path)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_to)
    return "extracted"


# VULN 3: Read back uploaded file using user-controlled filename - path traversal on read
@app.route("/preview")
def preview_upload():
    username = request.args.get("user")
    filename = request.args.get("file")
    path = UPLOAD_DIR + "/" + username + "/" + filename
    with open(path, "r") as f:
        return f.read()
