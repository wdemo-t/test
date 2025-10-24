from flask import Flask, request, jsonify, send_file
import sqlite3
import os
import subprocess
import pickle
import hashlib
import requests
from helper import generate_token, weak_hash

app = Flask(__name__)

# Hardcoded credentials (insecure)
ADMIN_USER = "admin"
ADMIN_PASS = "password123"  # intentionally weak and hardcoded

DB_PATH = "/mnt/data/vuln_app.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Simple users table
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    # Insert a test user with weak hash
    c.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'alice', ?)",
              (weak_hash("alicepw"),))
    conn.commit()
    conn.close()

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    # Insecure password check using the weak hash function and string concat in SQL (SQL injection)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = "SELECT id FROM users WHERE username = '%s' AND password = '%s'" % (username, weak_hash(password))
    # Vulnerable: using string formatting for SQL queries
    c.execute(query)
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({"status": "ok", "user_id": row[0]})
    return jsonify({"status": "fail"}), 401

@app.route("/search")
def search():
    # Uses eval on user input (extremely dangerous)
    expr = request.args.get("expr", "2+2")
    try:
        # Dangerous: evaluating arbitrary expressions from users
        result = eval(expr)
        return jsonify({"result": str(result)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/run")
def run():
    # Command injection via unsanitized shell invocation
    filename = request.args.get("file", "ls")
    # Dangerous: passing user input into shell command
    output = subprocess.check_output("ls " + filename, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    return jsonify({"output": output})

@app.route("/upload_pickle", methods=["POST"])
def upload_pickle():
    # Insecure: unpickling user-supplied data
    f = request.files.get("data")
    if not f:
        return "no file", 400
    data = f.read()
    obj = pickle.loads(data)  # Vulnerable: arbitrary code execution via pickle
    return jsonify({"loaded_type": str(type(obj))})

@app.route("/fetch")
def fetch():
    # Insecure HTTP request with SSL verification disabled
    url = request.args.get("url", "https://example.com")
    r = requests.get(url, verify=False)  # insecure: disable cert verification
    return jsonify({"status_code": r.status_code, "len": len(r.content)})

@app.route("/token")
def token():
    # Uses insecure token generator
    t = generate_token()
    return jsonify({"token": t})

@app.route("/download_log")
def download_log():
    # Insecure file path handling (path traversal)
    fname = request.args.get("name", "app.log")
    path = os.path.join("/mnt/data/logs", fname)  # no sanitization
    if not os.path.exists(path):
        return "not found", 404
    return send_file(path, as_attachment=True)

if __name__ == "__main__":
    os.makedirs("/mnt/data/logs", exist_ok=True)
    # write a sample log file
    with open("/mnt/data/logs/app.log", "w") as fh:
        fh.write("sample log")
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
