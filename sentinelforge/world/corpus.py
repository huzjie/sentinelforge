# -*- coding: utf-8 -*-
"""Ground-truth corpus: realistic vulnerable code snippets + benign distractors.

Each sample carries exactly one true finding (type, severity, 1-based line,
human-readable description, remediation guidance and a gold patch). The scanner
runs its regex rules over ``text``; the oracle maps a matched candidate back to
a true finding so we can measure recall / precision / false-positive rate.
"""
from __future__ import annotations


# severity names are ordered by CVSS-like score (see analyze/severity.py)
SEVERITIES = ["critical", "high", "medium", "low", "info"]


def _s(id_, lang, text, findings, benign):
    return {"id": id_, "lang": lang, "text": text, "findings": findings, "benign": benign}


def make_samples():
    """Return the full corpus as a list of sample dicts."""
    samples = []

    samples.append(_s(
        "py_sqli_01", "python",
        """import sqlite3

def lookup_user(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cur.execute(query)
    return cur.fetchall()

def safe_lookup(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cur.fetchall()
""",
        [{"type": "sqli", "severity": "critical", "line": 6,
          "description": "SQL query built by string concatenation with untrusted input.",
          "remediation": "Use parameterized queries (placeholder + tuple) instead of string concatenation.",
          "gold_fix": "cur.execute(\"SELECT * FROM users WHERE name = ?\", (username,))"}],
        [{"line": 11, "text": 'cur.execute("SELECT * FROM users WHERE name = ?", (username,))'},
         {"line": 2, "text": 'conn = sqlite3.connect("app.db")'}],
    ))

    samples.append(_s(
        "py_sqli_02", "python",
        """import mysql.connector

def search(title):
    sql = "SELECT * FROM posts WHERE title LIKE '%" + title + "%'"
    return db.execute(sql)
""",
        [{"type": "sqli", "severity": "critical", "line": 4,
          "description": "SQL LIKE clause assembled via concatenation of untrusted title.",
          "remediation": "Bind parameters: \"LIKE %s\" with (\"%\"+title+\"%\",).",
          "gold_fix": 'sql = "SELECT * FROM posts WHERE title LIKE %s"\nparams = ("%" + title + "%",)'}],
        [{"line": 1, "text": "import mysql.connector"}],
    ))

    samples.append(_s(
        "py_cmdi_01", "python",
        """import os

def ping(host):
    os.system("ping -c 1 " + host)
""",
        [{"type": "cmdi", "severity": "critical", "line": 4,
          "description": "Untrusted host interpolated into a shell command via os.system.",
          "remediation": "Avoid shell; use subprocess.run with an argument list (shell=False).",
          "gold_fix": 'subprocess.run(["ping", "-c", "1", host], shell=False)'}],
        [{"line": 1, "text": "import os"}],
    ))

    samples.append(_s(
        "py_cmdi_02", "python",
        """import subprocess

def convert(path):
    subprocess.call("ffmpeg -i " + path + " out.mp4", shell=True)
""",
        [{"type": "cmdi", "severity": "high", "line": 4,
          "description": "subprocess.call with shell=True and concatenated untrusted path.",
          "remediation": "Pass an argument list and drop shell=True.",
          "gold_fix": 'subprocess.call(["ffmpeg", "-i", path, "out.mp4"])'}],
        [{"line": 1, "text": "import subprocess"}],
    ))

    samples.append(_s(
        "js_xss_01", "javascript",
        """function renderComment(comment) {
  document.getElementById("comments").innerHTML += comment;
}
""",
        [{"type": "xss", "severity": "high", "line": 2,
          "description": "Untrusted comment injected into innerHTML without escaping.",
          "remediation": "Use textContent or an escaping function before inserting into DOM.",
          "gold_fix": 'el.textContent += comment;'}],
        [{"line": 1, "text": "function renderComment(comment) {"}],
    ))

    samples.append(_s(
        "js_xss_02", "javascript",
        """function show(msg) {
  $("#box").html(msg);
}
""",
        [{"type": "xss", "severity": "high", "line": 2,
          "description": "jQuery .html() sinks untrusted msg as raw HTML.",
          "remediation": "Use .text(msg) or sanitize msg before rendering.",
          "gold_fix": '$("#box").text(msg);'}],
        [{"line": 1, "text": "function show(msg) {"}],
    ))

    samples.append(_s(
        "py_secret_01", "python",
        """import requests

API_KEY = "sk-live-9f8e7d6c5b4a3f2e1d0c"
def fetch():
    return requests.get("https://api.example.com", headers={"Authorization": "Bearer " + API_KEY})
""",
        [{"type": "secrets", "severity": "critical", "line": 3,
          "description": "Hardcoded API key literal committed to source.",
          "remediation": "Load the key from an environment variable / secret manager; rotate the exposed key.",
          "gold_fix": 'API_KEY = os.environ["EXAMPLE_API_KEY"]'}],
        [{"line": 1, "text": "import requests"}],
    ))

    samples.append(_s(
        "py_secret_02", "python",
        """DB_PASSWORD = "P@ssw0rd123!"
def connect():
    return pg.connect(host="db", password=DB_PASSWORD)
""",
        [{"type": "secrets", "severity": "high", "line": 1,
          "description": "Hardcoded database password.",
          "remediation": "Store credentials in a secret manager; use runtime injection.",
          "gold_fix": 'DB_PASSWORD = os.environ["DB_PASSWORD"]'}],
        [{"line": 3, "text": 'return pg.connect(host="db", password=DB_PASSWORD)'}],
    ))

    samples.append(_s(
        "py_trav_01", "python",
        """import os

def read_file(name):
    base = "/var/www/uploads"
    return open(os.path.join(base, name)).read()
""",
        [{"type": "pathtraversal", "severity": "high", "line": 5,
          "description": "User-controlled name joined under a base dir without sanitizing '..'.",
          "remediation": "Resolve and verify the real path stays within the base directory.",
          "gold_fix": 'full = os.path.realpath(os.path.join(base, name))\nif not full.startswith(base + os.sep): raise ValueError'}],
        [{"line": 2, "text": "import os"}],
    ))

    samples.append(_s(
        "py_weakcrypto_01", "python",
        """import hashlib

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()
""",
        [{"type": "weakcrypto", "severity": "high", "line": 4,
          "description": "Passwords hashed with MD5 (fast, collision-prone).",
          "remediation": "Use a slow, salted KDF such as hashlib.scrypt or PBKDF2-HMAC.",
          "gold_fix": 'return hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex()'}],
        [{"line": 1, "text": "import hashlib"}],
    ))

    samples.append(_s(
        "py_weakcrypto_02", "python",
        """import hashlib

def sign(data, secret):
    return hashlib.sha1((data + secret).encode()).hexdigest()
""",
        [{"type": "weakcrypto", "severity": "medium", "line": 4,
          "description": "SHA-1 used for integrity; known collision attacks.",
          "remediation": "Use SHA-256 or an HMAC with the secret.",
          "gold_fix": 'return hashlib.sha256((data + secret).encode()).hexdigest()'}],
        [{"line": 1, "text": "import hashlib"}],
    ))

    samples.append(_s(
        "py_ssrf_01", "python",
        """import requests

def proxy(url):
    return requests.get(url).text
""",
        [{"type": "ssrf", "severity": "high", "line": 4,
          "description": "Server fetches an arbitrary user-supplied URL (SSRF).",
          "remediation": "Validate scheme/host against an allow-list; block private ranges.",
          "gold_fix": 'if not allowed_host(url): raise ValueError("disallowed URL")'}],
        [{"line": 1, "text": "import requests"}],
    ))

    samples.append(_s(
        "py_deser_01", "python",
        """import pickle

def load(data):
    return pickle.loads(data)
""",
        [{"type": "deserialization", "severity": "critical", "line": 4,
          "description": "Untrusted data deserialized with pickle (arbitrary code execution).",
          "remediation": "Never unpickle untrusted input; use JSON or a safe schema.",
          "gold_fix": 'import json\nreturn json.loads(data)'}],
        [{"line": 1, "text": "import pickle"}],
    ))

    samples.append(_s(
        "py_openredirect_01", "python",
        """from flask import redirect, request

@app.route("/go")
def go():
    return redirect(request.args.get("next"))
""",
        [{"type": "openredirect", "severity": "medium", "line": 5,
          "description": "Open redirect to a user-controlled 'next' parameter.",
          "remediation": "Validate the target against an allow-list of internal paths.",
          "gold_fix": 'target = request.args.get("next")\nif not target.startswith("/"): return redirect("/")'}],
        [{"line": 1, "text": "from flask import redirect, request"}],
    ))

    samples.append(_s(
        "go_sqli_01", "go",
        """func search(q string) (*sql.Rows, error) {
    query := "SELECT * FROM items WHERE name = '" + q + "'"
    return db.Query(query)
}
""",
        [{"type": "sqli", "severity": "critical", "line": 2,
          "description": "SQL built by concatenating user input in Go.",
          "remediation": "Use placeholders: db.Query(\"SELECT ... WHERE name = ?\", q).",
          "gold_fix": 'query := "SELECT * FROM items WHERE name = ?"\nreturn db.Query(query, q)'}],
        [{"line": 1, "text": "func search(q string) (*sql.Rows, error) {"}],
    ))

    samples.append(_s(
        "go_secret_01", "go",
        """var awsSecret = "AKIAIOSFODNN7EXAMPLE"
var awsKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
""",
        [{"type": "secrets", "severity": "critical", "line": 1,
          "description": "Hardcoded AWS access key id / secret pair.",
          "remediation": "Load credentials from environment or instance role; rotate them.",
          "gold_fix": 'awsSecret := os.Getenv("AWS_SECRET_ACCESS_KEY")'}],
        [{"line": 2, "text": 'var awsKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'}],
    ))

    samples.append(_s(
        "js_cmdi_01", "javascript",
        """const { exec } = require("child_process");

function run(cmd) {
  exec("sh -c " + cmd);
}
""",
        [{"type": "cmdi", "severity": "critical", "line": 4,
          "description": "Untrusted cmd concatenated into a shell command in Node.",
          "remediation": "Use execFile/spawn with an argument array and no shell.",
          "gold_fix": 'spawn(cmd.split(" ")[0], cmd.split(" ").slice(1))'}],
        [{"line": 1, "text": 'const { exec } = require("child_process");'}],
    ))

    samples.append(_s(
        "java_deser_01", "java",
        """public Object load(byte[] data) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    return ois.readObject();
}
""",
        [{"type": "deserialization", "severity": "critical", "line": 2,
          "description": "Java native deserialization of untrusted bytes.",
          "remediation": "Validate with an ObjectInputFilter allow-list before readObject.",
          "gold_fix": 'ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("!*"));'}],
        [{"line": 1, "text": "public Object load(byte[] data) throws Exception {"}],
    ))

    samples.append(_s(
        "py_secret_03", "python",
        """TOKEN = "ghp_0123456789abcdef0123456789abcdef0123"
""",
        [{"type": "secrets", "severity": "critical", "line": 1,
          "description": "Hardcoded GitHub personal access token.",
          "remediation": "Move to environment / secret store; revoke the exposed token.",
          "gold_fix": 'TOKEN = os.environ["GITHUB_TOKEN"]'}],
        [{"line": 1, "text": "TOKEN = ..."}],
    ))

    samples.append(_s(
        "py_ssrf_02", "python",
        """import urllib.request

def fetch(url):
    return urllib.request.urlopen(url).read()
""",
        [{"type": "ssrf", "severity": "high", "line": 4,
          "description": "Arbitrary URL fetched server-side via urllib.",
          "remediation": "Allow-list hosts and schemes; reject private IP ranges.",
          "gold_fix": 'if not is_allowed(url): raise ValueError'}],
        [{"line": 1, "text": "import urllib.request"}],
    ))

    samples.append(_s(
        "py_sqli_03", "python",
        """def get_user(uid):
    q = f"SELECT * FROM users WHERE id = {uid}"
    return db.execute(q)
""",
        [{"type": "sqli", "severity": "critical", "line": 2,
          "description": "f-string interpolates uid directly into SQL.",
          "remediation": "Bind uid as a parameter instead of f-string formatting.",
          "gold_fix": 'q = "SELECT * FROM users WHERE id = ?"\nreturn db.execute(q, (uid,))'}],
        [{"line": 1, "text": "def get_user(uid):"}],
    ))

    samples.append(_s(
        "py_openredirect_02", "python",
        """from django.shortcuts import redirect

def logout(request):
    return redirect(request.GET.get("next", "/"))
""",
        [{"type": "openredirect", "severity": "medium", "line": 4,
          "description": "Open redirect via 'next' query parameter.",
          "remediation": "Validate the target starts with '/' or matches an allow-list.",
          "gold_fix": 'target = request.GET.get("next", "/")\nif not target.startswith("/"): target = "/"'}],
        [{"line": 1, "text": "from django.shortcuts import redirect"}],
    ))

    samples.append(_s(
        "js_xss_03", "javascript",
        """function render(user) {
  document.write("<div>" + user.name + "</div>");
}
""",
        [{"type": "xss", "severity": "high", "line": 2,
          "description": "document.write sinks untrusted user.name without escaping.",
          "remediation": "Escape HTML or use DOM APIs (createElement/textContent).",
          "gold_fix": 'const d = document.createElement("div"); d.textContent = user.name;'}],
        [{"line": 1, "text": "function render(user) {"}],
    ))

    samples.append(_s(
        "py_trav_02", "python",
        """def download(filename):
    path = "/srv/files/" + filename
    return open(path).read()
""",
        [{"type": "pathtraversal", "severity": "high", "line": 2,
          "description": "filename concatenated onto a root path without traversal guard.",
          "remediation": "Reject '..' and resolve within the root directory.",
          "gold_fix": 'if ".." in filename: raise ValueError\npath = os.path.join("/srv/files", filename)'}],
        [{"line": 1, "text": "def download(filename):"}],
    ))

    return samples


def sample_ids():
    return [s["id"] for s in make_samples()]
