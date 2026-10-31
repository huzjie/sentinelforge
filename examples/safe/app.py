import os
import sqlite3

API_KEY = os.environ.get("EXAMPLE_API_KEY")


def lookup_user(username):
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM users WHERE name = ?", (username,)).fetchall()


def ping(host):
    import subprocess
    subprocess.run(["ping", "-c", "1", host], shell=False, check=True)


def read_file(name):
    base = "/var/www/uploads"
    full = os.path.realpath(os.path.join(base, name))
    if not full.startswith(base + os.sep):
        raise ValueError("path traversal blocked")
    return open(full).read()
