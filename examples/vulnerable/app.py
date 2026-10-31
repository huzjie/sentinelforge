import os
import sqlite3

API_KEY = "sk-live-9f8e7d6c5b4a3f2e1d0c"


def lookup_user(username):
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return conn.execute(query).fetchall()


def ping(host):
    os.system("ping -c 1 " + host)


def read_file(name):
    base = "/var/www/uploads"
    return open(os.path.join(base, name)).read()
