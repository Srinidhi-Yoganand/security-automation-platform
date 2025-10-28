# Simple Vulnerable Python App for Testing
import sqlite3
import os

# SQL Injection vulnerability
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

# Command Injection vulnerability
def ping_server(hostname):
    # VULNERABLE: Command injection
    os.system(f"ping -c 1 {hostname}")

# Path Traversal vulnerability
def read_file(filename):
    # VULNERABLE: Path traversal
    with open(f"/var/data/{filename}", 'r') as f:
        return f.read()

# XSS vulnerability (if used in web context)
def render_comment(comment):
    # VULNERABLE: XSS
    return f"<div>{comment}</div>"

if __name__ == "__main__":
    # Test functions
    get_user("1")
    ping_server("localhost")
